package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	. "github.com/logrusorgru/aurora"
	"github.com/proabiral/gorequest"
	"github.com/proabiral/inception/helpers"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/go-playground/validator.v10"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Provider struct {
	Vulnerability string     `json:"vulnerability" validate:"required"`
	Method        string     `json:"method"`
	Body          string     `json:"body"`
	Endpoint      []string   `json:"endpoint" validate:"required"`
	SendIn        string     `json:"sendIn"`
	Headers       [][]string `json:"headers"`
	CheckIn       string     `json:"checkIn"`
	CheckFor      string     `json:"checkFor"`
	Color         string     `json:"color"`
	StatusCode    []int      `json:"statusCode"`
	RegexCheck    bool       `json:"regexCheck"`
	ContentLength struct {
		Length   int    `json:"length"`
		Operator string `json:"operator"`
	} `json:"contentLength"`
}

type VulnerabilityJson struct {
	Vulnerability    string `json:"vulnerability"`
	Endpoint         string `json:"endpoint"`
	StatusCode       int    `json:"statusCode"`
	ResponseContains string `json:"responseContains,omitempty"`
}

var JsonOutput []VulnerabilityJson

func color(c string, text string) Value {
	switch c {
	case "blue":
		return Bold(Blue(text))
	case "red":
		return Bold(Red(text))
	case "yellow":
		return Bold(Brown(text))
	default:
		return Bold(Red(text))
	}
}

var myProvider []Provider

var (
	DomainList    string
	Threads       int
	Verbose       bool
	ProviderFile  string
	OutputFile    string
	Timeout       int
	Silent        bool
	https         bool
	caseSensitive bool
	noProgressBar bool
)

var (
	delimiter    string
	ifVulnerable bool
	match        string
	scheme       string
)

var bar *pb.ProgressBar

func readFile(file string) string {
	contentByte, err := ioutil.ReadFile(file)
	errCheck(err)
	content := string(contentByte)
	return content
}

func readLines(r io.Reader) []string {
	scanner := bufio.NewScanner(r)
	domains := []string{}
	for scanner.Scan() {
		domain := scanner.Text()
		domain = strings.TrimSpace(domain)
		domains = append(domains, domain)
	}
	return domains
}

func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

func errCheck(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func printIfNotSilent(message string) {
	if !Silent {
		fmt.Println(message)
	}
}

func stringReplacer(URL string, value string) (string, error) {
	u, err := url.Parse(URL)
	if err != nil {
		printIfNotSilent(err.Error())
		return "", err
	}

	fqdn := u.Host
	domain, _ := publicsuffix.EffectiveTLDPlusOne(fqdn)
	tld, _ := publicsuffix.PublicSuffix(fqdn)
	hostname := strings.Replace(domain, "."+tld, "", -1)
	r := strings.NewReplacer("$fqdn", fqdn,
		"$domain", domain,
		"$hostname", hostname)
	// Replace all pairs.
	result := r.Replace(value)
	return result, nil
}

func request(domain string, provider Provider) []error {
	var URL string
	if https {
		scheme = "https://"
	} else {
		scheme = "http://"
	}

	// get array of Endpoint and loop endpoint here, so that same bug can be checked on multiple endpoint.
	for count, endpoint := range provider.Endpoint {

		if strings.Contains(domain, "://") {
			URL = domain + endpoint
		} else {
			// if URL with http:// or https:// is not passed scheme is added
			URL = scheme + domain + endpoint
		}

		//replacing keywords {$domain, $hostname, $fqdn} from endpoints,vulnerability name, body and checkFor if any
		// need to find a way to replace headers
		URL, err := stringReplacer(URL, URL)
		if err != nil {
			continue
		}
		provider.Vulnerability, _ = stringReplacer(URL, provider.Vulnerability)
		provider.Body, _ = stringReplacer(URL, provider.Body)
		provider.CheckFor, _ = stringReplacer(URL, provider.CheckFor)

		//   Replacing header does not works
		//for _,header := range provider.Headers {
		//	header[0] = stringReplacer(URL,header[0])
		//	header[1] = stringReplacer(URL,header[1])
		//}

		method := provider.Method
		if len(provider.Headers) == 0 { // todo correct this if statement, when no header is supplied.
			response, body, err := gorequest.New().
				TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
				Timeout(time.Second*10).
				CustomMethod(method, URL).
				Set("Referer", scheme+domain+"/").
				Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36").
				Send(provider.Body).
				End()

			if err != nil {
				if Verbose {
					fmt.Println(err)
					fmt.Println("skipping other endpoints (if any) for this vulnerability")
				}
				incrementTimes := len(provider.Endpoint) - count
				if !noProgressBar {
					for i := 0; i < incrementTimes; i++ {
						bar.Increment() //since the loop is returned on error, other endpoints for the vulnerability are skipped, but the counter needs to be increased.
					}
				}
				return nil
			} else {
				if !noProgressBar {
					bar.Increment()
				}
			}
			defer response.Body.Close()

			checker(URL, response, body, provider, endpoint)
		} else {
			response, body, err := gorequest.New().
				TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
				Timeout(time.Second*10).
				Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36").
				CustomMethod(method, URL).
				CustomHeader(provider.Headers). //added this method this gorequest library ... need to fork that library and import in this project so that everone pulling this could use it
				Send(provider.Body).
				End()

			if err != nil {
				if Verbose {
					fmt.Println(err)
					fmt.Println("skipping other endpoints (if any) for this vulnerability")
				}
				incrementTimes := len(provider.Endpoint) - count
				if !noProgressBar {
					for i := 0; i < incrementTimes; i++ {
						bar.Increment()
					}
				}
				return nil
			} else {
				if !noProgressBar {
					bar.Increment()
				}
			}
			defer response.Body.Close()

			checker(URL, response, body, provider, endpoint)
		}
	}
	return nil
}

func checkerLogic(checkAgainst string, stringToCheck []string, regexCheck bool) (bool, string) { //need a better logic to shorten this function

	isCompleteMatch := true
	matched := true
	matches := 0
	if !caseSensitive {
		checkAgainst = strings.ToLower(checkAgainst)
	}
	for _, checkfor := range stringToCheck {
		if regexCheck {
			var err error
			if !caseSensitive {
				checkfor = "(?i)" + checkfor
			}
			matched, err = regexp.Match(checkfor, []byte(checkAgainst))
			if matched {
				re := regexp.MustCompile(checkfor)
				checkfor = string(re.Find([]byte(checkAgainst))) // for printing what regex matched
			}
			if err != nil {
				log.Println(err)
			}
		} else {
			if !caseSensitive {
				checkfor = strings.ToLower(checkfor)
			}
			matched = strings.Contains(checkAgainst, checkfor) //checkAgainst body , checkFor string like [core]
		}
		if matched {
			matches += 1
			// returns immediately in case of |||| delimiter for match so that other test can be omitted
			if delimiter == "||||" {
				return true, checkfor //vulnerable
			}
		} else {
			isCompleteMatch = false
			// returns immediately in case of &&&& if one no match so that other test can be omitted
			if delimiter == "&&&&" {
				return false, "not vulnerable" //not vulnerable
			}
		}
	}

	if matches == 0 {
		return false, "not vulnerable"
	}

	if isCompleteMatch == true {
		return true, "all provided checks"
	}
	return true, "Error, check code returned from last return statement" //  golang throws error without return at end, all return statements are inside if else so golang needs to make sure if function returns
}

func printFunc(provider Provider, domain string, statusCode int, match string) {

	if ifVulnerable {

		fmt.Println("Issue detected    -", color(provider.Color, provider.Vulnerability))

		var vulJson VulnerabilityJson
		vulJson.Vulnerability = provider.Vulnerability
		vulJson.Endpoint = domain
		vulJson.StatusCode = statusCode

		fmt.Println("Endpoint          - " + domain)

		if len(provider.Headers) > 0 {
			fmt.Println("Headers           - ")
			for _, header := range provider.Headers {
				fmt.Print("                   ")
				fmt.Println(header[0], ":", header[1])
			}
		}

		if provider.Body != "" {
			fmt.Println("Request Body      - " + provider.Body)
		}

		fmt.Println("")
		fmt.Println("")

		fmt.Println("Response Status Code  - " + strconv.Itoa(statusCode))

		if provider.CheckFor != "" {
			vulJson.ResponseContains = match
			fmt.Println(provider.CheckIn + " contains - " + match)
		}

		fmt.Println("          --------------------------------------------------------------------------------          ")

		JsonOutput = append(JsonOutput, vulJson)
	}
}

func checker(URL string, response gorequest.Response, body string, provider Provider, endpoint string) {

	var stringToCheck []string

	//get status code to match from provider, if nostatus code present leave as it is. If present, status code must be matched to procced furhter check.....

	if strings.Contains(provider.CheckFor, "&&&&") {
		stringToCheck = strings.Split(provider.CheckFor, "&&&&")
		delimiter = "&&&&"
	} else {
		stringToCheck = strings.Split(provider.CheckFor, "||||")
		delimiter = "||||"
	}

	wrapper := func(statusCode int) {
		if provider.CheckIn == "responseBody" {
			ifVulnerable, match = checkerLogic(body, stringToCheck, provider.RegexCheck)
			printFunc(provider, URL, statusCode, match)
		} else {
			var responseHeaders string
			for headerName, value := range response.Header {
				responseHeaders += headerName + ": " + value[0] + "\n"
			}
			ifVulnerable, match = checkerLogic(responseHeaders, stringToCheck, provider.RegexCheck)
			printFunc(provider, URL, statusCode, match)
		}
	}

	statusCodeCheck := func() {
		if len(provider.StatusCode) == 0 { //when not defined.

			wrapper(response.StatusCode) // check for stings defined in provider
		} else {
			// loop through provider.StatusCode and call wrapper and end the loop if any match
			for _, statusCode := range provider.StatusCode {
				if statusCode == response.StatusCode {
					wrapper(statusCode) // check for stings defined in provider
					break
				}
			}
		}
	}

	if provider.ContentLength.Length != 0 {
		if provider.ContentLength.Operator == "<" {
			if provider.ContentLength.Length < int(response.ContentLength) {
				statusCodeCheck()
			}
		} else if provider.ContentLength.Operator == "=" {
			if provider.ContentLength.Length == int(response.ContentLength) {
				statusCodeCheck()
			}
		} else if provider.ContentLength.Operator == ">" {
			if provider.ContentLength.Length > int(response.ContentLength) {
				statusCodeCheck()
			}
		}
	} else {
		statusCodeCheck()
	}
}

func main() {

	path := os.Getenv("GOPATH") + "/src/github.com/proabiral/inception/"

	flag.IntVar(&Threads, "t", 200, "No of threads")
	flag.StringVar(&ProviderFile, "provider", path+"provider.json", "Path of provider file")
	flag.StringVar(&OutputFile, "o", "", "File to write JSON result")
	flag.StringVar(&DomainList, "d", path+"domains.txt", "Path of list of domains to run against")
	flag.BoolVar(&Verbose, "v", false, "Verbose mode")
	flag.BoolVar(&Silent, "silent", false, "Only prints when issue detected") //using silent and verbose together will print domains and payloads but will supress message like Reading from file
	flag.IntVar(&Timeout, "timeout", 10, "HTTP request Timeout")
	flag.BoolVar(&https, "https", false, "force https (works only if scheme is not provided in domain list")
	flag.BoolVar(&caseSensitive, "caseSensitive", false, "case sensitive checks")
	flag.BoolVar(&noProgressBar, "noProgressBar", false, "hide progress bar")
	flag.Parse()

	printIfNotSilent(`
(_)                    | | (_)            
 _ _ __   ___ ___ _ __ | |_ _  ___  _ __  
| | '_ \ / __/ _ \ '_ \| __| |/ _ \| '_ \ 
| | | | | (_|  __/ |_) | |_| | (_) | | | |
|_|_| |_|\___\___| .__/ \__|_|\___/|_| |_|
                 | |                      
                 |_|                      

	
	`)

	printIfNotSilent("Reading Providers from list at " + ProviderFile)

	contentJson := readFile(ProviderFile)

	err := json.Unmarshal([]byte(contentJson), &myProvider)
	errCheck(err)

	validate := validator.New()
	for i, _ := range myProvider {
		err = validate.Struct(myProvider[i])
		if err != nil {
			log.Printf("Error on index number %d of given JSON Fingerprint Array", i)
		}
		errCheck(err)
	}

	printIfNotSilent("Reading Domains from list at " + DomainList)

	domainSrc, err := os.Open(DomainList)
	errCheck(err)
	defer domainSrc.Close() //defer executes at end of function
	domainCount, err := lineCounter(domainSrc)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error while counting: %v", err)
		os.Exit(1)
	}

	printIfNotSilent("Domain Count : " + strconv.Itoa(domainCount))
	endpointCount := 0
	for _, provider := range myProvider {
		endpointCount += len(provider.Endpoint)
	}
	printIfNotSilent("Total Number of Endpoints : " + strconv.Itoa(endpointCount))

	requestCount := domainCount * endpointCount
	printIfNotSilent("Total Number of Requests to be sent : " + strconv.Itoa(requestCount))

	domainSrc, err = os.Open(DomainList)
	errCheck(err)
	defer domainSrc.Close() //defer executes at end of function
	domains := readLines(domainSrc)

	hosts := make(chan string, Threads)
	providerC := make(chan Provider)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	printIfNotSilent("Running test cases against provided domains ..... ")

	// create and start new bar
	if !noProgressBar {
		bar = pb.Full.Start(requestCount)
	}
	for i := 0; i < Threads; i++ {
		go func() {
			for {
				host := <-hosts
				providerS := <-providerC

				if host == "" {
					break
				}
				error := request(host, providerS)
				if Verbose {
					if error != nil {
						fmt.Println(error)
					}
				}
			}
			processGroup.Done()
		}()
	}

	for _, provider := range myProvider {
		for _, domain := range domains {
			hosts <- domain
			providerC <- provider
		}
	}

	close(hosts)
	close(providerC)
	processGroup.Wait()
	if !noProgressBar {
		bar.Finish()
	}

	b, err := json.MarshalIndent(JsonOutput, "", "    ")
	if err != nil {
		fmt.Println(err)
	}

	if OutputFile != "" {
		helpers.WriteFile(b, OutputFile)
		printIfNotSilent("Result written to file " + OutputFile)
	}

	printIfNotSilent("Completed")
}
