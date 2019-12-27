package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"
	. "github.com/logrusorgru/aurora"
	"github.com/proabiral/gorequest"
	"strconv"
	"net/url"
	"golang.org/x/net/publicsuffix"
)

type Provider struct {
	Vulnerability string     `json:"vulnerability"`
	Method        string     `json:"method"`
	Body          string     `json:"body"`
	Endpoint      []string   `json:"endpoint"`
	SendIn        string     `json:"sendIn"`
	Headers       [][]string `json:"headers"`
	CheckIn       string     `json:"checkIn"`
	CheckFor      string     `json:"checkFor"`
	Color         string     `json:"color"`
	StatusCode    []int      `json:"statusCode"`
}

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
	DomainList   string
	Threads      int
	Verbose      bool
	ProviderFile string
	Timeout      int
	Silent       bool
	https        bool
)

var (
	delimiter    string
	ifVulnerable bool
	match        string
	scheme       string
)

func readFile(file string) string {
	contentByte, err := ioutil.ReadFile(file)
	errCheck(err)
	content := string(contentByte)
	return content
}

func readLines(file string) []string {
	domainSrc, err := os.Open(file)
	errCheck(err)
	defer domainSrc.Close() //defer executes at end of function
	scanner := bufio.NewScanner(domainSrc)
	domains := []string{}
	for scanner.Scan() {
		domain := scanner.Text()
		domains = append(domains, domain)
	}
	return domains
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

func stringReplacer(URL string, value string) (string,error){
	u, err := url.Parse(URL)
	if err != nil {
		printIfNotSilent(err.Error())
		return "",err
	}

	fqdn:=u.Host
	domain, _ := publicsuffix.EffectiveTLDPlusOne(fqdn)
	tld, _ := publicsuffix.PublicSuffix(fqdn)
	hostname := strings.Replace(domain, "."+tld, "", -1)
	r := strings.NewReplacer("$fqdn", fqdn,
		"$domain", domain,
		"$hostname", hostname)
	// Replace all pairs.
	result := r.Replace(value)
	return result,nil
}

func request(domain string, provider Provider) []error {
	var URL string
	if https {
		scheme = "https://"
	} else {
		scheme = "http://"
	}

	// get array of Endpoint and loop endpoint here, so that same bug can be checked on multiple endpoint.
	for _, endpoint := range provider.Endpoint {

		if (strings.Contains(domain, "://")){
			URL = domain + endpoint
		}	else{
		// if URL with http:// or https:// is not passed scheme is added
			URL = scheme + domain + endpoint
		}

		//replacing keywords {$domain, $hostname, $fqdn} from endpoints,vulnerability name, body and checkFor if any
		// need to find a way to replace headers
		URL,err:=stringReplacer(URL,URL)
		if (err != nil) {
			continue
		}
		provider.Vulnerability,_=stringReplacer(URL,provider.Vulnerability)
		provider.Body,_ = stringReplacer(URL,provider.Body)
		provider.CheckFor,_ = stringReplacer(URL,provider.CheckFor)

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
				fmt.Println(err)
				return nil
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
				return nil
			}
			defer response.Body.Close()

			checker(URL, response, body, provider, endpoint)
		}
	}
	return nil
}

func checkerLogic(checkAgainst string, stringToCheck []string) (bool, string) { //need a better logic to shorten this function

	isCompleteMatch := true

	matches := 0

	for _, checkfor := range stringToCheck {
		if strings.Contains(checkAgainst, checkfor) { //checkAgainst body , checkFor string like [core]
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
		return true, "all check"
	}
	return true, "Error, check code returned from last return statement" //  golang throws error without return at end, all return statements are inside if else so golang needs to make sure if function returns
}

func printFunc(provider Provider, domain string, statusCode int) {
	if ifVulnerable {
		fmt.Println("Issue detected    -", color(provider.Color, provider.Vulnerability))
		fmt.Println("Endpoint          - "+domain)
		fmt.Println("Headers           - ")
		for _, header := range(provider.Headers){
			fmt.Print("                   ")
			fmt.Println(header[0],":",header[1])
		}

		fmt.Println("Request Body      - "+provider.Body)

		fmt.Println("")
		fmt.Println("")

		fmt.Println("Response Status Code  - "+strconv.Itoa(statusCode))

		fmt.Println(provider.CheckIn+" contains - "+provider.CheckFor)
		fmt.Println("          --------------------------------------------------------------------------------          ")
	}	
}

func checker(URL string, response gorequest.Response, body string, provider Provider, endpoint string) {

	var stringToCheck []string
	var vulnerable bool

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
			ifVulnerable, match = checkerLogic(body, stringToCheck)
			printFunc(provider, URL, statusCode)
		} else {
			var responseHeaders string
			for headerName, value := range response.Header {
				responseHeaders += headerName + ": " + value[0] + "\n"
			}
			ifVulnerable, match = checkerLogic(responseHeaders, stringToCheck)
			printFunc(provider, URL, statusCode)
		}
	}

	if (len(provider.StatusCode)==0){//when not defined.
		wrapper(response.StatusCode) // check for stings defined in provider
	} else {
		// loop through provider.StatusCode and call wrapper and end the loop if any match
		for _, statusCode := range provider.StatusCode {
			if statusCode == response.StatusCode {
				wrapper(statusCode) // check for stings defined in provider
				vulnerable=true
				break
			}
		}
		if !vulnerable {
			ifVulnerable, match = false, "not vulnerable" //if statusCode does not match ; not vulnerable
		}
	}
}

func main() {

	path := os.Getenv("GOPATH") + "/src/github.com/proabiral/inception/"

	flag.IntVar(&Threads, "t", 200, "No of threads")
	flag.StringVar(&ProviderFile, "provider", path+"provider.json", "Path of provider file")
	flag.StringVar(&DomainList, "d", path+"domains.txt", "Path of list of domains to run against")
	flag.BoolVar(&Verbose, "v", false, "Verbose mode")
	flag.BoolVar(&Silent, "silent", false, "Only prints when issue detected") //using silent and verbose together will print domains and payloads but will supress message like Reading from file
	flag.IntVar(&Timeout, "timeout", 10, "HTTP request Timeout")
	flag.BoolVar(&https, "https", false, "force https (works only if scheme is not provided in domain list")
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

	printIfNotSilent("Reading Domains from list at " + DomainList)

	domains := readLines(DomainList)

	hosts := make(chan string, Threads)
	providerC := make(chan Provider)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	printIfNotSilent("Running test cases against provided domains ..... ")

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

	printIfNotSilent("Completed")

}
