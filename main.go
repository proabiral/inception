package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"bufio"
	"github.com/parnurzeal/gorequest"
	"strings"
	"encoding/json"
	"sync"
	"crypto/tls"
	"time"
	"flag"
	."github.com/logrusorgru/aurora"
)

type Provider struct{
	Vulnerability string `json:"vulnerability"`
	SendIn string `json:"sendIn"`
	Payload []string `json:"payload"`
	CheckIn string `json:"checkIn"`
	CheckFor string `json:"checkFor"`
	Color string `json:"color"`
}

func color(c string,text string) Value  {
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
)

var (
	delimiter string
	ifVulnerable bool
	match string
)

func readFile(file string) string{
	contentByte, err := ioutil.ReadFile(file)
	errCheck(err)
	content := string(contentByte)
	return content
}

func readLines(file string) []string{
	domainSrc, err := os.Open(file)
	errCheck(err)
	defer domainSrc.Close()   //defer executes at end of function
	scanner := bufio.NewScanner(domainSrc)
	domains := []string{}
	for scanner.Scan(){
		domain := scanner.Text()
		domains = append(domains, domain)
	}
	return domains
}

func errCheck(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func request(domain string, provider Provider) {
		if provider.SendIn == "url" {
			for _, payload := range (provider.Payload) {
				url := "http://" + domain + payload
				response, body, err := gorequest.New().
					TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
					Timeout(time.Second*10).
					Get(url).
					Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36").
					End()

				if Verbose {
					fmt.Println(url)
					if err != nil {
						fmt.Println(err)
					}
				}
				checker(domain, response, body, provider, payload)
			}

		} else if provider.SendIn == "header" {
			url := "http://" + domain
			//need to rewrite , need to better represent in json
			for i := 0; i < len(provider.Payload); i += 2 {
				response, body, err := gorequest.New().
					TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
					Timeout(time.Second*10).
					Get(url).
					Set(provider.Payload[i], provider.Payload[i+1]).
					Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36").
					End()

			if Verbose {
				fmt.Println(url, provider.Payload[i], provider.Payload[i+1])
				if err != nil {
					fmt.Println(err)
				}
			}
				checker(domain, response, body, provider, provider.Payload[i])

			}
		}
}

func checkerLogic(checkAgainst string, stringToCheck []string) (bool,string){   //need a better logic to shorten this function

	isCompleteMatch := true

	matches := 0

	for _,checkfor:= range stringToCheck{
		if strings.Contains(checkAgainst,checkfor){  //checkAgainst body , checkFor string like [core]
			matches += 1
			// returns immediately in case of |||| delimiter for match so that other test can be omitted
			if delimiter=="||||"{
				return true,checkfor //vulnerable
			}
		} else {
			isCompleteMatch = false
			// returns immediately in case of &&&& if one no match so that other test can be omitted
			if delimiter=="&&&&"{
				return false,"not vulnerable" //not vulnerable
			}
		}
	}

	if matches==0{
		return false,"not vulnerable"
	}

	if isCompleteMatch==true{
		return true,"all check"
	}
	return true,"Error, check code returned from last return statement" //  golang throws error without return at end, all return statements are inside if else so golang needs to make sure if function returns
}

func printFunc(provider Provider, domain string, payload string){
	if ifVulnerable {
		if provider.SendIn == "url" {
			fmt.Println("Issue detected :", color(provider.Color, provider.Vulnerability), "http://"+domain+payload, "response contains", match)
		} else {
			fmt.Println("Issue detected :", color(provider.Color, provider.Vulnerability), domain, "Payload Send",payload, "response contains", match)
		}
	}
}

func checker(domain string, response gorequest.Response, body string,  provider Provider, payload string)  {

	var stringToCheck []string

	if strings.Contains(provider.CheckFor,"&&&&"){
		stringToCheck=strings.Split(provider.CheckFor,"&&&&")
		delimiter="&&&&"
	} else {
		stringToCheck=strings.Split(provider.CheckFor,"||||")
		delimiter="||||"
	}

	//color:=provider.Color
	if provider.CheckIn == "responseBody"{
		ifVulnerable,match=checkerLogic(body,stringToCheck)
		printFunc(provider,domain,payload)
	}	else{
			var responseHeaders string
			for headerName, value := range response.Header {
				responseHeaders+=headerName+": "+value[0]+"\n"
			}
			ifVulnerable, match= checkerLogic(responseHeaders, stringToCheck)
			printFunc(provider,domain,payload)
	}
}

func main() {

	path:=os.Getenv("GOPATH")+"/src/github.com/proabiral/Inception/"

	flag.IntVar(&Threads,"t",200,"No of threads")
	flag.StringVar(&ProviderFile,"provider",path+"provider.json","Path of provider file")
	flag.StringVar(&DomainList,"d",path+"domains.txt","Path of list of domains to run against")
	flag.BoolVar(&Verbose,"v",false,"Verbose mode")
	flag.IntVar(&Timeout,"timeout",10,"HTTP request Timeout")
	flag.Parse()

	contentJson := readFile(ProviderFile)

	err := json.Unmarshal([]byte(contentJson), &myProvider)
	errCheck(err)

	domains := readLines(DomainList)

	hosts := make(chan string, Threads)
	providerC := make(chan Provider)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	for i := 0; i < Threads; i++ {
		go func() {
			for {
				host := <-hosts
				providerS := <- providerC

				if host == "" {
					break
				}
				request(host,providerS)
			}
			processGroup.Done()
		}()
	}

	for _, provider := range (myProvider) {
		for _, domain := range (domains) {
			hosts <- domain
			providerC <- provider
		}
	}

	close(hosts)
	close(providerC)
	processGroup.Wait()

	fmt.Println("Completed")
}