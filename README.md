# Inception
**Inception** is a highly configurable tool to check for whatever you like against any number of hosts.

This tool comes handy for bugbounty hunters who want to check for specific endpoint on large number of hosts and report if the endpoint contains certain string in response.

Inception is a Go version of [Snallygaster](https://github.com/hannob/snallygaster) and comes with a large number of test cases derived from Snallygaster plus more, added by me.    

Default test cases includes: test for publicly accesible git config file, .env file, magento config file, php info file, server stats page, Rails and Symfony database config files, CORS Misconfiguration check, basic XSS check at web root and few others.    

What differentiate Inception from Snallygaster is - it allows users to create & provide their own test cases without touching a single line of code.

The use of goroutine makes it very fast but it doesn't hammer a single domain concurrently with a large number of requests.

### Installation
Just make sure you have go installed and run the following command.
```sh
go get github.com/proabiral/inception
```

### Usage
```
▶️  inception -h
    Usage of inception:
      -d string
          Path of list of domains to run against (default "/home/user/go/src/github.com/proabiral/inception/domains.txt")
      -provider string
          Path of provider file (default "/home/user/go/src/github.com/proabiral/inception/provider.json")
      -t int
          No of threads (default 200)
      -silent
    	Only prints when issue detected
      -timeout int
          HTTP request Timeout (default 10)
      -v Verbose mode
```
   
#### Examples
```
▶️ inception -d /path/to/domainlist.txt
Issue detected : Server status is publicly viewable http://127.0.0.1/server-status response contains all check
Issue detected : PHP info is publicly viewable http://127.0.0.1/phpinfo.php response contains all check
Completed
```
All detected issues will be printed on screen as shown above. While if no issue is detected, a completion message is shown as `Completed`.    
Note: If error like `provider.json: no such file or directory` is thrown, provide the path of provider.json {default one located at your-gopath/src/github.com/proabiral/inception/provider.json} file with -provider option.    
    
### FAQs
Q. How should my domain list look like?    
A sample of domain list is provided with the tool. It's basically a list of line seperated domains without no protocol.
```
facebook.com
twitter.com
gmail.com
hackerone.com
bugcrowd.com
```

Q. How do I add my own test cases?    
You can use [providerCreate.html](https://proabiral.github.io/inception/providerCreate.html) to generate JSON. Just fill in the details and JSON as shown below will be generated.
```
[
   {
      "vulnerability":"Git Exposed publicly",
      "sendIn":"url",
      "payload":["/.git/config"],
      "checkIn":"responseBody",
      "checkFor":"[core]",
      "color":"red"
    },
    {
      "vulnerability": "XSS",
      "sendIn": "url",
      "color": "red",
      "payload": [
          "/?canary'\"><svg onload=alert(1)>"
      ],
      "checkIn": "responseBody",
      "checkFor": "<svg onload=alert(1)>"
    }
]
```
Save the generated JSON to some file and then run the tool by providing the path to the json file with `-provider` option:
```
▶️  inception -provider /path/to/your/provider.json -d /path/to/your/domainlist.txt
```

Q. Whats with the name?    
The name of tool is inspired from the movie Inception where DiCaprio steals secrets from subconscious mind of people. Similar to movie, this tool steal secrets from webserver.    
Also, `inception` because this is the first tool I am open sourcing.

### TODO
1. Add more vulnerability checks
2. Implement ReGex search in Response
3. Add key to each test case in provider.json and option to select/ignore a test case
4. Output result to file
5. Randomize User-Agent
6. Code refactor

## Thanks 
Thanks to [Iceman](https://twitter.com/Ice3man543) for reviewing the tool and suggesting this cool name.
Also concurrency module has been shamelessly stolen from his [Subover project](https://github.com/Ice3man543/SubOver)

