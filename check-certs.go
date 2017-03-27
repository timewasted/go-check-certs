// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"
)

const defaultConcurrency = 8

var (
	columnNames        = "Hostname -- Common Name -- S/N -- Time to expire -- Expiration date"
	errExpiringShortly = "%s: ** '%s' (S/N %X) expires in %d hours ** at %s!"
	errExpiringSoon    = "%s: '%s' (S/N %X) expires in roughly %d days on %s"
	errSunsetAlg       = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s' on %s."
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

var (
	hostsFile    = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	warnYears    = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths   = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays     = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg  = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
	concurrency  = flag.Int("concurrency", defaultConcurrency, "Maximum number of hosts to check at once.")
	outPutToFile = flag.Bool("output", false, "Output results to csv")        // create output file results.csv for results
	serveFile    = flag.Bool("serve", false, "Serve output csv on port 8080") // create outputfile and serve results.csv on port 8080
)

type certErrors struct {
	commonName string
	errs       []error
}

type hostResult struct {
	host  string
	err   error
	certs []certErrors
}

func main() {

	flag.Parse()

	if len(*hostsFile) == 0 {
		flag.Usage()
		return
	}
	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	if *concurrency < 0 {
		*concurrency = defaultConcurrency
	}
	if *outPutToFile {
		changeToCSV()
		// create output file for results, the writing occurs in processHosts
		createOutPutFile()
	}
	if *serveFile {
		*outPutToFile = true // set this so that writing occurs in processHosts
		changeToCSV()
		createOutPutFile()
		processHosts()
		serveHTTP()
	}

	//check hosts
	processHosts()
}

func processHosts() {
	done := make(chan struct{})
	defer close(done)

	hosts := queueHosts(done)
	results := make(chan hostResult)

	var wg sync.WaitGroup
	wg.Add(*concurrency)
	for i := 0; i < *concurrency; i++ {
		go func() {
			processQueue(done, hosts, results)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			fmt.Printf("%s: %v", r.host, r.err)
			continue
		}
		fmt.Println(columnNames)
		for _, cert := range r.certs {
			for _, err := range cert.errs {
				fmt.Println(err)
				// write output file
				if *outPutToFile {
					outPutFile(err)
				}
			}
		}
	}
}

func queueHosts(done <-chan struct{}) <-chan string {
	hosts := make(chan string)
	go func() {
		defer close(hosts)

		fileContents, err := ioutil.ReadFile(*hostsFile)
		if err != nil {
			return
		}
		lines := strings.Split(string(fileContents), "\n")
		for _, line := range lines {
			host := strings.TrimSpace(line)
			if len(host) == 0 || host[0] == '#' {
				continue
			}
			select {
			case hosts <- host:
			case <-done:
				return
			}
		}
	}()
	return hosts
}

func processQueue(done <-chan struct{}, hosts <-chan string, results chan<- hostResult) {
	for host := range hosts {
		select {
		case results <- checkHost(host):
		case <-done:
			return
		}
	}
}

func checkHost(host string) (result hostResult) {
	result = hostResult{
		host:  host,
		certs: []certErrors{},
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		result.err = err
		return
	}
	defer conn.Close()

	timeNow := time.Now()
	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}
			cErrs := []error{}

			// Check the expiration.
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				if expiresIn <= 48 {
					cErrs = append(cErrs, fmt.Errorf(errExpiringShortly, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn, cert.NotAfter))
				} else {
					cErrs = append(cErrs, fmt.Errorf(errExpiringSoon, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24, cert.NotAfter))
				}
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					cErrs = append(cErrs, fmt.Errorf(errSunsetAlg, host, cert.Subject.CommonName, cert.NotAfter, alg.name, cert.NotAfter))
				}
			}

			result.certs = append(result.certs, certErrors{
				commonName: cert.Subject.CommonName,
				errs:       cErrs,
			})
		}
	}

	return
}

func changeToCSV() {
	columnNames = "hostname, Common Name, S/N, time to expire, expiration date"
	errExpiringShortly = "%s,  ** '%s', (S/N %X), %d hours **, %s"
	errExpiringSoon = "%s, '%s', (S/N %X), %d days, %s"
	errSunsetAlg = "%s, '%s', (S/N %X), expires after the sunset date for its signature algorithm '%s'., %s"
}
