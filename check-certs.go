// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"
)

const defaultConcurrency = 8

var (
	hostsFile   = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	warnYears   = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths  = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays    = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	concurrency = flag.Int("concurrency", defaultConcurrency, "Maximum number of hosts to check at once.")
)

type certExpiration struct {
	commonName string
	expiresAt  time.Time
}

type hostResult struct {
	host  string
	err   error
	certs []certExpiration
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

	timeNow := time.Now()
	for r := range results {
		if r.err != nil {
			log.Printf("%s: %v\n", r.host, r.err)
			continue
		}
		for _, cert := range r.certs {
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.expiresAt) {
				expiresIn := int64(cert.expiresAt.Sub(timeNow).Hours())
				if expiresIn <= 48 {
					log.Printf("%s: ** %s expires in %d hours! **\n", r.host, cert.commonName, expiresIn)
				} else {
					log.Printf("%s: %s expires in roughly %d days.\n", r.host, cert.commonName, expiresIn/24)
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
		host: host,
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		result.err = err
		return
	}
	defer conn.Close()

	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}
			result.certs = append(result.certs, certExpiration{
				commonName: cert.Subject.CommonName,
				expiresAt:  cert.NotAfter,
			})
		}
	}

	return
}
