// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"
)

const maxConnections = 4

var (
	warnYears  = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays   = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
)
var checkHosts []string

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] host:port ...\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	flag.Parse()

	// Sanity check the warning thresholds.
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

	// Anything that's not a flag is treated as a host to check.
	checkHosts = flag.Args()
	if len(checkHosts) == 0 {
		printUsage()
		os.Exit(1)
	}
}

func main() {
	checkCertChan := make(chan string, maxConnections)
	defer close(checkCertChan)
	processingChan := make(chan interface{}, maxConnections+1)
	defer close(processingChan)

	for i := 0; i < maxConnections; i++ {
		go processHost(checkCertChan, processingChan)
	}

	for _, host := range checkHosts {
		checkCertChan <- host
	}

	for {
		if len(checkCertChan) == 0 && len(processingChan) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func processHost(hostChan <-chan string, processing chan interface{}) {
	for {
		host := <-hostChan
		processing <- nil
		checkCert(host)
		<-processing
	}
}

func checkCert(host string) {
	// Attempt to connect to the host.
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", host, err)
		return
	}
	defer conn.Close()

	var expiresIn int64
	currentTime := time.Now()
	checkedCert := make(map[string]interface{})

	// Check all certificates in the chain.
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			// Only check each certificate once.
			if _, checked := checkedCert[string(cert.Signature)]; checked {
				continue
			}
			checkedCert[string(cert.Signature)] = nil

			// Check the expiration date.
			if currentTime.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn = int64(cert.NotAfter.Sub(currentTime).Hours())
				if expiresIn <= 48 {
					fmt.Fprintf(os.Stdout, "%s: %s expires in %d hours!\n", host, cert.Subject.CommonName, expiresIn)
				} else {
					fmt.Fprintf(os.Stdout, "%s: %s expires in roughly %d days.\n", host, cert.Subject.CommonName, expiresIn/24)
				}
			}
		}
	}
}
