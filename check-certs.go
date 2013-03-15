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
	// No need to spawn a Go routine in we're just checking one host.
	if len(checkHosts) == 1 {
		checkCert(checkHosts[0], nil)
		return
	}

	var completed int
	ch := make(chan int)
	for _, host := range checkHosts {
		go checkCert(host, ch)
	}
	for {
		completed += <-ch
		if completed == len(checkHosts) {
			break
		}
	}
}

func checkCert(host string, ch chan int) {
	// Signal when we are done checking this host.
	defer func() {
		if ch != nil {
			ch <- 1
		}
	}()

	// Attempt a connection to the host.
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", host, err)
		return
	}
	defer conn.Close()

	checkedCert := make(map[string]bool)
	var expiresIn int64
	curTime := time.Now()
	// Check all of the certs in the chain.
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			// Ensure that each unique certificate is checked only once per host.
			if _, checked := checkedCert[string(cert.Signature)]; checked {
				continue
			}
			checkedCert[string(cert.Signature)] = true

			if curTime.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn = int64(cert.NotAfter.Sub(curTime).Hours())
				if expiresIn < 24 {
					fmt.Printf("%s: %s expires in %d hours!\n", host, cert.Subject.CommonName, expiresIn)
				} else {
					fmt.Printf("%s: %s expires in roughly %d days.\n", host, cert.Subject.CommonName, expiresIn/24)
				}
			}
		}
	}
}
