package main

import (
	"bufio"
	"fmt"
	"os"
)

func outPutFile(outPut error) error {
	f, err := os.OpenFile("results.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(outPut.Error() + "\n")
	if err != nil {
		return err
	}
	return nil

}

func createOutPutFile() {
	// write output file
	f, err := os.Create("results.csv")
	check(err)
	defer f.Close()

	w := bufio.NewWriter(f)
	// String to put into file
	_, err = fmt.Fprintf(w, "%s", columnNames+"\n")
	check(err)
	w.Flush()
	f.Close()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
