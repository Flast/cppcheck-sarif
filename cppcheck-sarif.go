package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
)

type cppLocation struct {
	XMLName xml.Name `xml:"location"`
	File    string   `xml:"file,attr"`
	Line    int      `xml:"line,attr"`
	Column  int      `xml:"column,attr"`
	Info    string   `xml:"info,attr,omitempty"`
}

type cppError struct {
	XMLName      xml.Name      `xml:"error"`
	Id           string        `xml:"id,attr"`
	Severity     string        `xml:"severity,attr"`
	Msg          string        `xml:"msg,attr"`
	Verbose      string        `xml:"verbose,attr"`
	Inconclusive bool          `xml:"inconclusive,attr,omitempty"`
	CWE          int           `xml:"cwe,attr,omitempty"`
	Locations    []cppLocation `xml:"location,omitempty"`
	Symbol       string        `xml:"symbol,omitempty"`
}

type cppErrors struct {
	XMLName xml.Name   `xml:"errors"`
	Errors  []cppError `xml:"error"`
}

type cppTool struct {
	XMLName xml.Name `xml:"cppcheck"`
	Version string   `xml:"version,attr"`
}

type cppResults struct {
	XMLName  xml.Name  `xml:"results"`
	Version  int       `xml:"version,attr"`
	Cppcheck cppTool   `xml:"cppcheck"`
	Errors   cppErrors `xml:"errors"`
}

func main() {
	outfile := flag.String("output", "", "Output SARIF file name")

	flag.Parse()

	infile := flag.Arg(0)

	var input io.Reader = os.Stdin
	var output io.Writer = os.Stdout

	if infile != "" {
		file, err := os.Open(infile)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			return
		}
		defer file.Close()

		input = file
	}

	if *outfile != "" {
		file, err := os.OpenFile(*outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			return
		}
		defer file.Close()

		output = file
	}

	bytes, err := io.ReadAll(input)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	var result cppResults
	if err := xml.Unmarshal(bytes, &result); err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	bytes, err = xml.Marshal(&result)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	fmt.Fprint(output, string(bytes))
}
