// Copyright (C) 2024 Kohei Takahashi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/xml"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
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

func mapSeverity(sev string) string {
	switch sev {
	case "error", "warning":
		return sev
	case "information":
		return "note"
	}
	return "none"
}

func sanitizeColumn(col int) int {
	if col == 0 {
		return 1
	} else {
		return col
	}
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
			panic(err)
		}
		defer file.Close()

		input = file
	}

	if *outfile != "" {
		file, err := os.OpenFile(*outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		output = file
	}

	bytes, err := io.ReadAll(input)
	if err != nil {
		panic(err)
	}

	var result cppResults
	if err := xml.Unmarshal(bytes, &result); err != nil {
		panic(err)
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}

	run := sarif.NewRunWithInformationURI("cppcheck", "https://cppcheck.sourceforge.io/")
	run.Tool.Driver.SemanticVersion = &result.Cppcheck.Version

	for _, err := range result.Errors.Errors {
		if err.Id == "checkersReport" {
			continue
		}

		run.AddRule(err.Id).
			WithDescription(err.Id)

		for _, loc := range err.Locations {
			run.AddDistinctArtifact(loc.File)
		}

		result := run.CreateResultForRule(err.Id).
			WithLevel(mapSeverity(strings.ToLower(err.Severity))).
			WithMessage(sarif.NewTextMessage(err.Msg))

		for _, loc := range err.Locations {
			region := sarif.NewRegion().
				WithStartLine(loc.Line).
				WithStartColumn(sanitizeColumn(loc.Column))
			if loc.Info != "" {
				region.WithTextMessage(loc.Info)
			}
			result.AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(sarif.NewSimpleArtifactLocation(loc.File)).
						WithRegion(region)))
		}
	}

	report.AddRun(run)

	_ = report.PrettyWrite(output)
}
