# cppcheck-sarif

[![Go Report Card](https://goreportcard.com/badge/github.com/Flast/cppcheck-sarif)](https://goreportcard.com/report/github.com/Flast/cppcheck-sarif)

cppcheck-sarif is a converter which converts cppcheck xml report to Static Analysis Results Interchange Format (SARIF).

## Build

```sh
go build .
```

## Example usage

```sh
cppcheck --xml --output-file=report.xml .
cppcheck-sarif report.xml -output report.sarif
```
