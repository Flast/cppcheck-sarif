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
cppcheck-sarif -output report.sarif report.xml
```

## GitHub Action usage

```
name: cppcheck

on:
  push:
    branches:
      - master

jobs:
  upload-sarif:
    runs-on: ubuntu-24.04
    permissions:
      security-events: write
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@v4

      - run: |
          sudo apt-get install -y cppcheck

      - run: |
          cppcheck --enable=all --xml --output-file=report.xml .

      - uses: Flast/cppcheck-sarif@v1
        with:
          input: report.xml
          output: report.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
          category: cppcheck
```
