# VirusTotal URL Scanner

## Overview

A Python-based URL scanning tool that automates URL analysis using the VirusTotal API v3.

The tool reads URLs from an input file, submits them to VirusTotal, retrieves analysis results, and classifies URLs based on security engine detection statistics.

## Features

- Bulk URL scanning from a text file.
- VirusTotal API v3 integration.
- Automated analysis status polling.
- Detection-based URL classification.
- Duplicate URL removal.
- Separate output files for each verdict.
- Exception handling for HTTP and connection errors.
- Scanning progress and summary statistics.

## Classification Logic

The tool uses a simple detection-based classification rule:

- **Malicious:** At least one security engine reports a malicious detection.
- **Clean:** No malicious detections are reported.

Note: Clean is an operational classification based on this tool's rule. It does not guarantee that a URL is safe.

## Requirements

- Python 3.x
- Requests library
- VirusTotal API key

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Add URLs to `file.txt`, one URL per line.
2. Run the script:

```bash
python scanner.py
```


## Output Files

| File | Description |
|---|---|
| clean.txt | URLs with zero malicious detections |
| malicious.txt | URLs with at least one malicious detection |
## Disclaimer

This project is intended for educational purposes and defensive security research.

The classification logic is intentionally simplified and should not be treated as a definitive security verdict.

VirusTotal API usage is subject to its applicable rate limits and terms of service.
