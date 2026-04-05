PQC Reporter — DevSecOps Executive Audit Report

A utility that ingests SAST, SCA, secrets and CBOM JSON outputs and produces a print-ready PDF executive audit report (cover, scorecard, findings, charts). The application renders an HTML template with Jinja2, generates figures with Matplotlib/Seaborn, and compiles the final PDF with WeasyPrint.

## Key features

- Consolidates findings from Semgrep-style SAST (`gl-sast-report.json`), Grype/Scan SCA (`vulnerabilities.json`), Gitleaks-style secret reports, and a final CBOM (`final-cbom.json`).
- Produces an `Executive_Audit_Report.pdf` and supporting PNG charts.
- Uses a printable A4 stylesheet tuned for WeasyPrint.

## Requirements

System packages required by WeasyPrint (Debian/Ubuntu):

- libpango-1.0-0
- libpangoft2-1.0-0
- libharfbuzz-subset0
- libjpeg-dev
- libopenjp2-7-dev
- libffi-dev
- libcairo2
- fonts-liberation

Python runtime: `python:3.12-slim`

Python packages:

- `weasyprint==68.1`
- `Jinja2`
- `pandas`
- `matplotlib`
- `seaborn`

## Installation (local / virtualenv)

1. Create and activate a Python 3.12 virtual environment.
2. Install system dependencies required by WeasyPrint (see Requirements).
3. Install the Python dependencies:

```bash
pip install --upgrade pip
pip install weasyprint==68.1 Jinja2 pandas matplotlib seaborn
```

## Usage

Run the report generator with the required arguments:

```bash
python main.py \
  --input-dir /path/to/json-reports \
  --cbom /path/to/final-cbom.json \
  --output-dir /path/to/output-dir \
  --project-name "Project Name"
```

Notes:

- `--input-dir` should contain the expected report files: `gl-sast-report.json`, `vulnerabilities.json`, and `gl-secret-detection-report.json` (when available).
- `--cbom` must point to the CBOM JSON file containing cryptographic components.
- The program writes `Executive_Audit_Report.pdf` and chart PNG files into `--output-dir`.

## Docker

The included Dockerfile builds a minimal container based on `python:3.12-slim`, installs the required system libraries for WeasyPrint and the Python stack, copies the application files and templates, and runs as a non-root user `reporter`.

Build the image:

```bash
docker build -t pqc-reporter .
```

Run the container (example):

```bash
docker run --rm -v "/absolute/path/to/project:/data" pqc-reporter \
  --input-dir /data/pqc-reports \
  --cbom /data/final-cbom.json \
  --output-dir /data/pqc-reports/report \
  --project-name "My Project"
```

## Files of interest

- `data_parser.py` — extracts and normalizes SAST, SCA and CBOM data into pandas structures.
- `visualizer.py` — generates the PNG charts used in the report.
- `main.py` — orchestrates data extraction, templating, and PDF compilation.
- `templates/report.html` and `templates/styles.css` — HTML template and print stylesheet used by WeasyPrint.

