# PQC Reporter — Enterprise DevSecOps Audit Engine

An advanced, containerized utility that aggregates DevSecOps pipeline outputs and ingests SAST, SCA, secrets and CBOM JSON and produces a print-ready PDF executive audit report (cover, scorecard, findings, charts). 

The engine utilizes Pandas for deep data extraction, Matplotlib/Seaborn for modular analytics charting, renders an HTML template with Jinja2, and WeasyPrint to render a mathematically precise A4 print stylesheet.

## Key features

- Consolidates findings from Semgrep-style SAST (`gl-sast-report.json`), Grype/Scan SCA (`vulnerabilities.json`), Gitleaks-style secret reports, and a final CBOM (`final-cbom.json`).
- Produces an `Executive_Audit_Report.pdf` and supporting PNG charts.
- Uses a printable A4 stylesheet tuned for WeasyPrint.
- **Advanced Analytics Engine:** Automatically calculates risk matrices and generates modular infographics, including Threat Landscapes, Cryptographic Profiles, and CVSS vs. EPSS scatter plots.
- **Hybrid CBOM Discovery:** Uses strict Regex and keyword analysis to identify cryptographic libraries (like `bcrypt` or `sha256-js`) even if the upstream scanner fails to tag them properly. Extracts PURLs, licenses, and integrity hashes for compliance auditing.
- **Strict Null-Safety & Fallbacks:** Highly resilient data parsing that gracefully handles malformed JSON arrays, missing keys, or custom scanner severities (e.g., automatically categorizing unknown severity strings to prevent pipeline crashes).

## Docker Deployment (Recommended)

The reporting engine is designed to run via Docker to isolate the heavy graphical dependencies (Cairo, Pango, WeasyPrint) from your host system or CI/CD runner.

### Option A: Quick Start (Pre-built Image)
The fastest way to use the reporter is via our published images in Dockerhub or GHRC. Docker will automatically pull the image if you don't have it locally.

Run the container using the Docker Hub registry:
```bash
docker run --rm -v "/absolute/path/to/project:/data" sujitheag/devsecops-pqc-reporter:latest \
  --input-dir /data/pqc-reports \
  --cbom /data/final-cbom.json \
  --output-dir /data/pqc-reports/report \
  --project-name "My Project"
```

Note: To use the GitHub Container Registry instead, swap the image name to `ghcr.io/sujith-eag/devsecops-pqc-reporter:latest`

---

### Option B: Build from Source (Local Development)
If you are modifying the HTML templates or the Python engine, you can build and run the image locally.

**1. Build the Image:**
```bash
docker build -t devsecops-pqc-reporter .
```

**2. Run the Report Generator:**
Mount your project directory to `/data` inside the container. The dynamic ownership sync will ensure the resulting PDF and PNGs are instantly editable by your local user.

```bash
docker run --rm -v "/absolute/path/to/project:/data" devsecops-pqc-reporter \
  --input-dir /data/pqc-reports \
  --cbom /data/final-cbom.json \
  --output-dir /data/pqc-reports/report \
  --project-name "My Project"
```

**Argument Reference:**
* `--input-dir`: Directory containing `gl-sast-report.json`, `vulnerabilities.json`, and `gl-secret-detection-report.json`.
* `--cbom`: Explicit path to your Cryptographic Bill of Materials (`final-cbom.json`).
* `--output-dir`: Directory where the final `Executive_Audit_Report.pdf` and analytical `.png` charts will be saved.
* `--project-name`: The title printed on the PDF Cover Page.

## Installation (local / virtualenv)

1. Create and activate a Python 3.12 virtual environment.

2. Install system dependencies required by WeasyPrint (Debian/Ubuntu):

```bash
sudo apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libjpeg-dev \
    libopenjp2-7-dev \
    libffi-dev \
    libcairo2 \
    fonts-liberation
```
3. Install the Python dependencies:

```bash
pip install --upgrade pip
pip install weasyprint==68.1 \
    Jinja2 \
    pandas \
    matplotlib \
    seaborn
```

4. Execute the orchestrator:

Run the report generator with the required arguments:

```bash
python main.py \
  --input-dir /path/to/json-reports \
  --cbom /path/to/final-cbom.json \
  --output-dir /path/to/output-dir \
  --project-name "Project Name"
```

## Project Architecture

```text
├── Dockerfile               # Minimal, root-proxied Python 3.12 container
├── README.md
└── src/                     # Application Source Code
    ├── main.py              # Orchestrator & Dynamic Permission Sync
    ├── data_parser.py       # Pandas extraction, CBOM hybrid rules
    ├── visualizer.py        # Modular ChartEngine (Seaborn/Matplotlib)
    └── templates/           
        ├── report.html      # Jinja2 Layout (2-column data presentation)
        └── styles.css       # Print-specific @page directives
```

## Files of interest

- `data_parser.py` — extracts and normalizes SAST, SCA and CBOM data into pandas structures.
- `visualizer.py` — generates the PNG charts used in the report.
- `main.py` — orchestrates data extraction, templating, and PDF compilation.
- `templates/report.html` and `templates/styles.css` — HTML template and print stylesheet used by WeasyPrint.

