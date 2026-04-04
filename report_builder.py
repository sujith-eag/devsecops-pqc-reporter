import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from weasyprint import HTML
from jinja2 import Template

# --- Configuration & Paths ---
INPUT_DIR = "/src/pqc-reports"
CBOM_FILE = "/src/final-cbom.json"
REPORT_DIR = os.path.join(INPUT_DIR, "report")
os.makedirs(REPORT_DIR, exist_ok=True)

SAST_FILE = os.path.join(INPUT_DIR, "gl-sast-report.json")
SCA_FILE = os.path.join(INPUT_DIR, "vulnerabilities.json")
SECRETS_FILE = os.path.join(INPUT_DIR, "gl-secret-detection-report.json")

# --- 1. Safe JSON Loader ---
def load_json_safely(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data if data else {}
    except json.JSONDecodeError:
        return {}

# --- 2. Data Extraction Functions ---
def extract_sast():
    data = load_json_safely(SAST_FILE)
    # Based on snippet, Semgrep uses 'vulnerabilities' array
    vulnerabilities = data.get('vulnerabilities', [])
    
    findings = []
    for issue in vulnerabilities:
        loc = issue.get('location', {})
        findings.append({
            'severity': issue.get('severity', 'Unknown'),
            'rule': issue.get('identifiers', [{}])[0].get('name', 'Unknown Rule'),
            'file': loc.get('file', 'Unknown File'),
            'line': loc.get('start_line', 'N/A'),
            'message': issue.get('message', '')
        })
    return pd.DataFrame(findings)

def extract_sca():
    data = load_json_safely(SCA_FILE)
    # Grype typically outputs a 'matches' array
    matches = data.get('matches', [])
    
    findings = []
    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        fix = vuln.get('fix', {})
        fix_versions = fix.get('versions', ['None Available'])
        
        findings.append({
            'severity': vuln.get('severity', 'Unknown'),
            'cve': vuln.get('id', 'Unknown CVE'),
            'library': artifact.get('name', 'Unknown Library'),
            'version': artifact.get('version', 'Unknown'),
            'fix_version': ", ".join(fix_versions),
            'description': vuln.get('description', 'No description')[:120] + '...'
        })
    return pd.DataFrame(findings)

def extract_cbom():
    data = load_json_safely(CBOM_FILE)
    components = data.get('components', [])
    
    providers = []
    primitives = []
    
    for comp in components:
        c_type = comp.get('type')
        name = comp.get('name', 'Unknown')
        
        if c_type == 'cryptographic-asset':
            props = comp.get('cryptoProperties', {})
            # Extract location from evidence if available
            occurrences = comp.get('evidence', {}).get('occurrences', [])
            location = occurrences[0].get('location', 'Unknown') if occurrences else 'Unknown'
            
            primitives.append({
                'name': name,
                'asset_type': props.get('assetType', 'Unknown'),
                'description': comp.get('description', ''),
                'location': location
            })
        elif c_type in ['library', 'framework'] and 'cryptoProperties' in comp:
            providers.append({
                'library': name,
                'version': comp.get('version', 'N/A'),
                'purl': comp.get('purl', 'Unknown')
            })
            
    return primitives, providers

# --- 3. Visualization Generation ---
def generate_charts(sast_df, sca_df):
    chart_path = os.path.join(REPORT_DIR, "threat_landscape.png")
    
    # Combine severities from both dataframes
    severities = []
    if not sast_df.empty:
        severities.extend(sast_df['severity'].tolist())
    if not sca_df.empty:
        severities.extend(sca_df['severity'].tolist())
        
    if not severities:
        # Create a blank success image if no findings
        fig, ax = plt.subplots(figsize=(6, 2))
        ax.text(0.5, 0.5, 'Zero Vulnerabilities Detected', ha='center', va='center', fontsize=12)
        ax.axis('off')
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        return chart_path

    # Plot using Seaborn
    plt.figure(figsize=(8, 4))
    sns.set_theme(style="whitegrid")
# Pass the data to both 'y' and 'hue', and disable the legend to clear the warning
    ax = sns.countplot(y=severities, order=['Critical', 'High', 'Medium', 'Low'], hue=severities, legend=False, palette="Reds_r")
    ax.set_title("Vulnerabilities by Severity", fontsize=14)
    ax.set_xlabel("Count")
    ax.set_ylabel("Severity")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()
    
    return chart_path

# --- 4. Templating & PDF Generation ---
def build_report():
    print("Extracting Data...")
    sast_df = extract_sast()
    sca_df = extract_sca()
    primitives, providers = extract_cbom()
    
    # Check secrets (simple count)
    secrets_data = load_json_safely(SECRETS_FILE)
    secrets_count = len(secrets_data) if isinstance(secrets_data, list) else 0

    print("Generating Visualizations...")
    chart_path = generate_charts(sast_df, sca_df)
    
    # Group SCA data for cleaner tables
    if not sca_df.empty:
        grouped_sca = sca_df.groupby(['library', 'version', 'fix_version']).apply(
            lambda x: x[['cve', 'severity', 'description']].to_dict('records')
        ).to_dict()
    else:
        grouped_sca = {}

    print("Rendering HTML Template...")
    # Self-contained Jinja2 Template
    html_template = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; color: #333; margin: 40px; }
            h1, h2 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 5px; }
            .badge { padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            .badge-high { background-color: #e74c3c; color: white; }
            .badge-medium { background-color: #f39c12; color: white; }
            .card { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; background: #f9f9f9; }
            .code-snippet { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 4px; font-family: monospace; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>DevSecOps Executive Audit Report</h1>
        <img src="file://{{ chart_path }}" style="width: 100%; max-width: 600px; margin-bottom: 20px;">
        
        <h2>1. Executive Summary</h2>
        <ul>
            <li><b>Leaked Secrets:</b> {{ secrets_count }} detected</li>
            <li><b>Total SAST Flaws:</b> {{ sast_count }}</li>
            <li><b>Vulnerable Dependencies:</b> {{ sca_count }} CVEs</li>
        </ul>

        <h2>2. Developer Action Plan: Code Flaws (SAST)</h2>
        {% if sast_records|length == 0 %}
            <p>✅ Zero code flaws detected.</p>
        {% else %}
            {% for item in sast_records %}
            <div class="card">
                <b>[{{ item.severity }}] {{ item.rule }}</b><br>
                <i>File: {{ item.file }} (Line {{ item.line }})</i>
                <div class="code-snippet">{{ item.message }}</div>
            </div>
            {% endfor %}
        {% endif %}

        <h2>3. Developer Action Plan: Dependency Upgrades (SCA)</h2>
        {% if grouped_sca|length == 0 %}
            <p>✅ Zero dependency vulnerabilities detected.</p>
        {% else %}
            {% for key, cves in grouped_sca.items() %}
            <div class="card">
                <b>Library:</b> {{ key[0] }} (Current: {{ key[1] }}) &rarr; <b>Upgrade to:</b> <span style="color: green;">{{ key[2] }}</span>
                <table>
                    <tr><th>CVE</th><th>Severity</th><th>Description</th></tr>
                    {% for cve in cves %}
                    <tr><td>{{ cve.cve }}</td><td>{{ cve.severity }}</td><td>{{ cve.description }}</td></tr>
                    {% endfor %}
                </table>
            </div>
            {% endfor %}
        {% endif %}

        <h2>4. Cryptographic Audit (CBOM)</h2>
        <h3>A. Cryptographic Primitives & Assets</h3>
        <table>
            <tr><th>Name</th><th>Asset Type</th><th>Location</th><th>Description</th></tr>
            {% for prim in primitives %}
            <tr><td>{{ prim.name }}</td><td>{{ prim.asset_type }}</td><td>{{ prim.location }}</td><td>{{ prim.description }}</td></tr>
            {% endfor %}
        </table>

        <h3>B. Cryptographic Providers (Libraries)</h3>
        <table>
            <tr><th>Library</th><th>Version</th><th>PURL</th></tr>
            {% for prov in providers %}
            <tr><td>{{ prov.library }}</td><td>{{ prov.version }}</td><td>{{ prov.purl }}</td></tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    
    template = Template(html_template)
    rendered_html = template.render(
        secrets_count=secrets_count,
        sast_count=len(sast_df),
        sca_count=len(sca_df),
        sast_records=sast_df.to_dict('records') if not sast_df.empty else [],
        grouped_sca=grouped_sca,
        primitives=primitives,
        providers=providers,
        chart_path=chart_path
    )
    
    print("Exporting PDF via WeasyPrint...")
    pdf_path = os.path.join(REPORT_DIR, "Executive_Audit_Report.pdf")
    HTML(string=rendered_html).write_pdf(pdf_path)
    print(f"✅ Success! Report generated at: {pdf_path}")

if __name__ == "__main__":
    build_report()