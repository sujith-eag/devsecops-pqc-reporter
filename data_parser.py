import json
import os
import logging
import pandas as pd

logger = logging.getLogger(__name__)

# --- Safe JSON Loader ---
def load_json_safely(filepath):
    """Safely load JSON with error handling for missing or malformed files."""
    if not os.path.exists(filepath):
        logger.warning(f"File not found, skipping: {filepath}")
        return {}
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data if data else {}
    except json.JSONDecodeError as e:
        logger.error(f"Malformed JSON in {filepath}: {e}")
        return {}

# --- Data Extraction Functions ---
def extract_sast(filepath):
    data = load_json_safely(filepath)
    vulnerabilities = data.get('vulnerabilities', [])
    
    findings = []
    for issue in vulnerabilities:
        loc = issue.get('location', {})
        findings.append({
            'severity': issue.get('severity', 'Unknown'),
            'rule': issue.get('identifiers', [{}])[0].get('name', 'Unknown Rule'),
            'file': loc.get('file', 'Unknown File'),
            'line': loc.get('start_line', 'N/A'),
            'message': issue.get('message', 'No details provided.')
        })
    return pd.DataFrame(findings)

def extract_sca(filepath):
    data = load_json_safely(filepath)
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
    df = pd.DataFrame(findings)
    
    # Group the dataframe to prevent massive, unreadable tables
    if not df.empty:
        return df.groupby(['library', 'version', 'fix_version']).apply(
            lambda x: x[['cve', 'severity', 'description']].to_dict('records')
        ).to_dict(), df
    return {}, df

def extract_cbom(filepath):
    data = load_json_safely(filepath)
    components = data.get('components', [])
    
    providers = []
    primitives = []
    
    for comp in components:
        c_type = comp.get('type')
        name = comp.get('name', 'Unknown')
        
        if c_type == 'cryptographic-asset':
            props = comp.get('cryptoProperties', {})
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

def get_secrets_count(filepath):
    data = load_json_safely(filepath)
    return len(data) if isinstance(data, list) else 0