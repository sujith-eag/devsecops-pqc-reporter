import json
import os
import logging
import pandas as pd
import re

logger = logging.getLogger(__name__)

# --- Severity Mapping for Sorting ---
# This allows Pandas to mathematically sort text-based severities
SEVERITY_WEIGHT = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Unknown': 5}

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

def extract_sast(filepath):
    """Extracts code flaws, groups them by Rule, and flags False Positives."""
    data = load_json_safely(filepath)
    vulnerabilities = data.get('vulnerabilities', [])
    
    findings = []
    for issue in vulnerabilities:
        loc = issue.get('location', {})
        flags = issue.get('flags', [])
        
        # Check if Semgrep flagged this as a likely false positive
        is_false_positive = any(f.get('type') == 'flagged-as-likely-false-positive' for f in flags)
        
        findings.append({
            'severity': issue.get('severity', 'Unknown'),
            'confidence': issue.get('details', {}).get('confidence', {}).get('value', 'UNKNOWN'),
            'rule': issue.get('identifiers', [{}])[0].get('name', 'Unknown Rule'),
            'file': loc.get('file', 'Unknown File'),
            'line': loc.get('start_line', 'N/A'),
            'message': issue.get('message', 'No details provided.'),
            'is_fp': is_false_positive
        })
        
    df = pd.DataFrame(findings)
    if df.empty:
        return {}, df

    # Apply mathematical sorting weight
    df['sev_rank'] = df['severity'].map(SEVERITY_WEIGHT).fillna(4)
    
    # Sort globally by severity, then by rule name
    df = df.sort_values(by=['sev_rank', 'rule'])
    
    # Group by the Rule (e.g., all SQL Injections grouped together)
    grouped_sast = {}
    for (rule, severity), group in df.groupby(['rule', 'severity'], sort=False):
        grouped_sast[(rule, severity)] = group.to_dict('records')
        
    return grouped_sast, df

def extract_sca(filepath):
    """Extracts CVEs, enriches with CVSS/EPSS, and mathematically sorts the highest risks to the top."""
    data = load_json_safely(filepath)
    matches = data.get('matches', [])
    
    findings = []
    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        # Safe extraction of deep arrays (CVSS, EPSS, CWE)
        cvss_list = vuln.get('cvss', [{}])
        cvss_score = cvss_list[0].get('metrics', {}).get('baseScore', 0.0) if cvss_list else 0.0
        
        epss_list = vuln.get('epss', [{}])
        epss_score = epss_list[0].get('epss', 0.0) if epss_list else 0.0
        
        cwe_list = vuln.get('cwes', [{}])
        cwe_id = cwe_list[0].get('cwe', 'N/A') if cwe_list else 'N/A'

        findings.append({
            'severity': vuln.get('severity', 'Unknown'),
            'cvss_score': cvss_score,
            'epss_score': epss_score,
            'cwe': cwe_id,
            'cve': vuln.get('id', 'Unknown CVE'),
            'library': artifact.get('name', 'Unknown Library'),
            'version': artifact.get('version', 'Unknown'),
            'fix_version': ", ".join(vuln.get('fix', {}).get('versions', ['None Available'])),
            'description': vuln.get('description', 'No description')
        })
        
    df = pd.DataFrame(findings)
    if df.empty:
        return {}, df

    # Apply mathematical sorting weight
    df['sev_rank'] = df['severity'].map(SEVERITY_WEIGHT).fillna(4)
    
    # Sort primarily by Severity, secondarily by exact CVSS score (highest first)
    df = df.sort_values(by=['sev_rank', 'cvss_score'], ascending=[True, False])

    grouped_sca = {}
    # group by library keeping the sorted order
    for lib_keys, group in df.groupby(['library', 'version', 'fix_version'], sort=False):
        # Determine the maximum severity and CVSS for this specific library block
        max_sev = group['severity'].iloc[0] 
        max_cvss = group['cvss_score'].max()
        
        grouped_sca[lib_keys] = {
            'max_severity': max_sev,
            'max_cvss': max_cvss,
            'cves': group.to_dict('records')
        }
        
    # Final Polish: Sort the resulting dictionary blocks so the library with the highest CVSS is printed first
    sorted_grouped_sca = dict(sorted(grouped_sca.items(), key=lambda item: item[1]['max_cvss'], reverse=True))

    return sorted_grouped_sca, df

def extract_cbom(filepath):
    """Extracts Cryptographic Assets and Libraries using Advanced Regex Discovery."""
    data = load_json_safely(filepath)
    components = data.get('components') or []
    
    providers = []
    primitives = []
    
    # 1. Safe Substrings: Highly specific crypto terms
    CRYPTO_SUBSTRINGS = [
        'bcrypt', 'crypto', 'jwt', 'argon2', 'scrypt', 'jsonwebtoken', 
        'jws', 'hmac', 'pkcs', 'x509', 'forge', 'nacl', 'elliptic', 
        'pbkdf2', 'blake2', 'chacha', 'poly1305', 'webauthn'
    ]
    
    # 2. Strict Regex: Short acronyms bounded by start, end, hyphens, or dots
    # This catches "sha256-js" and "md5-browser" but IGNORES "includes" and "shallow"
    CRYPTO_REGEX = re.compile(r'(?i)(^|[-/.])(aes|des|rsa|md5|sha\d*|ssl|tls|ecc|dsa|mac)([-/.]|$)')
    
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
            
        elif c_type in ['library', 'framework']:
            name_lower = name.lower()
            
            # The Advanced Hybrid Check
            has_crypto_tag = 'cryptoProperties' in comp
            has_crypto_sub = any(k in name_lower for k in CRYPTO_SUBSTRINGS)
            has_crypto_reg = bool(CRYPTO_REGEX.search(name_lower))
            
            if has_crypto_tag or has_crypto_sub or has_crypto_reg:
                licenses = comp.get('licenses') or []
                license_id = licenses[0].get('license', {}).get('id', 'Unknown') if licenses else 'Unknown'
                
                hashes = comp.get('hashes') or []
                hash_alg = hashes[0].get('alg', 'Unknown') if hashes else 'Unknown'

                providers.append({
                    'library': name,
                    'version': comp.get('version', 'N/A'),
                    'purl': comp.get('purl', 'Unknown'),
                    'license': license_id,
                    'hash_alg': hash_alg
                })
            
    return primitives, providers

def get_secrets_count(filepath):
    data = load_json_safely(filepath)
    return len(data) if isinstance(data, list) else 0
