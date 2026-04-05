import argparse
import logging
import os
import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML, CSS

# Import our custom modules
import data_parser
import visualizer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def count_severities(df):
    """Helper function to calculate the Risk Matrix for the Executive Scorecard."""
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    if not df.empty and 'severity' in df.columns:
        val_counts = df['severity'].value_counts().to_dict()
        for k in counts.keys():
            counts[k] = val_counts.get(k, 0)
    return counts

def main():
    parser = argparse.ArgumentParser(description="Generate DevSecOps PDF Report")
    parser.add_argument("--input-dir", required=True, help="Directory containing JSON reports")
    parser.add_argument("--cbom", required=True, help="Path to final-cbom.json")
    parser.add_argument("--output-dir", required=True, help="Directory to save the PDF")
    parser.add_argument("--project-name", default="Application Security Scan", help="Name on the report cover")
    args = parser.parse_args()

    # Force absolute path to ensure WeasyPrint can resolve file:// URIs
    args.output_dir = os.path.abspath(args.output_dir) 
    os.makedirs(args.output_dir, exist_ok=True)

    logger.info("Starting Data Extraction...")
    grouped_sast, sast_df = data_parser.extract_sast(os.path.join(args.input_dir, "gl-sast-report.json"))
    grouped_sca, sca_df = data_parser.extract_sca(os.path.join(args.input_dir, "vulnerabilities.json"))
    primitives, providers = data_parser.extract_cbom(args.cbom)
    secrets_count = data_parser.get_secrets_count(os.path.join(args.input_dir, "gl-secret-detection-report.json"))

    logger.info("Generating Visualizations...")
    chart_paths = visualizer.generate_charts(sast_df, sca_df, primitives, args.output_dir)

    # --- NEW: Calculate Risk Matrix Data ---
    sast_matrix = count_severities(sast_df)
    sca_matrix = count_severities(sca_df)

    logger.info("Rendering Template...")
    # Calculate the absolute path to the templates directory dynamically
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('report.html')
    
    html_out = template.render(
        project_name=args.project_name,
        date_generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        secrets_count=secrets_count,
        sast_count=len(sast_df),
        sca_count=len(sca_df),
        sast_matrix=sast_matrix, # PASSED TO JINJA
        sca_matrix=sca_matrix,   # PASSED TO JINJA
        grouped_sast=grouped_sast,
        grouped_sca=grouped_sca,
        primitives=primitives,
        providers=providers,
        chart_paths=chart_paths
    )

    logger.info("Compiling PDF with WeasyPrint...")
    pdf_path = os.path.join(args.output_dir, "Executive_Audit_Report.pdf")
    
    # Render PDF using the HTML string and dynamic CSS path
    HTML(string=html_out).write_pdf(
        pdf_path,
        stylesheets=[CSS(os.path.join(template_dir, 'styles.css'))]
    )

    # DYNAMIC OWNERSHIP SYNC (Match Host Permissions)
    try:
        # Inspect the input directory to find the host user's UID and GID
        dir_stat = os.stat(args.input_dir)
        host_uid = dir_stat.st_uid
        host_gid = dir_stat.st_gid

        # 1. Sync Output Directory
        os.chown(args.output_dir, host_uid, host_gid)

        # 2. Sync Charts
        for key, path in chart_paths.items():
            if path and os.path.exists(path):
                os.chown(path, host_uid, host_gid)
                os.chmod(path, 0o644) # Standard read/write permissions

        # 3. Sync PDF
        if os.path.exists(pdf_path):
            os.chown(pdf_path, host_uid, host_gid)
            os.chmod(pdf_path, 0o644) 
            
        logger.info(f"Permissions synced successfully to Host UID:{host_uid} GID:{host_gid}")
    except Exception as e:
        logger.warning(f"Could not sync file ownership: {e}")
    
    logger.info(f"✅ Success! Report generated at: {pdf_path}")

if __name__ == "__main__":
    main()