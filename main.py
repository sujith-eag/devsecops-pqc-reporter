import argparse
import logging
import os
import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

# Import our custom modules
import data_parser
import visualizer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Generate DevSecOps PDF Report")
    parser.add_argument("--input-dir", required=True, help="Directory containing JSON reports")
    parser.add_argument("--cbom", required=True, help="Path to final-cbom.json")
    parser.add_argument("--output-dir", required=True, help="Directory to save the PDF")
    parser.add_argument("--project-name", default="Application Security Scan", help="Name on the report cover")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    logger.info("Starting Data Extraction...")
    grouped_sast, sast_df = data_parser.extract_sast(os.path.join(args.input_dir, "gl-sast-report.json"))
    grouped_sca, sca_df = data_parser.extract_sca(os.path.join(args.input_dir, "vulnerabilities.json"))
    primitives, providers = data_parser.extract_cbom(args.cbom)
    secrets_count = data_parser.get_secrets_count(os.path.join(args.input_dir, "gl-secret-detection-report.json"))

    logger.info("Generating Visualizations...")
    chart_paths = visualizer.generate_charts(sast_df, sca_df, primitives, args.output_dir)

    logger.info("Rendering Template...")
    env = Environment(loader=FileSystemLoader('/app/templates'))
    template = env.get_template('report.html')
    
    html_out = template.render(
        project_name=args.project_name,
        date_generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        secrets_count=secrets_count,
        sast_count=len(sast_df),
        sca_count=len(sca_df),
        grouped_sast=grouped_sast,
        grouped_sca=grouped_sca,
        primitives=primitives,
        providers=providers,
        chart_paths=chart_paths
    )

    logger.info("Compiling PDF with WeasyPrint...")
    pdf_path = os.path.join(args.output_dir, "Executive_Audit_Report.pdf")
    
    # Render PDF using the HTML string and the separate CSS file
    HTML(string=html_out).write_pdf(
        pdf_path, 
        stylesheets=[CSS('/app/templates/styles.css')]
    )
    
    # to make file permission readable
    os.chmod(pdf_path, 0o666)
    
    
    logger.info(f"✅ Success! Report generated at: {pdf_path}")

if __name__ == "__main__":
    main()