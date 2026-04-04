import os
import logging
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger(__name__)

def generate_charts(sast_df, sca_df, output_dir):
    chart_path = os.path.join(output_dir, "threat_landscape.png")
    
    severities = []
    if not sast_df.empty: severities.extend(sast_df['severity'].tolist())
    if not sca_df.empty: severities.extend(sca_df['severity'].tolist())
        
    if not severities:
        logger.info("Zero vulnerabilities found. Generating empty state chart.")
        fig, ax = plt.subplots(figsize=(8, 2))
        ax.text(0.5, 0.5, '✅ Zero Vulnerabilities Detected Across All Scanners', 
                ha='center', va='center', fontsize=14, color='green', fontweight='bold')
        ax.axis('off')
        plt.savefig(chart_path, bbox_inches='tight', transparent=True)
        plt.close()
        return chart_path

    logger.info("Generating Threat Landscape chart.")
    plt.figure(figsize=(8, 4))
    sns.set_theme(style="whitegrid")
    
    # FIXED: Using both 'y' and 'hue' to satisfy modern Seaborn requirements
    ax = sns.countplot(y=severities, order=['Critical', 'High', 'Medium', 'Low'], 
                       hue=severities, legend=False, palette="Reds_r")
    
    ax.set_title("Vulnerabilities by Severity", fontsize=14, pad=15)
    ax.set_xlabel("Count")
    ax.set_ylabel("Severity")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()
    
    return chart_path