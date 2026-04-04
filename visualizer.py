import os
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger(__name__)

# Standardized Enterprise Color Palette for Severities
SEV_COLORS = {
    'Critical': '#8b0000', # Dark Red
    'High': '#e74c3c',     # Bright Red
    'Medium': '#f39c12',   # Orange
    'Low': '#f1c40f',      # Yellow
    'Info': '#3498db',     # Blue
    'Unknown': '#95a5a6'   # Grey
}

def generate_charts(sast_df, sca_df, primitives, output_dir):
    """Generates professional infographics and returns a dictionary of their file paths."""
    
    chart_paths = {
        'landscape': os.path.join(output_dir, "threat_landscape.png"),
        'crypto': os.path.join(output_dir, "crypto_profile.png")
    }
    
    _generate_threat_landscape(sast_df, sca_df, chart_paths['landscape'])
    _generate_crypto_donut(primitives, chart_paths['crypto'])
    
    return chart_paths

def _generate_threat_landscape(sast_df, sca_df, output_path):
    logger.info("Generating Threat Landscape Bar Chart...")
    
    # 1. Aggregate the data
    severities = []
    if not sast_df.empty: severities.extend(sast_df['severity'].tolist())
    if not sca_df.empty: severities.extend(sca_df['severity'].tolist())
        
    if not severities:
        _generate_empty_state(output_path, '✅ Zero Vulnerabilities Detected')
        return

    # If a weird severity like "Negligible" appears, force it to 'Unknown' so Seaborn doesn't crash
    cleaned_severities = [s if s in SEV_COLORS else 'Unknown' for s in severities]

    df = pd.DataFrame({'Severity': cleaned_severities})
    order = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']    

    # 2. Setup the Matplotlib figure
    plt.figure(figsize=(7, 3.5))
    sns.set_theme(style="white") # Clean white background (no gridlines)
    
    # 3. Create the bar chart using our standard color palette
    ax = sns.countplot(
        data=df, 
        y='Severity', 
        order=[s for s in order if s in df['Severity'].values], 
        palette=SEV_COLORS,
        hue='Severity', 
        legend=False
    )
    
    # 4. Professional Styling: Remove borders (spines) and axis lines
    sns.despine(left=True, bottom=True)
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.set_xticks([]) # Remove bottom numbers
    
    # 5. Add direct data labels to the end of each bar
    for p in ax.patches:
        width = p.get_width()
        if width > 0:
            ax.text(width + 0.3, p.get_y() + p.get_height()/2., 
                    f'{int(width)}', 
                    ha="left", va="center", fontsize=12, fontweight='bold', color='#2c3e50')
            
    plt.title("Vulnerabilities by Severity", fontsize=14, fontweight='bold', color='#2c3e50', pad=15)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300) # High DPI for crisp PDF printing
    plt.close()

def _generate_crypto_donut(primitives, output_path):
    logger.info("Generating Cryptographic Profile Donut Chart...")
    
    if not primitives:
        _generate_empty_state(output_path, 'No Cryptographic Assets Detected')
        return

    # Extract algorithm/asset names
    names = [p.get('name', 'Unknown') for p in primitives]
    df = pd.DataFrame({'Algorithm': names})
    counts = df['Algorithm'].value_counts()

    # Limit to top 5 to prevent the chart from becoming unreadable, group rest into "Other"
    if len(counts) > 5:
        top_counts = counts[:4].copy()
        top_counts['Other'] = counts[4:].sum()
        counts = top_counts
        
    plt.figure(figsize=(5, 5))
    
    # Modern Blue/Teal color palette for Crypto
    colors = ['#2980b9', '#3498db', '#1abc9c', '#16a085', '#bdc3c7']
    
    # Create the pie chart
    wedges, texts, autotexts = plt.pie(
        counts, 
        labels=counts.index, 
        autopct='%1.1f%%', 
        startangle=90, 
        colors=colors,
        textprops=dict(color="#2c3e50", fontweight='bold')
    )
    
    # Draw a white circle in the center to turn the pie into a Donut
    centre_circle = plt.Circle((0,0), 0.70, fc='white')
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)
    
    plt.title("Cryptographic Algorithms", fontsize=14, fontweight='bold', color='#2c3e50', pad=15)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def _generate_empty_state(output_path, message):
    """Generates a placeholder graphic so the PDF layout doesn't break."""
    fig, ax = plt.subplots(figsize=(7, 2))
    ax.text(0.5, 0.5, message, ha='center', va='center', fontsize=14, color='#27ae60', fontweight='bold')
    ax.axis('off')
    plt.savefig(output_path, bbox_inches='tight', transparent=True, dpi=300)
    plt.close()