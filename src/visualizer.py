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

class ChartEngine:
    """Modular engine for generating professional DevSecOps infographics."""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.chart_paths = {}
        sns.set_theme(style="white")

    def generate_all(self, sast_df, sca_df, primitives):
        """Orchestrator that registers and builds all required charts."""
        self.chart_paths['landscape'] = self._build_threat_landscape(sast_df, sca_df)
        self.chart_paths['crypto'] = self._build_crypto_donut(primitives)
        self.chart_paths['scatter'] = self._build_risk_scatter(sca_df)
        return self.chart_paths

    def _get_path(self, filename):
        return os.path.join(self.output_dir, filename)

    def _build_empty_state(self, filename, message):
        path = self._get_path(filename)
        fig, ax = plt.subplots(figsize=(7, 2))
        ax.text(0.5, 0.5, message, ha='center', va='center', fontsize=14, color='#27ae60', fontweight='bold')
        ax.axis('off')
        plt.savefig(path, bbox_inches='tight', transparent=True, dpi=300)
        plt.close()
        return path

    def _build_threat_landscape(self, sast_df, sca_df):
        logger.info("Generating Threat Landscape Bar Chart...")
        path = self._get_path("threat_landscape.png")
        
        severities = []
        if not sast_df.empty: severities.extend(sast_df['severity'].tolist())
        if not sca_df.empty: severities.extend(sca_df['severity'].tolist())
            
        if not severities:
            return self._build_empty_state("threat_landscape.png", '✅ Zero Vulnerabilities Detected')

        # If a weird severity like "Negligible" appears, force it to 'Unknown' so Seaborn doesn't crash
        cleaned_severities = [s if s in SEV_COLORS else 'Unknown' for s in severities]

        df = pd.DataFrame({'Severity': cleaned_severities})
        order = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']    

        plt.figure(figsize=(7, 3.5))
        ax = sns.countplot(
            data=df, y='Severity', order=[s for s in order if s in df['Severity'].values], 
            palette=SEV_COLORS, hue='Severity', legend=False
        )
        
        sns.despine(left=True, bottom=True)
        ax.set_xlabel("")
        ax.set_ylabel("")
        ax.set_xticks([])
        
        for p in ax.patches:
            width = p.get_width()
            if width > 0:
                ax.text(width + 0.3, p.get_y() + p.get_height()/2., f'{int(width)}', 
                        ha="left", va="center", fontsize=12, fontweight='bold', color='#2c3e50')
                
        plt.title("Vulnerabilities by Severity", fontsize=14, fontweight='bold', color='#2c3e50', pad=15)
        plt.tight_layout()
        plt.savefig(path, dpi=300)
        plt.close()
        return path

    def _build_crypto_donut(self, primitives):
        logger.info("Generating Cryptographic Profile Donut Chart...")
        path = self._get_path("crypto_profile.png")
        
        if not primitives:
            return self._build_empty_state("crypto_profile.png", 'No Cryptographic Assets Detected')

        names = [p.get('name', 'Unknown') for p in primitives]
        df = pd.DataFrame({'Algorithm': names})
        counts = df['Algorithm'].value_counts()

        if len(counts) > 5:
            top_counts = counts[:4].copy()
            top_counts['Other'] = counts[4:].sum()
            counts = top_counts
            
        plt.figure(figsize=(5, 5))
        colors = ['#2980b9', '#3498db', '#1abc9c', '#16a085', '#bdc3c7']
        
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=90, 
                colors=colors, textprops=dict(color="#2c3e50", fontweight='bold'))
        
        centre_circle = plt.Circle((0,0), 0.70, fc='white')
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)
        
        plt.title("Cryptographic Algorithms", fontsize=14, fontweight='bold', color='#2c3e50', pad=15)
        plt.tight_layout()
        plt.savefig(path, dpi=300)
        plt.close()
        return path

    def _build_risk_scatter(self, sca_df):
        logger.info("Generating CVSS vs EPSS Scatter Plot...")
        path = self._get_path("risk_scatter.png")
        
        # Validate data presence
        if sca_df.empty or 'cvss_score' not in sca_df.columns or 'epss_score' not in sca_df.columns:
            return self._build_empty_state("risk_scatter.png", 'Not Enough Data for Risk Matrix')

        # Filter out purely zero-scored rows to prevent graph clustering at origin
        plot_df = sca_df[(sca_df['cvss_score'] > 0) | (sca_df['epss_score'] > 0)].copy()
        if plot_df.empty:
            return self._build_empty_state("risk_scatter.png", 'Zero Scorable Vulnerabilities')

        plt.figure(figsize=(6, 4))
        
        # Create scatter plot mapped by severity colors
        ax = sns.scatterplot(
            data=plot_df, x='cvss_score', y='epss_score',
            hue='severity', palette=SEV_COLORS, s=100, alpha=0.8, edgecolor='black'
        )

        sns.despine()
        plt.title("SCA Risk Matrix (CVSS vs EPSS)", fontsize=14, fontweight='bold', color='#2c3e50', pad=15)
        plt.xlabel("CVSS Base Score (Damage)", fontweight='bold', color='#7f8c8d')
        plt.ylabel("EPSS Probability (Exploitability)", fontweight='bold', color='#7f8c8d')
        plt.grid(True, linestyle='--', alpha=0.3)

        # Reposition legend cleanly outside the plot
        handles, labels = ax.get_legend_handles_labels()
        if handles:
            ax.legend(handles=handles, labels=labels, title="Severity", bbox_to_anchor=(1.05, 1), loc='upper left')

        plt.tight_layout()
        plt.savefig(path, dpi=300)
        plt.close()
        return path

# Legacy wrapper to ensure main.py does not break
def generate_charts(sast_df, sca_df, primitives, output_dir):
    engine = ChartEngine(output_dir)
    return engine.generate_all(sast_df, sca_df, primitives)