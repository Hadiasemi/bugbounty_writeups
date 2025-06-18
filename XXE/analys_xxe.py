import pandas as pd
import requests
from bs4 import BeautifulSoup
import time
import re
from urllib.parse import urlparse
import logging
from typing import Dict, List, Optional
import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import warnings
warnings.filterwarnings('ignore')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XXEAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the XXE analyzer with CSV data"""
        self.df = pd.read_csv(csv_file_path)
        # Clean bounty column on initialization
        if 'Bounty' in self.df.columns:
            self.df['Bounty_numeric'] = self.df['Bounty'].astype(str).str.replace(r'[$,]', '', regex=True).astype(float)
        else:
            self.df['Bounty_numeric'] = 0

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def extract_details_from_url(self, url: str) -> Dict[str, str]:
        """Extract XXE-specific details from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            xxe_info = {
                'XXE Type': self._detect_xxe_type(soup),
                'Vulnerable Functionality': self._detect_functionality(soup),
                'Impact': self._assess_impact(soup),
                'Bypass Method': self._detect_bypass_method(soup),
            }
            
            return xxe_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()

    def _detect_xxe_type(self, soup: BeautifulSoup) -> str:
        """Detect the type of XXE attack."""
        text_content = soup.get_text().lower()
        if 'blind' in text_content:
            return 'Blind XXE'
        if 'oob' in text_content or 'out-of-band' in text_content:
            return 'OOB XXE'
        if 'error-based' in text_content:
            return 'Error-Based XXE'
        if 'billion laughs' in text_content or 'dos' in text_content:
            return 'Billion Laughs (DoS)'
        if 'local file' in text_content or 'file read' in text_content:
            return 'Classic (Local File Read)'
        return 'Classic (Local File Read)'

    def _detect_functionality(self, soup: BeautifulSoup) -> str:
        """Detect the vulnerable application functionality."""
        text_content = soup.get_text().lower()
        functionalities = {
            'File Upload (XML/Office Docs)': ['upload', 'docx', 'xlsx', 'pptx', 'svg', 'xml file'],
            'API Endpoint (XML Body)': ['api', 'soap', 'rest', 'xml body'],
            'Document Processing': ['pdf generation', 'document conversion', 'reporting'],
            'Feed Parsing (RSS/Atom)': ['rss', 'atom', 'feed', 'xml feed'],
        }
        for func, keywords in functionalities.items():
            if any(keyword in text_content for keyword in keywords):
                return func
        return 'API Endpoint (XML Body)'

    def _assess_impact(self, soup: BeautifulSoup) -> str:
        """Assess the impact of the XXE vulnerability."""
        text_content = soup.get_text().lower()
        impacts = {
            'Information Disclosure (LFI)': ['information disclosure', 'lfi', 'local file inclusion', '/etc/passwd'],
            'Server-Side Request Forgery (SSRF)': ['ssrf', 'server-side request forgery', 'internal network'],
            'Denial of Service (DoS)': ['dos', 'denial of service', 'billion laughs', 'crash'],
            'Remote Code Execution (RCE)': ['rce', 'remote code execution', 'expect://'],
        }
        for impact, keywords in impacts.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'Information Disclosure (LFI)'

    def _detect_bypass_method(self, soup: BeautifulSoup) -> str:
        """Detect any bypass methods used for XXE filters."""
        text_content = soup.get_text().lower()
        bypasses = {
            'Parameter Entities': ['parameter entity', '%'],
            'CDATA Sections': ['cdata'],
            'UTF-7 Encoding': ['utf-7'],
            'Protocol Handlers (e.g., file://)': ['file://', 'http://', 'gopher://'],
            'No Bypass Needed': ['no bypass', 'no filter', 'direct'],
        }
        for bypass, keywords in bypasses.items():
            if any(keyword in text_content for keyword in keywords):
                return bypass
        return 'No Bypass Needed'

    def _get_default_values(self) -> Dict[str, str]:
        """Return default values when URL processing fails"""
        return { 'XXE Type': 'unknown', 'Vulnerable Functionality': 'unknown', 'Impact': 'unknown', 'Bypass Method': 'unknown' }

    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        """Process all URLs in the CSV and add new columns"""
        new_columns = ['XXE Type', 'Vulnerable Functionality', 'Impact', 'Bypass Method']
        for col in new_columns:
            if col not in self.df.columns:
                self.df[col] = ''
        
        total_urls = len(self.df)
        for index, row in self.df.iterrows():
            url = row['URL']
            if pd.isna(url): continue
            logger.info(f"Processing {index + 1}/{total_urls}: {url}")
            url_info = self.extract_details_from_url(url)
            for col, value in url_info.items():
                self.df.at[index, col] = value
            time.sleep(delay)
            if (index + 1) % 5 == 0 or (index + 1) == total_urls:
                self.save_progress(f'xxe_analysis_progress_{index + 1}.csv')
        return self.df

    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")

    def save_results(self, filename: str = 'xxe_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")

    def create_comprehensive_plots(self):
        """Generate comprehensive plots for XXE analysis, excluding 'unknown' category."""
        plt.style.use('seaborn-v0_8-whitegrid')
        fig, axes = plt.subplots(2, 2, figsize=(20, 16))
        fig.suptitle('XXE Comprehensive Analysis', fontsize=22, fontweight='bold')

        # Filtered DataFrame for plotting
        plot_df = self.df[self.df['XXE Type'] != 'unknown']

        # Plotting functions with filtered data
        sns.barplot(y=plot_df['XXE Type'].value_counts().index, x=plot_df['XXE Type'].value_counts().values, ax=axes[0, 0], palette='viridis').set_title('XXE Types', fontsize=16)
        sns.barplot(y=plot_df['Impact'].value_counts().index, x=plot_df['Impact'].value_counts().values, ax=axes[0, 1], palette='plasma').set_title('Impact of XXE', fontsize=16)
        sns.barplot(y=plot_df['Vulnerable Functionality'].value_counts().index, x=plot_df['Vulnerable Functionality'].value_counts().values, ax=axes[1, 0], palette='magma').set_title('Vulnerable Functionalities', fontsize=16)
        sns.barplot(y=plot_df['Bypass Method'].value_counts().index, x=plot_df['Bypass Method'].value_counts().values, ax=axes[1, 1], palette='crest').set_title('Filter Bypass Methods', fontsize=16)

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig('xxe_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'xxe_comprehensive_analysis.png'")

    def generate_summary_report(self) -> Dict:
        """Generate a summary report with key metrics, excluding 'unknown' category."""
        # Filter out 'unknown' before generating distributions
        filtered_df = self.df[self.df['XXE Type'] != 'unknown']

        summary = {
            'basic_statistics': { 'total_reports': len(self.df), 'total_bounty': self.df['Bounty_numeric'].sum(), 'average_bounty': self.df['Bounty_numeric'].mean() },
            'distributions': {
                'xxe_type': filtered_df['XXE Type'].value_counts().to_dict(),
                'impact': filtered_df['Impact'].value_counts().to_dict(),
                'functionality': filtered_df['Vulnerable Functionality'].value_counts().to_dict(),
                'bypass_method': filtered_df['Bypass Method'].value_counts().to_dict(),
            }
        }
        return summary
    
    def create_interactive_dashboard(self, summary_data):
        """Generate an interactive HTML dashboard from the summary data"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive XXE Vulnerability Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
    <style> body { font-family: 'Inter', sans-serif; } .chart-container { border-radius: 0.75rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1); transition: all 0.2s ease-in-out; } .chart-container:hover { transform: translateY(-5px); box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -2px rgb(0 0 0 / 0.1); } </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-gray-50 text-gray-800">
    <div class="container mx-auto p-8">
        <header class="text-center mb-10"><h1 class="text-4xl font-bold">XXE Vulnerability Analysis</h1></header>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div class="bg-white p-6 chart-container"><div id="chart-xxe-type"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-impact"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-functionality"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-bypass"></div></div>
        </div>
    </div>
    <script>
        const analysisData = JSON.parse(`{{SUMMARY_JSON}}`);
        function processChartData(dataObject) {
            // The JSON is already filtered, so no need to filter for 'unknown' here
            const sortedArray = Object.entries(dataObject).sort(([, a], [, b]) => a - b);
            return { labels: sortedArray.map(item => item[0]), values: sortedArray.map(item => item[1]) };
        }
        const layout = (title) => ({ title, margin: { l: 250, r: 20, t: 80, b: 50 }, paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)', font: { family: 'Inter', color: '#374151' } });
        
        const xxeTypeData = processChartData(analysisData.distributions.xxe_type);
        Plotly.newPlot('chart-xxe-type', [{ x: xxeTypeData.values, y: xxeTypeData.labels, type: 'bar', orientation: 'h', marker: {color: 'rgba(79, 70, 229, 0.8)'} }], layout('XXE Types'));
        
        const impactData = processChartData(analysisData.distributions.impact);
        Plotly.newPlot('chart-impact', [{ x: impactData.values, y: impactData.labels, type: 'bar', orientation: 'h', marker: {color: 'rgba(219, 39, 119, 0.8)'} }], layout('Impact of XXE'));
        
        const funcData = processChartData(analysisData.distributions.functionality);
        Plotly.newPlot('chart-functionality', [{ x: funcData.values, y: funcData.labels, type: 'bar', orientation: 'h', marker: {color: 'rgba(34, 197, 94, 0.8)'} }], layout('Vulnerable Functionalities'));

        const bypassData = processChartData(analysisData.distributions.bypass_method);
        Plotly.newPlot('chart-bypass', [{ x: bypassData.values, y: bypassData.labels, type: 'bar', orientation: 'h', marker: {color: 'rgba(245, 158, 11, 0.8)'} }], layout('Bypass Methods'));
    </script>
</body>
</html>
        """
        final_html = html_template.replace('{{SUMMARY_JSON}}', json.dumps(summary_data))
        with open('xxe_interactive_dashboard.html', 'w', encoding='utf-8') as f:
            f.write(final_html)
        logger.info("Interactive dashboard saved to xxe_interactive_dashboard.html")

# Main execution block
if __name__ == "__main__":
    input_csv_file = './xxe_writeups.csv' 
    
    try:
        analyzer = XXEAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
    else:
        print("Starting XXE vulnerability analysis...")
        
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        analyzer.save_results('xxe_analysis_complete.csv')

        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        
        summary = analyzer.generate_summary_report()
        with open('xxe_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        analyzer.create_interactive_dashboard(summary)
        
        print("\nXXE ANALYSIS COMPLETE!")
        print("Generated: xxe_analysis_complete.csv, xxe_comprehensive_analysis.png, xxe_analysis_summary_report.json, xxe_interactive_dashboard.html")

