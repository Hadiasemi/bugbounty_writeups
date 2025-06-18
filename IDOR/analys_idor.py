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

class IDORAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the IDOR analyzer with CSV data"""
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
        """Extract IDOR-specific details from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            idor_info = {
                'ID Type': self._detect_id_type(soup),
                'Way to predict the identifier': self._detect_prediction_method(soup), # Renamed for clarity
                'Functionality': self._detect_functionality(soup),
                'Impact': self._assess_impact(soup),
                'Parameter Location': self._detect_parameter_location(soup),
            }
            
            return idor_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()

    def _detect_id_type(self, soup: BeautifulSoup) -> str:
        """Detect the type of identifier used in the IDOR attack"""
        text_content = soup.get_text().lower()
        id_types = {
            'Decimal 8 or more digits': ['decimal id', 'numeric id', r'\d{8,}'],
            'Decimal shorter than 8 digits': ['user id', 'integer id', r'\b\d{1,7}\b'],
            'UUID': ['uuid', 'guid', '[a-f0-9]{8}-[a-f0-9]{4}-'],
            'Hexadecimal 8 or more digits': ['hexadecimal', 'hex id', r'\b[a-f0-9]{8,}\b'],
            'Name/Email': ['email', 'username', 'name@'],
            'Hash': ['hash', 'md5', 'sha1', 'sha256'],
            'Other - non-bruteforceable': ['unpredictable', 'random string', 'base64'],
            'Other - bruteforceable': ['sequential', 'guessable', 'predictable'],
        }
        for id_type, keywords in id_types.items():
            if any(re.search(keyword, text_content) for keyword in keywords):
                return id_type
        return 'Decimal shorter than 8 digits'

    def _detect_prediction_method(self, soup: BeautifulSoup) -> str:
        """Detect how the vulnerable ID was predicted or obtained"""
        text_content = soup.get_text().lower()
        methods = {
            'Public ID': ['public id', 'exposed id', 'another user', 'different account'],
            'Integer enumeration': ['enumerate', 'sequential', 'incrementing'],
            'Bruteforce': ['bruteforce', 'brute force', 'guess'],
            'Signing Oracle': ['signing oracle', 'jwt', 'token signing'],
            'Information Disclosure': ['leaked', 'disclosed', 'api response'],
        }
        for method, keywords in methods.items():
            if any(keyword in text_content for keyword in keywords):
                return method
        return 'Public ID'

    def _detect_functionality(self, soup: BeautifulSoup) -> str:
        """Detect the vulnerable application functionality"""
        text_content = soup.get_text().lower()
        functionalities = {
            'Creating/Modifying/Deleting Data': ['delete', 'update', 'modify', 'create', 'edit', 'add', 'remove'],
            'Reading Private Data': ['view', 'read', 'access', 'download', 'export', 'profile'],
            'Authentication': ['authentication', 'authorization', 'access control', 'login'],
            'Billing/Payments': ['billing', 'payment', 'subscription', 'invoice'],
        }
        for func, keywords in functionalities.items():
            if any(keyword in text_content for keyword in keywords):
                return func
        return 'Reading Private Data'

    def _assess_impact(self, soup: BeautifulSoup) -> str:
        """Assess the impact of the IDOR vulnerability"""
        text_content = soup.get_text().lower()
        impacts = {
            'Account Takeover': ['account takeover', 'ato', 'takeover'],
            'Reading data': ['read data', 'view data', 'information disclosure', 'pii disclosure'],
            'Modifying data': ['modify data', 'update data', 'change data'],
            'Deleting data': ['delete data', 'remove data', 'destroy data'],
            'Executing Actions': ['perform action', 'execute action', 'unauthorized action'],
        }
        for impact, keywords in impacts.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'Reading data'

    def _detect_parameter_location(self, soup: BeautifulSoup) -> str:
        """Detect where the vulnerable parameter was located"""
        text_content = soup.get_text().lower()
        locations = {
            'HTTP Body': ['json', 'post request', 'request body'],
            'URL Path': ['url path', '/users/', '/api/v1/'],
            'Query Parameter': ['query parameter', '?id=', '?user_id='],
            'Cookie': ['cookie', 'session id'],
            'HTTP Header': ['http header', 'x-user-id'],
        }
        for loc, keywords in locations.items():
            if any(keyword in text_content for keyword in keywords):
                return loc
        return 'URL Path'

    def _get_default_values(self) -> Dict[str, str]:
        """Return default values when URL processing fails"""
        return { 'ID Type': 'unknown', 'Way to predict the identifier': 'unknown', 'Functionality': 'unknown', 'Impact': 'unknown', 'Parameter Location': 'unknown' }

    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        """Process all URLs in the CSV and add new columns"""
        new_columns = ['ID Type', 'Way to predict the identifier', 'Functionality', 'Impact', 'Parameter Location']
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
            if (index + 1) % 10 == 0 or (index + 1) == total_urls:
                self.save_progress(f'idor_analysis_progress_{index + 1}.csv')
        return self.df

    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")

    def save_results(self, filename: str = 'idor_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")

    def create_comprehensive_plots(self):
        """Generate comprehensive plots for IDOR analysis"""
        plt.style.use('seaborn-v0_8-whitegrid')
        fig, axes = plt.subplots(2, 2, figsize=(20, 16))
        fig.suptitle('IDOR Comprehensive Analysis', fontsize=22, fontweight='bold')

        # ID Type Distribution
        id_type_counts = self.df['ID Type'].value_counts().head(10)
        sns.barplot(y=id_type_counts.index, x=id_type_counts.values, ax=axes[0, 0], palette='viridis')
        axes[0, 0].set_title('Top 10 Vulnerable ID Types', fontsize=16)

        # Impact Distribution
        impact_counts = self.df['Impact'].value_counts().head(8)
        axes[0, 1].pie(impact_counts.values, labels=impact_counts.index, autopct='%1.1f%%', startangle=90, colors=sns.color_palette('pastel'))
        axes[0, 1].set_title('IDOR Impact Distribution', fontsize=16)
        axes[0, 1].axis('equal')

        # Functionality Distribution
        func_counts = self.df['Functionality'].value_counts().head(8)
        sns.barplot(y=func_counts.index, x=func_counts.values, ax=axes[1, 0], palette='crest')
        axes[1, 0].set_title('Top 8 Vulnerable Functionalities', fontsize=16)

        # Parameter Location
        location_counts = self.df['Parameter Location'].value_counts()
        sns.barplot(x=location_counts.index, y=location_counts.values, ax=axes[1, 1], palette='flare')
        axes[1, 1].set_title('Parameter Location Distribution', fontsize=16)

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig('idor_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'idor_comprehensive_analysis.png'")

    def generate_summary_report(self) -> Dict:
        """Generate a summary report with key metrics and bounty analysis"""
        
        bounty_by_id_type = self.df.groupby('ID Type')['Bounty_numeric'].agg(['count', 'mean']).reset_index()
        bounty_by_id_type = bounty_by_id_type.rename(columns={'count': 'NO reports', 'mean': 'AVG Bounty'})
        bounty_by_id_type_dict = bounty_by_id_type.set_index('ID Type').to_dict('index')

        summary = {
            'basic_statistics': {
                'total_reports': len(self.df),
                'total_bounty': self.df['Bounty_numeric'].sum(),
                'average_bounty': self.df['Bounty_numeric'].mean(),
            },
            'distributions': {
                'id_type': self.df['ID Type'].value_counts().to_dict(),
                'impact': self.df['Impact'].value_counts().to_dict(),
                'functionality': self.df['Functionality'].value_counts().to_dict(),
                'prediction_method': self.df['Way to predict the identifier'].value_counts().to_dict(),
                'parameter_location': self.df['Parameter Location'].value_counts().to_dict(),
            },
            'bounty_by_id_type': bounty_by_id_type_dict
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
    <title>Interactive IDOR Vulnerability Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        .chart-container {
            border-radius: 0.75rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            transition: all 0.2s ease-in-out; display: flex; flex-direction: column; justify-content: center;
        }
        .chart-container:hover { transform: translateY(-5px); box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -2px rgb(0 0 0 / 0.1); }
    </style>
     <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-gray-50 text-gray-800">
    <div class="container mx-auto p-4 md:p-8">
        <header class="text-center mb-10">
            <h1 class="text-3xl md:text-4xl font-bold text-gray-900">IDOR Vulnerability Analysis</h1>
        </header>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div class="bg-white p-6 chart-container"><div id="chart-id-type" class="w-full h-96"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-impact" class="w-full h-96"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-functionality" class="w-full h-96"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-prediction" class="w-full h-96"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-location" class="w-full h-96"></div></div>
            <div class="bg-white p-6 chart-container"><div id="chart-avg-bounty" class="w-full h-96"></div></div>
        </div>
    </div>
    <script>
        const analysisData = JSON.parse(`{{SUMMARY_JSON}}`);
        function processChartData(dataObject, filterUnknown = true) {
            let data = { ...dataObject };
            if (filterUnknown && data.unknown) delete data.unknown;
            const sortedArray = Object.entries(data).sort(([, a], [, b]) => a - b);
            return { labels: sortedArray.map(item => item[0]), values: sortedArray.map(item => item[1]) };
        }
        const commonLayout = { margin: { l: 250, r: 20, t: 80, b: 50 }, paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)', font: { family: 'Inter, sans-serif', color: '#374151' }, title: { font: { size: 18 } } };
        const pieLayout = { ...commonLayout, margin: { l: 20, r: 20 }, legend: { x: 1, y: 0.5, xanchor: 'left' } };
        
        const idTypeData = processChartData(analysisData.distributions.id_type);
        Plotly.newPlot('chart-id-type', [{ x: idTypeData.values, y: idTypeData.labels, type: 'bar', orientation: 'h', marker: { color: 'rgba(79, 70, 229, 0.8)' } }], { ...commonLayout, title: 'Vulnerable ID Types' }, {responsive: true});
        
        const impactData = processChartData(analysisData.distributions.impact);
        Plotly.newPlot('chart-impact', [{ x: impactData.values, y: impactData.labels, type: 'bar', orientation: 'h', marker: { color: 'rgba(219, 39, 119, 0.8)' } }], { ...commonLayout, title: 'Impact of IDOR' }, {responsive: true});
        
        const funcData = processChartData(analysisData.distributions.functionality);
        Plotly.newPlot('chart-functionality', [{ x: funcData.values, y: funcData.labels, type: 'bar', orientation: 'h', marker: { color: 'rgba(34, 197, 94, 0.8)' } }], { ...commonLayout, title: 'Vulnerable Functionality' }, {responsive: true});
        
        const predData = processChartData(analysisData.distributions.prediction_method);
        Plotly.newPlot('chart-prediction', [{ x: predData.values, y: predData.labels, type: 'bar', orientation: 'h', marker: { color: 'rgba(245, 158, 11, 0.8)' } }], { ...commonLayout, title: 'ID Prediction Methods' }, {responsive: true});

        const locationData = processChartData(analysisData.distributions.parameter_location);
        Plotly.newPlot('chart-location', [{ values: locationData.values, labels: locationData.labels, type: 'pie', hole: .4, textinfo: 'percent+label' }], { ...pieLayout, title: 'Parameter Location', showlegend: false }, {responsive: true});

        const bountyData = processChartData(Object.fromEntries(Object.entries(analysisData.bounty_by_id_type).map(([k, v]) => [k, v['AVG Bounty']])));
        Plotly.newPlot('chart-avg-bounty', [{ x: bountyData.values, y: bountyData.labels, type: 'bar', orientation: 'h', marker: { color: 'rgba(14, 165, 233, 0.8)' }, text: bountyData.values.map(v => `$${v.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`), textposition: 'inside' }], { ...commonLayout, title: 'Average Bounty by ID Type', xaxis: { title: 'Average Bounty ($)'}}, {responsive: true});
    </script>
</body>
</html>
        """
        
        # Replace the placeholder with the actual JSON data
        final_html = html_template.replace('{{SUMMARY_JSON}}', json.dumps(summary_data))
        
        with open('idor_interactive_dashboard.html', 'w') as f:
            f.write(final_html)
        logger.info("Interactive dashboard saved to idor_interactive_dashboard.html")


# Main execution block
if __name__ == "__main__":
    input_csv_file = './idor_writeups.csv' 
    
    try:
        analyzer = IDORAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
        logger.error("Please make sure the file exists and the path is correct.")
    else:
        print("Starting IDOR vulnerability analysis...")
        
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        analyzer.save_results('idor_analysis_complete.csv')

        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        
        summary = analyzer.generate_summary_report()
        with open('idor_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        analyzer.create_interactive_dashboard(summary)
        
        print("\nIDOR ANALYSIS COMPLETE!")
        print("Generated: idor_analysis_complete.csv, idor_comprehensive_analysis.png, idor_analysis_summary_report.json, idor_interactive_dashboard.html")

