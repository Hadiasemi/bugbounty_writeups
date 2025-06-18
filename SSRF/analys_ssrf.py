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

class SSRFAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the SSRF analyzer with CSV data"""
        self.df = pd.read_csv(csv_file_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def extract_functionality_from_url(self, url: str) -> Dict[str, str]:
        """Extract functionality information from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract various functionalities based on common patterns
            functionality_info = {
                'functionality': self._detect_functionality(soup, url),
                'parameter_name': self._extract_parameter_names(soup),
                'bypass_method': self._detect_bypass_method(soup),
                'read_capability': self._detect_read_capability(soup),
                'impact': self._assess_impact_detailed(soup),
                'impact_severity': self._assess_impact_severity(soup),
                'attack_vector': self._identify_attack_vector(soup),
                'technical_details': self._extract_technical_details(soup),
                'comments': self._extract_key_comments(soup)
            }
            
            return functionality_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()
    
    def _detect_functionality(self, soup: BeautifulSoup, url: str) -> str:
        """Detect the main functionality vulnerable to SSRF"""
        text_content = soup.get_text().lower()
        
        functionalities = {
            'import by url': ['import', 'url', 'fetch', 'download', 'retrieve'],
            'webhook': ['webhook', 'callback', 'notification', 'ping'],
            'url preview': ['preview', 'unfurl', 'link preview', 'meta', 'og:'],
            'file upload': ['upload', 'file', 'attachment', 'media'],
            'image processing': ['image', 'resize', 'thumbnail', 'convert', 'process'],
            'pdf generation': ['pdf', 'generate', 'report', 'document', 'headless browser'],
            'api integration': ['api', 'integration', 'third party', 'external'],
            'feed reader': ['rss', 'feed', 'xml', 'atom'],
            'proxy/redirect': ['proxy', 'forward', 'relay', 'redirect'],
            'monitoring': ['monitor', 'health check', 'ping', 'status'],
            'oauth/auth': ['oauth', 'authentication', 'login', 'authorize'],
            'cloud services': ['aws', 'gcp', 'azure', 'cloud', 'metadata'],
            'email/notification': ['email', 'mail', 'notify', 'alert'],
            'backup/sync': ['backup', 'sync', 'synchronize', 'mirror']
        }
        
        functionality_scores = {func: sum(1 for kw in kws if kw in text_content) for func, kws in functionalities.items()}
        
        if any(functionality_scores.values()):
            return max(functionality_scores, key=functionality_scores.get)
        
        return 'unknown'
    
    def _extract_parameter_names(self, soup: BeautifulSoup) -> str:
        """Extract parameter names mentioned in the content"""
        text_content = soup.get_text()
        
        param_patterns = [
            r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
            r'parameter[:\s]+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*"http',
        ]
        
        found_params = {match for pattern in param_patterns for match in re.findall(pattern, text_content, re.IGNORECASE)}
        
        priority_params = ['url', 'uri', 'endpoint', 'callback', 'webhook', 'src', 'host', 'redirect_uri']
        
        text_lower = text_content.lower()
        for param in priority_params:
            if param in text_lower:
                found_params.add(param)

        return ', '.join(sorted(list(found_params))[:3]) or 'url'
    
    def _detect_bypass_method(self, soup: BeautifulSoup) -> str:
        """Detect SSRF bypass methods mentioned"""
        text_content = soup.get_text().lower()
        
        bypass_methods = {
            'iframe embedding': ['<iframe src=', '<iframe', 'iframe src'],
            'redirect': ['redirect', '302', '301', 'location header'],
            'dns rebinding': ['dns rebinding', 'rebind'],
            'url encoding': ['url encoding', 'percent encoding'],
            'ip bypass': ['127.0.0.1', 'localhost', '0.0.0.0', 'internal ip', '169.254'],
            'protocol bypass': ['file://', 'gopher://', 'dict://'],
            'no address bypass necessary': ['no bypass', 'direct', 'no filter'],
        }
        
        for method, keywords in bypass_methods.items():
            if any(keyword in text_content for keyword in keywords):
                return method
        
        return 'redirect'
    
    def _detect_read_capability(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text().lower()
        if 'blind' in text_content: return 'blind'
        if 'partial' in text_content: return 'partial-read'
        if 'full' in text_content: return 'full-read'
        return 'full-read'
    
    def _assess_impact_detailed(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text().lower()
        impact_categories = {
            'rce': ['rce', 'remote code execution'],
            'cloud metadata': ['cloud metadata', 'instance metadata'],
            'internal network access': ['internal network', 'port scan'],
            'credential theft': ['token', 'credential', 'secret', 'api key'],
            'data exfiltration': ['data exfiltration', 'sensitive data'],
            'file system access': ['file system', 'local file', 'file read'],
        }
        for impact, keywords in impact_categories.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'information disclosure'
    
    def _assess_impact_severity(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text().lower()
        if 'critical' in text_content: return 'critical'
        if 'high' in text_content: return 'high'
        if 'medium' in text_content: return 'medium'
        if 'low' in text_content: return 'low'
        return 'medium'
    
    def _identify_attack_vector(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text().lower()
        if 'api' in text_content: return 'api endpoint'
        if 'mobile' in text_content: return 'mobile app'
        return 'web application'

    def _extract_technical_details(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text()
        match = re.search(r'technical details?[:\s]+(.*?)(?:\n\s*\n|\.$)', text_content, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:300] if match else 'standard ssrf exploitation'

    def _extract_key_comments(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text()
        match = re.search(r'conclusion[:\s]+(.*?)(?:\n\s*\n|\.$)', text_content, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:300] if match else 'ssrf vulnerability with impact on internal resources'

    def _get_default_values(self) -> Dict[str, str]:
        return {
            'functionality': 'unknown', 'parameter_name': 'url', 'bypass_method': 'redirect',
            'read_capability': 'unknown', 'impact': 'unknown', 'impact_severity': 'unknown',
            'attack_vector': 'unknown', 'technical_details': 'could not extract', 'comments': 'could not extract'
        }
    
    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        new_columns = ['functionality', 'parameter_name', 'bypass_method', 'read_capability', 'impact', 'impact_severity', 'attack_vector', 'technical_details', 'comments']
        for col in new_columns:
            if col not in self.df.columns: self.df[col] = ''
        
        for index, row in self.df.iterrows():
            logger.info(f"Processing {index + 1}/{len(self.df)}: {row['URL']}")
            url_info = self.extract_functionality_from_url(row['URL'])
            for col, value in url_info.items():
                self.df.at[index, col] = value
            time.sleep(delay)
            if (index + 1) % 10 == 0 or (index + 1) == len(self.df):
                self.save_progress(f'ssrf_analysis_progress_{index + 1}.csv')
        return self.df
    
    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")
    
    def save_results(self, filename: str = 'ssrf_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")
    
    def create_comprehensive_plots(self):
        plt.style.use('seaborn-v0_8-whitegrid')
        fig, axes = plt.subplots(2, 2, figsize=(20, 16))
        fig.suptitle('SSRF Comprehensive Analysis', fontsize=22, fontweight='bold')
        
        # Functionality Distribution
        func_counts = self.df['functionality'].value_counts().head(10)
        sns.barplot(y=func_counts.index, x=func_counts.values, ax=axes[0, 0], palette='viridis')
        axes[0, 0].set_title('Top 10 Vulnerable Functionalities', fontsize=16)

        # Impact Distribution
        impact_counts = self.df['impact'].value_counts().head(8)
        axes[0, 1].pie(impact_counts.values, labels=impact_counts.index, autopct='%1.1f%%', startangle=90)
        axes[0, 1].set_title('SSRF Impact Distribution', fontsize=16)
        axes[0, 1].axis('equal')

        # Bypass Methods
        bypass_counts = self.df['bypass_method'].value_counts().head(8)
        sns.barplot(y=bypass_counts.index, x=bypass_counts.values, ax=axes[1, 0], palette='crest')
        axes[1, 0].set_title('Top 8 SSRF Bypass Methods', fontsize=16)

        # Impact Severity
        severity_counts = self.df['impact_severity'].value_counts().reindex(['critical', 'high', 'medium', 'low'], fill_value=0)
        sns.barplot(x=severity_counts.index, y=severity_counts.values, ax=axes[1, 1], palette='flare')
        axes[1, 1].set_title('Impact Severity Distribution', fontsize=16)

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig('ssrf_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'ssrf_comprehensive_analysis.png'")

    def create_interactive_plots(self):
        # Interactive Heatmap: Functionality vs Impact
        crosstab = pd.crosstab(self.df['functionality'], self.df['impact'])
        fig = px.imshow(crosstab, title="Functionality vs. Impact Heatmap", aspect="auto")
        fig.write_html("ssrf_functionality_impact_heatmap.html")
        logger.info("Interactive heatmap saved to ssrf_functionality_impact_heatmap.html")

    def generate_advanced_summary_report(self) -> Dict:
        self.df['Bounty_numeric'] = pd.to_numeric(self.df['Bounty'], errors='coerce').fillna(0)
        report = {
            "basic_statistics": {
                "total_reports": len(self.df),
                "total_bounty": self.df['Bounty_numeric'].sum(),
                "average_bounty": self.df['Bounty_numeric'].mean(),
            },
            "distributions": {
                "functionality": self.df['functionality'].value_counts().to_dict(),
                "impact": self.df['impact'].value_counts().to_dict(),
                "bypass_methods": self.df['bypass_method'].value_counts().to_dict(),
            }
        }
        return report

# Main execution block
if __name__ == "__main__":
    input_csv_file = './ssrf_writeups.csv' 
    
    try:
        analyzer = SSRFAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
    else:
        print("Starting SSRF vulnerability analysis...")
        
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        analyzer.save_results('ssrf_analysis_complete.csv')

        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        analyzer.create_interactive_plots()
        
        summary = analyzer.generate_advanced_summary_report()
        with open('ssrf_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        print("\nSSRF ANALYSIS COMPLETE!")
        print("Generated: ssrf_analysis_complete.csv, ssrf_comprehensive_analysis.png, ssrf_functionality_impact_heatmap.html, ssrf_analysis_summary_report.json")

