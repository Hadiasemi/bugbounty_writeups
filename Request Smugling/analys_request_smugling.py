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

class SmugglingAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the Request Smuggling analyzer with CSV data"""
        self.df = pd.read_csv(csv_file_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def extract_details_from_url(self, url: str) -> Dict[str, str]:
        """Extract Request Smuggling-specific details from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            smuggling_info = {
                'smuggling_type': self._detect_smuggling_type(soup),
                'desync_impact': self._assess_desync_impact(soup),
                'vulnerable_component': self._detect_vulnerable_component(soup),
                'obfuscation_method': self._detect_obfuscation_method(soup),
                'impact_severity': self._assess_impact_severity(soup),
                'technical_details': self._extract_technical_details(soup),
            }
            
            return smuggling_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()

    def _detect_smuggling_type(self, soup: BeautifulSoup) -> str:
        """Detect the type of HTTP Request Smuggling (CL.TE, TE.CL, etc.)"""
        text_content = soup.get_text().lower()
        types = {
            'CL.TE': ['cl.te', 'cl-te', 'content-length then transfer-encoding'],
            'TE.CL': ['te.cl', 'te-cl', 'transfer-encoding then content-length'],
            'TE.TE': ['te.te', 'te-te', 'transfer-encoding then transfer-encoding', 'obfuscating te header'],
            'HTTP/2 Downgrade': ['http/2', 'h2.h1', 'downgrade attack', 'h2 smuggle'],
        }
        for smuggle_type, keywords in types.items():
            if any(keyword in text_content for keyword in keywords):
                return smuggle_type
        return 'CL.TE' # Common default

    def _assess_desync_impact(self, soup: BeautifulSoup) -> str:
        """Assess the impact achieved through the desynchronization"""
        text_content = soup.get_text().lower()
        impacts = {
            'Cache Poisoning/Deception': ['cache poisoning', 'cache deception', 'poison the cache'],
            'Bypass Security Controls/WAF': ['bypass', 'waf bypass', 'block rule', 'front-end security'],
            'Session Hijacking/Request Capture': ['hijack', 'capture request', 'steal session', 'session hijacking', 'credential theft'],
            'Internal SSRF': ['ssrf', 'internal request', 'smuggled ssrf'],
            'Stored XSS': ['xss', 'cross-site scripting', 'reflected xss'],
            'Account Takeover': ['account takeover', 'ato'],
            'Reveal Front-End Rewriting': ['reveal rewrite', 'request rewriting', 'internal headers'],
        }
        for impact, keywords in impacts.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'Bypass Security Controls/WAF'

    def _detect_vulnerable_component(self, soup: BeautifulSoup) -> str:
        """Detect the vulnerable front-end or back-end component mentioned"""
        text_content = soup.get_text().lower()
        components = {
            'Front-End Proxy (General)': ['front-end', 'proxy', 'reverse proxy', 'load balancer'],
            'Cloudflare': ['cloudflare'],
            'Akamai': ['akamai'],
            'Varnish': ['varnish'],
            'Nginx': ['nginx'],
            'HAProxy': ['haproxy'],
            'Apache': ['apache'],
            'Back-End Server (General)': ['back-end', 'application server'],
        }
        for component, keywords in components.items():
            if any(keyword in text_content for keyword in keywords):
                return component
        return 'Front-End Proxy (General)'

    def _detect_obfuscation_method(self, soup: BeautifulSoup) -> str:
        """Detect any special obfuscation methods used"""
        text_content = soup.get_text().lower()
        methods = {
            'Header Obfuscation (Newline)': ['newline', '\\n', 'obfuscate', 'header injection'],
            'Case-Sensitivity': ['case', 'uppercase', 'lowercase'],
            'Header-Name Obfuscation': ['underscore', 'content_length'],
            'Whitespace Obfuscation': ['whitespace', 'tabs', 'space'],
        }
        for method, keywords in methods.items():
            if any(keyword in text_content for keyword in keywords):
                return method
        return 'None'

    def _assess_impact_severity(self, soup: BeautifulSoup) -> str:
        """Assess the severity level of the impact"""
        text_content = soup.get_text().lower()
        if any(k in text_content for k in ['critical', 'hijack', 'capture', 'account takeover', 'ssrf', 'rce']):
            return 'critical'
        if any(k in text_content for k in ['high', 'cache poisoning', 'waf bypass', 'xss']):
            return 'high'
        if any(k in text_content for k in ['medium', 'reveal rewrite']):
            return 'medium'
        if any(k in text_content for k in ['low', 'informational']):
            return 'low'
        return 'high' # Default for most smuggling

    def _extract_technical_details(self, soup: BeautifulSoup) -> str:
        """Extract key technical details or the payload from the report"""
        text_content = soup.get_text()
        # Prioritize finding the payload itself
        patterns = [
            r'Payload[:\s]+(POST.*?)(?:\n\s*\n|\Z)',
            r'Request[:\s]+(POST.*?)(?:\n\s*\n|\Z)',
            r'Proof of Concept[:\s]+(.*?)(?:\n\s*\n|\.$)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text_content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip().replace('\n', ' ')[:400]
        return 'Standard CL.TE or TE.CL payload'

    def _get_default_values(self) -> Dict[str, str]:
        return {
            'smuggling_type': 'unknown',
            'desync_impact': 'unknown',
            'vulnerable_component': 'unknown',
            'obfuscation_method': 'unknown',
            'impact_severity': 'unknown',
            'technical_details': 'could not extract',
        }

    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        new_columns = ['smuggling_type', 'desync_impact', 'vulnerable_component', 
                       'obfuscation_method', 'impact_severity', 'technical_details']
        for col in new_columns:
            self.df[col] = ''
        
        total_urls = len(self.df)
        for index, row in self.df.iterrows():
            url = row['URL']
            logger.info(f"Processing {index + 1}/{total_urls}: {url}")
            url_info = self.extract_details_from_url(url)
            for col, value in url_info.items():
                self.df.at[index, col] = value
            time.sleep(delay)
            if (index + 1) % 10 == 0 or (index + 1) == total_urls:
                self.save_progress(f'smuggling_analysis_progress_{index + 1}.csv')
                logger.info(f"Progress saved: {index + 1}/{total_urls} completed")
        return self.df

    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")

    def save_results(self, filename: str = 'smuggling_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")

    def create_comprehensive_plots(self):
        plt.style.use('seaborn-v0_8-darkgrid')
        fig, axes = plt.subplots(2, 2, figsize=(20, 16))
        fig.suptitle('HTTP Request Smuggling Analysis', fontsize=22, fontweight='bold')

        # 1. Smuggling Types
        type_counts = self.df['smuggling_type'].value_counts()
        sns.barplot(x=type_counts.index, y=type_counts.values, ax=axes[0, 0], palette='viridis')
        axes[0, 0].set_title('Request Smuggling Types Distribution', fontsize=16)
        axes[0, 0].set_ylabel('Count')

        # 2. Desynchronization Impacts
        impact_counts = self.df['desync_impact'].value_counts()
        sns.barplot(y=impact_counts.index, x=impact_counts.values, ax=axes[0, 1], palette='plasma')
        axes[0, 1].set_title('Impact of Desynchronization', fontsize=16)
        axes[0, 1].set_xlabel('Count')

        # 3. Impact Severity
        severity_counts = self.df['impact_severity'].value_counts().reindex(['critical', 'high', 'medium', 'low'], fill_value=0)
        axes[1, 0].pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                       startangle=90, colors=['#d62728', '#ff7f0e', '#ffbb78', '#1f77b4'])
        axes[1, 0].set_title('Impact Severity', fontsize=16)
        axes[1, 0].axis('equal')

        # 4. Vulnerable Components
        component_counts = self.df['vulnerable_component'].value_counts()
        sns.barplot(y=component_counts.index, x=component_counts.values, ax=axes[1, 1], palette='cubehelix')
        axes[1, 1].set_title('Commonly Implicated Components', fontsize=16)
        axes[1, 1].set_xlabel('Count')

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.savefig('smuggling_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'smuggling_comprehensive_analysis.png'")
        
        self.create_interactive_plots()

    def create_interactive_plots(self):
        # Interactive Sankey Diagram: Type -> Component -> Impact
        sankey_data = self.df[['smuggling_type', 'vulnerable_component', 'desync_impact']].dropna()
        all_nodes = list(set(sankey_data['smuggling_type']) | set(sankey_data['vulnerable_component']) | set(sankey_data['desync_impact']))
        node_dict = {node: i for i, node in enumerate(all_nodes)}
        
        links = []
        # Type -> Component
        for _, row in sankey_data.groupby(['smuggling_type', 'vulnerable_component']).size().reset_index(name='count').iterrows():
            links.append({'source': node_dict[row['smuggling_type']], 'target': node_dict[row['vulnerable_component']], 'value': row['count']})
        # Component -> Impact
        for _, row in sankey_data.groupby(['vulnerable_component', 'desync_impact']).size().reset_index(name='count').iterrows():
            links.append({'source': node_dict[row['vulnerable_component']], 'target': node_dict[row['desync_impact']], 'value': row['count']})
            
        fig = go.Figure(data=[go.Sankey(
            node=dict(pad=15, thickness=20, label=all_nodes, color='royalblue'),
            link=dict(source=[l['source'] for l in links], target=[l['target'] for l in links], value=[l['value'] for l in links])
        )])
        fig.update_layout(title_text="Request Smuggling Flow: Technique → Component → Impact", font_size=12)
        fig.write_html("smuggling_attack_flow_sankey.html")
        logger.info("Interactive Sankey diagram saved as smuggling_attack_flow_sankey.html")

    def generate_summary_report(self) -> Dict:
        summary = {
            'statistics': {
                'total_reports_analyzed': len(self.df),
            },
            'distributions': {
                'smuggling_type': self.df['smuggling_type'].value_counts().to_dict(),
                'desync_impact': self.df['desync_impact'].value_counts().to_dict(),
                'vulnerable_component': self.df['vulnerable_component'].value_counts().to_dict(),
                'impact_severity': self.df['impact_severity'].value_counts().to_dict(),
            },
            'key_insights': {
                'most_common_technique': self.df['smuggling_type'].mode()[0] if not self.df['smuggling_type'].empty else 'N/A',
                'most_severe_impact': self.df['desync_impact'].mode()[0] if not self.df['desync_impact'].empty else 'N/A',
                'most_implicated_component': self.df['vulnerable_component'].mode()[0] if not self.df['vulnerable_component'].empty else 'N/A',
            },
            'security_recommendations': self._generate_security_recommendations()
        }
        return summary

    def _generate_security_recommendations(self) -> List[str]:
        recommendations = [
            "Normalize ambiguous requests at the front-end proxy to prevent interpretation differences.",
            "Use HTTP/2 end-to-end and disable HTTP downgrade capabilities if possible.",
            "Reject requests containing both 'Content-Length' and 'Transfer-Encoding' headers.",
            "Ensure the front-end and back-end servers have identical timeout settings to prevent sockets from being poisoned and reused.",
            "Regularly audit front-end proxy configurations for any non-standard behavior that could be abused."
        ]
        return recommendations

# Main execution block
if __name__ == "__main__":
    # !!! IMPORTANT: Replace 'your_smuggling_data.csv' with the path to your CSV file.
    # The CSV must have a column named 'URL'.
    input_csv_file = './request smuggling_writeups.csv'
    
    try:
        analyzer = SmugglingAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
        logger.error("Please make sure the file exists and the path is correct.")
    else:
        print("Starting HTTP Request Smuggling vulnerability analysis...")
        print(f"Processing URLs from {input_csv_file}. Progress will be saved every 10 URLs.")
        
        # Process all URLs
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        
        # Save final results
        analyzer.save_results('smuggling_analysis_complete.csv')
        
        # Generate plots and summary
        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        summary = analyzer.generate_summary_report()
        
        # Save summary report to JSON
        with open('smuggling_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        print("\n" + "="*60)
        print("REQUEST SMUGGLING ANALYSIS COMPLETE!")
        print("="*60)
        
        print("\n📊 KEY INSIGHTS:")
        print(f"  • Total reports analyzed: {summary['statistics']['total_reports_analyzed']}")
        print(f"  • Most common technique: {summary['key_insights']['most_common_technique']}")
        print(f"  • Most frequent impact: {summary['key_insights']['most_severe_impact']}")
        print(f"  • Most implicated component: {summary['key_insights']['most_implicated_component']}")
        
        print("\n🚨 SECURITY RECOMMENDATIONS:")
        for i, rec in enumerate(summary['security_recommendations'], 1):
            print(f"  {i}. {rec}")
            
        print(f"\n📁 FILES GENERATED:")
        print(f"  • smuggling_analysis_complete.csv - Full dataset with analysis.")
        print(f"  • smuggling_comprehensive_analysis.png - Static plot with key distributions.")
        print(f"  • smuggling_attack_flow_sankey.html - Interactive attack flow diagram.")
        print(f"  • smuggling_analysis_summary_report.json - Detailed summary in JSON format.")
