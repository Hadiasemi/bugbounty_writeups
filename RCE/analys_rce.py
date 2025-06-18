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

class RCEAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the RCE analyzer with CSV data"""
        self.df = pd.read_csv(csv_file_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def extract_details_from_url(self, url: str) -> Dict[str, str]:
        """Extract RCE-specific details from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            rce_info = {
                'functionality': self._detect_functionality(soup),
                'vulnerability_type': self._detect_vulnerability_type(soup),
                'execution_context': self._detect_execution_context(soup),
                'attack_vector': self._detect_attack_vector(soup),
                'language_or_framework': self._detect_language_or_framework(soup),
                'impact': self._assess_impact(soup),
                'impact_severity': self._assess_impact_severity(soup),
                'technical_details': self._extract_technical_details(soup),
            }
            
            return rce_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()

    def _detect_functionality(self, soup: BeautifulSoup) -> str:
        """Detect the application functionality that was exploited."""
        text_content = soup.get_text().lower()
        funcs = {
            'Imports/Sharing': ['import', 'sharing', 'export', 'download feature'],
            'File Management': ['file management', 'file upload', 'file write', 'unzip', 'decompress'],
            'Admin/Config Panel': ['admin panel', 'config', 'settings', 'configuration'],
            'Image Processing': ['image processing', 'imagemagick', 'thumbnails'],
            'User Profile/Content': ['user profile', 'user content', 'posts', 'comments'],
            'CI/CD Pipeline': ['ci/cd', 'jenkins', 'gitlab ci', 'github actions', 'build process'],
        }
        for func, keywords in funcs.items():
            if any(keyword in text_content for keyword in keywords):
                return func
        return 'General Application Logic'

    def _detect_vulnerability_type(self, soup: BeautifulSoup) -> str:
        """Detect the root cause of the RCE vulnerability (the 'Reason' column)."""
        text_content = soup.get_text().lower()
        vuln_types = {
            'Command Injection': ['command injection', 'os command', 'shell command', '`', '$(', 'system(', 'exec('],
            'Insecure Deserialization': ['deserialization', 'unserialize', 'pickle', 'ysoserial', 'java deserialization'],
            'Unrestricted File Write/Upload': ['file upload', 'unrestricted file', 'arbitrary file', 'webshell', '.php', '.jsp', '.aspx'],
            'Server-Side Template Injection (SSTI)': ['ssti', 'template injection', 'jinja2', 'freemarker', 'velocity', '{{', '{%'],
            'Code Injection': ['code injection', 'eval(', 'require(', 'include('],
            'XXE': ['xxe', 'xml external entity'],
            'Log Poisoning': ['log poisoning', 'log file'],
        }
        for vuln_type, keywords in vuln_types.items():
            if any(keyword in text_content for keyword in keywords):
                return vuln_type
        return 'Command Injection'

    def _detect_execution_context(self, soup: BeautifulSoup) -> str:
        """Detect the environment where the RCE occurs (the 'Type' column)."""
        text_content = soup.get_text().lower()
        contexts = {
            'Server-side RCE': ['server-side', 'server rce', 'web server'],
            'Desktop App RCE': ['desktop app', 'electron', 'client-side rce'],
            'CI/CD Pipeline RCE': ['ci/cd', 'build server', 'jenkins', 'gitlab runner'],
        }
        for context, keywords in contexts.items():
            if any(keyword in text_content for keyword in keywords):
                return context
        return 'Server-side RCE'

    def _detect_attack_vector(self, soup: BeautifulSoup) -> str:
        """Detect how the RCE was delivered"""
        text_content = soup.get_text().lower()
        vectors = {
            'Web Application Parameter': ['parameter', 'query string', 'post data', 'form'],
            'API Endpoint': ['api', 'rest endpoint', 'graphql'],
            'Third-party Library': ['library', 'dependency', 'third party', 'cve-'],
            'File Upload Feature': ['upload', 'file format', 'metadata'],
            'Server Configuration': ['misconfiguration', 'server config'],
            'User-Agent Header': ['user-agent', 'ua string'],
        }
        for vector, keywords in vectors.items():
            if any(keyword in text_content for keyword in keywords):
                return vector
        return 'Web Application Parameter'

    def _detect_language_or_framework(self, soup: BeautifulSoup) -> str:
        """Detect the programming language or framework exploited"""
        text_content = soup.get_text().lower()
        tech = {
            'PHP': ['php', 'wordpress', 'drupal', 'laravel'],
            'Java': ['java', 'jvm', 'tomcat', 'jboss', 'spring', 'struts'],
            'Python': ['python', 'django', 'flask', 'pickle'],
            'NodeJS': ['nodejs', 'node.js', 'npm', 'javascript', 'express'],
            'Ruby': ['ruby', 'rails'],
            '.NET': ['dotnet', '.net', 'asp.net', 'c#'],
            'Generic Linux': ['linux', 'shell', 'bash'],
        }
        for language, keywords in tech.items():
            if any(keyword in text_content for keyword in keywords):
                return language
        return 'Generic Linux'

    def _assess_impact(self, soup: BeautifulSoup) -> str:
        """Assess the primary impact of the RCE (the 'Exploit' column)."""
        text_content = soup.get_text().lower()
        impacts = {
            'Shell/Command Execution': ['shell', 'reverse shell', 'command', 'netcat', 'nc -e'],
            'Full System Compromise': ['root', 'administrator', 'system compromise'],
            'Data Exfiltration': ['data exfiltration', 'steal data', 'database dump', '/etc/passwd'],
            'Service Disruption (DoS)': ['dos', 'denial of service', 'crash'],
            'Internal Network Pivoting': ['pivot', 'internal network', 'scan internal'],
        }
        for impact, keywords in impacts.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'Shell/Command Execution'

    def _assess_impact_severity(self, soup: BeautifulSoup) -> str:
        return 'critical' # RCE is almost always critical.

    def _extract_technical_details(self, soup: BeautifulSoup) -> str:
        text_content = soup.get_text()
        patterns = [
            r'Payload[:\s]+(.*?)(?:\n\s*\n|\Z)',
            r'Proof of Concept[:\s]+(.*?)(?:\n\s*\n|\.$)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text_content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip().replace('\n', ' ')[:400]
        return 'Payload not explicitly detailed'
    
    def _get_default_values(self) -> Dict[str, str]:
        return {
            'functionality': 'unknown',
            'vulnerability_type': 'unknown',
            'execution_context': 'unknown',
            'attack_vector': 'unknown',
            'language_or_framework': 'unknown',
            'impact': 'unknown',
            'impact_severity': 'critical',
            'technical_details': 'could not extract',
        }

    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        new_columns = ['functionality', 'vulnerability_type', 'execution_context', 'attack_vector', 
                       'language_or_framework', 'impact', 'impact_severity', 'technical_details']
        for col in new_columns:
            if col not in self.df.columns:
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
                self.save_progress(f'rce_analysis_progress_{index + 1}.csv')
                logger.info(f"Progress saved: {index + 1}/{total_urls} completed")
        return self.df

    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")

    def save_results(self, filename: str = 'rce_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")

    def create_comprehensive_plots(self):
        plt.style.use('seaborn-v0_8-whitegrid')
        fig, axes = plt.subplots(3, 2, figsize=(20, 24)) # Changed to 3x2 grid
        fig.suptitle('Remote Code Execution (RCE) Vulnerability Analysis', fontsize=22, fontweight='bold')

        # 1. RCE Vulnerability Types ('Reason')
        vuln_counts = self.df['vulnerability_type'].value_counts()
        sns.barplot(y=vuln_counts.index, x=vuln_counts.values, ax=axes[0, 0], palette='magma')
        axes[0, 0].set_title('Common RCE Vulnerability Types (Reason)', fontsize=16)
        axes[0, 0].set_xlabel('Count')

        # 2. Exploited Languages / Frameworks
        lang_counts = self.df['language_or_framework'].value_counts()
        sns.barplot(y=lang_counts.index, x=lang_counts.values, ax=axes[0, 1], palette='viridis')
        axes[0, 1].set_title('Exploited Technologies', fontsize=16)
        axes[0, 1].set_xlabel('Count')

        # 3. Application Functionality
        func_counts = self.df['functionality'].value_counts()
        sns.barplot(y=func_counts.index, x=func_counts.values, ax=axes[1, 0], palette='crest')
        axes[1, 0].set_title('Vulnerable Application Functionality', fontsize=16)
        axes[1, 0].set_xlabel('Count')

        # 4. Execution Context ('Type')
        context_counts = self.df['execution_context'].value_counts()
        sns.barplot(x=context_counts.index, y=context_counts.values, ax=axes[1, 1], palette='flare')
        axes[1, 1].set_title('RCE Execution Context (Type)', fontsize=16)
        axes[1, 1].set_ylabel('Count')

        # 5. Attack Vectors
        vector_counts = self.df['attack_vector'].value_counts()
        axes[2, 0].pie(vector_counts.values, labels=vector_counts.index, autopct='%1.1f%%',
                       startangle=90, colors=sns.color_palette('pastel'))
        axes[2, 0].set_title('RCE Attack Vectors', fontsize=16)

        # 6. RCE Impacts ('Exploit')
        impact_counts = self.df['impact'].value_counts()
        axes[2, 1].pie(impact_counts.values, labels=impact_counts.index, autopct='%1.1f%%',
                       startangle=140, colors=sns.color_palette('Set2'))
        axes[2, 1].set_title('Impact of RCE (Exploit)', fontsize=16)

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.savefig('rce_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'rce_comprehensive_analysis.png'")
        
        self.create_interactive_plots()

    def create_interactive_plots(self):
        # Updated Sankey: Functionality -> Vulnerability Type -> Execution Context -> Impact
        sankey_data = self.df[['functionality', 'vulnerability_type', 'execution_context', 'impact']].dropna()
        nodes = list(set(sankey_data['functionality']) | set(sankey_data['vulnerability_type']) | set(sankey_data['execution_context']) | set(sankey_data['impact']))
        node_dict = {node: i for i, node in enumerate(nodes)}
        
        links = []
        for col1, col2 in [('functionality', 'vulnerability_type'), ('vulnerability_type', 'execution_context'), ('execution_context', 'impact')]:
            grouped = sankey_data.groupby([col1, col2]).size().reset_index(name='count')
            for _, row in grouped.iterrows():
                links.append({'source': node_dict[row[col1]], 'target': node_dict[row[col2]], 'value': row['count']})
                
        fig = go.Figure(data=[go.Sankey(
            node=dict(pad=15, thickness=20, label=nodes, color='teal'),
            link=dict(source=[l['source'] for l in links], target=[l['target'] for l in links], value=[l['value'] for l in links])
        )])
        fig.update_layout(title_text="RCE Attack Flow: Functionality → Vulnerability → Context → Impact", font_size=12)
        fig.write_html("rce_attack_flow_sankey.html")
        logger.info("Interactive Sankey diagram saved as rce_attack_flow_sankey.html")

    def generate_summary_report(self) -> Dict:
        summary = {
            'statistics': { 'total_reports_analyzed': len(self.df) },
            'distributions': {
                'functionality': self.df['functionality'].value_counts().to_dict(),
                'vulnerability_type': self.df['vulnerability_type'].value_counts().to_dict(),
                'execution_context': self.df['execution_context'].value_counts().to_dict(),
                'language_or_framework': self.df['language_or_framework'].value_counts().to_dict(),
                'attack_vector': self.df['attack_vector'].value_counts().to_dict(),
                'impact': self.df['impact'].value_counts().to_dict(),
            },
            'key_insights': {
                'most_common_vuln_type': self.df['vulnerability_type'].mode()[0] if not self.df['vulnerability_type'].empty else 'N/A',
                'most_exploited_functionality': self.df['functionality'].mode()[0] if not self.df['functionality'].empty else 'N/A',
                'most_common_exec_context': self.df['execution_context'].mode()[0] if not self.df['execution_context'].empty else 'N/A',
            },
            'security_recommendations': self._generate_security_recommendations()
        }
        return summary

    def _generate_security_recommendations(self) -> List[str]:
        return [
            "Always sanitize and validate all user-supplied input. Never trust user input.",
            "Use parameterized queries and prepared statements to prevent injection attacks.",
            "Avoid direct calls to OS commands. Use built-in language functions where possible.",
            "Implement strong controls on file uploads: restrict file types, rename files on upload, and serve them from a non-executable domain.",
            "Keep all libraries, frameworks, and server software up-to-date to patch known vulnerabilities.",
            "Use secure, modern serialization formats and avoid deserializing untrusted data.",
            "Apply the principle of least privilege. Run application processes with the minimum permissions necessary.",
        ]

# Main execution block
if __name__ == "__main__":
    # !!! IMPORTANT: Replace 'your_rce_data.csv' with the path to your CSV file.
    # The CSV must have columns like 'URL', 'Bounty', 'Program', etc.
    input_csv_file = './rce_writeups.csv'
    
    try:
        analyzer = RCEAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
        logger.error("Please make sure the file exists and the path is correct.")
    else:
        print("Starting Remote Code Execution (RCE) vulnerability analysis...")
        print(f"Processing URLs from {input_csv_file}. Progress will be saved every 10 URLs.")
        
        # Process all URLs
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        
        # Save final results
        analyzer.save_results('rce_analysis_complete.csv')
        
        # Generate plots and summary
        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        summary = analyzer.generate_summary_report()
        
        # Save summary report to JSON
        with open('rce_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        print("\n" + "="*60)
        print("RCE ANALYSIS COMPLETE!")
        print("="*60)
        
        print("\n📊 KEY INSIGHTS:")
        print(f"  • Total reports analyzed: {summary['statistics']['total_reports_analyzed']}")
        print(f"  • Most common vulnerability type (Reason): {summary['key_insights']['most_common_vuln_type']}")
        print(f"  • Most exploited functionality: {summary['key_insights']['most_exploited_functionality']}")
        print(f"  • Most common execution context (Type): {summary['key_insights']['most_common_exec_context']}")
        
        print("\n🚨 SECURITY RECOMMENDATIONS:")
        for i, rec in enumerate(summary['security_recommendations'], 1):
            print(f"  {i}. {rec}")
            
        print(f"\n📁 FILES GENERATED:")
        print(f"  • rce_analysis_complete.csv - Full dataset with RCE analysis.")
        print(f"  • rce_comprehensive_analysis.png - Static plot with key distributions.")
        print(f"  • rce_attack_flow_sankey.html - Interactive attack flow diagram.")
        print(f"  • rce_analysis_summary_report.json - Detailed summary in JSON format.")
