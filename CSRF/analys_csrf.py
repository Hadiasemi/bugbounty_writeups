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

class CSRFAnalyzer:
    def __init__(self, csv_file_path: str):
        """Initialize the CSRF analyzer with CSV data"""
        self.df = pd.read_csv(csv_file_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def extract_details_from_url(self, url: str) -> Dict[str, str]:
        """Extract CSRF-specific details from a given URL"""
        try:
            logger.info(f"Processing URL: {url}")
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            csrf_info = {
                'functionality': self._detect_functionality(soup),
                'request_method': self._detect_request_method(soup),
                'anti_csrf_bypass': self._detect_anti_csrf_bypass(soup),
                'impact': self._assess_impact(soup),
                'impact_severity': self._assess_impact_severity(soup),
                'attack_vector': self._identify_attack_vector(soup),
                'technical_details': self._extract_technical_details(soup),
                'comments': self._extract_key_comments(soup)
            }
            
            return csrf_info
            
        except requests.RequestException as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            return self._get_default_values()
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            return self._get_default_values()

    def _detect_functionality(self, soup: BeautifulSoup) -> str:
        """Detect the main functionality vulnerable to CSRF"""
        text_content = soup.get_text().lower()
        functionalities = {
            'account management': ['password', 'email', 'profile', 'account', 'delete account', 'update setting'],
            'content management': ['post', 'comment', 'publish', 'delete post', 'update content'],
            'e-commerce': ['add to cart', 'checkout', 'purchase', 'order', 'payment'],
            'social actions': ['like', 'follow', 'friend request', 'share', 'vote'],
            'administrative actions': ['user management', 'privilege', 'role', 'admin action'],
            'form submission': ['submit', 'form', 'contact us', 'feedback']
        }
        for functionality, keywords in functionalities.items():
            if any(keyword in text_content for keyword in keywords):
                return functionality
        return 'unknown'

    def _detect_request_method(self, soup: BeautifulSoup) -> str:
        """Detect the HTTP request method used in the CSRF attack"""
        text_content = soup.get_text().lower()
        if 'post request' in text_content or 'http post' in text_content or 'post form' in text_content:
            return 'POST'
        if 'get request' in text_content or 'http get' in text_content or 'link-based' in text_content:
            return 'GET'
        if 'put request' in text_content:
            return 'PUT'
        if 'delete request' in text_content:
            return 'DELETE'
        return 'POST' # Default assumption

    def _detect_anti_csrf_bypass(self, soup: BeautifulSoup) -> str:
        """Detect the anti-CSRF mechanism that was bypassed"""
        text_content = soup.get_text().lower()
        bypass_methods = {
            'no token': ['no token', 'token not implemented', 'missing token', 'no anti-csrf'],
            'token validation bypass': ['token validation', 'token not checked', 'token verification bypass'],
            'referer validation bypass': ['referer check', 'referer validation', 'origin header', 'bypass referer'],
            'samesite cookie bypass': ['samesite', 'lax', 'strict', 'cookie policy'],
            'token reuse': ['reused token', 'token not expiring', 'static token'],
            'token exposed in url': ['token in url', 'token leakage', 'get request with token'],
            'json-based csrf': ['json', 'content-type', 'application/json'],
            'custom header bypass': ['x-requested-with', 'custom header check']
        }
        for method, keywords in bypass_methods.items():
            if any(keyword in text_content for keyword in keywords):
                return method
        return 'no token' # Most common reason

    def _assess_impact(self, soup: BeautifulSoup) -> str:
        """Assess the impact of the CSRF vulnerability"""
        text_content = soup.get_text().lower()
        impacts = {
            'account takeover': ['account takeover', 'ato', 'takeover', 'change password', 'change email'],
            'unauthorized actions': ['unauthorized action', 'post content', 'send message', 'perform action'],
            'information disclosure': ['information disclosure', 'leak', 'sensitive data'],
            'privilege escalation': ['privilege escalation', 'gain admin', 'escalate privileges'],
            'resource manipulation': ['delete data', 'modify content', 'update settings']
        }
        for impact, keywords in impacts.items():
            if any(keyword in text_content for keyword in keywords):
                return impact
        return 'unauthorized actions'

    def _assess_impact_severity(self, soup: BeautifulSoup) -> str:
        """Assess the severity level of the impact"""
        text_content = soup.get_text().lower()
        if any(k in text_content for k in ['critical', 'account takeover', 'rce']):
            return 'critical'
        if any(k in text_content for k in ['high', 'privilege escalation', 'sensitive']):
            return 'high'
        if any(k in text_content for k in ['medium', 'unauthorized actions', 'delete data']):
            return 'medium'
        if any(k in text_content for k in ['low', 'limited', 'ui redressing']):
            return 'low'
        return 'medium'

    def _identify_attack_vector(self, soup: BeautifulSoup) -> str:
        """Identify the primary attack vector"""
        text_content = soup.get_text().lower()
        if 'api' in text_content or 'endpoint' in text_content:
            return 'api endpoint'
        if 'form' in text_content:
            return 'form-based attack'
        if 'link' in text_content or 'img src' in text_content or '<img>' in text_content:
            return 'link/image-based attack'
        return 'web application'

    def _extract_technical_details(self, soup: BeautifulSoup) -> str:
        """Extract key technical details from the report"""
        text_content = soup.get_text()
        patterns = [
            r'technical details?[:\s]+(.*?)(?:\n\s*\n|\.$)',
            r'proof of concept[:\s]+(.*?)(?:\n\s*\n|\.$)',
            r'exploitation[:\s]+(.*?)(?:\n\s*\n|\.$)'
        ]
        for pattern in patterns:
            match = re.search(pattern, text_content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip().replace('\n', ' ')[:300]
        return 'standard csrf exploitation'

    def _extract_key_comments(self, soup: BeautifulSoup) -> str:
        """Extract key comments or summary findings"""
        text_content = soup.get_text()
        sections = ['conclusion', 'impact', 'summary', 'takeaway']
        for section in sections:
            pattern = rf'{section}[:\s]+(.*?)(?:\n\s*\n|\.$)'
            match = re.search(pattern, text_content, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip().replace('\n', ' ')[:300]
        return 'State-changing action vulnerable to CSRF'

    def _get_default_values(self) -> Dict[str, str]:
        """Return default values when URL processing fails"""
        return {
            'functionality': 'unknown',
            'request_method': 'unknown',
            'anti_csrf_bypass': 'unknown',
            'impact': 'unknown',
            'impact_severity': 'unknown',
            'attack_vector': 'unknown',
            'technical_details': 'could not extract',
            'comments': 'could not extract'
        }

    def process_all_urls(self, delay: float = 2.0) -> pd.DataFrame:
        """Process all URLs in the CSV and add new columns"""
        new_columns = ['functionality', 'request_method', 'anti_csrf_bypass', 'impact', 
                       'impact_severity', 'attack_vector', 'technical_details', 'comments']
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
                self.save_progress(f'csrf_analysis_progress_{index + 1}.csv')
                logger.info(f"Progress saved: {index + 1}/{total_urls} completed")
        return self.df

    def save_progress(self, filename: str):
        self.df.to_csv(filename, index=False)
        logger.info(f"Progress saved to {filename}")

    def save_results(self, filename: str = 'csrf_analysis_complete.csv'):
        self.df.to_csv(filename, index=False)
        logger.info(f"Complete analysis saved to {filename}")

    def create_comprehensive_plots(self):
        """Generate comprehensive plots for CSRF analysis"""
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(3, 2, figsize=(18, 22))
        fig.suptitle('Comprehensive CSRF Vulnerability Analysis', fontsize=20, fontweight='bold')
        
        # 1. Vulnerable Functionalities
        func_counts = self.df['functionality'].value_counts().head(10)
        sns.barplot(x=func_counts.values, y=func_counts.index, ax=axes[0, 0], palette='viridis')
        axes[0, 0].set_title('Top 10 Vulnerable Functionalities', fontsize=14)
        axes[0, 0].set_xlabel('Count')
        axes[0, 0].set_ylabel('Functionality')

        # 2. Impact Distribution
        impact_counts = self.df['impact'].value_counts().head(8)
        axes[0, 1].pie(impact_counts.values, labels=impact_counts.index, autopct='%1.1f%%',
                       startangle=90, colors=sns.color_palette('pastel'))
        axes[0, 1].set_title('CSRF Impact Distribution', fontsize=14)
        axes[0, 1].axis('equal')

        # 3. Anti-CSRF Bypass Methods
        bypass_counts = self.df['anti_csrf_bypass'].value_counts().head(8)
        sns.barplot(x=bypass_counts.values, y=bypass_counts.index, ax=axes[1, 0], palette='crest')
        axes[1, 0].set_title('Common Anti-CSRF Bypasses', fontsize=14)
        axes[1, 0].set_xlabel('Count')
        axes[1, 0].set_ylabel('Bypass Method')

        # 4. Impact Severity
        severity_counts = self.df['impact_severity'].value_counts().reindex(['critical', 'high', 'medium', 'low'], fill_value=0)
        sns.barplot(x=severity_counts.index, y=severity_counts.values, ax=axes[1, 1],
                    palette={'critical': '#ff4444', 'high': '#ff8800', 'medium': '#ffaa00', 'low': '#88ff88'})
        axes[1, 1].set_title('Impact Severity Distribution', fontsize=14)
        axes[1, 1].set_xlabel('Severity Level')
        axes[1, 1].set_ylabel('Count')

        # 5. Request Method Distribution
        method_counts = self.df['request_method'].value_counts()
        sns.barplot(x=method_counts.index, y=method_counts.values, ax=axes[2, 0], palette='magma')
        axes[2, 0].set_title('Vulnerable Request Methods', fontsize=14)
        axes[2, 0].set_xlabel('HTTP Method')
        axes[2, 0].set_ylabel('Count')
        
        # 6. Attack Vector
        vector_counts = self.df['attack_vector'].value_counts()
        axes[2, 1].pie(vector_counts.values, labels=vector_counts.index, autopct='%1.1f%%',
                       startangle=90, colors=sns.color_palette('Set2'))
        axes[2, 1].set_title('Attack Vector Distribution', fontsize=14)
        axes[2, 1].axis('equal')

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig('csrf_comprehensive_analysis.png', dpi=300)
        logger.info("Comprehensive analysis plot saved as 'csrf_comprehensive_analysis.png'")
        
        self.create_interactive_plots()

    def create_interactive_plots(self):
        """Create interactive plots using Plotly"""
        # 1. Interactive Heatmap: Functionality vs. Impact
        func_impact = pd.crosstab(self.df['functionality'], self.df['impact'])
        fig = px.imshow(func_impact, title="Functionality vs. Impact Heatmap",
                        labels=dict(x="Impact Type", y="Functionality", color="Count"),
                        aspect="auto")
        fig.write_html("csrf_functionality_impact_heatmap.html")
        
        # 2. Interactive Sankey Diagram: Bypass -> Functionality -> Impact
        sankey_data = self.df[['anti_csrf_bypass', 'functionality', 'impact']].dropna()
        all_nodes = list(set(sankey_data['anti_csrf_bypass']) | set(sankey_data['functionality']) | set(sankey_data['impact']))
        node_dict = {node: i for i, node in enumerate(all_nodes)}
        
        links = []
        # Bypass -> Functionality
        for _, row in sankey_data.groupby(['anti_csrf_bypass', 'functionality']).size().reset_index(name='count').iterrows():
            links.append({'source': node_dict[row['anti_csrf_bypass']], 'target': node_dict[row['functionality']], 'value': row['count']})
        # Functionality -> Impact
        for _, row in sankey_data.groupby(['functionality', 'impact']).size().reset_index(name='count').iterrows():
            links.append({'source': node_dict[row['functionality']], 'target': node_dict[row['impact']], 'value': row['count']})
            
        fig = go.Figure(data=[go.Sankey(
            node=dict(pad=15, thickness=20, label=all_nodes),
            link=dict(source=[l['source'] for l in links], target=[l['target'] for l in links], value=[l['value'] for l in links])
        )])
        fig.update_layout(title_text="CSRF Attack Flow: Bypass Method → Functionality → Impact", font_size=10)
        fig.write_html("csrf_attack_flow_sankey.html")
        
        logger.info("Interactive plots saved as HTML files.")

    def generate_summary_report(self) -> Dict:
        """Generate a summary report with key metrics"""
        self.df['Bounty_numeric'] = pd.to_numeric(self.df.get('Bounty'), errors='coerce').fillna(0)
        
        summary = {
            'basic_statistics': {
                'total_reports': len(self.df),
                'total_bounty': self.df['Bounty_numeric'].sum(),
                'average_bounty': self.df['Bounty_numeric'].mean(),
            },
            'distributions': {
                'functionality': self.df['functionality'].value_counts().to_dict(),
                'impact': self.df['impact'].value_counts().to_dict(),
                'impact_severity': self.df['impact_severity'].value_counts().to_dict(),
                'anti_csrf_bypass': self.df['anti_csrf_bypass'].value_counts().to_dict(),
                'request_method': self.df['request_method'].value_counts().to_dict(),
            },
            'key_insights': {
                'most_common_vulnerable_functionality': self.df['functionality'].mode()[0],
                'most_common_impact': self.df['impact'].mode()[0],
                'most_common_bypass': self.df['anti_csrf_bypass'].mode()[0],
            },
            'security_recommendations': self._generate_security_recommendations()
        }
        return summary

    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        top_bypass = self.df['anti_csrf_bypass'].mode()[0]
        
        recommendations.append("Always use and validate anti-CSRF tokens for all state-changing requests.")
        if top_bypass == 'no token':
            recommendations.append("Primary focus should be on implementing anti-CSRF tokens where they are missing.")
        elif top_bypass == 'referer validation bypass':
            recommendations.append("Strengthen Referer and Origin header validation, but do not rely on it as the sole defense.")
        
        recommendations.append("Implement the SameSite=Strict or SameSite=Lax cookie attribute for session cookies.")
        recommendations.append("For APIs, consider using custom request headers (e.g., X-Requested-With) as a defense-in-depth measure.")
        recommendations.append("Ensure tokens are not leaked in URLs or server logs.")
        recommendations.append("Use the double-submit cookie pattern if maintaining server-side state for tokens is not feasible.")
        
        return recommendations


# Main execution block
if __name__ == "__main__":
    # !!! IMPORTANT: Replace 'your_csrf_data.csv' with the path to your CSV file.
    # The CSV must have a column named 'URL'.
    input_csv_file = './csrf_writeups.csv' 
    
    try:
        analyzer = CSRFAnalyzer(input_csv_file)
    except FileNotFoundError:
        logger.error(f"Error: The file '{input_csv_file}' was not found.")
        logger.error("Please make sure the file exists and the path is correct.")
    else:
        print("Starting CSRF vulnerability analysis...")
        print(f"Processing URLs from {input_csv_file}. Progress will be saved every 10 URLs.")
        
        # Process all URLs
        analyzed_df = analyzer.process_all_urls(delay=2.0)
        
        # Save final results
        analyzer.save_results('csrf_analysis_complete.csv')
        
        # Generate plots and summary
        print("\nGenerating analysis plots and reports...")
        analyzer.create_comprehensive_plots()
        summary = analyzer.generate_summary_report()
        
        # Save summary report to JSON
        with open('csrf_analysis_summary_report.json', 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        print("\n" + "="*60)
        print("CSRF ANALYSIS COMPLETE!")
        print("="*60)
        
        print("\n📊 KEY INSIGHTS:")
        print(f"  • Total reports analyzed: {summary['basic_statistics']['total_reports']}")
        print(f"  • Most common vulnerable function: {summary['key_insights']['most_common_vulnerable_functionality']}")
        print(f"  • Most frequent impact: {summary['key_insights']['most_common_impact']}")
        print(f"  • Most common bypass method: {summary['key_insights']['most_common_bypass']}")
        
        print("\n🚨 SECURITY RECOMMENDATIONS:")
        for i, rec in enumerate(summary['security_recommendations'], 1):
            print(f"  {i}. {rec}")
            
        print(f"\n📁 FILES GENERATED:")
        print(f"  • csrf_analysis_complete.csv - Full dataset with new analysis columns.")
        print(f"  • csrf_comprehensive_analysis.png - Static plot with key distributions.")
        print(f"  • csrf_functionality_impact_heatmap.html - Interactive heatmap.")
        print(f"  • csrf_attack_flow_sankey.html - Interactive attack flow diagram.")
        print(f"  • csrf_analysis_summary_report.json - Detailed summary in JSON format.")
