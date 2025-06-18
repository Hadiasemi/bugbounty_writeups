import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

# Data from your rce_analysis_summary_report.json file
json_data = {
  "statistics": {
    "total_reports_analyzed": 1008
  },
  "distributions": {
    "functionality": {
      "Imports/Sharing": 450,
      "General Application Logic": 168,
      "Admin/Config Panel": 156,
      "unknown": 110,
      "File Management": 65,
      "User Profile/Content": 55,
      "CI/CD Pipeline": 4
    },
    "vulnerability_type": {
      "Command Injection": 685,
      "Unrestricted File Write/Upload": 115,
      "unknown": 110,
      "Insecure Deserialization": 58,
      "Server-Side Template Injection (SSTI)": 18,
      "Code Injection": 12,
      "Log Poisoning": 5,
      "XXE": 5
    },
    "execution_context": {
      "Server-side RCE": 797,
      "unknown": 110,
      "CI/CD Pipeline RCE": 66,
      "Desktop App RCE": 35
    },
    "language_or_framework": {
      "PHP": 285,
      "Java": 253,
      "Generic Linux": 194,
      "unknown": 110,
      "Python": 80,
      ".NET": 46,
      "NodeJS": 29,
      "Ruby": 11
    },
    "attack_vector": {
      "Web Application Parameter": 844,
      "unknown": 110,
      "API Endpoint": 21,
      "Third-party Library": 21,
      "File Upload Feature": 12
    },
    "impact": {
      "Shell/Command Execution": 790,
      "unknown": 110,
      "Full System Compromise": 85,
      "Service Disruption (DoS)": 15,
      "Data Exfiltration": 7,
      "Internal Network Pivoting": 1
    }
  }
}

# --- Data Processing and Plotting Script ---

# Convert dictionary data to pandas Series
distributions = json_data['distributions']
series_dict = {key: pd.Series(value) for key, value in distributions.items()}

# Filter out 'unknown' from each series if it exists
for key, series in series_dict.items():
    if 'unknown' in series.index:
        series_dict[key] = series.drop('unknown')

# Assign filtered series back to variables
vuln_counts = series_dict['vulnerability_type']
lang_counts = series_dict['language_or_framework']
func_counts = series_dict['functionality']
context_counts = series_dict['execution_context']
vector_counts = series_dict['attack_vector']
impact_counts = series_dict['impact']


# Set up the plot style and figure
plt.style.use('seaborn-v0_8-whitegrid')
fig, axes = plt.subplots(3, 2, figsize=(20, 24))
fig.suptitle('Remote Code Execution (RCE) Vulnerability Analysis', fontsize=22, fontweight='bold')

# 1. Common RCE Vulnerability Types (Reason)
sns.barplot(y=vuln_counts.index, x=vuln_counts.values, ax=axes[0, 0], palette='magma', hue=vuln_counts.index, legend=False)
axes[0, 0].set_title('Common RCE Vulnerability Types (Reason)', fontsize=16)
axes[0, 0].set_xlabel('Count')
axes[0, 0].set_ylabel('vulnerability_type')


# 2. Exploited Technologies
sns.barplot(y=lang_counts.index, x=lang_counts.values, ax=axes[0, 1], palette='viridis', hue=lang_counts.index, legend=False)
axes[0, 1].set_title('Exploited Technologies', fontsize=16)
axes[0, 1].set_xlabel('Count')
axes[0, 1].set_ylabel('language_or_framework')

# 3. Vulnerable Application Functionality
sns.barplot(y=func_counts.index, x=func_counts.values, ax=axes[1, 0], palette='crest', hue=func_counts.index, legend=False)
axes[1, 0].set_title('Vulnerable Application Functionality', fontsize=16)
axes[1, 0].set_xlabel('Count')
axes[1, 0].set_ylabel('functionality')

# 4. RCE Execution Context (Type)
sns.barplot(x=context_counts.index, y=context_counts.values, ax=axes[1, 1], palette='flare', hue=context_counts.index, legend=False)
axes[1, 1].set_title('RCE Execution Context (Type)', fontsize=16)
axes[1, 1].set_ylabel('Count')
axes[1, 1].set_xlabel('')


# 5. RCE Attack Vectors -- REVERTED TO PIE CHART
# Explode the smaller slices to help with label overlap
vector_explode = [0.1 if x < vector_counts.max() else 0 for x in vector_counts.values]
axes[2, 0].pie(vector_counts.values, labels=vector_counts.index, autopct='%1.1f%%',
               startangle=90, colors=sns.color_palette('pastel'),
               explode=vector_explode, textprops={'fontsize': 10})
axes[2, 0].set_title('RCE Attack Vectors', fontsize=16)

# 6. Impact of RCE (Exploit) -- REVERTED TO PIE CHART
# Explode the smaller slices to help with label overlap
impact_explode = [0.1 if x < impact_counts.max() else 0 for x in impact_counts.values]
axes[2, 1].pie(impact_counts.values, labels=impact_counts.index, autopct='%1.1f%%',
               startangle=140, colors=sns.color_palette('Set2'),
               explode=impact_explode, textprops={'fontsize': 10})
axes[2, 1].set_title('Impact of RCE (Exploit)', fontsize=16)

# Manually adjust subplot parameters to give more space for labels
fig.subplots_adjust(left=0.3, hspace=0.4, wspace=0.3)


# Save the figure to a file
output_filename = 'RCE_Analysis_Chart_Pies_Restored.png'
plt.savefig(output_filename, dpi=300, bbox_inches='tight')

print(f"Chart saved as '{output_filename}'")
