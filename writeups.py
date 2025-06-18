import requests
import pandas as pd

# Your HackerOne credentials
H1_USER = "cybersentinelx"
H1_TOKEN = "l5ZbJLmL5knlm1z47eu3c+WpgKujexbrJIvmAep+e5Y="

# Step 1: Fetch PentesterLand writeups
pl = requests.get("https://pentester.land/writeups.json").json()["data"]
df = pd.DataFrame(pl)
bug_type = input("Put the Bug: ")

# Filter for bug type
df = df[df["Bugs"].apply(lambda bugs: any(bug_type.lower() in b.lower() for b in bugs))].copy()

# Flatten and clean columns
df["Title"] = df["Links"].apply(lambda x: x[0]["Title"])
df["URL"] = df["Links"].apply(lambda x: x[0]["Link"])
df["Authors"] = df["Authors"].apply(", ".join)
df["Programs"] = df["Programs"].apply(", ".join)
df["Bugs"] = df["Bugs"].apply(", ".join)
df['Bounty'] = pd.to_numeric(df['Bounty'].replace('[\$,]', '', regex=True), errors='coerce').fillna(0)

# Sort by Bounty in descending order
df = df.sort_values(by='Bounty', ascending=False)

# Step 2: Function to fetch HackerOne reports by keyword
def fetch_hackerone_links(keyword):
    params = {
        "queryString": keyword,
        "page[number]": 1,
        "page[size]": 5
    }
    try:
        r = requests.get(
            "https://api.hackerone.com/v1/hackers/hacktivity",
            params=params,
            auth=(H1_USER, H1_TOKEN),
            headers={"Accept": "application/json"}
        )
        r.raise_for_status()
        items = r.json().get("data", [])
        result = []
        for item in items:
            attr = item.get("attributes", {})
            title = attr.get("title", "").strip()
            url = attr.get("url", "").strip()
            if url and "hackerone.com/reports/" in url:
                result.append({"WriteupTitle": keyword, "ReportTitle": title, "ReportURL": url})
        return result
    except:
        return []

# Step 3: Collect HackerOne matches
h1_records = []
for title in df["Title"]:
    h1_records.extend(fetch_hackerone_links(title))

# Step 4: Save writeups CSV
writeup_cols = ["Title", "URL", "Authors", "Programs", "Bugs", "Bounty", "PublicationDate", "AddedDate"]
df[writeup_cols].to_csv(f"{bug_type.lower()}_writeups.csv", index=False, encoding="utf-8")
print(f"✅ Saved: {bug_type.lower()}_writeups.csv")

# Step 5: Save HackerOne matches CSV
if h1_records:
    pd.DataFrame(h1_records).to_csv(f"{bug_type.lower()}_hackerone.csv", index=False, encoding="utf-8")
    print(f"✅ Saved: {bug_type.lower()}_hackerone.csv")
else:
    print("⚠️ No HackerOne reports matched.")

