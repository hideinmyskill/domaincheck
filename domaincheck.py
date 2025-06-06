import pandas as pd
import re
import requests
import json
import openpyxl
import argparse
import datetime
import os

def getVTResults(apikey, domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {
        "x-apikey": apikey
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if malicious == 0 and suspicious == 0:
            res = "Clean"
        else:
            res = f"Flagged: {malicious + suspicious}/{total}"
        
    else:
        res = f"Failed to fetch data: {response.status_code} - {response.text}"

    result = {"status": res, "vturl":data['data']['links']['self']}
    return result


def main():
     
    parser = argparse.ArgumentParser(description='Check domain reputation using VirusTotal API')
    parser.add_argument('-k', required=True, help='VirusTotal API key')
    parser.add_argument('-f', required=True, help='Path to file extracted from paloalto')
    args = parser.parse_args()

    APIKEY = str(args.k)

    tsvfile = pd.read_csv(args.f, sep='\t')
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    total_rows = int(len(tsvfile['Description']))
    loading_bar_length = 50

    domains_df = pd.DataFrame(columns=["Domains", "Status", "VirusTotal Link", "Alert Link"])
    
    dateNow = datetime.datetime.now().strftime("%d-%m-%Y")

    for index, row in enumerate(zip(tsvfile['Alert Id'],tsvfile['Description'])):

        extract_domain = re.findall(domain_pattern, row[1])
        extract_alertID = row[0]

        data = getVTResults(APIKEY, extract_domain[0])
        domains_df.loc[index+1] = [f"{extract_domain[0]}", f"{data['status']}", f"https://www.virustotal.com/gui/domain/{extract_domain[0]}", f"https://hso.xdr.au.paloaltonetworks.com/card/alert/{extract_alertID}"]

        progress = index / total_rows
        filled_length = int(loading_bar_length * progress)
        bar = '=' * filled_length + ' ' * (loading_bar_length - filled_length)
        print(f'\r[{bar}] {int(progress * 100)}%', end='', flush=True)

    os.makedirs("tsv-files", exist_ok=True)
    os.makedirs("output", exist_ok=True)
    domains_df.to_excel(f'output\\XDR-Domains-Output-{dateNow}.xlsx', index=False)
    print(f"\nCompleted: check the filename 'XDR-Domains-Output-{dateNow}.xlsx' inside output folder. ")

main()