import requests
import json
from cve.models import *
import datetime
import os
from pyExploitDb import PyExploitDb
import time

# Initialize clone of exploit-db
pEdb = PyExploitDb()
pEdb.debug = False
pEdb.openFile()

def exploit_db_poc(cve):
    """
    Searches exploit db for the given CVE.
    If a PoC exploit exists, it returns True, and False otherwise.
    """
    results = pEdb.searchCve(cve)
    if results:
        return True
    else:
        return False

def get_EPSS(cve):
    """
    FIRST.org API to get EPSS score for a given CVE
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    r = requests.get(url)
    if r.ok:
        try:
            return r.json()['data'][0]['epss']
        except IndexError:
            return None
    else:
        return None

def get_basic_CVE_info_NVD(cve):
    """
    NVD NIST API to get basic information on a given CVE
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"    
    r = requests.get(url, headers={'apiKey': os.environ['NVD_API_KEY']})
    if r.ok:
        return r.json()['vulnerabilities'][0]
    else:
        print(r.text, r.status_code)
        return None

def OTX_pulse(cve):
    """
    AllienVault API to get pulse information & indicators for a given CVE
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve}"
    headers = {'X-OTX-API-KEY':os.environ['OTX_KEY']}
    r = requests.get(url, headers=headers)
    if r.ok:
        try:
            return r.json()['pulse_info']['count']
        except KeyError:
            return 0

def get_all_KEV_NVD():
    """
    Queries NVD NIST API to get all Known Exploited Vulnerabilities (KEV) and write them in db
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&"    
    response = requests.get(url, headers={'apiKey': os.environ['NVD_API_KEY']})
    data = response.json()
    for item in data['vulnerabilities']:
        if not Vulnerability.objects.filter(cve_id=item['cve']['id']).exists():
            nvd_data = get_basic_CVE_info_NVD(item['cve']['id'])
            if nvd_data:
                try:
                    cvss = nvd_data['cve']['metrics']['cvssMetricV31']['cvssData']['baseScore'],
                    attack_vector = nvd_data['cve']['metrics']['cvssMetricV31']['cvssData']['attackVector'],
                except KeyError:  # it didn't find CVSS v3.1, try for v2
                    try:
                        cvss = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'],
                        attack_vector = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['attackVector'],
                    except KeyError:  # it didn't find CVSS v2, print out what you found and move on
                        print(nvd_data['cve']['metrics'].keys())
                        print(item['cve']['id'])
                        cvss = attack_vector = None
                Vulnerability.objects.create(
                    cve_id = item['cve']['id'],
                    epss = get_EPSS(item['cve']['id']),
                    pulses = OTX_pulse(item['cve']['id']),
                    cvss = cvss,
                    attack_vector = attack_vector,
                    date_discovered = datetime.datetime.strptime(item['cve']['published'].split('T')[0], '%Y-%m-%d').date(),
                    KEV = True,
                    exploit_db = exploit_db_poc(item['cve']['id'])
                )
            time.sleep(6)  # Add 6" sleep to avoid being throttled out by NIST's API
