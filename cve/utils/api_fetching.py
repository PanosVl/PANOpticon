import requests
import json
from cve.models import *
import datetime
import os
from pyExploitDb import PyExploitDb

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
    r = requests.get(url)
    if r.ok:
        return r.json()['vulnerabilities'][0]
    else:
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
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev'
    response = requests.get(url)
    data = response.json()
    for item in data['vulnerabilities']:
        if not Vulnerability.objects.filter(cve_id=item['cve']['id']).exists():
            epss = get_EPSS(item['cve']['id'])
            
            Vulnerability.objects.create(
                cve_id = item['cve']['id'],
                epss = epss,
                KEV = True,
                pulses = OTX_pulse(item['cve']['id']),
                date_discovered = datetime.datetime.strptime(item['cve']['published'].split('T')[0], '%Y-%m-%d').date(),
                exploit_db = exploit_db_poc(item['cve']['id'])
            )
