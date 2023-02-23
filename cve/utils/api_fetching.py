import requests
import json
from cve.models import *
import datetime
import os

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
    Queries NVD NIST API to get all Known Exploited Vulnerabilities (KEV) and write them in db.
    It can be run multiple times to update vulnerabilities.
    """
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev'
    response = requests.get(url)
    data = response.json()
    for item in data['vulnerabilities']:
        epss = get_EPSS(item['cve']['id'])
        cve_id = item['cve']['id']
        pulses = OTX_pulse(item['cve']['id'])
        date = datetime.datetime.strptime(item['cve']['published'].split('T')[0], '%Y-%m-%d').date()
        if not Vulnerability.objects.filter(cve_id=item['cve']['id']).exists():
            # Create vulnerability            
            Vulnerability.objects.create(
                cve_id = cve_id,
                epss = epss,
                actively_exploited = True,
                pulses = pulses,
                date_discovered = date
            )
        else:
            # Update vulnerability in case it already exists
            v = Vulnerability.objects.get(cve_id=cve_id)
            v.epss = epss
            v.pulses = pulses
            v.save()           
