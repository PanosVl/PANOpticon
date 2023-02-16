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

def pulse(cve):
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

def load_up(json_file):
    """
    Uses JSON file from CISA's Known Exploited Vulnerabilities (KEV) to pull information on the said CVEs and update the database
    """
    with open(json_file) as json_file_stream:
        data_dictionary = json.load(json_file_stream)

        for vulnerability_object in data_dictionary['vulnerabilities']:
            epss = get_EPSS(vulnerability_object['cveID'])
            nvd_data = get_basic_CVE_info_NVD(vulnerability_object['cveID'])
            if epss and nvd_data:
                Vulnerability.objects.create(
                    cve_id = vulnerability_object['cveID'],
                    epss = epss,
                    actively_exploited = True,
                    pulses = pulse(vulnerability_object['cveID']),
                    date_discovered = datetime.datetime.strptime(nvd_data['cve']['published'].split('T')[0], '%Y-%m-%d').date()
                )