import requests
import json
from cve.models import *


def get_EPSS(cve):
    # url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve
    # r = requests.get(url)
    # data = r.json()
    # return data['result']['CVE_Items'][0]['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'][0]['versionValue']
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    r = requests.get(url)
    return r.json()['data'][0]['epss']

def get_basic_CVE_info_NVD(cve):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    r = requests.get(url)
    if r.ok:
        return r.json()['vulnerabilities'][0]

def load_up(json_file):
    """
    Uses JSON file from CISA's Known Exploited Vulnerabilities (KEV) to pull information on the said CVEs and update the database
    """    
    with open(json_file) as json_file_stream:
        data_dictionary = json.load(json_file_stream)

        for vulnerability_object in data_dictionary['vulnerabilities']:
            epss = get_EPSS(vulnerability_object['cveID'])
            Vulnerability.objects.create(
                cve_id = vulnerability_object['cveID'],
                epss = epss, 
                actively_exploited = True
            )