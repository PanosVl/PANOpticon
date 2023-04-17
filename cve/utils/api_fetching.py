import requests
import json
from cve.models import *
import datetime
import os
from pyExploitDb import PyExploitDb
import time
import logging

# Initialize logger
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('app.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

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
        try:
            if not Vulnerability.objects.filter(cve_id=item['cve']['id']).exists():
                nvd_data = get_basic_CVE_info_NVD(item['cve']['id'])
                if nvd_data:
                    cvss = attack_vector = None
                    try:
                        cvss = nvd_data['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],
                        attack_vector = nvd_data['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'],
                    except KeyError as e:  # it didn't find CVSS v3.1, try for v2
                        logger.warning('no cvss 3.1')
                        logger.warning(str(e))
                        pass                
                    try:
                        logger.warning("CVSS v3.1 not found, trying for CVSS 2:")
                        cvss = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'],                        
                        attack_vector = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector'],
                    except KeyError as e:  # it didn't find CVSS v2, print out what you found and move on
                        logger.warning('no cvss 2')
                        logger.warning(str(e))
                        pass
                    
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
        except Exception as e:
            logger.error(f"Exception occured: {str(e)}")
            logger.error(f"cve_ID: {item['cve']['id']}")
            logger.error(f"epss: {get_EPSS(item['cve']['id'])}")
            logger.error(f"CVSS: {cvss}")
            logger.error(f"Attack Vector: {attack_vector}")

def get_statistics():
    """
    Returns Efficiency & Coverage compared to CVSS and EPSS based metrics. 
    Efficiency = TP / (TP + FP)
    Coverage = TP / (TP + FN)
    TP = True Positive
    FP = False Positive
    FN = False Negative
    We assume prioritization is done on CVSS >= 7 and EPSS >= 0.150
    """
    tp_cvss = Vulnerability.objects.filter(cvss__gte=7, KEV=True).count()
    fp_cvss = Vulnerability.objects.filter(cvss__gte=7, KEV=False).count()
    fn_cvss = Vulnerability.objects.filter(cvss__lt=7, KEV=True).count()
    tp_epss = Vulnerability.objects.filter(epss__gte=0.150, KEV=True).count()
    fp_epss = Vulnerability.objects.filter(epss__gte=0.150, KEV=False).count()
    fn_epss = Vulnerability.objects.filter(epss__lt=0.150, KEV=True).count()
    efficiency_cvss = (tp_cvss / (tp_cvss + fp_cvss)) * 100
    coverage_cvss = (tp_cvss / (tp_cvss + fn_cvss)) * 100
    efficiency_epss = (tp_epss / (tp_epss + fp_epss)) * 100
    coverage_epss = (tp_epss / (tp_epss + fn_epss)) * 100
    print(f"CVSS Efficiency: {efficiency_cvss} %")
    print(f"EPSS Efficiency: {efficiency_epss} %")
    print(f"CVSS Coverage: {coverage_cvss} %")
    print(f"CVSS Coverage: {coverage_epss} %")
