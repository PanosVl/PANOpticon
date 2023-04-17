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
    headers = {'X-OTX-API-KEY': os.environ['OTX_KEY']}
    r = requests.get(url, headers=headers)
    if r.ok:
        try:
            return r.json()['pulse_info']['count']
        except KeyError:
            return 0


def create_objects(data):
    """
    Expects a dictionary of CVEs from NVD NIST API.
    """
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
                        logger.warning(
                            "CVSS v3.1 not found, trying for CVSS 2:")
                        cvss = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'],
                        attack_vector = nvd_data['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector'],
                    except KeyError as e:  # it didn't find CVSS v2, print out what you found and move on
                        logger.warning('no cvss 2')
                        logger.warning(str(e))
                        pass

                    Vulnerability.objects.create(
                        cve_id=item['cve']['id'],
                        epss=get_EPSS(item['cve']['id']),
                        pulses=OTX_pulse(item['cve']['id']),
                        cvss=cvss,
                        attack_vector=attack_vector,
                        date_discovered=datetime.datetime.strptime(
                            item['cve']['published'].split('T')[0], '%Y-%m-%d').date(),
                        KEV=True,
                        exploit_db=exploit_db_poc(item['cve']['id'])
                    )
                # Add 6" sleep to avoid being throttled out by NIST's API
                time.sleep(6)
        except Exception as e:
            logger.error(f"Exception occured: {str(e)}")
            logger.error(f"cve_ID: {item['cve']['id']}")
            logger.error(f"epss: {get_EPSS(item['cve']['id'])}")
            logger.error(f"CVSS: {cvss}")
            logger.error(f"Attack Vector: {attack_vector}")


def get_all_KEV_NVD():
    """
    Queries NVD NIST API to get all Known Exploited Vulnerabilities (KEV) and write them in db
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&"
    response = requests.get(url, headers={'apiKey': os.environ['NVD_API_KEY']})
    data = response.json()
    create_objects(data)


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
    print(f"EPSS Coverage: {coverage_epss} %")


def get_cves_by_year(year):
    """
    Retrieves all CVEs published in the specified year from the NVD CVE feeds API.
    year: string "YYYY"
    """
    # Set the base URL for the NVD CVE feeds API
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    # Read the NVD API key from an environment variable
    api_key = os.environ.get('NVD_API_KEY')

    # Define the query parameters to retrieve CVEs published in the specified year
    params = {
        "publishedStartDate": f"{year}-01-01T00:00:00:000 UTC-05:00",
        "publishedEndDate": f"{year}-12-31T23:59:59:999 UTC-05:00",
        "resultsPerPage": 5000,  # Maximum number of results per page
    }
    headers = {"apiKey": api_key}

    cves = []
    page_num = 0
    while True:
        try:
            # Increment the page number
            page_num += 1

            # Set the start index for the next page of results
            params['startIndex'] = (page_num - 1) * params['resultsPerPage']

            # Send a GET request to the NVD CVE feeds API to retrieve the CVEs
            response = requests.get(base_url, params=params, headers=headers)

            # Extract the list of CVEs from the response JSON
            data = response.json()
            create_objects(data)

            # Append the CVEs to the list of all CVEs
            # cves.extend(data['result']['CVE_Items'])

            # Check if there are any more pages of results
            if len(data['vulnerabilities']) < params['resultsPerPage']:
                break
        except Exception as e:
            print(
                f"There was an exception while trying to create objects: {e}")
            print(response.text, response.status_code)

    # Print the total number of CVEs retrieved
    print(f"Number of CVEs published in {year}: {len(cves)}")

    return cves
