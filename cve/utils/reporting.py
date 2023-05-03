from cve.models import *

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

def get_numbers():
    """
    Returns:
    - number of CVEs with CVSS >= 7 and KEV = True (True Positive)
    - number of CVEs with CVSS < 7 and KEV = False (True Negative)
    - number of CVEs with CVSS >= 7 and KEV = False (False Positive)
    - number of CVEs with CVSS < 7 and KEV = True (False Negative)
    """
    print(f"True positives: {Vulnerability.objects.filter(cvss__gte=7, KEV=True).count()}")
    print(f"True negatives: {Vulnerability.objects.filter(cvss__lt=7, KEV=False).count()}")
    print(f"False positives: {Vulnerability.objects.filter(cvss__lt=7, KEV=False).count()}")
    print(f"False negatives: {Vulnerability.objects.filter(cvss__lt=7, KEV=True).count()}")
    

