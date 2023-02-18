from django.contrib import admin
from cve.models import *

class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'epss', 'pulses', 'actively_exploited', 'date_discovered')
    search_fields = ('cve_id', 'epss', 'pulses', 'actively_exploited', 'date_discovered')

admin.site.register(Vulnerability, VulnerabilityAdmin)
