from django.contrib import admin
from cve.models import *

class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'epss', 'actively_exploited')
    search_fields = ('cve_id', 'epss', 'actively_exploited')

admin.site.register(Vulnerability, VulnerabilityAdmin)
