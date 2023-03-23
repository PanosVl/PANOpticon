from django.contrib import admin
from cve.models import *


class ReadOnlyAdmin(admin.ModelAdmin):
    actions = None
    list_display_links = ['cve_id']
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False
    def has_delete_permission(self, request, obj=None):
        return False
    def get_readonly_fields(self, request, obj=None):
        # Make all fields read-only
        return [field.name for field in obj._meta.fields]

class VulnerabilityAdmin(ReadOnlyAdmin):
    list_display = ('cve_id', 'epss', 'cvss', 'attack_vector', 'pulses', 'date_discovered', 'KEV', 'exploit_db')
    search_fields = ('cve_id', 'epss', 'cvss', 'attack_vector', 'pulses', 'date_discovered', 'KEV', 'exploit_db')

admin.site.register(Vulnerability, VulnerabilityAdmin)
