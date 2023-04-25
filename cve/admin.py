from django.contrib import admin

from cve.models import *
from cve.utils.api_fetching import *


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
    list_display = ('cve_id', 'epss', 'cvss_version', 'cvss', 'attack_vector',
                    'pulses', 'date_discovered', 'KEV', 'exploit_db')
    search_fields = ('cve_id', 'epss', 'cvss_version', 'cvss', 'attack_vector',
                     'pulses', 'date_discovered', 'KEV', 'exploit_db')

    def get_search_results(self, request, queryset, search_term):
        # Call the parent implementation to get the queryset with the search term applied
        queryset, use_distinct = super().get_search_results(request, queryset, search_term)

        # Check if the queryset is empty
        if not queryset:
            # Fetch the CVE details from the external API
            # TODO: Call function to fetch all information about that specific CVE
            print("CVE not found in database, fetching from external API...")
            vulnerability = get_one_by_CVE(search_term)
            
            # Return the newly created Vulnerability object as the search result (QS)
            return Vulnerability.objects.filter(id=vulnerability.id), False            

        return queryset, use_distinct


admin.site.register(Vulnerability, VulnerabilityAdmin)
