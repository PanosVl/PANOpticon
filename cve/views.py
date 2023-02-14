from django.views.generic import TemplateView, ListView

from cve.models import *

class HomePageView(TemplateView):
    template_name = "home.html"

class SearchResultsView(ListView):
    model = Vulnerability
    template_name = "search_results.html"

