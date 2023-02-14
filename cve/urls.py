from django.urls import path

from cve.views import *

urlpatterns = [
    path("search/", SearchResultsView.as_view(), name="search_results"),
    path("", HomePageView.as_view(), name="home"),
]