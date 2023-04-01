from django.contrib import admin
from django.urls import path, reverse_lazy
from django.views.generic.base import RedirectView
from cve.views import *

urlpatterns = [
    # path('', RedirectView.as_view(url=reverse_lazy('admin:index'))),
    path('', home, name='home'),
    path('admin/', admin.site.urls),
]