from django.shortcuts import render
from django.conf import settings
from cve.models import *

def home(request):
    context =  {'server_name': settings.SERVER_NAME}
    return render(request, 'home.html', context)


