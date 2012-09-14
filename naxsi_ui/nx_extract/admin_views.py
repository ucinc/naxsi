from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required

from django.http import HttpResponse

@login_required
def graph(request):
    return HttpResponse("les graphs seront ici")

@login_required
def log_feeder(request):    
    return HttpResponse('<pre>' + request.user.get_profile().allowed_log_files + '</pre>')


