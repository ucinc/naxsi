# Create your views here.

from django.http import HttpResponse

def index(request):
    r = HttpResponse()
    r.status_code = 302
    r['Location'] = '/admin/'
    return r
