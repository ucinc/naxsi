from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django import utils
from django.http import HttpResponse

from tailer import Tailer

from nx_extract.models import nx_fmt, nx_request, InputType, Zone, nx_user
from nx_extract.wl_generation import wlgen
from django.db import transaction
from django.db.models import Max, Count

from django import forms

from django_filters.filterset  import *

from django_filters.filters  import *

import cgi
import copy
import itertools
import operator

import time

from datetime import datetime, timedelta

#from filtrator.filtrator import Filtrator


@login_required
def graph(request):
    return HttpResponse("les graphs seront ici")

# def is_covered(final, item):
#     mres = []

#     if item in final:
#         mres.append(item)
#         return mres
    
#     for e in final:
#         if len(item["uri"]) > 0 and len(e["uri"]) > 0 and e["uri"] != item["uri"]:
#             continue
#         if item["nx_id"] > 0 and e["nx_id"] > 0 and e["nx_id"] != item["nx_id"]:
#             continue
#         if item["zone"] != Zone.ALL and e["zone"] != Zone.ALL and e["zone"] != item["zone"]:
#             continue
#         if len(item["var_name"]) > 0 and len (e["var_name"]) > 0 and e["var_name"] != item["var_name"]:
#             continue
#         mres.append(e) 
#     return mres

# @login_required
# def exc_viewer(request):
    
#     rep = HttpResponse()
#     y = nx_fmt.objects
#     y.filter(server="blog.memze.ro")
#     x = y.values('type', 'uri', 'zone_raw', 'nx_id', 'var_name', 'zone', 'zone_extra').distinct()
#     total_peers = nx_fmt.objects.values('ip_client').distinct().count()
#     total_hit = nx_fmt.objects.all().count()
#     final = []
#     for item in x:
#         tmp = nx_fmt.objects.filter(type=item['type'],
#                               uri=item['uri'], zone_raw=item['zone_raw'],
#                               nx_id=item['nx_id'], var_name=item['var_name'])
#         count = tmp.count()
#         pcount = tmp.values('ip_client').distinct().count()
#         item['mcount'] = count
#         item["rcount"] = 0
#         item["pcount"] = pcount
#         citem = item
#         for x in ["DoesNotExists1235432", "uri", "var_name"]:
#             citem = copy.deepcopy(citem)
#             if x in citem:
#                 citem[x] = ""
#             existing = is_covered(final, citem)
#             if len(existing) is 0:
#                 final.append(citem)
#             elif len(existing) > 10:
#                 for todel in existing:
#                     citem["rcount"] += 1
#                     final.remove(todel)
#                 final.append(citem)
#     final = sorted(final, key=lambda mfinal: mfinal["mcount"], reverse=True)
#     for item in final:
#         if (item["pcount"] <= (total_peers/100)):
#             continue
#         rep.write(item)
#         rep.write("</br>")
#     return rep

# import pprint



# def user_data(dataset, request):
#     allowed_files = request.user.get_profile().allowed_log_files.split('\r\n')
#     mfilter = []
#     for f in allowed_files:
#         mfilter.append(Q(origin_log_file=f))
#     return dataset.objects.filter(reduce(operator.or_, mfilter))    

def is_allowed(lfile, request):
    """ returns true if the user is allowed to access logfile """
    allowed_files = request.user.get_profile().allowed_log_files.split('\r\n')
    if lfile not in allowed_files:
        False
    return True

import pprint

@login_required
def wl_gen(request):
    ret = HttpResponse()    
    if not "log" in request.GET:
        return HttpResponse("no target logfile supplied.")
    lfile = request.GET['log']
    if not is_allowed(lfile, request):
        return HttpResponse("You can't generate exceptions for this file (disallowed).")
    exceptions = nx_fmt.udata.allowed_data(request).filter(origin_log_file=lfile)
    wlgenerator = wlgen(exceptions)
    wl = wlgenerator.gen_wl()
    for rule in wl:
        ret.write("# Rule was triggered "+str(rule['mcount'])+" times, by "+str(rule['pcount'])+" peers\n<br/>")
        ret.write(wlgenerator.format_rules_output(rule)+"\n<br/>")
#        ret += rule
    return ret

@login_required
#@transaction.commit_on_success
def log_feeder(request):
    ## should be factorized :(
    allowed_files = request.user.get_profile().allowed_log_files.split('\r\n')
    lfile = ""
    if not "log" in request.GET:
        return render_to_response('admin/inject.html', 
                                  {'err_msg' : 'No logfile provided (use "log" argument)'},
                                  context_instance=RequestContext(request))
    lfile = request.GET['log']
    if not is_allowed(lfile, request):
        return render_to_response('admin/inject.html', 
                                  {'err_msg' : 'Unable to import '+lfile+', file is not allowed for you.'},
                                  context_instance=RequestContext(request))
    srclog = Tailer(lfile)
    if srclog.open_log() is False:
        return render_to_response('admin/inject.html', 
                                  {'err_msg': 'Unable to import '+lfile+', file cannot be opened.'},
                                  context_instance=RequestContext(request))
    
    exc_before = nx_fmt.udata.allowed_data(request).count()
    req_before = nx_request.udata.allowed_data(request).count()
    startdate = None
    if "incremental" in request.GET:
        incremental = True
        mode = "incremental"
    else:
        incremental = False
        mode = "full import"
    if incremental is True:
        startdate = nx_fmt.udata.allowed_data(request).filter(origin_log_file=srclog.filename).aggregate(Max('date'))
        ret = srclog.backlog(output=None, callback=srclog.dummy_callback, startdate=startdate['date__max'])
    else:
        ret = srclog.backlog(output=None, callback=srclog.dummy_callback)
    srclog.finish_imports(ret)
    exc_after = nx_fmt.udata.allowed_data(request).count()
    req_after = nx_request.udata.allowed_data(request).count()
    if startdate is not None:
        return render_to_response('admin/inject.html', 
                                  {'success': 1, 
                                   'exc_before': exc_before, 
                                   'exc_after': exc_after,
                                   'req_before': req_before,
                                   'req_after':req_after,
                                   'mode':mode,
                                   'startdate':startdate['date__max']
                                   }, 
                                  context_instance=RequestContext(request))

    else:
        return render_to_response('admin/inject.html', 
                                  {'success': 1, 
                                   'exc_before': exc_before, 
                                   'exc_after': exc_after,
                                   'req_before': req_before,
                                   'req_after':req_after,
                                   'mode':mode
                                   }, 
                                  context_instance=RequestContext(request))

def to_utc(dt, epoch=datetime(1970,1,1)):
    td = dt - epoch
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6


class MyFilter(FilterSet):
    nx_id = NumberFilter(lookup_type='exact')
    def __init__(self, *args, **kwargs):
        username = kwargs['username']
        del kwargs['username']
        super(MyFilter, self).__init__(*args, **kwargs)
        self.filters['origin_log_file'] = MultipleChoiceFilter(widget=forms.SelectMultiple(),
                                                               name='Log File',
                                                               label='Log File',
                                                               choices=[(filename['allowed_log_files'], filename['allowed_log_files']) for filename in nx_user.objects.filter(user__exact=username).values('allowed_log_files')])        
        self.filters['date'] = DateTimeFilter()

    class Meta:
        model = nx_fmt
        fields = [f.attname for f in nx_fmt._meta.fields]

@login_required
def dashboard(request):
#    count_sql = nx_fmt.objects.filter(nx_id__lte=1099, nx_id__gte=1000,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_xss = nx_fmt.objects.filter(nx_id__lte=1399, nx_id__gte=1300,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_rfi = nx_fmt.objects.filter(nx_id__lte=1199, nx_id__gte=1100,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_upload = nx_fmt.objects.filter(nx_id__lte=1599, nx_id__gte=1500,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_dt = nx_fmt.objects.filter(nx_id__lte=1299, nx_id__gte=1200,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_evade = nx_fmt.objects.filter(nx_id__lte=1499, nx_id__gte=1400,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count_intern = nx_fmt.objects.filter(nx_id__lte=10, nx_id__gte=0,type=InputType.EXCEPTION).aggregate(Count('nx_id'))
#    count = nx_fmt.objects.values('date').filter(type=InputType.EXCEPTION).annotate(d=Count('date'))[:100]
    
#    filtrator = Filtrator(nx_fmt)
    total_dict = {}
#    print count
#    for key,group in itertools.groupby(count, key= lambda x:x['date']):
#        for element in group:
#            d = time.mktime(key.timetuple()) * 1000
#            if total_dict.get(int(d)):
#                total_dict[int(d)] += element['d']
#            else:
#                total_dict[int(d)] = element['d']
#    sorted_count = sorted(total_dict.iteritems(), key=operator.itemgetter(0))
#    print sorted_count, count
#    print dir(nx_fmt)

    print '>>>>>>>>>>>>>>>>>>>>>>>>'
    print request.POST
    print '<<<<<<<<<<<<<<<<<<<<<<<'
    f  = MyFilter(request.POST or None,queryset=nx_fmt.objects.all(), username=request.user)
    corres_array = {}
    for key, value in f.form.fields.items():
        corres_array[key]=value.widget.render(key,'')
        
    return render_to_response('admin/dashboard.html', locals(), context_instance=RequestContext(request))


@login_required
def request_inspector(request):
    return render_to_response('admin/request_inspector.html', locals(), context_instance=RequestContext(request))
