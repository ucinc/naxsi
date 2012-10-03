from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django import utils
from django.http import HttpResponse

from tailer import Tailer

from nx_extract.models import nx_fmt, InputType, Zone, nx_user

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


def dummy_callback(mdict, output, mworld):
#    return
    i = 0
    mset = []
    while "id"+str(i) in mdict:
        iitem = nx_fmt()
        iitem.origin_log_file = mdict["log_file"]
        iitem.date = mdict["date"].strftime("%Y-%m-%d %H:%M:%S%Z")
        iitem.ip_client = mdict["ip"]
        iitem.total_processed = int(mdict["total_processed"])
        iitem.total_blocked = int(mdict["total_blocked"])
        iitem.learning_mode = int(mdict.get("learning", 0))
        iitem.false_positive = 0
        iitem.status_set_by_user = 0
        iitem.type = InputType.EXCEPTION
        iitem.comment = "imported from log."
        iitem.server = mdict["server"]
        iitem.uri = mdict["uri"].encode('string_escape', 'backslashreplace')
        iitem.zone_raw = mdict["zone"+str(i)]
        iitem.nx_id = int(mdict["id"+str(i)])
        iitem.var_name = mdict["var_name"+str(i)]
        x = iitem.zone_raw
        if "|" in x:
            iitem.zone = getattr(Zone, x[:x.find("|")], Zone.ERROR)
            x = x[x.find("|")+1:]
            iitem.zone_extra = getattr(Zone, x[x.find("|")+1:], 
                                       Zone.ERROR)
        else:
            iitem.zone = getattr(Zone, x, Zone.ERROR)
            iitem.zone_extra = Zone.ERROR
        mworld.append(iitem)
        i += 1
    return None


def is_covered(final, item):
    mres = []

    if item in final:
        mres.append(item)
        return mres
    
    for e in final:
        if len(item["uri"]) > 0 and len(e["uri"]) > 0 and e["uri"] != item["uri"]:
            continue
        if item["nx_id"] > 0 and e["nx_id"] > 0 and e["nx_id"] != item["nx_id"]:
            continue
        if item["zone"] != Zone.ALL and e["zone"] != Zone.ALL and e["zone"] != item["zone"]:
            continue
        if len(item["var_name"]) > 0 and len (e["var_name"]) > 0 and e["var_name"] != item["var_name"]:
            continue
        mres.append(e) 
    return mres

@login_required
def exc_viewer(request):
    
    rep = HttpResponse()
    y = nx_fmt.objects
    y.filter(server="blog.memze.ro")
    x = y.values('type', 'uri', 'zone_raw', 'nx_id', 'var_name', 'zone', 'zone_extra').distinct()
    total_peers = nx_fmt.objects.values('ip_client').distinct().count()
    total_hit = nx_fmt.objects.all().count()
    final = []
    for item in x:
        tmp = nx_fmt.objects.filter(type=item['type'],
                              uri=item['uri'], zone_raw=item['zone_raw'],
                              nx_id=item['nx_id'], var_name=item['var_name'])
        count = tmp.count()
        pcount = tmp.values('ip_client').distinct().count()
        item['mcount'] = count
        item["rcount"] = 0
        item["pcount"] = pcount
        citem = item
        for x in ["DoesNotExists1235432", "uri", "var_name"]:
            citem = copy.deepcopy(citem)
            if x in citem:
                citem[x] = ""
            existing = is_covered(final, citem)
            if len(existing) is 0:
                final.append(citem)
            elif len(existing) > 10:
                for todel in existing:
                    citem["rcount"] += 1
                    final.remove(todel)
                final.append(citem)
    final = sorted(final, key=lambda mfinal: mfinal["mcount"], reverse=True)
    for item in final:
        if (item["pcount"] <= (total_peers/100)):
            continue
        rep.write(item)
        rep.write("</br>")
    return rep

@login_required
#@transaction.commit_on_success
def log_feeder(request):
    srclog = Tailer(request.user.get_profile().allowed_log_files.strip())
    if srclog.open_log() is False:
        return render_to_response('admin/inject.html', {'filename': srclog.filename},context_instance=RequestContext(request))
    before_import = nx_fmt.objects.count()
    startdate = nx_fmt.objects.filter(origin_log_file=srclog.filename).aggregate(Max('date'))
    ret = srclog.backlog(output=None, callback=dummy_callback, startdate=startdate['date__max'])
    item_size = len(ret)
    while len(ret):
        sub = ret[:50]
        nx_fmt.objects.bulk_create(sub)
        ret = ret[50:]
    
    after_import = nx_fmt.objects.count()
    return render_to_response('admin/inject.html', {'before_import': before_import, 'item_size': item_size, 'after_import': after_import}, context_instance=RequestContext(request))

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
