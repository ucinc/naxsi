from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django import utils
from django.http import HttpResponse

from tailer import Tailer
from nx_extract.models import nx_fmt, InputType, Zone
from django.db import transaction
from django.db.models import Max
#from melter import *

import cgi
import copy

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
    rep = HttpResponse()
    # rep.write("NAN MAIS TROP LOL")
    # return rep
    srclog = Tailer(request.user.get_profile().allowed_log_files)
    if srclog.open_log() is False:
        rep.write('<pre> Unable to open log file : '+srclog.filename+'</pre>')
        return rep
    rep.write("Before Import :"+str(nx_fmt.objects.count())+"\n")
    startdate = nx_fmt.objects.filter(origin_log_file=srclog.filename).aggregate(Max('date'))
    ret = srclog.backlog(output=None, callback=dummy_callback, startdate=startdate['date__max'])
    rep.write("item size:"+str(len(ret)))
    while len(ret):
        sub = ret[:50]
        nx_fmt.objects.bulk_create(sub)
        ret = ret[50:]
    
#    nx_fmt.objects.bulk_create(ret)
    rep.write('Successfully imported log file !')
    rep.write("After Import "+str(nx_fmt.objects.count())+" items.")
    return rep
#    return HttpResponse('<pre>' + request.user.get_profile().allowed_log_files + '</pre>')


