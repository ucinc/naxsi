from nx_extract.models import nx_fmt, nx_request, Zone, InputType
import copy
import pprint
from django.db.models import Count

class wlgen:
    def __init__(self, data):
        # pointer to filtered nx_fmt
        self.data = data
        pprint.pprint(data[0])
    def format_rules_output(self, i):
        r = ""
        if i['pratio'] <= 5 or i['mratio'] <= 5:
            r += "#"
        r += 'BasicRule wl:' + str(i['nx_id']) + ' "mz:'
        if len(i['uri']) > 0:
            r += '$URL:' + i['uri']
            if i['zone'] != Zone.ERROR and i['zone'] != Zone.REQUEST:
                r += '|'
        
        # For internal rule, there is no need to add mz
        if i['zone'] == Zone.REQUEST:
            pass
        elif i['zone'] == Zone.URL:
            r += "URL"
        elif i['zone'] == Zone.ARGS:
            if len(i['var_name']) > 0:
                r += "$ARGS_VAR:"+i['var_name']
            else:
                r += "ARGS"
        elif i['zone'] == Zone.HEADERS:
            if len(i['var_name']) > 0:
                r += "$HEADERS_VAR:"+i['var_name']
            else:
                r += "HEADERS"
        elif i['zone'] == Zone.BODY:
            if len(i['var_name']) > 0:
                r += "$BODY_VAR:"+i['var_name']
            else:
                r += "BODY"
        elif i['zone'] == Zone.FILE_EXT:
            if len(i['var_name']) > 0:
                r += "$BODY_VAR:"+i['var_name']+"|FILE_EXT"
            else:
                r += "BODY|FILE_EXT"
        else:
            r += "Unknown zone, please report bug to naxsi team:"+str(i)
            
        if i['zone_extra'] == Zone.NAME:
            r += "|NAME"
        r += '";'
        return r

    def format_rule(self, rl):
        pass
    def get_false_positives(self):
        """ extract false positives tagged by user """
        return self.data.filter(false_positive=True)
    def gen_wl(self, f_rules_count=10):
        # extract unique/distinct couples
        dist_items = self.data.values('type', 'uri', 'nx_id', 'var_name', 'zone', 'zone_extra')
#        print "There is "+str(dist_items)+" unique exceptions11111!"
        # get global counts
        total_peers = self.data.values('ip_client').distinct().count()
        total_hits = self.data.count()
        final = []
        for item in dist_items:
            item["rcount"] = 1
            # then, try to see if 
            # 1) this exception is already covered
            # 2) removing uri covers more expceptions
            # 3) removing varname covers '' ''
            # 4) removing ID covers '' '' (put weight?)
            for x in ["DoesNotExists1235432", "uri", "var_name", "nx_id"]:
                citem = copy.deepcopy(item)
                if x in citem:
                    if x == "nx_id":
                        citem[x] = 0
                    else:
                        citem[x] = ""
                existing = self.is_covered(final, citem)
                if len(existing) is 0:
                    final.append(citem)
                    citem["mcount"], citem["mratio"], citem["pcount"], citem["pratio"] = self.get_counts(citem, total_peers, total_hits)
                elif len(existing) > f_rules_count:
                    for todel in existing:
                        citem["rcount"] += todel["rcount"]
                        final.remove(todel)
                    citem["mcount"], citem["mratio"], citem["pcount"], citem["pratio"] = self.get_counts(citem, total_peers, total_hits)
                    final.append(citem)
                    
        final = sorted(final, key=lambda mfinal: mfinal["mcount"], reverse=True)
        # now we have factorized exceptions, clear according to peer ratio and hit ratio
        
        return final
    def get_counts(self, i, total_peers, total_hits):
        #dist_items = self.data.values('type', 'uri', 'nx_id', 'var_name', 'zone', 'zone_extra').annotate(mcount = Count('total_processed'))
        dist_items = self.data
        if len(i["uri"]) > 0:
            dist_items = dist_items.filter(uri=i["uri"])
        if i["nx_id"] != 0:
            dist_items = dist_items.filter(nx_id=i["nx_id"])
        if len(i["var_name"]) > 0:
            dist_items = dist_items.filter(var_name=i["var_name"])
        if i["zone"] != Zone.ALL:
            dist_items = dist_items.filter(zone=i["zone"])
        htot = dist_items.distinct().count()
        ptot = dist_items.values("ip_client").distinct().count()
        return (htot, ((float(htot)/float(total_hits))*100), ptot, ((float(ptot)/float(total_peers))*100))
    
    def is_covered(self, final, item):
        """ returns the objects present in 'item' that 
        are already covering exception 'final' """
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
    
