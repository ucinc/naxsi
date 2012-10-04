from nx_extract.models import nx_fmt, nx_request, Zone, InputType
import copy
import pprint

class wlgen:
    def __init__(self, data):
        # pointer to filtered nx_fmt
        self.data = data

    def format_rules_output(self, i):
#        pprint.pprint(i)
        r = 'BasicRule wl:' + str(i['nx_id']) + ' "mz:'
        if len(i['uri']) > 0:
            r += '$URL:' + i['uri']
            if i['zone'] != Zone.ERROR and i['zone'] != Zone.REQUEST:
                r += '|'
        
        # For internal rule, there is no need to add mz
        if i['zone'] == Zone.REQUEST:
            r += '";'
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
        dist_items = self.data.values('type', 'uri', 'nx_id', 'var_name', 'zone', 'zone_extra').distinct()
        # get global counts
        total_peers = self.data.values('ip_client').distinct().count()
        total_hit = self.data.count()
#        print "We have "+str(len(dist_items))+" unique exceptions"
        final = []
        for item in dist_items:
#            pprint.pprint(item)
            # get he count of exceptions / peers that triggered a specific exception
            tmp = self.data.filter(type=item['type'],
                                   uri=item['uri'], zone=item['zone'], zone_extra=item['zone_extra'],
                                   nx_id=item['nx_id'], var_name=item['var_name'])
            count = tmp.count()
            pcount = tmp.values('ip_client').distinct().count()
            item['mcount'] = count
            item["rcount"] = 0
            item["pcount"] = pcount
            # then, try to see if 
            # 1) this exception is already covered
            # 2) removing uri covers more expceptions
            # 3) removing varname covers '' ''
            # 4) removing ID covers '' '' (put weight?)
            for x in ["DoesNotExists1235432", "uri", "var_name"]:
                citem = copy.deepcopy(item)
                if x in citem:
                    citem[x] = ""
                existing = self.is_covered(final, citem)
                if len(existing) is 0:
                    print "[f,u:"+citem['uri']+"]"
                    final.append(citem)
                elif len(existing) > f_rules_count:
                    print "[r,(n)u:"+citem['uri']+"]"
                    for todel in existing:
                        citem["rcount"] += 1
                        final.remove(todel)
                    final.append(citem)
        final = sorted(final, key=lambda mfinal: mfinal["mcount"], reverse=True)
            # now we have factorized exceptions, clear according to peer ratio and hit ratio
        return final

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
    
