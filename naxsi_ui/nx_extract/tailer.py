import time, os, sys
import datetime
import urllib
from django.db import transaction
from nx_extract.models import nx_fmt, Zone, InputType

class Tailer:
    def __init__(self, filename, date_format='%Y/%m/%d %H:%M:%S',
                 eod_marker=', client: '):
        self.filename = filename
        self.dfmt = date_format
        self.last_size = -1
        self.eod_marker = eod_marker
        self.possible_parse_methods = ["NAXSI_DATA_to_dict", 
                                       "NAXSI_FMT_to_dict",
                                       "NAXSI_WL_to_dict"]

    def dummy_callback(self, mdict, output, mworld):
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
            iitem.comment = "(shell) imported from log."
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
        if len(mworld) > 20:
            tpop = []
            while len(mworld) > 0:
                tpop.append(mworld.pop())
            nx_fmt.objects.bulk_create(tpop)
        return None

    def match_periods(self, date, backlog):
        keep = False
        for periods in backlog:
            if periods[0] is not "":
                bot = datetime.datetime.strptime(periods[0], self.dfmt)
                if date < bot:
#                    print "Discarding line, "+str(date)+" is older than old limit:"+str(bot)
                    continue
            if periods[1] is not "":
                top = datetime.datetime.strptime(periods[1], self.dfmt)
                if date > top:
 #                   print "Discarding line, "+str(date)+" is newer than new limit:"+str(top)
                    continue
            keep = True
        return keep
    
    def string_to_dict(self, sub, line_items):
        """
        Mimics parseurl* mecanisms, but includes
        assumptions as it is used to parse on nginx logs
        """
        end = sub.find("\"")
        if end > 0:
            sub = sub[:end]
        while len(sub) > 0:
            end_name = sub.find("=")
            end_data = sub.find("&")
            if end_name < 0:
                break
            if end_data < 0:
                end_data = len(sub)
            name = sub[:end_name]
            value = sub[end_name+1:end_data]
            #x in string.printable
            
            line_items[name] = value
            sub = sub[end_data+1:]
    
    def NAXSI_WL_to_dict(self, line):
#        if line.statswith()
        return None
    def NAXSI_DATA_to_dict(self, line):
        if line.find(": NAXSI_LOG: ") == -1:
            return None
        line_items = {}
        sub = line.split("NAXSI_LOG: ")[1]
        sub = sub.split(", client:")[0]
        if sub.startswith("H:"):
            sub = sub[2:]
            line_items["RAW_REQUEST_HEADERS"] = {}
            self.string_to_dict(sub, line_items["RAW_REQUEST_HEADERS"])
        elif sub.startswith("B:"):
            line_items["RAW_REQUEST_BODY"] = sub[2:]
            line_items["DECODED_REQUEST_BODY"] = urllib.unquote(sub[2:])
        else:
            print "Unable to handle NAXSI HTTP request:"
            print line
        return line_items

    def NAXSI_FMT_to_dict(self, line):
        if line.find(" NAXSI_FMT: ip=") == -1:
            return None
        line_items = {}
        sub = line.split("NAXSI_FMT: ")[1]
        self.string_to_dict(sub, line_items)
        return line_items

    def line_to_dict(self, line):
        for i in self.possible_parse_methods:
            func = getattr(self, i)
            x = func(line)
            if x is not None:
                return x
        return None
#    @
    
    def backlog(self, backlog=[["", ""]], callback=None, output=None, startdate=None):
        res = []
        if output is not None:
            output.write("Starting import\n")
        #xxx
        #lastdate = nx_fmt.objects.all().aggregate(Max('date'))
        
        for line in self.fd:
            sys.stdout.flush()
            if line.find(' [') is -1:
                if output is not None:
                    output.write("line discarded: "+line)
                continue
            date_raw = line[:line.find(' [')]
            try:
                date = datetime.datetime.strptime(date_raw, self.dfmt)
            except ValueError:
                continue
            if not self.match_periods(date, backlog):
                continue
            if startdate is not None:
                x = [[startdate.strftime(self.dfmt), ""]]
                if not self.match_periods(date, x):
                    continue
            cut = line.find(self.eod_marker)
            if cut <= 0:
                continue
            line = line[:cut]
            items = self.line_to_dict(line)
            if items is None:
                continue
            items["date"] = date
            items["date_raw"] = date_raw
            if output is not None:
                output.write("Successfully imported line.")
                
            if callback is not None:
                output.write("callback!") if output is not None else ''
                items["log_file"] = self.filename
                x = callback(items, output, res)
 #               if x is not None:
 #                   res.append(x)
 #           else:
 #               output.write("append!") if output is not None else ''
 #               res.append(items)
        return res
    
    def tail(self):
        """ Tails a file"""
        print "Current pos:"+str(self.fd.tell())
        self.last_seen = os.stat(self.filename)
        if self.last_size < 0:
            self.last_size = self.last_seen.st_size
            self.fd.seek(self.last_size)
        print "Current size:"+str(self.last_size)
        if self.last_seen.st_size is self.last_size:
            return ""
        self.fd.seek(self.last_size)
        ret = self.backlog()
        self.last_size = self.last_seen.st_size
        return ret

    def open_log(self):
        try:
            self.fd = open(self.filename, 'r')
        except:
            self.fd = None
            return False
        return True



# if __name__  == '__main__':
#     logfile = "/home/bui/secdev/naxsi/nginx-blog.memze.ro_error.log"
#     requests = Tailer(logfile)
#     if not requests.open_log():
#         print "Cannot open log"
#     print "PARSING NAXSI_DATA :"
#     res = requests.backlog()
#     print str(len(res))+" items."
#     print "------- shit is getting real"
#     mset = []
#     fset = set()
#     for item in res:
#         i = 0
#         while "id"+str(i) in item:
#             targ = Item()
#             targ.item_type = Types.EXCEPTION
#             targ.date = item["date"]
#             targ.nx_id = int(item["id"+str(i)])
#             targ.ip_client = item["ip"]
#             targ.learning_mode = int(item.get("learning", -1))
#             targ.server = item["server"]
#             targ.uri = item["uri"]
#             targ.zone_raw = item.get("zone"+str(i), "?")
#             targ.var_name = item.get("var_name"+str(i), "")
#             targ.origin_log_file = logfile
#             targ.total_processed = int(item.get("total_processed", "0"))
#             targ.total_blocked = int(item.get("total_blocked", "0"))
            
#             x = targ.zone_raw
#             if "|" in x:
#                 targ.zone = getattr(Zone, x[:x.find("|")], Zone.ERROR)
#                 x = x[x.find("|")+1:]
#                 targ.zone_extra = getattr(ZoneExtra, x[x.find("|")+1:], 
#                                              ZoneExtra.ERROR)
#             else:
#                 targ.zone = getattr(Zone, x, Zone.ERROR)
                
                    
#                 #pprint.pprint(targ)
#             i += 1
#             mset.append(targ)
#             if random.randint(1, 100) % 3 == 1:
#                 fset.add(targ)


# print "Items in set:"+str(len(fset))
# print "Full items:"+str(len(mset))
# #pprint.pprint(fset)
# for x in mset:
#     if x in fset:
#         print "Already present#####"
#         pprint.pprint(x)
#     else:
#         print "not present @@@"
#         if random.randint(1, 100) % 3 == 1:
#             print "insert!!!!!"
#             pprint.pprint(x)
#             fset.add(x)

#             fset.add(targ)
# print "--- final repr ----"
# print "Items in set:"+str(len(fset))
# print "Full items:"+str(len(mset))
# pprint.pprint(fset)


