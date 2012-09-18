from django.core.management.base import BaseCommand, CommandError
#Standalone command to allow offline logfile injection
from nx_extract.tailer import Tailer
from nx_extract.models import nx_fmt, Zone, InputType
import pprint

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
    return None


class Command(BaseCommand):
    args = '/path/to/log_file [start-end] [-end] [start-]\n'
    args += 'Periods are in the format: Y/M/D H:M:S\n'
    args += 'ie. /tmp/log1 "2012/1/13 00:00:00-2012/2/31 00:00:00"\n'
    args += 'or: /tmp/log1 "2012/1/13 00:00:00-" (everything AFTER 2012/1/13)\n'
    args += 'or: /tmp/log1 "-2012/1/13 00:00:00" (everything BEFORE 2012/1/13)\n'
    mhelp = 'Import specified log files\n'

    def handle(self, *args, **options):
        if len(args) < 1:
            self.stdout.write(self.mhelp)
            self.stdout.write(self.args)
            return
        self.stdout.write('Preparing to import ['+args[0]+']\n')
        self.stdout.write('Currently, there is '+str(nx_fmt.objects.count())+" exception objects\n")
        log = Tailer(args[0])
        if log.open_log() is False:
            self.stdout.write("Unable to open "+log.filename+"\n")
            return
        periods=[]
        cpt=1
        while cpt < len(args):
            print "PERIOD ? "+args[cpt]
            prds = args[cpt].split("-")
            if len(prds) != 2:
                self.stdout.write("Period(s) must be interval, splitted by '-'")
                return
            sub = []
            sub.append(prds[0])
            sub.append(prds[1])
            periods.append(sub)
            cpt += 1
        self.stdout.write("Starting full import ...\n")
        if len(periods) > 0:
            self.stdout.write("Limiting import to periods:\n")
            pprint.pprint(periods)
            ret = log.backlog(output=None, callback=dummy_callback, backlog=periods)
        else:
            self.stdout.write("Full import, no period specified.\n")
            ret = log.backlog(output=None, callback=dummy_callback)
#        return

        self.stdout.write("Imported "+str(len(ret))+" items.\n")
        while len(ret):
            sub = ret[:50]
            nx_fmt.objects.bulk_create(sub)
            ret = ret[50:]
        self.stdout.write('After import, there is '+str(nx_fmt.objects.count())+" exception objects\n")
        
