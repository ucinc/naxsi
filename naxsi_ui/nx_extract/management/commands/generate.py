from django.core.management.base import BaseCommand, CommandError
#Standalone command to allow offline logfile injection
from nx_extract.tailer import Tailer
from nx_extract.models import nx_fmt, nx_request, Zone, InputType
from nx_extract.wl_generation import wlgen

import pprint

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
        cpt=0
        if args[cpt].startswith('.') or args[cpt].startswith('/') or args[cpt].startswith('~'):
            wlsrc = nx_fmt.objects.filter(origin_log_file=args[cpt])
            print "Limiting WL generation to file "+args[cpt]
            cpt += 1
        else:
            wlsrc = nx_fmt.objects.all()
            print "'"+args[0]+"' is not a file, generating WL for whole DB"
        periods=[]
        print "nb args:"+str(len(args))
        while cpt < len(args):
            prds = args[cpt].split("-")
            if len(prds) != 2:
                self.stdout.write("Period(s) must be interval, splitted by '-'")
                return
            sub = []
            sub.append(prds[0])
            sub.append(prds[1])
            periods.append(sub)
            cpt += 1
#        if len(periods) > 0:
#            for itv in periods:
#                pprint.pprint(itv)
        wlgenerator = wlgen(wlsrc)
        wl = wlgenerator.gen_wl()
        for rule in wl:
            print("# Rule was triggered "+str(rule['mcount'])+" times ("+str(rule["mratio"])+"%), by "+str(rule['pcount'])+" peers ("+str(rule['pratio'])+"%) - aggregates "+str(rule['rcount'])+" rules\n")
            print(wlgenerator.format_rules_output(rule)+"\n<br/>")
        #log.finish_imports(ret)
#        self.stdout.write('After import, there is '+str(nx_fmt.objects.count())+" exception objects\n")
#        self.stdout.write('After import, there is '+str(nx_request.objects.count())+" requests objects\n")
        
