from django.core.management.base import BaseCommand, CommandError
#Standalone command to allow offline logfile injection
from nx_extract.tailer import Tailer
from nx_extract.models import nx_fmt, nx_request, Zone, InputType
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
        self.stdout.write('Preparing to import ['+args[cpt]+']\n')
        self.stdout.write('Currently, there is '+str(nx_fmt.objects.count())+" exception objects\n")
        log = Tailer(args[cpt])
        if log.open_log() is False:
            self.stdout.write("Unable to open "+log.filename+"\n")
            return
        cpt += 1
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
        self.stdout.write("Starting full import ...\n")
        if len(periods) > 0:
            self.stdout.write("Limiting import to periods:\n")
            pprint.pprint(periods)
            ret = log.backlog(output=None, callback=log.dummy_callback, backlog=periods)
        else:
            self.stdout.write("Full import, no period specified.\n")
            ret = log.backlog(output=None, callback=log.dummy_callback)
        log.finish_imports(ret)
        self.stdout.write('After import, there is '+str(nx_fmt.objects.count())+" exception objects\n")
        self.stdout.write('After import, there is '+str(nx_request.objects.count())+" requests objects\n")
        
