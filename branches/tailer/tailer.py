import time, os
import datetime

import pprint

class Tailer:
    def __init__(self, filename, date_format='%Y/%m/%d %H:%M:%S'):
        self.filename = filename
        self.dfmt = date_format
        self.last_size = -1
    
    def match_periods(self, date, backlog):
        keep = False
        for periods in backlog:
            if periods[0] is not "":
                bot = datetime.datetime.strptime(periods[0], self.dfmt)
                if date < bot:
                    print "Discarding line, "+str(date)+" is older than old limit:"+str(bot)
                    continue
            if periods[1] is not "":
                top = datetime.datetime.strptime(periods[1], self.dfmt)
                if date > top:
                    print "Discarding line, "+str(date)+" is newer than new limit:"+str(top)
                    continue
            keep = True
        return keep

    def line_to_dict(self, line):
        line_items = {}
        sub = line.split("NAXSI_FMT: ")[1]
        end = line.find("\"")
        if end > 0:
            sub = sub[:end]
        while len(sub) > 0:
            end_name = sub.find("=")
            end_data = sub.find("&")
            if end_name < 0:
                break
            if end_data < 0:
                end_data = sub.find(",")
                if end_data < 0:
                    sub = ""
            name = sub[:end_name]
            value = sub[end_name+1:end_data]
            line_items[name] = value
            sub = sub[end_data+1:]
        return line_items
            
    def backlog(self, backlog=[["", ""]]):
        res = []
        for line in self.fd:
            if not ' NAXSI_FMT: ip=' in line:
                continue
            date_raw = line[:line.find(' [')]
            print "date:"+date_raw
            date = datetime.datetime.strptime(date_raw, self.dfmt)
            if not self.match_periods(date, backlog):
                continue
            items = self.line_to_dict(line)
            items["date"] = date
            items["date_raw"] = date_raw
            res.append(items)
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
    
    

if __name__  == '__main__':
    foo = Tailer("/tmp/01_UNPREDICTABLE_NOTHING")
    if not foo.open_log():
        print "Cannot open log"
        exit
    print "Success :)"
    # res = foo.backlog([ ["2012/09/11 23:02:10", "2012/09/11 23:06:13"],
    #                     ["", "2012/09/11 21:00:00"],
    #                     ["2012/09/11 23:42:00", ""]])
    res = foo.backlog()
    pprint.pprint(res)
    while True:
        res = foo.tail()
        pprint.pprint(res)
        time.sleep(1)
    

