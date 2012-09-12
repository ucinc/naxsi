import time, os
import datetime
import urllib

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
                end_data = sub.find(", ")
                if end_data < 0:
                    sub = ""
            name = sub[:end_name]
            value = sub[end_name+1:end_data]
            line_items[name] = value
            sub = sub[end_data+1:]
    
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
        return self.NAXSI_DATA_to_dict(line)

    def backlog(self, backlog=[["", ""]]):
        res = []
        for line in self.fd:
            if line.find(' [') is -1:
                print "Invalid line (discarded) :"
                print line
                continue
            date_raw = line[:line.find(' [')]
            print "date:"+date_raw
            try:
                date = datetime.datetime.strptime(date_raw, self.dfmt)
            except ValueError:
                print "Invalid date format '"+date_raw+"'"
                continue
            if not self.match_periods(date, backlog):
                continue
            items = self.line_to_dict(line)
            if items is None:
                print "Line parsing failed:"
                print line
                items = {}
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
#    logs = Tailer("/tmp/nginx_error.log")
    requests = Tailer("/tmp/pokemon_error.log")
    
 #   if not logs.open_log():
  #      print "Cannot open log"
    if not requests.open_log():
        print "Cannot open log"


   # print "PARSING NAXSI_FMT :"
   # res = logs.backlog()
   # pprint.pprint(res)
    # while True:
    #     res = logs.tail()
    #     pprint.pprint(res)
    #     time.sleep(1)
    

    print "PARSING NAXSI_DATA :"
    res = requests.backlog()
    pprint.pprint(res)
    # while True:
    #     res = logs.tail()
    #     pprint.pprint(res)
    #     time.sleep(1)
    


