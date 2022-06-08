#   import libs

import re
import normalization
import time
from pprint import pprint
import decoding
import classification
import json

#   read log file in real time 
pattern=format_pat= re.compile( 
r"(?P<host>(?:[\d\.]|[\da-fA-F:])+)\s" 
r"(?P<identity>\S*)\s" 
r"(?P<user>\S*)\s"
r"\[(?P<time>.*?)\]\s"
r'"(?P<request>.*?)"\s'
r"(?P<status>\d+)\s"
r"(?P<bytes>\S*)\s"
r'"(?P<referer>.*?)"\s'
r'"(?P<user_agent>.*?)"\s*' 
)
filePath = 'miniapache.log'
file=open (filePath,"r")
while 1:
    where = file.tell()
    line = file.readline().strip()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
        print ("event: "+line)  #   new line created in log file

        #   create new event object and set parameters

        event = normalization.event()
        event_parameters=event.reg().match(line).groupdict()
        event.host=event_parameters['host']
        event.identity=event_parameters['identity']
        event.user=event_parameters['user']
        event.time=event_parameters['time']
        event.request=event_parameters['request']
        event.status=event_parameters['status']
        event.bytes=event_parameters['bytes']
        event.referer=event_parameters['referer']
        event.user_agent=event_parameters['user_agent']

        #   print the event object and request parameters

        #pprint(vars(event))
        #print(decoding.decode().decodejson(event.get_request_parameters()))
        
        a=decoding.decode().decodejson(event.get_request_parameters())
        #print(classification.detection().classifier(a))
        aa=classification.detection().classifier(a)
        for i in aa['data']:
            i.setdefault("host",event.host)
            i.setdefault("time",event.time)
        print(aa)
        print("-------------------------------------------------------------------")
        #print(decoding.decode().autodecoder("<A HREF=\"http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D\">XSS</A>"))
        fi= open("result.json", "w")
        json.dump(aa, fi)
        fi.close()