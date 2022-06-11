#   import libs

import re
import normalization
import time
from pprint import pprint
import decoding
import classification
import json

#   read log file in real time 

filePath = 'C:\\xampp\\apache\\logs\\access.log'
file=open (filePath,"r")
co=0
errors=0
while 1:
    
    where = file.tell()
    line = file.readline().strip()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
        #print ("event: "+line)  #   new line created in log file
        event = normalization.event()
        event_parameters=event.reg().match(line).groupdict()
        if normalization.event().skip(event_parameters['request']):
            continue
        #   create new event object and set parameters
        
        event.host=event_parameters['host']
        event.identity=event_parameters['identity']
        event.user=event_parameters['user']
        event.time=event_parameters['time']
        event.request=event_parameters['request']
        event.status=event_parameters['status']
        event.bytes=event_parameters['bytes']
        event.referer=event_parameters['referer']
        event.user_agent=event_parameters['user_agent']
        if str(event.status).startswith("4") or str(event.status).startswith("5"):
            errors=errors+1
        #   print the event object and request parameters

        #pprint(vars(event))
        #print(decoding.decode().decodejson(event.get_request_parameters()))
        
        a=decoding.decode().decodejson(event.get_request_parameters())
        #print(classification.detection().classifier(a))
        aa=classification.detection().classifier(a)
        for i in aa['data']:
            i.setdefault("host",event.host)
            i.setdefault("time",event.time)
            #i.setdefault("request",event.request)
        aa['counter']=co
        aa['errors']=errors
        co=co+1
        print(aa)
        
        print("-------------------------------------------------------------------")
        #print(decoding.decode().autodecoder("<A HREF=\"http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D\">XSS</A>"))
        fi= open("C:\\xampp\\htdocs\\bwapp\\bWAPP\website\\result.json", "w")
        json.dump(aa, fi)
        #fi.close()
        