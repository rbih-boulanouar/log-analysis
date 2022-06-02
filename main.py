#   import libs

import re
import normalization
import time
from pprint import pprint
import decoding

#   read log file in real time 

filePath = 'miniapache.log'
file=open (filePath,"r")
while 1:
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
        print ("event: "+line)  #   new line created in log file

        #   create new event object and set parameters

        event = normalization.event()
        event_parameters=event.pattern.match(line).groupdict()
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

        pprint(vars(event))
        print(event.get_request_parameters())
        