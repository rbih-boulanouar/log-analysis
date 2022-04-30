#   import libs

import re
import logevent
import time
from pprint import pprint

#   regular expression for getting event parameters

ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
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

        event = logevent.event()
        event_parameters=pattern.match(line).groupdict()
        event.host=event_parameters['host']
        event.identity=event_parameters['identity']
        event.user=event_parameters['identity']
        event.time=event_parameters['time']
        event.request=event_parameters['request']
        event.status=event_parameters['status']
        event.bytes=event_parameters['bytes']
        event.referer=event_parameters['referer']
        event.user_agent=event_parameters['user_agent']

        #   print the event object and request parameters

        pprint(vars(event))
        print(event.get_request_parameters())
