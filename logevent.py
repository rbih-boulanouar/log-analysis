#   import libs

from urllib.parse import urlsplit, parse_qs
import re

#   Event Class with all attributes 

class event:
    def __init__(self,host,identity,user,time,request,status,r_bytes,referer,user_agent):
        self.host=host
        self.identity=identity
        self.user=user
        self.time=time
        self.request=request
        self.status=status
        self.bytes=bytes
        self.referer=referer
        self.user_agent=user_agent
    def __init__(self):
        pass

    #   function for getting all rhe parameters from the request url   

    def get_request_parameters(self):
        url_parameters_pattern='(?:\?|&|;)([^=]+)=([^&|;]+)'
        return re.findall(url_parameters_pattern, self.request.split(" ")[1])
