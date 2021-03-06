#   import libs

from urllib.parse import urlsplit, parse_qs
import re

#   Event Class with all attributes 

class event:
    i=0
#   regular expression for getting event parameters

    def get_attributes(self):
        return re.compile( 
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

#   Event attributes 

    def __init__(self,host,identity,user,time,request,status,r_bytes,referer,user_agent):
        self.host=host
        self.identity=identity
        self.user=user
        self.time=time
        self.request=request
        self.status=status
        self.bytes=r_bytes
        self.referer=referer
        self.user_agent=user_agent
    def __init__(self):
        pass

    #   function for getting all rhe parameters from the request url   

    def get_request_parameters(self):
        url_parameters_pattern='(?:\?|&|;)([^=]+)=([^&|;]+)'
        try:
            parameters_tuple= re.findall(url_parameters_pattern, self.request.split(" ")[1])
            return dict((x, y) for x, y in parameters_tuple)
        except:
            return {}
    def skip(self,request):
        extentions=[".jpeg",".jpg",".png",".css",".gif",".js",".json",]
        for i in extentions:
            if request.endswith(i):
                return True
            else:
                return False

