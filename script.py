import re

class event:
    # source_ip
    # request_time
    # request_method
    # path
    # request_length
    # url
    # user_agent
    # parameters
    def __init__(self,source_ip,request_time,request_method,path,request_length,url,user_agent):
        self.source_ip=source_ip
        self.request_time=request_time
        self.request_method=request_method
        self.path=path
        self.request_length=request_length
        self.url=url
        self.user_agent=user_agent
        self.parameters=parameters
    def __init__(self):
        pass

    def get_parameters(path):
        return re.search(url_parameters_pattern, path)

ip_address_pattern="\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
url_parameters_pattern="\?|\&)([^=]+)\=([^&]+"

max_date=0
file = open("apach.log","r" ,encoding="utf-8")
events = file.readlines()
for uevent in events:
    normalized_event=event()
    normalized_event.source_ip= re.search(ip_address_pattern, event)[0]

