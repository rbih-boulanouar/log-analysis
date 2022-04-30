import base64
import urllib.parse
import html

class decode:

    #   decode Base64

    def Base64(coded_string):
        return base64.b64decode(coded_string)

    #   decode url encoding

    def url(coded_string):
        return urllib.parse.unquote(coded_string)

    #   Decode HTML entities

    def  html_entities(coded_string):
        return html.unescape(coded_string)

    #   we can add any type of encoding we want based on the Web application 