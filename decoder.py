import base64
import urllib.parse
import html

class decode:

    #   check if string is base64 encoded

    def isBase64(self, string):
        try:
            return base64.b64encode(base64.b64decode(string)) == string
        except Exception:
            return False

    #   decode Base64

    def Base64(self, coded_string):
        return base64.b64decode(coded_string)

    #   check if string is urlencoded

    def isUrlEncoded(self, string):
        try:
            return urllib.parse.quote(urllib.parse.unquote(string)) == string
        except Exception:
            return False

    #   decode urlencode

    def url(self,coded_string):
        return urllib.parse.unquote(coded_string)

    #   check if string is HTMLentitie

    def isHTMLEntitie(self, string):
        try:
            return html.escape(html.unescape(string)) == string
        except Exception:
            return False


    #   Decode HTML entities

    def  html_entitie(self, coded_string):
        return html.unescape(coded_string)

    #   we can add any type of encoding we want based on the Web application 