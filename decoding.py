import base64
import urllib.parse
import html
import ftfy

class decode:

    #   check if string is base64 encoded

    def isBase64(self, string):
        try:
            return base64.b64encode(base64.b64decode(string)).decode("utf-8") == string
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

    def html_entitie(self, coded_string):
        return html.unescape(coded_string)

    #   check if string is unicode

    def isUnicode(self, string):
        if string.isascii():
            return True
        else:
            return False
    
    #   decode unicode

    def Unicode(self, string):

        return ftfy.fix_text(string)

    def autodecoder(self, string):
        string=self.url(string)
        try:
            if self.isBase64(str(string)):

                return self.Base64(string).decode("utf-8")
            
            elif self.isUnicode(string):
                
                return self.Unicode(string)
            
            elif self.isHTMLEntitie(string):
                
                return str(self.html_entitie(string))
            else:
                return string
        except:
            return string

    def decodejson(self, json):
            decoded_parameters={}
            for i in json:
                decoded_parameters[self.autodecoder(i)]=self.autodecoder(json[i])
            return decoded_parameters

    #   we can add any type of encoding we want based on the Web application 