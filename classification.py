import re
import decoding
class detection:
    result={"data":[]}
    def lfi_detector(self,s):
        str=r"'../|/..|..\\|\\..'gmi"
        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            with open("payloads/lfi.txt", "r", encoding="utf-8") as file:
                for i in file.readlines():
                    if s == decoding.decode().autodecoder(i.strip()):
                        return True
                    else:
                        return False
    def ldap_detector(self,s):
        str=""

        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            return False

    def crlf_detector(self,s):
        str="\\r|\\n\"gmi\""

        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            with open("payloads/CRLF injection.txt", "r", encoding="utf-8") as file:
                for i in file.readlines():
                    if s == decoding.decode().autodecoder(i.strip()) :
                        return True
                    else:
                        return False

    def command_detector(self,s):
        str="'\&|\||\`|\$()|\/bin|chmod|ls|chown|grep|alias|pwd|cd|sudo|rm|mv|mkdir|touch|;|\./|htop|ps|apt|pacman|yum|kill|wget|exec|/usr|c:\\|curl'gmi"

        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            with open("payloads/command injection.txt", "r", encoding="utf-8") as file:
                for i in file.readlines():
                    if s == decoding.decode().autodecoder(i.strip()):
                        return True
                    else:
                        return False
            
    def code_detector(self,s):
        str="'[|]|\{|\}|\(\)|\);|\^|\$|abstrac|callable|catch|class|declare|default|echo|else|elseif|foreach|function|goto|if\(|implements|include_once|instanceof|insteadof|isset|namespace|require|require_once|return|throw|trait|unset|xor|yield|yield from'gmi"

        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            return False

    def sqli_detector(self,s):
        str="('(''|[^'])*')|(;)|(\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT(INTO){0,1}|MERGE|SELECT|UPDATE|UNION(ALL){0,1})\b)ixg"

        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            with open("payloads\sql injection\detect\Generic_ErrorBased.txt", "r", encoding="utf-8") as file:
                for i in file.readlines():
                    if s == decoding.decode().autodecoder(i.strip()):
                        return True
                    else:
                        return False

    def xss_detector(self,s):
        str = ("<[^\\w<>]*(?:[^<>\""
        "\'\\s]*:)?[^\\w<>]*("
        "?:\\W*s\\W*c\\W*r\\W"
        "*i\\W*p\\W*t|\\W*f\\"
        "W*o\\W*r\\W*m|\\W*s"
        "\\W*t\\W*y\\W*l\\W*e"
        "|\\W*s\\W*v\\W*g|\\W"
        "*m\\W*a\\W*r\\W*q\\W"
        "*u\\W*e\\W*e|(?:\\W*"
        "l\\W*i\\W*n\\W*k|\\W"
        "*o\\W*b\\W*j\\W*e\\W"
        "*c\\W*t|\\W*e\\W*m\\"
        "W*b\\W*e\\W*d|\\W*a"
        "\\W*p\\W*p\\W*l\\W*e"
        "\\W*t|\\W*p\\W*a\\W*"
        "r\\W*a\\W*m|\\W*i?\\"
        "W*f\\W*r\\W*a\\W*m\\"
        "W*e|\\W*b\\W*a\\W*s"
        "\\W*e|\\W*b\\W*o\\W*"
        "d\\W*y|\\W*m\\W*e\\W"
        "*t\\W*a|\\W*i\\W*m\\"
        "W*a?\\W*g\\W*e?|\\W*"
        "v\\W*i\\W*d\\W*e\\W*"
        "o|\\W*a\\W*u\\W*d\\W"
        "*i\\W*o|\\W*b\\W*i\\"
        "W*n\\W*d\\W*i\\W*n\\"
        "W*g\\W*s|\\W*s\\W*e"
        "\\W*t|\\W*i\\W*s\\W*"
        "i\\W*n\\W*d\\W*e\\W*"
        "x|\\W*a\\W*n\\W*i\\W"
        "*m\\W*a\\W*t\\W*e)[^"
        ">\\w])|(?:<\\w[\\s\\"
        "S]*[\\s\\0\\/]|[\'\""
        "])(?:formaction|styl"
        "e|background|src|low"
        "src|ping|on(?:d(?:e("
        "?:vice(?:(?:orienta|"
        "mo)tion|proximity|fo"
        "und|light)|livery(?:"
        "success|error)|activ"
        "ate)|r(?:ag(?:e(?:n("
        "?:ter|d)|xit)|(?:ges"
        "tur|leav)e|start|dro"
        "p|over)?|op)|i(?:s(?"
        ":c(?:hargingtimechan"
        "ge|onnect(?:ing|ed))"
        "|abled)|aling)|ata(?"
        ":setc(?:omplete|hang"
        "ed)|(?:availabl|chan"
        "g)e|error)|urationch"
        "ange|ownloading|blcl"
        "ick)|Moz(?:M(?:agnif"
        "yGesture(?:Update|St"
        "art)?|ouse(?:PixelSc"
        "roll|Hittest))|S(?:w"
        "ipeGesture(?:Update|"
        "Start|End)?|crolledA"
        "reaChanged)|(?:(?:Pr"
        "ess)?TapGestur|Befor"
        "eResiz)e|EdgeUI(?:C("
        "?:omplet|ancel)|Star"
        "t)ed|RotateGesture(?"
        ":Update|Start)?|A(?:"
        "udioAvailable|fterPa"
        "int))|c(?:o(?:m(?:p("
        "?:osition(?:update|s"
        "tart|end)|lete)|mand"
        "(?:update)?)|n(?:t(?"
        ":rolselect|extmenu)|"
        "nect(?:ing|ed))|py)|"
        "a(?:(?:llschang|ch)e"
        "d|nplay(?:through)?|"
        "rdstatechange)|h(?:("
        "?:arging(?:time)?ch)"
        "?ange|ecking)|(?:fst"
        "ate|ell)change|u(?:e"
        "change|t)|l(?:ick|os"
        "e))|m(?:o(?:z(?:poin"
        "terlock(?:change|err"
        "or)|(?:orientation|t"
        "ime)change|fullscree"
        "n(?:change|error)|ne"
        "twork(?:down|up)load"
        ")|use(?:(?:lea|mo)ve"
        "|o(?:ver|ut)|enter|w"
        "heel|down|up)|ve(?:s"
        "tart|end)?)|essage|a"
        "rk)|s(?:t(?:a(?:t(?:"
        "uschanged|echange)|l"
        "led|rt)|k(?:sessione"
        "|comma)nd|op)|e(?:ek"
        "(?:complete|ing|ed)|"
        "(?:lec(?:tstar)?)?t|"
        "n(?:ding|t))|u(?:cce"
        "ss|spend|bmit)|peech"
        "(?:start|end)|ound(?"
        ":start|end)|croll|ho"
        "w)|b(?:e(?:for(?:e(?"
        ":(?:scriptexecu|acti"
        "va)te|u(?:nload|pdat"
        "e)|p(?:aste|rint)|c("
        "?:opy|ut)|editfocus)"
        "|deactivate)|gin(?:E"
        "vent)?)|oun(?:dary|c"
        "e)|l(?:ocked|ur)|roa"
        "dcast|usy)|a(?:n(?:i"
        "mation(?:iteration|s"
        "tart|end)|tennastate"
        "change)|fter(?:(?:sc"
        "riptexecu|upda)te|pr"
        "int)|udio(?:process|"
        "start|end)|d(?:apter"
        "added|dtrack)|ctivat"
        "e|lerting|bort)|DOM("
        "?:Node(?:Inserted(?:"
        "IntoDocument)?|Remov"
        "ed(?:FromDocument)?)"
        "|(?:CharacterData|Su"
        "btree)Modified|A(?:t"
        "trModified|ctivate)|"
        "Focus(?:Out|In)|Mous"
        "eScroll)|r(?:e(?:s(?"
        ":u(?:m(?:ing|e)|lt)|"
        "ize|et)|adystatechan"
        "ge|pea(?:tEven)?t|mo"
        "vetrack|trieving|cei"
        "ved)|ow(?:s(?:insert"
        "ed|delete)|e(?:nter|"
        "xit))|atechange)|p(?"
        ":op(?:up(?:hid(?:den"
        "|ing)|show(?:ing|n))"
        "|state)|a(?:ge(?:hid"
        "e|show)|(?:st|us)e|i"
        "nt)|ro(?:pertychange"
        "|gress)|lay(?:ing)?)"
        "|t(?:ouch(?:(?:lea|m"
        "o)ve|en(?:ter|d)|can"
        "cel|start)|ime(?:upd"
        "ate|out)|ransitionen"
        "d|ext)|u(?:s(?:erpro"
        "ximity|sdreceived)|p"
        "(?:gradeneeded|dater"
        "eady)|n(?:derflow|lo"
        "ad))|f(?:o(?:rm(?:ch"
        "ange|input)|cus(?:ou"
        "t|in)?)|i(?:lterchan"
        "ge|nish)|ailed)|l(?:"
        "o(?:ad(?:e(?:d(?:met"
        "a)?data|nd)|start)?|"
        "secapture)|evelchang"
        "e|y)|g(?:amepad(?:(?"
        ":dis)?connected|butt"
        "on(?:down|up)|axismo"
        "ve)|et)|e(?:n(?:d(?:"
        "Event|ed)?|abled|ter"
        ")|rror(?:update)?|mp"
        "tied|xit)|i(?:cc(?:c"
        "ardlockerror|infocha"
        "nge)|n(?:coming|vali"
        "d|put))|o(?:(?:(?:ff"
        "|n)lin|bsolet)e|verf"
        "low(?:changed)?|pen)"
        "|SVG(?:(?:Unl|L)oad|"
        "Resize|Scroll|Abort|"
        "Error|Zoom)|h(?:e(?:"
        "adphoneschange|l[dp]"
        ")|ashchange|olding)|"
        "v(?:o(?:lum|ic)e|ers"
        "ion)change|w(?:a(?:i"
        "t|rn)ing|heel)|key(?"
        ":press|down|up)|(?:A"
        "ppComman|Loa)d|no(?:"
        "update|match)|Reques"
        "t|zoom))[\\s\\0]*=")
        regexp = re.compile(str)
        if regexp.search(s):
            return True
        else:
            with open("payloads/xss.txt", "r", encoding="utf-8") as file:
                for i in file.readlines():
                    if s == decoding.decode().autodecoder(i.strip()):
                        return True
                    else:
                        return False
    def classifier(self,json):
        for i in json:
            if self.xss_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"XSS"})
            elif self.sqli_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"SQL INJECTION"})
            elif self.lfi_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"LFI INJECTION"})
            elif self.command_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"COMMAND INJECTION"})
            elif self.code_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"CODE INJECTION"})
            elif self.crlf_detector(json[i]):
                self.result["data"].append({i:json[i],"attacktype":"CRLF INJECTION"})
            
        return self.result