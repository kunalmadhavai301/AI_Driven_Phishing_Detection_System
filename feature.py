import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import datetime
import dateutil.parser as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except Exception:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
            self.url
        )
        if match:
            return -1
        return 1

    def symbol(self):
        if "@" in self.url:
            return -1
        return 1

    def redirecting(self):
        if self.url.rfind('//') > 7:
            return -1
        return 1

    def prefixSuffix(self):
        if '-' in self.domain:
            return -1
        return 1

    def SubDomains(self):
        dot_count = self.url.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    def Hppts(self):
        try:
            if self.urlparse and self.urlparse.scheme == 'https':
                return 1
            return -1
        except Exception:
            return -1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (expiration_date - creation_date).days
            if age >= 365:
                return 1
            return -1
        except Exception:
            return -1

    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head_link in head.find_all('link', href=True):
                    dots = [x.start() for x in re.finditer(r'\.', head_link['href'])]
                    if self.url in head_link['href'] or len(dots) == 1 or self.domain in head_link['href']:
                        return 1
            return -1
        except Exception:
            return -1

    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except Exception:
            return -1

    def HTTPSDomainURL(self):
        if 'https' in self.domain:
            return -1
        return 1

    def RequestURL(self):
        try:
            i, success = 0, 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start() for x in re.finditer(r'\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success += 1
                i += 1
            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success += 1
                i += 1
            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success += 1
                i += 1
            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start() for x in re.finditer(r'\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success += 1
                i += 1
            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif 22.0 <= percentage < 61.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return 1
        except Exception:
            return -1

    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1
            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif 31.0 <= percentage <= 67.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return 1
        except Exception:
            return -1

    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for script in self.soup.find_all('script', src=True):
                dots = [x.start() for x in re.finditer(r'\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success += 1
                i += 1
            for link in self.soup.find_all('link', href=True):
                dots = [x.start() for x in re.finditer(r'\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success += 1
                i += 1
            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif 17.0 <= percentage < 81.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return 1
        except Exception:
            return -1

    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1
            for form in self.soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0
                else:
                    return 1
        except Exception:
            return -1

    def InfoEmail(self):
        try:
            if re.findall(r"mailto:", self.response.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except Exception:
            return -1

    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    def IframeRedirection(self):
        try:
            if re.findall(r"<iframe>|<iframe", self.response.text):
                return -1
            else:
                return 1
        except Exception:
            return -1

    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except Exception:
                pass
            today = datetime.now()
            age = (today - creation_date).days
            if age >= 180:
                return 1
            return -1
        except Exception:
            return -1

    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except Exception:
                pass
            today = datetime.now()
            age = (today - creation_date).days
            if age >= 180:
                return 1
            return -1
        except Exception:
            return -1

    def WebsiteTraffic(self):
        try:
            url = f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}"
            xml = urllib.request.urlopen(url).read()
            soup = BeautifulSoup(xml, "xml")
            rank = int(soup.find("REACH")["RANK"])
            if rank < 100000:
                return 1
            return 0
        except Exception:
            return -1

    def PageRank(self):
        try:
            return 1
        except Exception:
            return -1

    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            return -1
        except Exception:
            return -1

    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except Exception:
            return -1

    def StatsReport(self):
        try:
            url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            try:
                ip_address = socket.gethostbyname(self.domain)
            except Exception:
                ip_address = ""
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except Exception:
            return 1

    def getFeaturesList(self):
        return self.features
