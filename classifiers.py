import re
import tldextract
from datetime import datetime
from dateutil.relativedelta import relativedelta
from urllib.request import Request, urlopen, ssl, socket
# from urllib.error import URLError, HTTPError
import json
import favicon
import requests
import socket
import OpenSSL
import ssl




def get_source(url):
    r = requests.get(url)
    page_source = r.text
    page_source = page_source.split('\n')
    return page_source

#ADDRESS BAR FEATURES

def IP(url):
    ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url)
    if(len(ip_candidates)==0):
        # print("no ips in url")
        return 1
    return -1


def length(url):
    if len(url) > 75:
        # print("longer than 75")
        return -1
    if len(url) >= 54:
        return 0
    else:
         return 1

def shortened(url):
    shorteners=["bit.ly", "goo.gl", "tinyurl","ow.ly"]
    for string in shorteners:
        if string in url:
            # print("shortener")
            return -1
    return 1

def at_symbol(url):
    if '@' in url:
        print("@")
        return -1
    return 1

def redirect_slashes(url):
    url=url[8:]
    if "//" in url:
        # print("redirect slashes")
        return -1
    return 1

def prefsuf(url):
    if '-' in url:
        # print("presuf")
        return -1
    return 1

def subdomain(url):
    result=tldextract.extract(url)
    subdomain=result.subdomain
    if subdomain=="" or subdomain=="www":
        return 1
    dot=0
    if "www" in subdomain:
        subdomain = subdomain.replace("www.","");
    for character in subdomain:
        if character == '.':
            dot=dot+1
    if(dot==0):
        return 0
    if(dot>0):
        # print("subdomains")
        return -1


def certificate(url,domain):
    #Check when ssl certificate is valid until and who issued it
    if url.startswith("https"):
        result=tldextract.extract(url)
        domain=result.subdomain + '.' + result.domain+'.'+result.suffix

        try:
            cert=ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            issuer=str(x509.get_issuer())
            x509info=x509.get_notBefore()
            reg_day = x509info[6:8].decode("utf-8")
            reg_month = x509info[4:6].decode("utf-8")
            reg_year = x509info[:4].decode("utf-8")
            reg_date = str(reg_day) + "-" + str(reg_month) + "-" + str(reg_year)
            registration = datetime.strptime(reg_date, "%d-%m-%Y" )
            one_year_back = datetime.now() - relativedelta(years=1)
            trusted_issuers=["Comodo","GeoTrust","Network Solutions","Thawte","Doster","VeriSign","DigiCert" ]
            trusted=False
            for authority in trusted_issuers:
                if authority in str(issuer):
                    trusted=True
            if registration<one_year_back and trusted:
                return 1
            if registration<one_year_back and "Let's Encrypt" in str(issuer):
                return -1
            if registration<one_year_back and not trusted:
                return 0
        except:
            return 0
    return -1


def domain_reg_length(url,domain):
    result=tldextract.extract(url)
    # domain=None
    # count=0
    # while domain is None and count < 50:
    #     try:
    #         count=count+1
    #         domain=whois.whois(result.subdomain+'.'+result.domain+'.'+result.suffix)
    #     except:
    #         pass
    # if domain is None:
    #     return 0
    if domain is None:
        return 0
    exp_date=domain.expiration_date
    one_year = datetime.now() + relativedelta(years=1)
    # if (exp_date=="Creation_date_not_found"):
    #     return 0
    if exp_date is None:
        return 0
    if isinstance(exp_date,list):
        exp_date=exp_date[0]
    if exp_date<one_year:
        # print(exp_date)
        # print("expires soon")
        return -1

    return 1




def favicon_domain(url):
    try:
        icons = favicon.get(url)
    except:
        return 0
    if len(icons)==0:
        return 0
    icon=icons[0]
    url_favicon=(icon.url)
    result_favicon=tldextract.extract(url_favicon)
    result=tldextract.extract(url)
    if result_favicon.domain==result.domain:
        return 1
    return -1


# def port(url):
#     if url.startswith("https"):
#         return 1
#     print("http")
#     return -1

def https_domain(url):
    result=tldextract.extract(url)
    if "https" in (result.subdomain + '.' + result.domain+'.'+result.suffix):
        # print("https in domain")
        return -1
    return 1


def request_url(site,soup):
    # tags =soup.findAll('img', attrs={'src': re.compile("^http")})
    tags =soup.findAll('img')
    same=0
    different=0
    for tag in tags:
        tag_domain=tldextract.extract(str(tag))
        site_domain=tldextract.extract(site)
        if len(tag_domain) == 0:
            same=same+1
        if not tag_domain.subdomain+'.'+tag_domain.domain==site_domain.subdomain+'.'+site_domain.domain:
            different=different+1
        else:
            same=same+1


    try:
        fraction=different/(same+different)
    except:
        return 0
    # print(fraction)
    if fraction<0.22:
        return 1
    if fraction>0.61:
        return -1
    return 0


def url_anchor(site,soup):
    tags =soup.findAll('a', attrs={'href': re.compile("")})
    same=0
    different=0

    for tag in tags:
        tag_domain=tldextract.extract(str(tag))
        site_domain=tldextract.extract(site)
        if len(tag_domain) == 0:
            same=same+1
        if "void(" in tag:
            different=different+1
        if not tag_domain.subdomain+'.'+tag_domain.domain==site_domain.subdomain+'.'+site_domain.domain:
            different=different+1
        else:
            same=same+1
    try:
        fraction=different/(same+different)
    except:
        return 0

    # print(same,different,fraction)
    if fraction<0.32:
        return 1
    if fraction>0.67:
        return -1
    return 0

def links_in_tags(site,soup):
    # script_tags =soup.findAll('script', attrs={'src': re.compile("^http")})
    meta_tags =soup.findAll('meta')
    # link_tags=soup.findAll('link', attrs={'href': re.compile("^http")})
    link_tags=soup.findAll('link')
    script_tags =soup.findAll('script',attrs={'src': re.compile("")})
    tags=script_tags+meta_tags+link_tags
    same=0
    different=0

    for tag in tags:
        tag_domain=tldextract.extract(str(tag))
        site_domain=tldextract.extract(site)
        if len(tag_domain) == 0:
            same=same+1
        if not tag_domain.subdomain+'.'+tag_domain.domain==site_domain.subdomain+'.'+site_domain.domain:
            different=different+1
        else:
            same=same+1

    try:
        fraction=different/(same+different)
    except:
        return 0
    if fraction<0.17:
        return 1
    if fraction>0.81:
        return -1
    return 0


def sfh(url,soup):
    form = soup.find('form')
    if form is None:
        return 0
    action=form.get('action')
    if action is None:
        return -1
    if "about:blank" in action:
        return(-1)
    # if "http" in action or "www" in action or ".com" or ".net" in action:
    result_form=tldextract.extract(action)
    result=tldextract.extract(url)
    if len(result_form.domain) == 0:
        return 1
    if not result_form.subdomain+'.'+result_form.domain==result.subdomain+'.'+result.domain:
        return(0)
        # print("sfh_different")
    return(1)



def mailto(soup):
    # if "mail()" or "mailto:" in str(soup):
    if "mailto:" in str(soup):
        # print(soup)
        # print("mail")
        return -1
    return 1

# def abnormal_url(url):


def redirect(request):
    # print(type(request))
    r = request
    if len(r.history) <= 1:
        return 1
        if len(r.history)>3:
            return -1
    return 0

def on_mouseover(soup):
    if "onMouseOver=\"window.status" in str(soup):
        # print("onmouseover")
        return -1
    return 1

def rightclick(soup):
    if ".button==2" in str(soup):
        # print("rightclick disabled")
        return -1
    return 1

def popup(soup):
    if "\"popup\"" in str(soup):
        # print("popup")
        return -1
    return 1

def Iframe(soup):
    if "iframe" in str(soup):
        return -1
    return 1

def domain_age(url,domain):
    result=tldextract.extract(url)
    # domain=None
    # count=0
    # while domain is None and count < 50:
    #     try:
    #         count=count+1
    #         domain=whois.whois(result.domain+'.'+result.suffix)
    #     except:
    #         pass
    if domain is None:
        return 0
    #Sometimes returns list, sometimes returns one date- how horribly inconvenient!
    reg_date=domain.creation_date
    if reg_date is None:
        return 0
    six_months_ago = datetime.now() - relativedelta(months=6)
    if isinstance(reg_date,list):
        reg_date=reg_date[0]

    if reg_date>six_months_ago:
        return -1
    return 1

def DNSRecord(url,domain):
    result=tldextract.extract(url)
    # domain=whois.whois(result.domain+'.'+result.suffix)
    if domain is None:
        return -1
    return 1


def website_traffic(top_domains,url):
    result=tldextract.extract(url)
    if result.domain+'.'+result.suffix in top_domains:
        # print("topdomain")
        return 1
    return -1

#
# def pagerank(url):
#     return -1
#
# def googleindex(url):
#     return -1

# def linkspointing(url):
#     return -1

def statistical_report(url):
    topips=['64.70.19.203', '216.218.185.162', '172.217.14.161', '175.126.123.219', '156.251.148.212', '54.83.43.69', '47.91.170.222', '173.230.141.80', '103.44.28.169', '103.44.28.181', '108.61.203.22', '23.20.239.12', '153.92.0.100', '141.8.224.221', '184.168.131.241', '122.10.109.175', '209.202.252.66', '199.59.242.153', '69.172.201.153', '91.227.52.108', '35.186.238.101', '185.164.136.124', '69.16.230.42', '18.216.20.136', '211.231.99.250', '59.188.232.88', '160.121.242.52', '91.195.240.126', '37.157.192.102', '67.227.226.240', '52.58.78.16', '198.11.172.242', '3.234.181.234', '172.120.69.45', '204.95.99.26', '193.109.247.10', '52.69.166.231', '23.89.1.166', '18.211.9.206', '72.52.178.23', '204.11.56.48', '193.109.247.224', '47.75.126.218', '156.234.215.125', '23.253.126.58', '23.236.62.147', '47.245.9.22', '104.239.157.210', '208.91.197.46', '209.99.40.223']
    topdomains=["docs.google.com","storage.googleapis.com","firebasestorage.googleapis.com","cheaproomsvalencia.com","playarprint.com",\
    "forms.office.com","bit.ly","sites.google.com","ivanidzakovic.com","drive.google.com","forms.gle","codesandbox.io",".sharepoint.com","onedrive.live.com",\
    "advonationusa.com","infopublishersassociation.com","vmorefraud.com","stolizaparketa.ru","mytanfarma.com","zohard.com","southcountyclassified.com","tptelecom","tinyurl.com"]
    topips=[]
    ip_list = []
    result=tldextract.extract(url)
    try:
        ais = socket.getaddrinfo(result.subdomain + '.' + result.domain+'.'+result.suffix,0,0,0,0)
        for result in ais:
          ip_list.append(result[-1][0])
        ip_list = list(set(ip_list))
        for ip in ip_list:
            if ip in topips:
                return -1
    except:
        pass
    for domain in topdomains:
        if domain in url:
            # print("phish report")
            return -1
    return 1
