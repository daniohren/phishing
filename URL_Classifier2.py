import csv
import pandas as pd
import tldextract
# from bs4 import BeautifulSoup
import re
import whois
import numpy as np
from datetime import datetime
from dateutil.relativedelta import relativedelta
import requests
import ssl
from IPy import IP
from socket import *



#ADDRESS BAR FEATURES
def alive(url):
    try:
        requests_output = requests.get(url,timeout=3)
        if requests_output.status_code==200:
            return 1
        if requests_output.status_code==401 or requests_output.status_code==403:
            return 0
        else:
            return -1
    except requests.exceptions.Timeout:
        return -1

    except requests.exceptions.ConnectionError:
        return -1
    except:
        return 0


def is_private(ip):
    #print(ip)
    ip_public_filter = IP(ip)
    if ip_public_filter.iptype()== 'PRIVATE':
        # print("Private IP!")
        return True

def IPinURL(url):
    ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url)
    if(len(ip_candidates)==0):
        # print("no ips in url")
        return 1
    if isinstance(ip_candidates,list):
        ip_candidates=ip_candidates[0]
    if is_private(ip_candidates):
        return 1
    return -1


def tld(tldextract_output):

    df = pd.read_excel('spamhaus_13052020.xlsx')
    dict=df.set_index('tld')['score'].to_dict()
    # if df['tld'].str.contains(tldextract_output.suffix).any():
    if tldextract_output.suffix in dict.keys():
        return -dict[tldextract_output.suffix]
    else:
         return -0.5


def length(url):
    return -(len(url))/100


def shortened(url):
    shorteners=["bit.ly", "goo.gl", "tinyurl","ow.ly","bit.do"]
    for string in shorteners:
        if string in url:
            # print("shortener")
            return -1
    return 1

def at_symbol(url):
    if '@' in url:
        # print("@")
        return -1
    return 1

def redirect_slashes(url):
    url=url[8:]
    if "//" in url:
        # print("redirect slashes")
        return -1
    return 1

def prefsuf(tldextract_output):
    if '-' in tldextract_output.subdomain + '.' + tldextract_output.domain:
        # print("presuf")
        return -1
    return 1

def subdomain(tldextract_output):
    subdomain=tldextract_output.subdomain
    if subdomain=="" or subdomain=="www":
        return 0
    dot=1
    if "www" in subdomain:
        subdomain = subdomain.replace("www.","");
    for character in subdomain:
        if character == '.':
            dot=dot+1
    return -dot




def certificate(tldextract_output):

    #Check when ssl certificate is valid until and who issued it
    if tldextract_output.subdomain=="":
        domain=tldextract_output.domain+'.'+tldextract_output.suffix
    else:
        domain=tldextract_output.subdomain + '.' + tldextract_output.domain+'.'+tldextract_output.suffix
    try:
        setdefaulttimeout(3)
        cert=ssl.get_server_certificate((domain, 443))

    except:
        return -1
    return 1


def domain_age(whois_output):

    if whois_output is None:
        return 0.18
    reg_date=whois_output.creation_date
    # six_months_ago = datetime.now() - relativedelta(months=6)
    if isinstance(reg_date,str):
        if "Aug-1996" in str(reg_date):
            return 9

    if isinstance(reg_date,list):
        # print(reg_date)
        reg_date=reg_date[0]
    try:
        difference=datetime.now()-reg_date
        return(difference.days/1000)
    except:
        return 0.18




def reg_length(whois_output):
    if whois_output is None:
        return 0.365
    exp_date=whois_output.expiration_date
    # six_months_ago = datetime.now() - relativedelta(months=6)
    if isinstance(exp_date,list):
        # print(exp_date)
        exp_date=exp_date[0]
    try:
        difference=datetime.now()-exp_date
        return(-difference.days/1000)
    except:
        return 0.365

    # print(difference.days,type(difference.days))


def https_domain(tldextract_output):
    if "https" in (tldextract_output.subdomain + '.' + tldextract_output.domain+'.'+tldextract_output.suffix):
        # print("https in domain")
        return -1
    if ".com" in (tldextract_output.subdomain + tldextract_output.domain) or "org" in (tldextract_output.subdomain + tldextract_output.domain):
        return -1
    return 1




def website_traffic(top_sites,tldextract_output):
    if top_sites['Domains'].str.contains(tldextract_output.domain + '.' + tldextract_output.suffix).any():
        # print("topdomain")
        return 1
    return -1




def statistical_report(url,tldextract_output):

    topdomains=["docs.google.com","storage.googleapis.com","firebasestorage.googleapis.com","cheaproomsvalencia.com","playarprint.com",\
    "forms.office.com","bit.ly","sites.google.com","ivanidzakovic.com","drive.google.com","forms.gle","codesandbox.io",".sharepoint.com","onedrive.live.com",\
    "advonationusa.com","infopublishersassociation.com","vmorefraud.com","stolizaparketa.ru","mytanfarma.com","zohard.com","southcountyclassified.com","tptelecom","tinyurl.com"]

    for domain in topdomains:
        if domain in url:
            # print("phish report")
            return -1
    return 1


def get_training_features(urls):
    top_sites = pd.read_csv('top-1m.csv')
    top_count = top_sites['Domains'].count()

    features = np.zeros([urls.count(),14])
    # already_visited={}

    for i in range(urls.count()):
        url = urls[i]
        if not url.startswith("http"):
            url="https://"+url

        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix
        try:
            # whois_output=whois.whois(tldextract_output.domain + '.' + tldextract_output.suffix)
            whois_output=whois.whois(url)
        except:
            whois_output=None


        row = [IPinURL(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),\
               prefsuf(tldextract_output),subdomain(tldextract_output),tld(tldextract_output),\
               https_domain(tldextract_output),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)\
               ,certificate(tldextract_output),domain_age(whois_output), reg_length(whois_output)]
        # sum_row=np.sum(row)
        # non_zero=np.sum(row!=0)
        # variance=np.var(row)
        # row.append(sum_row)
        # row.append(non_zero)
        # row.append(variance)
        features[i] = row
        # already_visited[site]=row

        # print(row)

        print(url,i)

    return(features)




def get_test_features(urls):
    top_sites = pd.read_csv('top-1m.csv')
    top_count = top_sites['Domains'].count()

    features = np.zeros([urls.count(),17])
    already_analysed={}

    for i in range(urls.count()):
        url = urls[i]
        if not url.startswith("http"):
            url="https://"+url

        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix
        #Avoid duplication of work for repeat urls
        if site in already_analysed:
            features[i] = already_analysed[site]
            continue
            
        try:
            whois_output=whois.whois(url)
        except:
            whois_output=None


        row = [IPinURL(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),\
               prefsuf(tldextract_output),subdomain(tldextract_output),tld(tldextract_output),\
               https_domain(tldextract_output),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)\
               ,certificate(tldextract_output),domain_age(whois_output), reg_length(whois_output)]
        sum_row=np.sum(row)
        non_zero=np.count_nonzero(row)
        variance=np.var(row)
        row.append(sum_row)
        row.append(non_zero)
        row.append(variance)
        features[i] = row
        already_analysed[site]=row

        # print(row)

        print(url,i)

    return(features)
