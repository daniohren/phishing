import csv
import pandas as pd
import tldextract
import re
import whois
import numpy as np
from IPy import IP
import math


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
    try:
        ip_public_filter = IP(ip)
        #If not a valid IP then return true as not suspicious
    except:
        return True
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


def tld(tldextract_output,tld_dict):


    # if df['tld'].str.contains(tldextract_output.suffix).any():
    if tldextract_output.suffix in tld_dict.keys():
        return -tld_dict[tldextract_output.suffix]
    else:
         return -0.5


def url_length(url):
    return -(len(url))/100

def subdomain_length(url,tldextract_output):
    len_fqdn=len(tldextract_output.subdomain)+len(tldextract_output.domain)+len(tldextract_output.suffix)
    len_path=len(url)-len_fqdn
    return -len_path/100

def length_ratio(url,tldextract_output):
    len_fqdn=len(tldextract_output.subdomain)+len(tldextract_output.domain)+len(tldextract_output.suffix)
    len_path=len(url)-len_fqdn
    ratio=len(url)/len_path
    return -ratio

def shortened(url):
    shorteners=["bit.ly", "goo.gl", "tinyurl","ow.ly","bit.do"]
    for string in shorteners:
        if string in url:
            # print("shortener")
            return -1
    return 1

def at_symbol(url):
    return -url.count('@')

def redirect_slashes(url):
    url=url[8:]
    if "//" in url:
        # print("redirect slashes")
        return -1
    return 1

def prefsuf(url):
    return -url.count('-')

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

def other_suffix(url,tldextract_output):
    suffix=tldextract_output.suffix
    removed_suffix_url = url.replace(suffix,"")
    impersonate_suffixes=[".com", ".org", ".co.uk", ".edu"]
    for string in impersonate_suffixes:
        if string in removed_suffix_url:
            return -1
    return 1



def entropy(string):
        "Calculates the Shannon entropy of a string"

        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return -entropy/5

def nan_entropy(url):
    nans={'/':0.275,'.':0.225,'-':0.14,'=':0.11,';':0.07,'?':0.06,'_':0.05,'%':0.03,'&':0.027,'@':0.025,':':0.01,'~':0.008,'+':0.007,'!':0.006,',':0.004,')':0.001,'}':0.001,']':0.001,'(':0.001,'[':0.001,'{':0.001,'$':0.0001,'#':0.0001,'*':0.0001}
    nan_entropy=0
    for letter in url:
        if letter in nans:
            p=nans[letter]
            nan_entropy=nan_entropy+(p*math.log2(p))
    return nan_entropy
#
# def num_nums(url):
#     nums=0
#     for character in url:
#         if character.isdigit():
#             nums=nums+1
#     return nums



def certificate(tldextract_output):

    #Check when ssl certificate is valid until and who issued it
    if tldextract_output.subdomain=="":
        domain=tldextract_output.domain+'.'+tldextract_output.suffix
    else:
        domain=tldextract_output.subdomain + '.' + tldextract_output.domain+'.'+tldextract_output.suffix
    try:
        setdefaulttimeout(3)
        cert=ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer=str(x509.get_issuer())
        if "Let's Encrypt" in issuer:
            return 0
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


def https_url(url):
    url_stripped=url
    if url.startswith("https"):
        url_stripped = url[4:]
    if url.startswith("http"):
        url_stripped = url[3:]
    if "https" in url_stripped:
        # print("https in domain")
        return -1
    return 1

def suspicious_word_count(url):
    words=["confirm","account","secure","webscr","login","signin","submit","update","logon","secure","wp","cmd","admin"]
    count=0
    for word in words:
        if word in url:
            count=count+1
    return -count

def free_hosting(url):
    #Free web hosts as identified: https://blackbackhacker.blogspot.com/2012/09/free-hosting-sites-for-phishers.html
    hosts=["000webhost","weebly","Hostinger","InfinityFree","FreeHosting","FreeHostia","awardspace","t35hosting","webnode","wix","site123","wordpress","strikingly","jimdo","simplesite","mozello","blogspot"]
    for host in hosts:
        if host in url:
            return -1
    return 1


def website_traffic(top_sites,tldextract_output):
    if top_sites['Domains'].str.contains(tldextract_output.domain + '.' + tldextract_output.suffix).any():
        return 1
    return -1



def statistical_report(url,tldextract_output):
#These domains have been most frequently hosted for phishing in recent phishtank data.
    topdomains=["docs.google.com","storage.googleapis.com","firebasestorage.googleapis.com","cheaproomsvalencia.com","playarprint.com",\
    "forms.office.com","bit.ly","sites.google.com","ivanidzakovic.com","drive.google.com","forms.gle","codesandbox.io",".sharepoint.com","onedrive.live.com",\
    "advonationusa.com","infopublishersassociation.com","vmorefraud.com","stolizaparketa.ru","mytanfarma.com","zohard.com","southcountyclassified.com","tptelecom","tinyurl.com"]

    for domain in topdomains:
        if domain in url:
            # print("phish report")
            return -1
    return 1


def get_train_features(urls):
    top_sites = pd.read_csv('top-1h.csv')

    features = np.zeros([urls.count(),18])
    df = pd.read_excel('spamhaus_13052020.xlsx')
    tld_dict=df.set_index('tld')['score'].to_dict()
    # already_visited={}

    for i in range(urls.count()):
        url = urls[i]
        if not url.startswith("http"):
            url="http://"+url

        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix



        row = [IPinURL(url),url_length(url),subdomain_length(url,tldextract_output),length_ratio(url,tldextract_output),shortened(url),at_symbol(url),redirect_slashes(url),\
               prefsuf(url),subdomain(tldextract_output),other_suffix(url,tldextract_output),entropy(url),nan_entropy(url),tld(tldextract_output,tld_dict),\
               https_url(url),suspicious_word_count(url),free_hosting(url),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)]


        features[i] = row
        # already_visited[site]=row

        # print(row)
        # print(row)
        if i%100==0:
            print(i)
        # print(i,row)

    return(features)




def get_test_features(urls):
    top_sites = pd.read_csv('top-1h.csv')


    features = np.zeros([urls.count(),21])
    df = pd.read_excel('spamhaus_13052020.xlsx')
    tld_dict=df.set_index('tld')['score'].to_dict()


    for i in range(urls.count()):
        url = urls[i]
        if not url.startswith("http"):
            url="https://"+url

        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix



        row = [IPinURL(url),url_length(url),subdomain_length(url,tldextract_output),length_ratio(url,tldextract_output),shortened(url),at_symbol(url),redirect_slashes(url),\
               prefsuf(url),subdomain(tldextract_output),other_suffix(url,tldextract_output),entropy(url),nan_entropy(url),tld(tldextract_output,tld_dict),\
               https_url(url),suspicious_word_count(url),free_hosting(url),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)]


        sum_row=np.sum(row)
        non_zero=np.count_nonzero(row)
        variance=np.var(row)
        row.append(sum_row)
        row.append(non_zero)
        row.append(variance)
        features[i] = row


        print(url,i)

    return(features)
