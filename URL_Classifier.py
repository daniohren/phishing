import csv
import pandas as pd
import numpy as np
from classifiers import *
import urllib.request
import tldextract
from bs4 import BeautifulSoup
import re
import urllib.request
import whois



def get_features(urls):
    top_sites = pd.read_csv('top-1m.csv')
    top_count = top_sites['Domains'].count()

    features = np.zeros([top_count,25+3])
    already_visited={}
    
    for i in range(urls['Urls'].count()):
        url = urls['Urls'][i]
        print(url)
        
        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix
        domain = whois.whois(tldextract_output.domain + '.' + tldextract_output.suffix)
        
        #Check if we've already ranked this site (then save some time and don't query)
        if site in already_visited:
            features[i] = already_visited[site]
            continue

        requests_output = requests.get(url)
        if requests_output.status_code != 200:
            [IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(url),certificate(url,domain),0,\
            0,https_domain(url),0,0,0,0,0,0,0,0,0,0,DNSRecord(url,domain),website_traffic(top_sites,url),statistical_report(url)]
            print(row)
            sum_row=sum(row)
            non_zero=sum(row!=0)
            variance=np.var(features)
            row.append(sum_row)
            row.append(non_zero)
            row.append(variance)
            features[i] = row
            already_visited[site]=row
            
        else:
            page_source = requests_output.text
            soup = BeautifulSoup(page_source, "html.parser")
            row = [IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(url),certificate(url,domain),domain_reg_length(url,domain),\
 favicon_domain(url),https_domain(url),request_url(url,soup),url_anchor(url,soup),links_in_tags(url,soup),sfh(url,soup),mailto(soup),redirect(requests_output),on_mouseover(soup),\
            rightclick(soup),popup(soup),domain_age(url,domain),DNSRecord(url,domain),website_traffic(top_sites,url),statistical_report(url)]
            print(row)
            sum_row=np.sum(row)
            non_zero=np.sum(row!=0)
            variance=np.var(features)
            row.append(sum_row)
            row.append(non_zero)
            row.append(variance)
            features[i] = row
            already_visited[site]=row

    return(features)