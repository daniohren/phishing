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

    features = np.zeros([urls.count(),25+3])
    already_visited={}
    
    for i in range(urls.count()):
        url = urls[i]
        
        tldextract_output = tldextract.extract(url)
        site = tldextract_output.subdomain + '.' + tldextract_output.domain + '.' + tldextract_output.suffix
        domain = whois.whois(tldextract_output.domain + '.' + tldextract_output.suffix)
        
        #Check if we've already ranked this site (then save some time and don't query)
        if site in already_visited:
            features[i] = already_visited[site]
            continue

        requests_output = requests.get(url)
        if requests_output.status_code != 200:
            row = [IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(tldextract_output),certificate(url,tldextract_output),0,\
            0,https_domain(tldextract_output),0,0,0,0,0,0,0,0,0,0,0,DNSRecord(domain),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)]
            sum_row=np.sum(row)
            non_zero=np.sum(row!=0)
            variance=np.var(row)
            row.append(sum_row)
            row.append(non_zero)
            row.append(variance)
            features[i] = row
            already_visited[site]=row
            
        else:
            page_source = requests_output.text
            soup = BeautifulSoup(page_source, "html.parser")
            row = [IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),\
                   prefsuf(url),subdomain(tldextract_output),certificate(url,tldextract_output),domain_reg_length(domain),favicon_domain(url,tldextract_output),\
                   https_domain(tldextract_output),request_url(url,soup),url_anchor(url,soup),links_in_tags(url,soup),sfh(url,soup,tldextract_output),\
                   mailto(soup),redirect(requests_output),on_mouseover(soup),rightclick(soup),popup(soup),\
                   Iframe(soup),domain_age(domain),DNSRecord(domain),website_traffic(top_sites,tldextract_output),statistical_report(url,tldextract_output)]
            sum_row=np.sum(row)
            non_zero=np.sum(row!=0)
            variance=np.var(row)
            row.append(sum_row)
            row.append(non_zero)
            row.append(variance)
            features[i] = row
            already_visited[site]=row
            
        print(url,': Completed')

    return(features)
