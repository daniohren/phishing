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
import statistics



def get_features(urls):
    top_sites = pd.read_csv('top-1m.csv')
    top_count = top_sites['Domains'].count()

    features = np.zeros([top_count,27])
    count=0
    already_visited={}
    
    for url in urls.iterrows():
        print(url)
        tldextract_output=tldextract.extract(url)
        site=tldextract_output.subdomain+'.'+tldextract_output.domain+'.'+tldextract_output.suffix
        domain=None
        domain_count=0
        while domain is None and count < 50:
            try:
                domain_count=domain_count+1
                domain=whois.whois(result.domain+'.'+result.suffix)
            except:
                pass


        # print(row)
        try:
            r = requests.get(url)
        except:
            row=[url,IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(url),certificate(url,domain),0,\
            0,https_domain(url),0,0,0,0,0,0,0,0,0,0,DNSRecord(url,domain),website_traffic(top_sites,url),statistical_report(url)]
            features=row[1:]
            Sum=sum(features)
            row.append(Sum)
            non_zero=0
            for entry in features:
                if not entry == 0:
                    non_zero=non_zero+1
            row.append(non_zero)
            variance=statistics.variance(features)
            row.append(variance)
            csv_writer.writerow(row)
            already_visited[site]=row
            continue

        #Check if we've already ranked this site (then save some time and don't query)
        if site in already_visited:
            csv_writer.writerow(already_visited[site])
            continue


        # print(r.status_code,type(r.status_code))
        #If can't access page then can't do live feature analysis
        if not r.status_code == 200:
            row=[url,IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(url),certificate(url,domain),0,\
            0,https_domain(url),0,0,0,0,0,0,0,0,0,0,DNSRecord(url,domain),website_traffic(top_sites,url),statistical_report(url)]
            continue

        else:
            page_source = r.text
            # html_page = urllib.request.urlopen(url)
            soup = BeautifulSoup(page_source, "html.parser")
            #top domains
            csv_file=open('top-1m.csv')
            csv_reader = csv.reader(csv_file, delimiter=',')
            top_sites=[]
            count=0
            for row in csv_reader:
                top_sites.append(row[1])
                count=count+1
                # if count==700000:
                #     print("finished")
                #     break;
            # print(type(r))

            row=[url,IP(url),length(url),shortened(url),at_symbol(url),redirect_slashes(url),prefsuf(url),subdomain(url),certificate(url,domain),domain_reg_length(url,domain),\
            favicon_domain(url),https_domain(url),request_url(url,soup),url_anchor(url,soup),links_in_tags(url,soup),sfh(url,soup),mailto(soup),redirect(r),on_mouseover(soup),\
            rightclick(soup),popup(soup),domain_age(url,domain),DNSRecord(url,domain),website_traffic(top_sites,url),statistical_report(url)]
            features=row[1:]
            Sum=sum(features)
            row.append(Sum)
            non_zero=0
            for entry in features:
                if not entry == 0:
                    non_zero=non_zero+1
            row.append(non_zero)
            variance=statistics.variance(features)
            row.append(variance)


        # print(row)

        # print(mailto(soup))

        count=count+1
        csv_writer.writerow(row)
        already_visited[site]=row



    return(features)
