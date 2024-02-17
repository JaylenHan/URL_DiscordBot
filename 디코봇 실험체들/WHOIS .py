import whois
from urllib.parse import urlparse
import tldextract
from whois.parser import PywhoisError
from ipwhois import ipwhois

info_list = []
try:
    url = 'https://www.naver.com'
    parse = tldextract.extract(url)
    domain = parse.subdomain + '.' + parse.domain + '.' + parse.suffix
    info = whois.whois(domain)
    domain_name = info.domain_name,
    domain_country = info.country
    info_list.extend([domain_name , domain_country])
    print(info_list)

except PywhoisError as e:
    print('한국 Whois 데이터베이스에 존재하지 않는 URL입니다. 외국 사이트거나 악성 사이트이니 주의를 요합니다!',e)
