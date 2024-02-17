import whois
from urllib.parse import urlparse
import tldextract
from ipwhois import IPWhois
from whois.parser import PywhoisError
import socket
ip_info_list = []
#먼저 socket을 통해 ip를 알아내야 함.
try:
    url = ('https://infura-ipfs.io/ipfs/QmRMc1gh96QhP1BKxp6i4FUayui1h2TdPFueuf2dHzTXXd/jooochogwindidi2.html')
    parsing_domain = tldextract.extract(url)
    real_domain = parsing_domain.subdomain +'.'+ parsing_domain.domain +'.'+ parsing_domain.suffix
    ipaddress = socket.gethostbyname(real_domain)
    ip_info = IPWhois(ipaddress)
    info_info = ip_info.lookup_whois()
    info_details = info_info['nets'][0]
    ip_info_list.extend([ipaddress,info_details['name'],info_details['country'],info_details['address']])


except UnicodeError as e: # shortURL일 경우 or 각 도메인의 파싱이 불가능할 경우
    print("정상적이지 않은 URL이거나, SHORT URL 입니다.")

# print(info_details)