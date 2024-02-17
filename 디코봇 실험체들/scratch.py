import discord
import asyncio
from datetime import datetime
import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import numpy as np
from tld import get_tld
import warnings
import whois
import tldextract
from whois.parser import PywhoisError
from ipwhois import IPWhois
import socket
import requests



warnings.filterwarnings(action='ignore') # FutureWarning 경고문 생략하기 위함. (아마 sklearn 버전 때문에 그런듯)

alexa_path = 'C:\\Users\\cile0\\Desktop\\AI 모델\\'
model_path = 'C:\\Users\\cile0\\Desktop\\AI 모델\\'

model = joblib.load(model_path + 'rf91.pickle')
alexa_10k = pd.read_csv(alexa_path + 'cloudflare-radar-domains-top-100000-20230821-20230828.csv')

TOKEN = 'MTE0NDg0NTEyNjc4NzY3ODI3OQ.G0ZDHv.3hrqZPm0MpwRHZt8iaCq-L6EfRWwNHfpcRcxDo'
CHANNEL_ID = '1143560639550341233'

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents = intents) # client = 디코 봇\

# Feature Engineering Refactoring
# 일괄 처리를 위한 함수화
def fd_length(parsedpath):
    try:
        tmp = parsedpath.split('/')[1]
    except:
        tmp = ''
    return len(tmp)

def feature_extract(urldata):
    def parsetest(url):
        try:
            urlparse(url if url[0:4] == 'http' else "//" + url)
            return True
        except:
            return False

    tmp = urldata['url'].apply(lambda i: parsetest(i))
    urldata = urldata[tmp == True]

    url = urldata['url'].apply(lambda i: i if i[0:4] == 'http' else "//" + i)
    parsed = url.apply(lambda i: urlparse(i))
    tld = url.apply(lambda i: get_tld(i, fail_silently=True))

    urldata['scheme'] = parsed.apply(lambda i: i.scheme)
    urldata['netloc'] = parsed.apply(lambda i: i.netloc)
    urldata['params'] = parsed.apply(lambda i: i.params)
    urldata['query'] = parsed.apply(lambda i: i.query)
    urldata['fragment'] = parsed.apply(lambda i: i.fragment)
    urldata['tld'] = tld
    # Length Feature
    # Length of URL
    urldata['url_length'] = urldata['url'].apply(lambda i: len(i))

    # Path Length
    urldata['path_length'] = parsed.apply(lambda i: len(i.path))

    # Count Feature
    # 특수문자
    special_symbols = ['-', '?', '.', '=', '/']
    for letter in special_symbols:
        urldata['count ' + letter] = urldata['url'].apply(lambda i: i.count(letter))

    # path부분의 /
    urldata['count_dir'] = parsed.apply(lambda i: i.path.count('/'))

    # Use of IP or not in domain
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:  # 존재
            # print match.group()
            return 1
        else:  # 없음
            # print 'No matching pattern found'
            return -1

    urldata['use_of_ip'] = urldata['url'].apply(lambda i: having_ip_address(i))

    # URL 속에 파일 확장자가 들어있는가?
    # 파일 확장자가 들어있으면 1 , 없으면 -1
    def url_has_file(url):
        match = re.search(
            '\.exe|\.zip|\.reg|\.rar|\.js|\.java|\.lib|\.log|\.bat|\.cmd|\.vbs|\.lnk|\.php|\.html|\.htm|\.hwp|\.hwpx|\.pptx|\.docx|\.iso|\.xls|\.xlsx',
            url)
        if match:
            return 1
        else:
            return -1

    urldata['url_has_file'] = urldata['url'].apply(lambda i: url_has_file(i))

    alexa_10k_list = []

    for i in alexa_10k.index.values:
        alexa_10k_list.append(alexa_10k['domain'][i])

    def dom_alexa_rank(url):
        ext = tldextract.extract(url)
        domain = ext.domain + '.' + ext.suffix
        if domain in alexa_10k_list:
            return 1
        else:
            return -1

    urldata['dom_alexa_rank'] = urldata['url'].apply(lambda i: dom_alexa_rank(i))

    # 각 URL의 엔트로피 계산
    def entropy(url):
        url = url.lower()  # 알파벳 개수 세야 해서 소문자로 통일
        url_dict = {}  # 알파벳 개수 중복 피해야 해서 일단 Dictionary 사용했음
        url_len = len(url)  # url 길이
        p_i = pp_i = entropy = 0
        # 위 공식 참고 , pp_i는 (p_i * log2(p_i)) 를 의미함
        for i in url:
            url_dict[i] = url.count(i)
        url_dict = list(url_dict.values())  # 원할하게 하려고 리스트로 바꿨음

        for j in url_dict:
            p_i = j / url_len
            pp_i = p_i * np.log2(p_i)
            entropy += pp_i
        return -(entropy)

    urldata['entropy'] = urldata['url'].apply(lambda i: entropy(i))

    # 검색량
    # def search_url_amount(url):
    # Daum_url='https://search.daum.net/search?w=tot&DA=YZR&t_nil_searchbox=btn&sug=&sugo=&sg=&o=&q='
    # strOri='&sm=tab_org&qvt=0'
    # response = requests.get(Daum_url + url +strOri)
    # getlen=len(response.text)
    # return getlen
    # urldata['search_url_amount'] = urldata['url'].apply(lambda i: search_url_amount(i))
    # 검색량 부분을 추가하니 5시간 돌려도 안끝나서 일단 주석처리
    return urldata

feature_columns = ['url_length','path_length', 'count -', 'count ?',
                   'count .', 'count =', 'count /', 'count_dir','url_has_file',
                    'entropy','use_of_ip','dom_alexa_rank']

def predict(url):
    new_url = pd.DataFrame({'url' : [url]})
    y_pred = feature_extract(new_url)
    y_pred = model.predict(y_pred[feature_columns])
    return y_pred[0]

# 여기까지 모델 관련 함수

def check_url(url): # 파라미터에는 파싱된 URL을 넣을 계획. URL인가 아닌가

    has_http = re.search('http://', url)
    has_https = re.search('https://', url)
    has_www = re.search('www.', url)
    is_short = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
        'tr\.im|link\.zip\.net', url)
    # url_extract = tldextract.extract(url)
    # extracted_domain = url_extract.domain + '.' + url_extract.suffix
    # http, www를 가지지 않은 url일 수도 있으니

    if has_http or has_https or has_www or is_short:
        return True
    # elif re.match(extracted_domain,url):
    #     return True
    else:
        return False

def parsing_message(message): # 메세지의 공백, 한글을 없앤 부분들을 리스트로 모아 반환
    # target_message = [] # 각 메세지의 공백과 한글을 뺀 리스트
    parsed_message = [] # 그 중에서 URL만 뽑은 리스트

    korean = re.compile('[\u3131-\u3163\uac00-\ud7a3]+') # 한글
    space_special = re.compile('\s+[!@#$%^&*()_+{}[\]:;<>,.?~\\-]+') # 빈칸+특수문자
    special_space = re.compile('[!@#$%^&*()_+{}[\]:;<>,.?~\\-]+\s') # 특수문자+빈칸

    remove_korean_message = re.sub(korean, '', message) # message에서 한글을 빼고
    remove_korean_special_message = re.sub(space_special,'', remove_korean_message) # 거기서 또 빈칸+특수문자를 빼고
    remove_final_message = re.sub(special_space,'', remove_korean_special_message) # 거기서 또 특수문자+빈칸을 빼서

    parsed_message = remove_final_message.split() # split해서 target_message에 집어 넣고


    return parsed_message

def whois_api_info(url): # WHOIS 및 IPWHOIS api를 이용해 해당 도메인에 대한 정보 제공
    info_dic = {}
    error_list = []
    try:
        parse = tldextract.extract(url)
        domain = parse.subdomain + '.' + parse.domain + '.' + parse.suffix
        domain_info = whois.whois(domain)
        ipaddress = socket.gethostbyname(domain)
        ip_info = IPWhois(ipaddress)
        info_info = ip_info.lookup_whois()
        info_details = info_info['nets'][0]

        domain_name = domain_info.domain_name
        info_dic['도메인 이름'] = domain_name
        info_dic['IP'] = ipaddress
        info_dic['기관명'] = info_details['description']
        info_dic['국가'] = info_details['country']
        info_dic['주소'] = info_details['address']

        return info_dic
        # info_dic  = {도메인 이름 : 도메인 , IP : IP , IP 주인 : name , 국가 : 국가코드 , 주소 : IP주소}

    except PywhoisError as e: # Whois 조회 중 에러가 발생할 경우 예외 처리
        error_list.append(f'! WHOIS 데이터베이스에 존재하지 않는 도메인입니다. ! 주의를 요합니다 !')
        return error_list

    except UnicodeError as u: # Socket 모듈을 통해 IP 조회 중 에러가 발생할 경우 예외 처리
        error_list.append(f"! 정상적이지 않은 URL이거나, SHORT URL 입니다 ! ! 주의를 요합니다 !")
        return error_list

    except socket.gaierror as s:
        error_list.append(f"! 정상적이지 않은 URL이거나, SHORT URL 입니다 ! ! 주의를 요합니다 !")
        return error_list

def search_url(url):
    Daum_url = 'https://search.daum.net/search?w=tot&DA=YZR&t_nil_searchbox=btn&sug=&sugo=&sg=&o=&q='
    strOri = '&sm=tab_org&qvt=0'
    response = requests.get(Daum_url + url + strOri)
    return response.text

def similar_url_check(url): # 주 도메인 부분에서 오타가 날 경우 검색어 정정
    if url not in '//':
        url = '//' + url
    url_search_result = search_url(urlparse(url).netloc)
    i = 0
    for text in list(url_search_result.split(' ')):
        if ('desc_info') in text:
            i = 1
        if i == 1:
            if ('</a>') in text:
                return text[text.find('>') + 1:text.find('<')]
                i = 0
    return -1





@client.event
async def on_ready(): # 봇 가동
    print(client.user.name)
    print('제돈햄칼 2호기 준비 완료')

@client.event
async def on_message(message): # 채널의 채팅에 대한 함수
    if message.author == client.user:
        return  # client는 디스코드 봇. -> 자기 자신의 채팅에는 함수가 반응 하지 않음.
    content = str(message.content)
    if check_url(content): # 메세지 전체에 url이 있다?
        for url in parsing_message(content): # 메세지에서 공백, 한글 빼고 리스트에 저장
            if check_url(url): # 그 안에서도 url이 있다?
                if predict(url) == 'benign': # 정상이면
                    emoji = '\N{baby angel}'
                    await message.add_reaction(emoji) # 천사 이모지로 반응

                    try:
                        await message.channel.send(f'{message.author.mention}님!  '
                                                   f'입력 하신 URL {url} 는\n'
                                                   f'*****정상 사이트***** 입니다!\n\n'
                                                   f'***================================***')
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n도메인 이름: {whois_api_info(url)["도메인 이름"]}\n'
                                                   f'해당 도메인의 IP: {whois_api_info(url)["IP"]}\n'
                                                   f'기관명: {whois_api_info(url)["기관명"]}\n'
                                                   f'국가 코드: {whois_api_info(url)["국가"]}\n'
                                                   f'세부 주소: {whois_api_info(url)["주소"]}\n\n'
                                                   f'***================================***')
                    except TypeError as t: # whois_api_info 함수에서 예외 처리되는 경우
                        emoji = '\N{warning sign}'
                        await message.add_reaction(emoji)  # 에러일 경우 주의 이모지로 반응
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n'
                                                   f'{whois_api_info(url)}\n\n'
                                                   f'***================================***')

                elif predict(url) == 'phishing':
                    emoji = '\N{imp}'
                    url_similar = similar_url_check(url) # 도메인 오타 정정 함수 (피싱 사이트들이 사례가 많아 우선 피싱에만 넣어놓음)
                    if url_similar != -1:
                        print(url_similar)
                    await message.add_reaction(emoji) # 악성들은 악마 이모지로 통일

                    try:
                        await message.channel.send(f'{message.author.mention}님!  '
                                                   f'입력 하신 URL {url} 는\n'
                                                   f'!!*****피싱 사이트*****!! 입니다\n\n'
                                                   f'***================================***')
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n도메인 이름: {whois_api_info(url)["도메인 이름"]}\n'
                                                   f'해당 도메인의 IP: {whois_api_info(url)["IP"]}\n'
                                                   f'기관명: {whois_api_info(url)["기관명"]}\n'
                                                   f'국가 코드: {whois_api_info(url)["국가"]}\n'
                                                   f'세부 주소: {whois_api_info(url)["주소"]}\n\n'
                                                   f'!!사이트의 정보가 주어져도 공격 받을 수 있음을 주의하세요!!\n\n'
                                                   f'***================================***')
                    except TypeError as t:
                        emoji = '\N{warning sign}'
                        await message.add_reaction(emoji)  # 에러일 경우 주의 이모지로 반응
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n'
                                                   f'{whois_api_info(url)}\n\n'
                                                   f'***================================***')
                elif predict(url) == 'defacement':
                    emoji = '\N{imp}'
                    await message.add_reaction(emoji)

                    try:
                        await message.channel.send(f'{message.author.mention}님!  '
                                                   f'입력 하신 URL {url} 는\n'
                                                   f'!!*****위조/변조된 사이트*****!! 입니다\n\n'
                                                   f'***================================***')
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n도메인 이름: {whois_api_info(url)["도메인 이름"]}\n'
                                                   f'해당 도메인의 IP: {whois_api_info(url)["IP"]}\n'
                                                   f'기관명: {whois_api_info(url)["기관명"]}\n'
                                                   f'국가 코드: {whois_api_info(url)["국가"]}\n'
                                                   f'세부 주소: {whois_api_info(url)["주소"]}\n\n'
                                                   f'!!사이트의 정보가 주어져도 공격 받을 수 있음을 주의하세요!!\n\n'
                                                   f'***================================***')
                    except TypeError as t:
                        emoji = '\N{warning sign}'
                        await message.add_reaction(emoji)  # 에러일 경우 주의 이모지로 반응
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n'
                                                   f'{whois_api_info(url)}\n\n'
                                                   f'***================================***')
                elif predict(url) == 'spam':
                    emoji = '\N{imp}'
                    await message.add_reaction(emoji)

                    try:
                        await message.channel.send(f'{message.author.mention}님!  '
                                                   f'입력 하신 URL {url} 는\n'
                                                   f'!!*****스팸 사이트*****!! 입니다\n\n'
                                                   f'***================================***')
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n도메인 이름: {whois_api_info(url)["도메인 이름"]}\n'
                                                   f'해당 도메인의 IP: {whois_api_info(url)["IP"]}\n'
                                                   f'기관명: {whois_api_info(url)["기관명"]}\n'
                                                   f'국가 코드: {whois_api_info(url)["국가"]}\n'
                                                   f'세부 주소: {whois_api_info(url)["주소"]}\n\n'
                                                   f'!!사이트의 정보가 주어져도 공격 받을 수 있음을 주의하세요!!\n\n'
                                                   f'***================================***')
                    except TypeError as t:
                        emoji = '\N{warning sign}'
                        await message.add_reaction(emoji)  # 에러일 경우 주의 이모지로 반응
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n'
                                                   f'{whois_api_info(url)}\n\n'
                                                   f'***================================***')
                elif predict(url) == 'malware':
                    emoji = '\N{imp}'
                    await message.add_reaction(emoji)

                    try:
                        await message.channel.send(f'{message.author.mention}님!  '
                                                   f'입력 하신 URL {url} 는\n'
                                                   f'!!*****악성 프로그램이 포함된 사이트*****!! 입니다\n\n'
                                                   f'***================================***')
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n도메인 이름: {whois_api_info(url)["도메인 이름"]}\n'
                                                   f'IP: {whois_api_info(url)["IP"]}\n'
                                                   f'기관명: {whois_api_info(url)["기관명"]}\n'
                                                   f'국가 코드: {whois_api_info(url)["국가"]}\n'
                                                   f'세부 주소: {whois_api_info(url)["주소"]}\n\n'
                                                   f'!!사이트의 정보가 주어져도 공격 받을 수 있음을 주의하세요!!\n\n'
                                                   f'***================================***')
                    except TypeError as t:
                        emoji = '\N{warning sign}'
                        await message.add_reaction(emoji)  # 에러일 경우 주의 이모지로 반응
                        await message.channel.send(f'\n\n**해당 사이트에 대한 정보**\n'
                                                   f'{whois_api_info(url)}\n\n'
                                                   f'***================================***')


                print(f'{url} : {predict(url)}') # 터미널에 URL의 로그를 남기기 위한 print 함수




client.run(TOKEN)