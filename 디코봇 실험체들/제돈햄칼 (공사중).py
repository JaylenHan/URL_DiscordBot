import discord
import asyncio
from datetime import datetime
import re
from urllib.parse import urlparse

TOKEN = 'MTE0NDg0NTEyNjc4NzY3ODI3OQ.G0ZDHv.3hrqZPm0MpwRHZt8iaCq-L6EfRWwNHfpcRcxDo'
CHANNEL_ID = '1143560639550341233'

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents = intents) # 디코봇을 의미


def check_url(url):
    tld_list = []
    has_http = re.search('http://', url)
    has_https = re.search('https://', url)
    has_www = re.search('www.', url)
    has_short = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
        'tr\.im|link\.zip\.net', url)
    if has_http or has_https or has_www or has_short:
        return True
    else:
        return False

@client.event
async def on_ready():
    print(client.user.name)
    print('제돈햄칼 2호기 준비 완료')

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if message.content == '!검사':
        await message.channel.send('검사를 입력합니다. URL을 입력해주세요.')
        try:
            user_response = await client.wait_for(
                'message',
                timeout=30,
                check=lambda msg: msg.author == message.author and msg.channel == message.channel
            )

            if check_url(user_response.content):
                await message.channel.send('정상입니다!')
            else:
                await message.channel.send('악성입니다! 물러서세요!')
        except asyncio.TimeoutError:
            await message.channel.send('시간 초과입니다. 검사를 다시 시작하세요.')


client.run(TOKEN)