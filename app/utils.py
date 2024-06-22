import json

import requests


def get_address(ip):
    params = {
        'ip': ip,
        'json': 'true'
    }
    res = requests.get('https://whois.pconline.com.cn/ipJson.jsp', params=params)
    if res.status_code == 200:
        res_text = res.text
        if res_text:
            js = json.loads(res_text)
            address = js.get('addr')
            return address
