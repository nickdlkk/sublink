import base64
import datetime
import json
import re
import urllib.parse

import requests
import yaml
from flask import Blueprint, request

from .model import *

blue = Blueprint('blue', __name__)
path = os.path.dirname(os.path.abspath(__file__))
subname_list = ['vless', 'vmess', 'ss', 'ssr', 'trojan', 'hysteria', 'hy2', 'hysteria2', 'http', 'https']
SkipCert = False
Udp = False
Emoji = False


def get_country_emoji(hostname):
    import socket
    # print(hostname)
    def is_valid_url(url):
        pattern = re.compile(r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$')
        return bool(pattern.match(url))

    ip = hostname
    if is_valid_url(ip):
        ip = socket.gethostbyname(hostname)
    response = requests.get(f"http://ipwho.is/{ip}")
    if response.status_code == 200:
        js = response.json()
        flag = js.get('flag')
        emoji = flag.get("emoji")
        # print(js)
        return emoji
    return hostname


def save_ip_address():  # 获取ip地址
    ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    params = {
        'ip': ip_address,
        'json': 'true'
    }
    res = requests.get('https://whois.pconline.com.cn/ipJson.jsp', params=params)
    # print(res.url)
    if res.status_code == 200:
        res_text = res.text
        if res_text:
            js = json.loads(res_text)
            timer = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
            address = js.get('addr')
            login = Login(ip=ip_address, address=address, time=timer)
            try:
                db.session.add(login)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                db.session.flush()
                print('错误信息:' + str(e))
            # print(res_text,type(js))
    # print(res.status_code)


def decode_base64_if_emoji(encoded_text):  # base64带emoji解码
    # 先解url编码
    encoded_text = urllib.parse.unquote(encoded_text)
    # 将字符串转换为字节流
    byte_text = encoded_text.encode('utf-8')
    # 使用Base64解码字节流
    decoded_bytes = base64.b64decode(byte_text)
    # 将字节流转换为文本
    decoded_text = decoded_bytes.decode('utf-8')
    return decoded_text


def if_ipv6_address(string):  # 判断ipv6
    pattern = r'\[([0-9a-fA-F:]+)\]'
    match = re.search(pattern, string)
    if match:
        ipv6_address = match.group(1)
        return ipv6_address
    else:
        return string


def decode_base64_if(text):  # base64解码
    try:
        name = ''
        decoded_text = text
        at = ''
        if '#' in decoded_text:
            name = '#' + decoded_text.split('#')[1]
            decoded_text = decoded_text.split('#')[0]
        if '@' in decoded_text:
            at = '@' + decoded_text.split('@')[1]
        padding = 4 - (len(decoded_text) % 4)
        # 判断是否需要补齐长度
        # print(decoded_text)
        if padding > 0 and padding < 4:
            # 添加填充字符
            decoded_text += "=" * padding

        decoded_text = base64.b64decode(decoded_text).decode('utf-8')
        # print('解：' + decoded_text)
        return decoded_text + at + name
    except Exception as e:
        # 如果无法解码为Base64，则返回原始文本
        # print(f'不是base64，错误信息：{str(e)}')
        return text


def clash_encode(subs):  # clash编码
    # 初始化 Clash 配置
    clash_config = {
        'proxies': [],
        'proxy-groups': []
    }
    proxy_name_list = []
    # 解析并添加节点到 Clash 配置
    for sub in subs:
        proxy_type = sub.node.split('://')[0]  # 节点类型
        proxy_test = sub.node  # 节点信息

        # print(proxy_type,proxy_test)
        def clash():
            if proxy_type == 'vless':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.vless()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'vmess':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.vmess()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'ss':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.ss()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'ssr':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.ssr()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'trojan':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.trojan()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'hysteria':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.hysteria()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'hy2' or proxy_type == 'hysteria2':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.hysteria2()
                clash_config['proxies'].append(proxy)
                proxy_name_list.append(proxy['name'])

        if proxy_type == 'http' or proxy_type == 'https':
            url = proxy_test
            response = requests.get(url)
            text = decode_base64_if(response.text)
            subs2 = text.split("\n")
            for sub2 in subs2:
                proxy_type = sub2.split("://")[0]
                proxy_test = sub2
                clash()
        else:
            clash()
    # 将 Clash 配置转为 YAML 格式
    with open(path + '/db/clash.yaml', 'r', encoding="UTF-8") as file:
        data = yaml.safe_load(file)
        data['proxies'] = clash_config['proxies']
        proxy_groups = data.get('proxy-groups')

        for proxy_group in proxy_groups:
            for proxies in proxy_group['proxies']:
                if proxies == 'auto':  # 判断是否包含auto字符串
                    proxy_group['proxies'].remove('auto')
                    for name_list in proxy_name_list:
                        proxy_group['proxies'].append(name_list)
            # print(proxy_group['proxies'])
        # print(data)
        clash_config_yaml = yaml.dump(data, sort_keys=False, allow_unicode=True)
        return clash_config_yaml


def surge_encode(subs):
    # 初始化 Clash 配置
    surge_config = {
        'proxy': [],
    }
    proxy_name_list = []
    # 解析并添加节点到 Clash 配置
    for sub in subs:
        proxy_type = sub.node.split('://')[0]  # 节点类型
        proxy_test = sub.node  # 节点信息

        def surge():
            if proxy_type == 'ss':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.ss()
                proxys = f"{proxy.get('name')} = ss, {proxy.get('server')}, {proxy.get('port')}, encrypt-method={proxy.get('cipher')}," \
                         f"password={proxy.get('password')}, tfo={proxy.get('tfo')}, udp-relay={proxy.get('udp')}"
                surge_config['proxy'].append(proxys)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'vmess':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.vmess()
                proxys = f"{proxy.get('name')} = vmess,{proxy.get('server')},{proxy.get('port')},username={proxy.get('uuid')}," \
                         f"tls={proxy.get('tls')},vmess-aead=true,skip-cert-verify={proxy.get('skip-cert-verify')},tfo={proxy.get('tfo')},udp-relay={proxy.get('udp')}"
                if proxy.get('network') == 'ws':
                    proxys += f",ws=true,ws-path={proxy['ws-opts']['path']},sni={proxy.get('server')}"
                    if proxy['ws-opts'].get('headers') != '' and proxy['ws-opts'].get('headers') != None:
                        proxys += f",ws-headers=Host:{proxy['ws-opts']['headers']['Host']}"
                surge_config['proxy'].append(proxys)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'trojan':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.trojan()
                proxys = f"{proxy.get('name')} = trojan,{proxy.get('server')},{proxy.get('port')},password={proxy.get('password')}," \
                         f"skip-cert-verify={proxy.get('skip-cert-verify')},tfo={proxy.get('tfo')},udp-relay={proxy.get('udp')}"
                if proxy.get('sni'):
                    proxys += f",sni={proxy['sni']}"
                if proxy.get('network') == 'ws':
                    proxys += f",ws=true,ws-path={proxy['ws-opts']['path']}"
                    if proxy['ws-opts'].get('headers') != '' and proxy['ws-opts'].get('headers') != None:
                        proxys += f",ws-headers=Host:{proxy['ws-opts']['headers']['Host']}"
                surge_config['proxy'].append(proxys)
                proxy_name_list.append(proxy['name'])
            if proxy_type == 'hy2' or proxy_type == 'hysteria2':
                node_parse = NodeParse()  # 创建 NodeParse 实例
                node_parse.proxy_test = proxy_test
                proxy = node_parse.hysteria2()
                proxys = f"{proxy.get('name')} = hysteria2,{proxy.get('server')},{proxy.get('port')},password={proxy.get('password')}," \
                         f"skip-cert-verify={proxy.get('skip-cert-verify')},udp-relay={proxy.get('udp')}"
                if proxy.get('sni'):
                    proxys += f",sni={proxy['sni']}"
                surge_config['proxy'].append(proxys)
                proxy_name_list.append(proxy['name'])

        if proxy_type == 'http' or proxy_type == 'https':
            url = proxy_test
            response = requests.get(url)
            text = decode_base64_if(response.text)
            subs2 = text.split("\n")
            for sub2 in subs2:
                proxy_type = sub2.split("://")[0]
                proxy_test = sub2
                surge()
        else:
            surge()
    config_file = path + '/db/surge.conf'

    def add_key_value_to_proxy(new_key_value):
        with open(config_file, 'r') as file:
            surge_config = file.read()
        # 找到 PROXY 节点的位置
        proxy_index = surge_config.find('[Proxy]')
        if proxy_index != -1:
            # 在 PROXY 节点的末尾添加新的键值对
            surge_config = surge_config[:proxy_index] + surge_config[proxy_index:].replace('[Proxy]',
                                                                                           f'[Proxy]\n{new_key_value}',
                                                                                           1)
        else:
            print("Proxy section not found in the configuration file.")

        return surge_config

    # 调用方法，传入配置文件路径和新的键值对
    config_text = add_key_value_to_proxy('\n'.join(surge_config['proxy']))
    autos = ','.join(proxy_name_list)
    config_text = re.sub('auto', autos, config_text)

    return config_text


class NodeParse():
    def __init__(self):
        # print('初始化')
        self.proxy_test = ''

    def vless(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        # print(f'测试{parse}')
        query = urllib.parse.parse_qs(parse.query)
        # print(query)
        for key, value in query.items():
            query[key] = value[0]
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)  # uuid@服务器:端口
        uuid = decode_base64_if(urlpath.split('@')[0])  # uuid
        proxy_name = urllib.parse.unquote(parse.fragment)  # url解码
        server_port = urlpath.split('@')[1]  # 服务器:端口
        server = if_ipv6_address(server_port.rsplit(':', 1)[0])  # 服务器
        if Emoji:
            proxy_name = get_country_emoji(server) + proxy_name
        port = server_port.rsplit(':', 1)[1]  # 端口
        # vless配置
        proxy = {
            'name': proxy_name,
            'type': 'vless',
            'uuid': uuid,
            'server': server,
            'client-fingerprint': 'chrome',
            'port': int(port),
            'network': query.get('type'),
            'udp': Udp,
            'skip-cert-verify': SkipCert,
            'tfo': False,
            'tls': True if query.get('security') else False,
        }
        # 替换规则
        if query.get('fp'):
            proxy['client-fingerprint'] = query.get('fp')
        if query.get('sni'):
            proxy['servername'] = query.get('sni')
        if query.get('flow'):
            proxy['flow'] = query.get('flow')
        if query.get('security') == 'reality':
            proxy['reality-opts'] = {
                'public-key': query.get('pbk')
            }
            sid = query.get('sid')
            if sid:
                proxy['reality-opts']['short-id'] = sid
        if query.get('type') == 'ws':
            proxy['ws-opts'] = {
                'path': query.get('path')
            }
            host = query.get('host')
            if host:
                proxy['ws-opts']['headers'] = {'Host': host}
        if query.get('cert'):
            if query.get('cert').lower() == 'true':
                proxy['skip-cert-verify'] = True
            else:
                proxy['skip-cert-verify'] = False
        return proxy

    def vmess(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        # parse = urllib.parse.urlparse(decode_base64_if(proxy_test))
        # print(f'测试{parse}')
        # print(f'类型{parse.query}')
        _SkipCert = SkipCert
        if parse.query != '':
            # print('非标准格式')
            query = urllib.parse.parse_qs(parse.query)
            info = decode_base64_if(parse.netloc)  # 加密方式:uuid@域名:端口
            for key, value in query.items():
                query[key] = value[0]
            name = query.get('remarks')
            uuid = info.split('@')[0].split(':')[1]
            server = info.split('@')[1].rsplit(':', 1)[0]
            port = int(info.split('@')[1].rsplit(':', 1)[1])
            aid = int(query.get('alterId'))
            cipher = info.split('@')[0].split(':')[0]
            network = 'ws' if query.get('obfs') == 'websocket' else ''
            tls = query.get('tls')
            pathA = query.get('path')
            host = query.get('obfsParam')
            if Emoji:
                name = get_country_emoji(server) + name
            if query.get('cert'):
                if query.get('cert').lower() == 'true':
                    _SkipCert = True
                else:
                    _SkipCert = False
            # print(server, port, network, uuid, tls)
        else:
            info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
            proxy = eval(decode_base64_if(info))
            name = proxy.get('ps')
            uuid = proxy.get('id')
            server = proxy.get('add')
            port = int(proxy.get('port'))
            aid = 0 if proxy.get('port') == "" else int(proxy.get('aid'))
            cipher = proxy.get('scy') if proxy.get('scy') else 'auto'
            network = proxy.get('net')
            tls = proxy.get('tls')
            pathA = proxy.get('path')
            host = proxy.get('host')
            if Emoji:
                name = get_country_emoji(server) + name

        proxys = {
            'name': name,
            'type': 'vmess',
            'uuid': uuid,
            'server': server,
            'port': port,
            'client-fingerprint': 'chrome',
            'tfo': False,  # 是否启用 TCP Fast Open
            'udp': Udp,
            'skip-cert-verify': _SkipCert,  # 是否跳过证书验证
            'alterId': aid,
            'cipher': cipher,
            'network': network,  # 代理的网络类型
            'tls': True if tls != 'none' and tls != '' else False
        }

        if network == 'ws':
            proxys['ws-opts'] = {
                'path': pathA,
            }
            # print(f'测试3{host}')
            if host != None and host != '':
                proxys['ws-opts']['headers'] = {
                    'Host': host
                }
        return proxys

    def ss(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)
        # print(f'测试{parse}')
        name = urllib.parse.unquote(parse.fragment)
        # print(urlpath)
        server = if_ipv6_address(urlpath.rsplit('@')[-1].rsplit(':', 1)[0])
        port = int(urlpath.rsplit('@')[-1].rsplit(':', 1)[1])
        index = urlpath.rfind("@")  # 找到最后一个 @ 符号的索引
        if Emoji:
            name = get_country_emoji(server) + name
        if index != -1:
            decode = decode_base64_if(urlpath[:index])
            # print('找到'+decode)
        else:
            decode = decode_base64_if(urlpath.split('@')[0])
            # print("未找到 @ 符号")
        # print(urlpath.split('@')[:-1])
        # decode = decode_base64_if(urlpath.split('@')[0])
        cipher = decode.split(':', maxsplit=2)[0]
        password = ':'.join(decode.split(':')[1:])
        # print(cipher, password)
        proxy = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': cipher,
            'password': password,
            'client-fingerprint': 'chrome',
            'tfo': False,
            'udp': Udp,
            'skip-cert-verify': SkipCert
        }
        return proxy

    def ssr(self):
        parse = urllib.parse.urlparse(self.proxy_test.replace('-', '+').replace('_', '/'))
        # print(f'测试{parse}')
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        # parse = urllib.parse.urlparse(decode_base64_if(proxy_test.replace('-', '+').replace('_', '/')))
        urlpath = decode_base64_if(info)
        query = urllib.parse.parse_qs(parse.query)
        port = int(urlpath.split(':')[1])
        protocol = urlpath.split(':')[2]
        cipher = urlpath.split(':')[3]
        obfs = urlpath.split(':')[4]
        server = if_ipv6_address(urlpath.split(':')[0])
        parse2 = urllib.parse.urlparse(urlpath.rsplit(':', 1)[1])
        password = decode_base64_if(parse2.path.replace('/', ''))
        query2 = urllib.parse.parse_qs(parse2.query)
        name = ""
        # print(query2.get('remarks'),query2 != '')
        if query.get('remarks'):
            name = decode_base64_if(query.get('remarks')[0])
        if query2.get('remarks'):
            name = decode_base64_if(query2.get('remarks')[0])
        if Emoji:
            name = get_country_emoji(server) + name
        proxy = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'protocol': protocol,
            'cipher': cipher,
            'obfs': obfs,
            'password': password,
            'udp': Udp,
            'skip-cert-verify': SkipCert
        }
        if query.get('cert'):
            if query.get('cert').lower() == 'true':
                proxy['skip-cert-verify'] = True
            else:
                proxy['skip-cert-verify'] = False
        return proxy

    def trojan(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        info = parse.netloc + parse.path if parse.path != '/' else parse.netloc
        urlpath = decode_base64_if(info)
        # print(f'测试{parse}')
        name = urllib.parse.unquote(parse.fragment)
        query = urllib.parse.parse_qs(parse.query)
        password = urlpath.split('@')[0]
        server = if_ipv6_address(urlpath.split('@')[1].rsplit(':', 1)[0])
        port = int(urlpath.split('@')[1].rsplit(':', 1)[1])
        if Emoji:
            name = get_country_emoji(server) + name
        proxy = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'client-fingerprint': 'chrome',
            'udp': Udp,
            'skip-cert-verify': SkipCert
        }
        for key, value in query.items():
            query[key] = value[0]
        if query.get('fp'):
            proxy['client-fingerprint'] = query.get('fp')
        if query.get('sni'):
            proxy['sni'] = query.get('sni')
        if query.get('flow'):
            proxy['flow'] = query.get('flow')
        if query.get('alpn'):
            proxy['alpn'] = query.get('alpn').split(",")
        if query.get('type'):
            if query.get('type') == 'ws':
                proxy['network'] = query.get('type')
                proxy['ws-opts'] = {
                    'path': query.get('path')
                }
                host = query.get('host')
                if host:
                    proxy['ws-opts']['headers'] = {'Host': host}
            if query.get('type') == 'grpc':
                proxy['network'] = query.get('type')
        if query.get('cert'):
            if query.get('cert').lower() == 'true':
                proxy['skip-cert-verify'] = True
            else:
                proxy['skip-cert-verify'] = False
        if query.get('serviceName'):
            #  grpc-opts:
            #       grpc-service-name: "example"
            proxy['grpc-opts'] = {
                'grpc-service-name': query.get('serviceName')
            }
        return proxy

    def hysteria(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        # parse = urllib.parse.urlparse(decode_base64_if(proxy_test))
        urlpath = decode_base64_if(parse.netloc)
        # print(f'测试{parse}')
        name = urllib.parse.unquote(parse.fragment)
        query = urllib.parse.parse_qs(parse.query)
        server = if_ipv6_address(urlpath.split(':')[0])
        port = int(urlpath.split(':')[1])
        if Emoji:
            name = get_country_emoji(server) + name
        proxy = {
            'name': name,
            'type': 'hysteria',
            'server': server,
            'port': port,
            'client-fingerprint': 'chrome',
            'protocol': 'udp',
            'udp': Udp,
            'skip-cert-verify': SkipCert
        }
        for key, value in query.items():
            query[key] = value[0]
        if query.get('auth'):
            proxy['auth_str'] = query.get('auth')
        if query.get('upmbps'):
            proxy['up'] = query.get('upmbps')
        if query.get('downmbps'):
            proxy['down'] = query.get('downmbps')
        if query.get('alpn'):
            proxy['alpn'] = [query.get('alpn')]
        if query.get('peer'):
            proxy['sni'] = query.get('peer')
        if query.get('cert'):
            if query.get('cert').lower() == 'true':
                proxy['skip-cert-verify'] = True
            else:
                proxy['skip-cert-verify'] = False
        return proxy

    def hysteria2(self):
        parse = urllib.parse.urlparse(self.proxy_test)
        # parse = urllib.parse.urlparse(decode_base64_if(proxy_test))
        urlpath = decode_base64_if(parse.netloc)
        # print(f'测试{parse}')
        name = urllib.parse.unquote(parse.fragment)
        query = urllib.parse.parse_qs(parse.query)
        password = urlpath.split('@')[0]
        server = if_ipv6_address(urlpath.split('@')[1].rsplit(':', 1)[0])
        port = int(urlpath.split('@')[1].rsplit(':', 1)[1])
        if Emoji:
            name = get_country_emoji(server) + name
        proxy = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'auth': password,
            'client-fingerprint': 'chrome',
            'udp': Udp,
            'skip-cert-verify': SkipCert
        }

        # proxy['skip-cert-verify'] = bool(query.get('cert', [str(SkipCert)])[0].capitalize())
        for key, value in query.items():
            query[key] = value[0]
        if query.get('sni'):
            proxy['sni'] = query.get('sni')
        if query.get('obfs') != 'none' and query.get('obfs') != None:
            proxy['obfs'] = query.get('obfs')
        if query.get('obfs-password'):
            proxy['obfs-password'] = query.get('obfs-password')
        if query.get('cert'):
            if query.get('cert').lower() == 'true':
                proxy['skip-cert-verify'] = True
            else:
                proxy['skip-cert-verify'] = False
        return proxy
