#!/usr/bin/env python3
# ========== User Configs Begin ==========
# 以下是可以自定义的配置：
STOP = False              # 暂停抓取节点
NAME_SHOW_TYPE = False    # 在节点名称前添加如 [Vmess] 的标签
NAME_NO_FLAGS  = False    # 将节点名称中的地区旗帜改为文本地区码
NAME_SHOW_SRC  = False    # 在节点名称前显示所属订阅编号 (订阅见 list_result.csv)
ABFURLS = (           # Adblock 规则黑名单
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    # "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    # "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
    # "https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt",
    # "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    # "https://anti-ad.net/adguard.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    # "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    # "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_lite.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/domain.txt",
)
ABFWHITE = (          # Adblock 规则白名单
    "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///./abpwhite.txt",
)
# ========== User Configs End ==========

# pyright: reportConstantRedefinition = none
# pyright: reportMissingTypeStubs = none
# pyright: reportRedeclaration = none
# pyright: reportMissingParameterType = none
# pyright: reportUnnecessaryIsInstance = none
# pyright: reportUnknownVariableType = none
# pyright: reportUnknownMemberType = none
# pyright: reportUnknownArgumentType = none
# pyright: reportArgumentType = none
# pyright: reportAttributeAccessIssue = none
# pyright: reportGeneralTypeIssues = none
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse, parse_qs
import requests
from requests_file import FileAdapter
import datetime
import traceback
import binascii
import threading
import sys
import os
import copy
import unicodedata
import re
from types import FunctionType as function
from typing import Set, List, Dict, Union, Callable, Any, Optional, Iterable, TypedDict

try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else:
    if not PROXY: PROXY = None
    LOCAL = not PROXY

def b64encodes(s: str):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def b64decodes_safe(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def normpath(url: str):
    if url.startswith('file://'):
        basedir = os.path.dirname(os.path.abspath(__file__))
        return url.replace('/./', '/'+basedir.lstrip('/').replace(os.sep, '/')+'/')
    return url

DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH: Dict[str, str] = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_TEMPLATE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

FAKE_IPS = "8.8.8.8; 8.8.4.4; 4.2.2.2; 4.2.2.1; 114.114.114.114; 127.0.0.1; 0.0.0.0".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

FETCH_TIMEOUT = (6, 5)

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8g5L2/5YqyIOWKsiDliqrlipsg5Yqg5rK5IOWlsyDmnYMg6L+Q5YqoIG9uZ3RhaXdhbg==').split()

# !!! JUST FOR DEBUGING !!!
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_DYNAMIC = os.path.exists("local_NO_DYNAMIC")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

STOP_FAKE_NODES = """vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NjU0Rlx1NjExRlx1NjVGNlx1NjcxRlx1RkYwQ1x1NjZGNFx1NjVCMFx1NjY4Mlx1NTA1QyIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjEiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NTk4Mlx1NjcwOVx1OTcwMFx1ODk4MVx1RkYwQ1x1ODFFQVx1ODg0Q1x1NjQyRFx1NUVGQSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjIiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NUU4Nlx1Nzk1RFx1NEUyRFx1NTZGRFx1NTE3MVx1NEVBN1x1NTE1QVx1NjIxMFx1N0FDQjEwNVx1NTQ2OFx1NUU3NFx1RkYwMSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjMiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
"""

d = datetime.datetime.now()
if STOP or ((d.month, d.day) in ((6, 4), (7, 1), (10, 1)) and not (LOCAL or PROXY)):
    DEBUG_NO_NODES = DEBUG_NO_DYNAMIC = STOP = True
    NAME_SHOW_TYPE = NAME_NO_FLAGS = NAME_SHOW_SRC = False
    BANNED_WORDS = []

session = requests.Session()
session.trust_env = False
if PROXY and not PROXY == 'NONE':
    session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.4.2 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
session.mount('file://', FileAdapter())

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

class Node:
    gNames: Set[str] = set()
    class DATA_TYPE(TypedDict):
        name: str
        type: str
        server: str
        port: int

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: Node.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else: raise TypeError(f"Got {type(data)}")
        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.names: Set[str] = {self.data['name']}

    def __str__(self):
        return self.url

    def __hash__(self):
        data = self.data
        try:
            path = ""
            if self.type == 'vmess':
                net: str = data.get('network', '')
                path = net+':'
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'h2':
                    opts: Dict[str, Any] = data.get('h2-opts', {})
                    path += ','.join(opts.get('host', []))
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'ss':
                opts: Dict[str, Any] = data.get('plugin-opts', {})
                path = opts.get('host', '')
                path += '/'+opts.get('path', '')
            elif self.type == 'ssr':
                path = data.get('obfs-param', '')
            elif self.type == 'trojan':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'vless':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'hysteria2':
                path = data.get('sni', '')+':'
                path += data.get('obfs-password', '')+':'
            path += '@'+','.join(data.get('alpn', []))+'@'+data.get('password', '')+data.get('uuid', '')
            hashstr = f"{self.type}:{data['server']}:{data['port']}:{path}"
            return hash(hashstr)
        except Exception:
            print("节点 Hash 计算失败！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return hash(self.url)

    def __eq__(self, other: Union['Node', Any]):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    @staticmethod
    def urlparse(url: str, scheme='', allow_fragments=True):
        if allow_fragments and '#' in url:
            segs = url.split('#')
            fragment = segs[-1]
            url = '#'.join(segs[:-1])
        else:
            fragment = None
        res = urlparse(url, scheme, allow_fragments=False)
        if fragment:
            res = res._replace(fragment=fragment)
        return res

    def load_url(self, url: str):
        try: self.type, dt = url.split("://", 1)
        except ValueError: raise NotANode(url)
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        if self.type == 'hy2': self.type = 'hysteria2'
        # === Fix end ===
        loader: Optional[Callable[[str, str], None]] = \
                getattr(self, '_load_'+self.type, None)
        if loader: loader(url, dt)
        else: raise UnsupportedType(self.type)
        if ('server' in self.data and ':' in self.data['server'] and 
                not self.data['server'].startswith('[')):
            # Fix IPv6
            self.data['server'] = f"[{self.data['server']}]"

    def _load_vmess(self, url: str, dt: str):
        v = VMESS_TEMPLATE.copy()
        try: v.update(json.loads(b64decodes(dt)))
        except Exception:
            raise UnsupportedType('vmess', 'SP')
        self.data = {}
        for key, val in v.items():
            if key in VMESS2CLASH:
                self.data[VMESS2CLASH[key]] = val
        self.data['tls'] = (v['tls'] == 'tls')
        self.data['alterId'] = int(self.data['alterId'])
        if v['net'] == 'ws':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['headers'] = {'Host': v['host']}
            self.data['ws-opts'] = opts
        elif v['net'] == 'h2':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['host'] = v['host'].split(',')
            self.data['h2-opts'] = opts
        elif v['net'] == 'grpc' and 'path' in v:
            self.data['grpc-opts'] = {'grpc-service-name': v['path']}

    def _load_ss(self, url: str, dt: str):
        info = dt.split('@')
        srvname = info.pop()
        if '#' in srvname:
            srv, name = srvname.split('#')
        else:
            srv = srvname
            name = ''
        segs = srv.split(':')
        port = segs[-1]
        server = ':'.join(segs[:-1])
        try:
            port = int(port)
        except ValueError:
            raise UnsupportedType('ss', 'SP')
        info = '@'.join(info)
        if not ':' in info:
            try:
                info = b64decodes_safe(info)
            except Exception:
                raise UnsupportedType('ss', 'SP')
        # ====== 修复：使用 rsplit 避免密码中包含 ':' ======
        if ':' in info:
            cipher, passwd = info.rsplit(':', 1)   # 从右侧分割，只分割一次
        else:
            cipher = info
            passwd = ''
        self.data = {'name': unquote(name), 'server': server,
                'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

    def _load_ssr(self, url: str, dt: str):
        # TODO: IPv6 server support
        if '?' in url:
            parts = dt.split(':')
        else:
            parts = b64decodes_safe(dt).split(':')
        try:
            passwd, info = parts[-1].split('/?')
        except: raise
        passwd = b64decodes_safe(passwd)
        self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                'password': passwd, 'name': ''}
        for kv in info.split('&'):
            k_v = kv.split('=', 1)
            if len(k_v) != 2:
                k = k_v[0]
                v = ''
            else: k,v = k_v
            if k == 'remarks':
                self.data['name'] = v
            elif k == 'group':
                self.data['group'] = v
            elif k == 'obfsparam':
                self.data['obfs-param'] = v
            elif k == 'protoparam':
                self.data['protocol-param'] = v

    def _load_trojan(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)}
        if not parsed.query: return
        # ====== 使用 parse_qs 处理查询参数 ======
        query = parse_qs(parsed.query)
        for k, vals in query.items():
            v = vals[0] if vals else ''
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni': self.data['sni'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                self.data['ws-opts']['path'] = v

    def _load_vless(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'vless', 'uuid': unquote(parsed.username)}
        self.data['tls'] = False
        if not parsed.query: return
        # ====== 使用 parse_qs 处理查询参数，避免 split 错误 ======
        query = parse_qs(parsed.query)
        for k, vals in query.items():
            v = vals[0] if vals else ''
            if k in ('allowInsecure', 'insecure'):
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'sni': self.data['servername'] = v
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k == 'type':
                self.data['network'] = v
            elif k == 'serviceName':
                if 'grpc-opts' not in self.data:
                    self.data['grpc-opts'] = {}
                self.data['grpc-opts']['grpc-service-name'] = v
            elif k == 'host':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                if 'headers' not in self.data['ws-opts']:
                    self.data['ws-opts']['headers'] = {}
                self.data['ws-opts']['headers']['Host'] = v
            elif k == 'path':
                if 'ws-opts' not in self.data:
                    self.data['ws-opts'] = {}
                self.data['ws-opts']['path'] = v
            elif k == 'flow':
                if v.endswith('-udp443'):
                    self.data['flow'] = v
                else: self.data['flow'] = v+'!'
            elif k == 'fp': self.data['client-fingerprint'] = v
            elif k == 'security' and v == 'tls':
                self.data['tls'] = True
            # ========== [FIX] 仅当 pbk 非空时才设置 reality-opts ==========
            elif k == 'pbk':
                if v.strip():  # 确保公钥不为空
                    if 'reality-opts' not in self.data:
                        self.data['reality-opts'] = {}
                    self.data['reality-opts']['public-key'] = v
            # ==================================================================
            elif k == 'sid':
                if 'reality-opts' not in self.data:
                    self.data['reality-opts'] = {}
                self.data['reality-opts']['short-id'] = v

    def _load_hysteria2(self, url: str, dt: str):
        parsed = self.urlparse(url)
        # ====== 修复：username 可能为 None ======
        username = unquote(parsed.username) if parsed.username else ''
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'type': 'hysteria2', 'password': username}
        if ':' in parsed.netloc:
            ports = parsed.netloc.split(':')[1]
            if ',' in ports:
                _, self.data['ports'] = ports.split(',',1)
            else:
                self.data['port'] = ports
            try: self.data['port'] = int(self.data['port'])
            except ValueError: self.data['port'] = 443
        else:
            self.data['port'] = 443
        self.data['tls'] = False
        if not parsed.query: return
        # ====== 使用 parse_qs ======
        query = parse_qs(parsed.query)
        for k, vals in query.items():
            v = vals[0] if vals else ''
            if k == 'insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'obfs', 'obfs-password'):
                self.data[k] = v
            elif k == 'fp': self.data['client-fingerprint'] = v

    def _load_tuic(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {
            'name': unquote(parsed.fragment), 'server': parsed.hostname,
            'type': 'tuic', 'uuid': unquote(parsed.username),
            'password': unquote(parsed.password) if parsed.password else '',
            'port': parsed.port or 136
        }
        if not parsed.query: return
        query = parse_qs(parsed.query)
        for k, vals in query.items():
            v = vals[0] if vals else ''
            if k == 'allow_insecure':
                self.data['skip-cert-verify'] = (v != '0')
            elif k == 'alpn':
                self.data['alpn'] = unquote(v).split(',')
            elif k in ('sni', 'udp_relay_mode'):
                self.data[k.replace('_','-')] = v
            elif k == 'fp': self.data['client-fingerprint'] = v
            elif k == 'congestion_control': self.data['congestion-controller'] = v

    def _load__legacy(self, url: str, dt: str):
        parsed = urlparse(url)
        # ====== 修复端口解析：提取纯数字端口 ======
        port_str = str(parsed.port) if parsed.port is not None else ''
        # 如果端口包含 ? 或 &，说明后面跟着查询参数，需要截断
        if '?' in port_str:
            port_str = port_str.split('?')[0]
        elif '&' in port_str:
            port_str = port_str.split('&')[0]
        try:
            port = int(port_str) if port_str else 0
        except ValueError:
            port = 0
        self.data = {
            'name': unquote(parsed.fragment),
            'type': 'socks5' if self.type.startswith('socks') else 'http',
            'tls': parsed.scheme == 'https',
            'server': parsed.hostname,
            'port': port,
            'username': parsed.username,
            'password': parsed.password
        }
        self.data = {k:v for k,v in self.data.items() if v != None}
        if self.type.startswith('socks'):
            self.type = self.data['type']

    _load_http = _load__legacy
    _load_https = _load__legacy
    _load_socks5 = _load__legacy
    _load_socks = _load__legacy

    def update(self, node: 'Node'):
        self.data.update(node.data)
        self.names.union(node.names)

    @property
    def name(self):
        def rate(name: str):
            r = 0
            if name.startswith('@'):
                r -= 5
            if any(127462<=ord(c)<=127487 for c in name):
                r += 6
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                r -= 3
            if any(word in name for word in BANNED_WORDS):
                r -= 100
            return r
        return sorted(list(self.names), key=rate)[0]

    def format_name(self, max_len=30):
        name = [ord(c) for c in self.name]
        for ch in '\N{MATHEMATICAL BOLD CAPITAL A}\N{MATHEMATICAL SANS-SERIF BOLD CAPITAL A}':
            name = [
                c - ord(ch) + ord('A') if ord(ch) <= c < ord(ch)+26 else c
                for c in name
            ]
        for ch in ('\N{MATHEMATICAL BOLD SMALL A}\N{MATHEMATICAL SANS-SERIF BOLD SMALL A}'
                    +'\N{REGIONAL INDICATOR SYMBOL LETTER A}'*NAME_NO_FLAGS):
            name = [
                c - ord(ch) + ord('a') if ord(ch) <= c < ord(ch)+26 else c
                for c in name
            ]
        name = ''.join([chr(c) for c in name])
        name = name.replace(chr(10144), '->')
        for word in BANNED_WORDS:
            name = name.replace(word, '*'*len(word))
        if len(name) > max_len:
            name = name[:max_len]
            if '\N{RIGHT-TO-LEFT MARK}' in name:
                name += '\N{LEFT-TO-RIGHT MARK}'
                print(name)
            name += '...'
        if NAME_SHOW_TYPE:
            if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                tp = self.type.upper()
            else:
                tp = self.type.title()
            name = f'[{tp}] ' + name
        if name in Node.gNames:
            i = 0
            new = name
            while new in Node.gNames:
                i += 1
                new = f"{name} #{i}"
            name = new
        self.data['name'] = name

    @property
    def isfake(self) -> bool:
        if STOP: return False
        try:
            if 'server' not in self.data: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            # TODO: Fake UUID
            # if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            #     return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                # That's not designed for China
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    @property
    def url(self) -> str:
        handler: Optional[Callable[[Node.DATA_TYPE], str]] = \
                getattr(self, '_url_'+self.type, None)
        if handler: return handler(self.data)
        else: raise UnsupportedType(self.type)

    def _url_vmess(self, data: DATA_TYPE) -> str:
        v = VMESS_TEMPLATE.copy()
        for key, val in data.items():
            if key in CLASH2VMESS:
                v[CLASH2VMESS[key]] = val
        if v['net'] == 'ws':
            if 'ws-opts' in data:
                try:
                    v['host'] = data['ws-opts']['headers']['Host']
                except KeyError: pass
                if 'path' in data['ws-opts']:
                    v['path'] = data['ws-opts']['path']
        elif v['net'] == 'h2':
            if 'h2-opts' in data:
                if 'host' in data['h2-opts']:
                    v['host'] = ','.join(data['h2-opts']['host'])
                if 'path' in data['h2-opts']:
                    v['path'] = data['h2-opts']['path']
        elif v['net'] == 'grpc':
            if 'grpc-opts' in data:
                if 'grpc-service-name' in data['grpc-opts']:
                    v['path'] = data['grpc-opts']['grpc-service-name']
        if data.get('tls'):
            v['tls'] = 'tls'
        return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

    def _url_ss(self, data: DATA_TYPE) -> str:
        passwd = b64encodes_safe(data['cipher']+':'+data['password'])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    def _url_ssr(self, data: DATA_TYPE) -> str:
        # TODO: Fix IPv6
        ret = (':'.join([str(data[_]) for _ in ('server','port',
                                    'protocol','cipher','obfs')]) +
                b64encodes_safe(data['password']) +
                f"remarks={b64encodes_safe(data['name'])}")
        for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
            if k in data:
                ret += '&'+urlk+'='+b64encodes_safe(data[k])
        return "ssr://"+ret

    # ====== 修复：增强 _url_trojan 容错 ======
    def _url_trojan(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'sni' in data:
            ret += f"sni={data['sni']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&"
                # 容错：检查 grpc-opts 是否存在
                if 'grpc-opts' in data and 'grpc-service-name' in data['grpc-opts']:
                    ret += f"serviceName={data['grpc-opts']['grpc-service-name']}"
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        ret = ret.rstrip('&')+'#'+name
        return ret

    # ====== 修复：增强 _url_vless 容错，处理缺失 uuid 和空公钥 ======
    def _url_vless(self, data: DATA_TYPE) -> str:
        # 如果 data 中没有 uuid，使用默认值
        uuid = data.get('uuid', DEFAULT_UUID)
        passwd = quote(uuid)
        name = quote(data['name'])
        ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'servername' in data:
            ret += f"sni={data['servername']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&"
                if 'grpc-opts' in data and 'grpc-service-name' in data['grpc-opts']:
                    ret += f"serviceName={data['grpc-opts']['grpc-service-name']}&"
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        if 'flow' in data:
            flow: str = data['flow']
            if flow.endswith('!'):
                ret += f"flow={flow[:-1]}&"
            else: ret += f"flow={flow}-udp443&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if data.get('tls'):
            ret += f"security=tls&"
        # ========== [FIX] 仅当 reality-opts 存在且公钥非空时才添加 ==========
        elif 'reality-opts' in data:
            opts: Dict[str, str] = data['reality-opts']
            pbk = opts.get('public-key', '').strip()
            sid = opts.get('short-id', '').strip()
            if pbk:  # 公钥有效才添加
                ret += f"security=reality&pbk={pbk}&"
                if sid:
                    ret += f"sid={sid}&"
        # =====================================================================
        ret = ret.rstrip('&')+'#'+name
        return ret

    # ====== 修复：增强 _url_hysteria2 容错，缺失 password 时使用空字符串 ======
    def _url_hysteria2(self, data: DATA_TYPE) -> str:
        passwd = quote(data.get('password', ''))
        name = quote(data.get('name', '未命名'))
        ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
        if 'ports' in data:
            ret += ','+data['ports']
        ret += '?'
        if 'skip-cert-verify' in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        for k in ('sni', 'obfs', 'obfs-password'):
            if k in data:
                ret += f"{k}={data[k]}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_tuic(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        uuid = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"tuic://{uuid}:{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allow_insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if 'congestion-controller' in data:
            ret += f"congestion_control={data['congestion-controller']}&"
        for k in ('sni', 'udp-relay-mode'):
            if k in data:
                ret += f"{k.replace('-','_')}={data[k]}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url__legacy(self, data: DATA_TYPE) -> str:
        tp = 'https
