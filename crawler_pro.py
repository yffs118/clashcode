#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import requests
import re
import yaml
import base64
import json
import socket
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
import hashlib

# ======================== 全局配置 ========================
MAX_DEPTH = 3
MAX_REQUESTS = 210
REQUEST_TIMEOUT = 30
KEYWORDS = ['node','subscri', 'feed', '.yaml', '.yml', '.txt']
OUTPUT_YAML = 'crawclash.yaml'
OUTPUT_TXT = 'crawsub.txt'
SOURCE_FILE = 'crawler.list'
CONNECT_TIMEOUT = 3
TEST_WORKERS = 20

# ======================== 辅助函数（解析与导出） ========================

def clean_url(url):
    if not url:
        return url
    return re.sub(r'[:,.?!;]+$', '', url.strip())

def safe_urljoin(base, url):
    if not url:
        return None
    try:
        return urljoin(base, url)
    except:
        return None

def is_direct_subscription(url):
    """严格判断是否为直接订阅链接（仅基于扩展名）"""
    if not url:
        return False
    lower = url.lower()
    return lower.endswith(('.yaml', '.yml', '.txt'))

def is_node_link(url):
    """判断 URL 是否可能是节点订阅链接（基于扩展名或关键字）"""
    if not url:
        return False
    lower = url.lower()
    if lower.endswith(('.yaml', '.yml', '.txt')):
        return True
    for kw in KEYWORDS:
        if kw.lower() in lower:
            return True
    return False

def fetch_content(url, retries=3, delay=1):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            if resp.encoding is None:
                resp.encoding = 'utf-8'
            return resp.text
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

def fetch_binary(url, retries=3, delay=1):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            if i < retries - 1:
                time.sleep(delay)
                continue
            raise
    return None

def parse_vmess(vmess_url):
    """解析 VMess 链接，返回标准节点字典"""
    if not vmess_url.startswith('vmess://'):
        return None
    try:
        b64 = vmess_url[8:]
        b64 += '=' * (4 - len(b64) % 4)
        decoded = base64.b64decode(b64).decode('utf-8')
        data = json.loads(decoded)
        node = {
            'type': 'vmess',
            'add': data.get('add', ''),
            'port': int(data.get('port', 0)),
            'id': data.get('id', ''),
            'aid': int(data.get('aid', 0)),
            'net': data.get('net', 'tcp'),
            'type_': data.get('type', 'none'),      # 原字段名为 'type'，为避免与节点类型冲突，重命名
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'tls': data.get('tls', ''),
            'sni': data.get('sni', ''),
            'cipher': data.get('scy', 'auto'),
            'raw': vmess_url,
        }
        if not node['add'] or not node['port'] or not node['id']:
            return None
        return node
    except Exception:
        return None

def parse_vless(vless_url):
    """解析 VLESS 链接"""
    if not vless_url.startswith('vless://'):
        return None
    try:
        parsed = urlparse(vless_url)
        uuid = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        node = {
            'type': 'vless',
            'add': host,
            'port': port,
            'uuid': uuid,
            'net': query.get('type', ['tcp'])[0],
            'tls': query.get('security', [''])[0] == 'tls',
            'sni': query.get('sni', [''])[0],
            'flow': query.get('flow', [''])[0],
            'encryption': query.get('encryption', ['none'])[0],
            'raw': vless_url,
        }
        if not node['uuid']:
            return None
        return node
    except Exception:
        return None

def parse_ss(ss_url):
    """解析 Shadowsocks 链接"""
    if not ss_url.startswith('ss://'):
        return None
    try:
        content = ss_url[5:]
        if '@' in content:
            prefix, suffix = content.split('@', 1)
            b64 = prefix.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method, password = decoded.split(':', 1)
            if '?' in suffix:
                host_port, _ = suffix.split('?', 1)
            else:
                host_port = suffix
            host, port = host_port.split(':')
            port = int(port)
        else:
            b64 = content.replace('-', '+').replace('_', '/')
            b64 += '=' * (4 - len(b64) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded:
                return None
            method_pass, host_port = decoded.split('@', 1)
            method, password = method_pass.split(':', 1)
            if '?' in host_port:
                host_port, _ = host_port.split('?', 1)
            host, port = host_port.split(':')
            port = int(port)

        node = {
            'type': 'ss',
            'add': host,
            'port': port,
            'method': method,
            'password': password,
            'raw': ss_url,
        }
        return node
    except Exception:
        return None

def parse_trojan(trojan_url):
    """解析 Trojan 链接"""
    if not trojan_url.startswith('trojan://'):
        return None
    try:
        parsed = urlparse(trojan_url)
        password = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        node = {
            'type': 'trojan',
            'add': host,
            'port': port,
            'password': password,
            'sni': query.get('sni', [host])[0],
            'allowInsecure': query.get('allowInsecure', ['0'])[0],
            'raw': trojan_url,
        }
        if not node['password']:
            return None
        return node
    except Exception:
        return None

def parse_node_link(link):
    """根据协议类型调用对应的解析函数"""
    if link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('ss://'):
        return parse_ss(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
    else:
        return None

def parse_subscription_content(content, url_hint=''):
    """
    解析订阅内容，返回节点列表。
    支持：
    - 标准 Clash YAML（proxies 字段，包含 vmess/vless/ss/trojan/http/socks5）
    - Clash 配置（proxy-providers 字段，自动下载 http 类型 provider）
    - Base64 编码的节点链接（每行一个链接）
    - 每行一个节点链接的纯文本
    返回的每个节点字典包含 'raw' 字段（原始链接字符串）
    """
    nodes = []
    if not content:
        return nodes

    # ---------- 第一步：尝试作为 Clash YAML 解析 ----------
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 1. 标准 proxies 字段（支持不同大小写）
            proxy_list = data.get('proxies') or data.get('Proxy') or data.get('proxy')
            if proxy_list and isinstance(proxy_list, list):
                for proxy in proxy_list:
                    if not isinstance(proxy, dict):
                        continue
                    ptype = proxy.get('type', '').lower()
                    if ptype not in ('vmess', 'vless', 'ss', 'trojan', 'http', 'socks5'):
                        continue
                    node = {
                        'type': ptype,
                        'add': proxy.get('server', ''),
                        'port': int(proxy.get('port', 0)),
                        'raw': f"{ptype}://{proxy.get('server', '')}:{proxy.get('port', 0)}"
                    }
                    if ptype in ('vmess', 'vless'):
                        uuid = proxy.get('uuid') or proxy.get('id', '')
                        node['id' if ptype == 'vmess' else 'uuid'] = uuid
                        node['aid'] = int(proxy.get('alterId', 0)) if ptype == 'vmess' else 0
                        node['cipher'] = proxy.get('cipher', 'auto')
                        node['net'] = proxy.get('network', 'tcp')
                        node['tls'] = proxy.get('tls', False)
                        node['sni'] = proxy.get('sni', '')
                        node['host'] = proxy.get('host', '')
                        node['path'] = proxy.get('path', '')
                        if ptype == 'vless':
                            node['flow'] = proxy.get('flow', '')
                            node['encryption'] = proxy.get('encryption', 'none')
                    elif ptype == 'ss':
                        node['method'] = proxy.get('cipher', '')
                        node['password'] = proxy.get('password', '')
                    elif ptype == 'trojan':
                        node['password'] = proxy.get('password', '')
                        node['sni'] = proxy.get('sni', '')
                        node['allowInsecure'] = '1' if proxy.get('skip-cert-verify', False) else '0'
                    if node['add'] and node['port']:
                        nodes.append(node)
                if nodes:
                    return nodes

            # 2. proxy-providers 字段
            if 'proxy-providers' in data:
                providers = data['proxy-providers']
                for provider_name, provider_config in providers.items():
                    if not isinstance(provider_config, dict):
                        continue
                    if provider_config.get('type') == 'http':
                        provider_url = provider_config.get('url')
                        if provider_url:
                            print(f"  Found proxy-provider '{provider_name}', downloading: {provider_url}")
                            try:
                                provider_content = fetch_binary(provider_url)
                                if provider_content:
                                    provider_text = provider_content.decode('utf-8', errors='ignore')
                                    sub_nodes = parse_subscription_content(provider_text, provider_url)
                                    nodes.extend(sub_nodes)
                                    print(f"  -> Got {len(sub_nodes)} nodes from provider")
                            except Exception as e:
                                print(f"  -> Error downloading provider {provider_url}: {e}")
                if nodes:
                    return nodes
    except Exception:
        pass

    # ---------- 第二步：尝试 Base64 解码 ----------
    try:
        b64_clean = re.sub(r'\s+', '', content)
        if re.match(r'^[A-Za-z0-9+/=_-]+$', b64_clean):
            b64_clean += '=' * (4 - len(b64_clean) % 4)
            decoded = base64.b64decode(b64_clean, altchars='-_').decode('utf-8', errors='ignore')
            for line in decoded.splitlines():
                line = line.strip()
                if line and line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
                    node = parse_node_link(line)
                    if node:
                        node['raw'] = line
                        nodes.append(node)
            if nodes:
                return nodes
    except Exception:
        pass

    # ---------- 第三步：按行解析节点链接 ----------
    for line in content.splitlines():
        line = line.strip()
        if line and line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
            node = parse_node_link(line)
            if node:
                node['raw'] = line
                nodes.append(node)

    return nodes

def normalize_node_key(node):
    """生成节点去重指纹（基于类型、地址、端口、关键凭证）"""
    if node.get('type') == 'vmess':
        key = f"vmess_{node.get('add')}_{node.get('port')}_{node.get('id')}"
    elif node.get('type') == 'vless':
        key = f"vless_{node.get('add')}_{node.get('port')}_{node.get('uuid')}"
    elif node.get('type') == 'ss':
        key = f"ss_{node.get('add')}_{node.get('port')}_{node.get('method')}_{node.get('password')}"
    elif node.get('type') == 'trojan':
        key = f"trojan_{node.get('add')}_{node.get('port')}_{node.get('password')}"
    else:
        key = f"{node.get('type')}_{node.get('add')}_{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()

def test_node_connectivity(node):
    """测试节点连通性（TCP 握手）"""
    host = node.get('add', '')
    port = node.get('port', 0)
    if not host or not port:
        return False
    try:
        ip = socket.gethostbyname(host)
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
            return True
    except:
        return False

def node_to_vmess_link(node):
    """将节点对象还原为原始链接字符串"""
    if node.get('raw') and node['raw'].startswith(('vmess://', 'vless://', 'ss://', 'trojan://')):
        return node['raw']

    ntype = node.get('type', '')
    if ntype == 'vmess':
        data = {
            'v': '2',
            'ps': '',
            'add': node.get('add', ''),
            'port': node.get('port', 0),
            'id': node.get('id', ''),
            'aid': node.get('aid', 0),
            'net': node.get('net', 'tcp'),
            'type': node.get('type_', 'none'),
            'host': node.get('host', ''),
            'path': node.get('path', ''),
            'tls': node.get('tls', ''),
            'sni': node.get('sni', ''),
        }
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        return 'vmess://' + b64
    elif ntype == 'vless':
        uuid = node.get('uuid') or node.get('id', '')
        host = node.get('add', '')
        port = node.get('port', 443)
        params = []
        if node.get('net'):
            params.append(f"type={node.get('net')}")
        if node.get('tls'):
            params.append("security=tls")
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('flow'):
            params.append(f"flow={node.get('flow')}")
        if node.get('encryption') and node['encryption'] != 'none':
            params.append(f"encryption={node.get('encryption')}")
        query = '&'.join(params)
        return f"vless://{uuid}@{host}:{port}?{query}" if query else f"vless://{uuid}@{host}:{port}"
    elif ntype == 'ss':
        auth = f"{node.get('method','')}:{node.get('password','')}"
        auth_b64 = base64.b64encode(auth.encode()).decode()
        return f"ss://{auth_b64}@{node.get('add','')}:{node.get('port',0)}"
    elif ntype == 'trojan':
        netloc = f"{node.get('password','')}@{node.get('add','')}:{node.get('port',443)}"
        params = []
        if node.get('sni'):
            params.append(f"sni={node.get('sni')}")
        if node.get('allowInsecure') == '1':
            params.append("allowInsecure=1")
        query = '&'.join(params)
        return f"trojan://{netloc}?{query}" if query else f"trojan://{netloc}"
    else:
        return node.get('raw', '')

def is_node_valid(node):
    """
    检查节点是否包含 Clash 所必需的字段。
    返回 True 表示有效，False 表示无效应丢弃。
    """
    node_type = node.get('type', '').lower()
    if not node_type:
        return False
    if node_type not in ('vmess', 'vless', 'ss', 'trojan', 'http', 'socks5'):
        return False
    if node_type == 'vmess':
        if not node.get('id'):
            return False
    elif node_type == 'vless':
        if not node.get('uuid'):
            return False
    elif node_type == 'ss':
        if not node.get('method') or not node.get('password'):
            return False
    elif node_type == 'trojan':
        if not node.get('password'):
            return False
    return True

def nodes_to_clash_yaml(nodes):
    """
    将节点列表转换为完整的 Clash 配置文件 YAML 字符串，
    仅包含有效节点，并生成 proxy-groups 和 rules。
    """
    if not nodes:
        return ""

    proxies = []
    node_names = []

    for idx, node in enumerate(nodes, start=1):
        if not is_node_valid(node):
            print(f"⚠️ 跳过无效节点: {node.get('add', 'unknown')} (type: {node.get('type', '')})")
            continue

        name = f"🛡️ node-{idx}"
        node_names.append(name)

        proxy = {
            'name': name,
            'type': node.get('type', 'vmess'),
            'server': node.get('add', ''),
            'port': node.get('port', 0),
        }

        ntype = node.get('type')
        if ntype == 'vmess':
            proxy['uuid'] = node.get('id', '')
            proxy['alterId'] = int(node.get('aid', 0))
            proxy['cipher'] = node.get('cipher', 'auto')
            proxy['network'] = node.get('net', 'tcp')
            if node.get('tls'):
                proxy['tls'] = True
            if node.get('sni'):
                proxy['sni'] = node.get('sni')
            if node.get('host'):
                proxy['host'] = node.get('host')
            if node.get('path'):
                proxy['path'] = node.get('path')

        elif ntype == 'vless':
            uuid = node.get('uuid') or node.get('id', '')
            proxy['uuid'] = uuid
            proxy['network'] = node.get('net', 'tcp')
            if node.get('tls'):
                proxy['tls'] = True
            if node.get('sni'):
                proxy['sni'] = node.get('sni')
            if node.get('flow'):
                proxy['flow'] = node.get('flow')
            if node.get('encryption'):
                proxy['encryption'] = node.get('encryption')

        elif ntype == 'ss':
            proxy['cipher'] = node.get('method', '')
            proxy['password'] = node.get('password', '')

        elif ntype == 'trojan':
            proxy['password'] = node.get('password', '')
            if node.get('sni'):
                proxy['sni'] = node.get('sni')
            if node.get('allowInsecure') == '1':
                proxy['skip-cert-verify'] = True

        elif ntype in ('http', 'socks5'):
            if node.get('username'):
                proxy['username'] = node.get('username')
            if node.get('password'):
                proxy['password'] = node.get('password')

        proxies.append(proxy)

    if not proxies:
        print("⚠️ 没有有效节点，无法生成 Clash 配置")
        return ""

    config = {
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': '🚀 选择代理',
                'type': 'select',
                'proxies': node_names
            },
            {
                'name': '🌐 自动测速',
                'type': 'url-test',
                'proxies': node_names,
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            }
        ],
        'rules': [
            'MATCH,🚀 选择代理'
        ]
    }
    return yaml.dump(config, default_flow_style=False, allow_unicode=True)

def nodes_to_base64(nodes):
    """
    将节点列表转换为 Base64 订阅字符串（每行一个原始链接）
    """
    links = []
    for node in nodes:
        link = node_to_vmess_link(node)
        if link:
            links.append(link)
    raw = '\n'.join(links)
    return base64.b64encode(raw.encode()).decode()

# ======================== 主爬虫类 ========================

class Crawler:
    def __init__(self):
        self.visited_urls = set()
        self.queue = deque()
        self.all_nodes = []
        self.request_count = 0

    def process_sources(self, lines):
        """
        预处理所有源，建立配对关系
        增强配对逻辑：
        1. 精确匹配 base
        2. 查找以 base 为前缀的更具体的 plain_page（路径更长）
        3. 回退到根域名匹配
        直接订阅判断：仅当 URL 以 .yaml/.yml/.txt 结尾时才视为直接订阅
        """
        wildcard_items = []  # (原始url, pattern_regex)
        direct_urls = []
        plain_pages_set = set()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # 处理 +date
            if line.startswith('+date'):
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                url_template = parts[1].strip()
                try:
                    url = datetime.now().strftime(url_template)
                except:
                    url = url_template
            else:
                url = line

            if '*' in url:
                pattern = re.escape(url).replace('\\*', '.*')
                regex = re.compile('^' + pattern + '$', re.IGNORECASE)
                wildcard_items.append((url, regex))
            else:
                if is_direct_subscription(url):
                    direct_urls.append(url)
                else:
                    clean = url.rstrip('/')
                    plain_pages_set.add(clean)

        wildcard_map = {}
        for url, regex in wildcard_items:
            base_part = url.split('*', 1)[0].rstrip('/')
            matched_base = None

            if base_part in plain_pages_set:
                matched_base = base_part
            else:
                candidates = [p for p in plain_pages_set if p.startswith(base_part) and p != base_part]
                if candidates:
                    matched_base = max(candidates, key=len)
                else:
                    parsed = urlparse(base_part)
                    root_url = f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
                    if root_url in plain_pages_set:
                        matched_base = root_url

            if matched_base:
                if matched_base not in wildcard_map:
                    wildcard_map[matched_base] = []
                wildcard_map[matched_base].append(regex)
            else:
                if base_part not in wildcard_map:
                    wildcard_map[base_part] = []
                wildcard_map[base_part].append(regex)

        plain_pages = list(plain_pages_set)
        return wildcard_map, direct_urls, plain_pages

    def enqueue(self, url, depth, patterns):
        if url in self.visited_urls:
            return
        if self.request_count >= MAX_REQUESTS:
            return
        self.queue.append((url, depth, patterns))

    def download_subscription(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        self.request_count += 1
        print(f"[{self.request_count}/{MAX_REQUESTS}] Downloading subscription: {url}")
        try:
            content = fetch_binary(url)
            if content is None:
                print(f"  -> No content (fetch failed)")
                return
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = ''
            if not text:
                print(f"  -> Empty content")
                return
            nodes = parse_subscription_content(text, url)
            if nodes:
                for node in nodes:
                    if 'raw' not in node or not node['raw']:
                        node['raw'] = node_to_vmess_link(node)
                self.all_nodes.extend(nodes)
                print(f"  -> Found {len(nodes)} nodes")
            else:
                print(f"  -> No nodes parsed")
        except Exception as e:
            print(f"  -> Error: {e}")

    def parse_page(self, html, base_url, depth, patterns):
        """解析页面，patterns可以是单个正则或列表"""
        if patterns and not isinstance(patterns, list):
            patterns = [patterns]

        soup = BeautifulSoup(html, 'html.parser')

        if patterns:
            text = soup.get_text()
            url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
            for match in url_regex.findall(text):
                url = clean_url(match)
                if url in self.visited_urls:
                    continue
                for pattern in patterns:
                    if pattern.match(url):
                        print(f"  Found wildcard-matched URL from text: {url}")
                        if depth < MAX_DEPTH:
                            self.enqueue(url, depth + 1, patterns)
                        break

        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = safe_urljoin(base_url, href)
            if not full_url:
                continue
            full_url = clean_url(full_url)
            if full_url in self.visited_urls:
                continue

            matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(full_url):
                        matched = True
                        break

            if matched:
                print(f"  Found wildcard-matched URL from href: {full_url}")
                if depth < MAX_DEPTH:
                    self.enqueue(full_url, depth + 1, patterns)
                continue

            if is_node_link(full_url):
                self.download_subscription(full_url)
                if depth < MAX_DEPTH and full_url not in self.visited_urls:
                    self.enqueue(full_url, depth + 1, patterns)

        text = soup.get_text()
        url_regex = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        for match in url_regex.findall(text):
            url = clean_url(match)
            if url in self.visited_urls:
                continue

            already_matched = False
            if patterns:
                for pattern in patterns:
                    if pattern.match(url):
                        already_matched = True
                        break
            if already_matched:
                continue

            if is_node_link(url):
                self.download_subscription(url)
                if depth < MAX_DEPTH and url not in self.visited_urls:
                    self.enqueue(url, depth + 1, patterns)

        node_link_regex = re.compile(r'(vmess|ss|trojan)://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        for match in node_link_regex.findall(text):
            link = match.strip()
            node = parse_node_link(link)
            if node:
                node['raw'] = link
                self.all_nodes.append(node)
                print(f"  Found direct node link: {link[:50]}...")

    def crawl(self, source_lines):
        wildcard_map, direct_urls, plain_pages = self.process_sources(source_lines)

        for url in direct_urls:
            self.download_subscription(url)

        for url in plain_pages:
            patterns = wildcard_map.pop(url, None)
            if patterns:
                self.enqueue(url, 1, patterns)
            else:
                self.enqueue(url, 1, None)

        for base_url, patterns in wildcard_map.items():
            self.enqueue(base_url, 1, patterns)

        print(f"📋 Initial queue size: {len(self.queue)}")

        while self.queue and self.request_count < MAX_REQUESTS:
            url, depth, patterns = self.queue.popleft()
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            self.request_count += 1
            print(f"[{self.request_count}/{MAX_REQUESTS}] Crawling: {url} (depth={depth})")
            try:
                html = fetch_content(url)
                if html is None:
                    continue
                self.parse_page(html, url, depth, patterns)
            except Exception as e:
                print(f"  Error crawling {url}: {e}")

        print(f"🏁 Crawl finished. Total requests: {self.request_count}, Nodes collected: {len(self.all_nodes)}")

    def dedupe_and_test(self):
        print("🔄 Deduplicating...")
        unique = {}
        for node in self.all_nodes:
            key = normalize_node_key(node)
            if key not in unique:
                unique[key] = node
        nodes = list(unique.values())
        print(f"   After dedupe: {len(nodes)} nodes")

        print("🌐 Testing connectivity...")
        valid_nodes = []
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as executor:
            future_to_node = {executor.submit(test_node_connectivity, node): node for node in nodes}
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    if future.result():
                        valid_nodes.append(node)
                    else:
                        print(f"   ❌ Unreachable: {node.get('add')}:{node.get('port')}")
                except Exception as e:
                    print(f"   ⚠️  Test error: {e}")
        print(f"   After connectivity test: {len(valid_nodes)} nodes")
        return valid_nodes

    def run(self):
        if not os.path.exists(SOURCE_FILE):
            print(f"❌ Error: Source file '{SOURCE_FILE}' not found.")
            sys.exit(1)

        with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        self.crawl(lines)

        if not self.all_nodes:
            print("❌ No nodes collected. Check your sources and network.")
            return

        valid_nodes = self.dedupe_and_test()

        if not valid_nodes:
            print("❌ No valid nodes after testing. No output files generated.")
            return

        clash_yaml = nodes_to_clash_yaml(valid_nodes)
        if clash_yaml:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                f.write(clash_yaml)
            print(f"✅ Clash YAML written to {OUTPUT_YAML}")
        else:
            print("❌ No valid nodes to write to Clash YAML")

        base64_str = nodes_to_base64(valid_nodes)
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write(base64_str)
        print(f"✅ Base64 subscription written to {OUTPUT_TXT}")

# ======================== 主入口 ========================
if __name__ == '__main__':
    crawler = Crawler()
    crawler.run()
