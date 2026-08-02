def to_clash_proxy(node):
    """
    将节点转换为 Clash proxy 字典，支持 vmess, vless, ss, trojan。
    完全模仿 JavaScript 的 toClashProxy 逻辑，并补齐 ws-opts 默认值。
    """
    ntype = node.get('type')
    if ntype == 'vmess':
        proxy = {
            'name': '',   # 名称由外部设置
            'type': 'vmess',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'alterId': int(node.get('alterId', 0)),
            'cipher': node.get('cipher', 'auto'),
            'tls': bool(node.get('tls', False)),
            'network': node.get('network', 'tcp'),
        }
        # 处理 ws 传输（始终添加 ws-opts，并设默认值，与 JS 一致）
        if node.get('network') == 'ws':
            ws_opts = {
                'path': node.get('path') or '/',   # 默认 '/'
                'headers': {
                    'Host': node.get('host') or node.get('add')   # 默认 server
                }
            }
            proxy['ws-opts'] = ws_opts

        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        return proxy

    elif ntype == 'vless':
        proxy = {
            'name': '',
            'type': 'vless',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'uuid': node.get('uuid', ''),
            'network': node.get('network', 'tcp'),
            'tls': bool(node.get('tls', False)),
            'flow': node.get('flow', ''),
            'encryption': node.get('encryption', 'none'),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        return proxy

    elif ntype == 'ss':
        return {
            'name': '',
            'type': 'ss',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'cipher': node.get('method', ''),
            'password': node.get('password', ''),
        }

    elif ntype == 'trojan':
        proxy = {
            'name': '',
            'type': 'trojan',
            'server': node.get('add', ''),
            'port': int(node.get('port', 0)),
            'password': node.get('password', ''),
        }
        if node.get('sni'):
            proxy['sni'] = node.get('sni')
        if node.get('allowInsecure') == '1' or node.get('allowInsecure') is True:
            proxy['skip-cert-verify'] = True
        return proxy

    else:
        return None
