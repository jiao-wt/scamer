# service_detector.py
import socket
import requests
import re

# 服务识别特征字典
SERVICE_SIGNATURES = {
    'redis': {
        'ports': [6379],
        'probe': '*1\r\n$4\r\nPING\r\n',
        'response': '+PONG',
        'banner_offset': 0
    },
    'mysql': {
        'ports': [3306],
        'probe': b'\x01\x00\x00\x00\x0a',  # 简单的握手包
        'response': b'MySQL',
        'banner_offset': 10
    },
    'ssh': {
        'ports': [22],
        'probe': '',  # SSH服务会主动发送banner
        'response': 'SSH-',
        'banner_offset': 0
    },
    'ftp': {
        'ports': [21],
        'probe': '',  # FTP服务会主动发送banner
        'response': '220',
        'banner_offset': 0
    },
    'http': {
        'ports': [80, 8080, 8000, 5000],
        'probe': 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
        'response': 'HTTP/',
        'banner_offset': 0
    },
    'https': {
        'ports': [443],
        'probe': '',  # HTTPS需要SSL握手，这里简化处理
        'response': '',
        'banner_offset': 0,
        'tls': True
    }
}

# Web CMS 指纹识别规则
CMS_FINGERPRINTS = {
    'WordPress': {
        'headers': [
            ('X-Powered-By', 'WordPress'),
            ('Set-Cookie', 'wordpress'),
        ],
        'content': [
            r'wp-content',
            r'wp-includes',
            r'WordPress.com',
        ],
        'files': {
            '/wp-login.php': r'WordPress',
            '/wp-admin/': r'WordPress',
        }
    },
    'Joomla': {
        'headers': [
            ('X-Powered-By', 'Joomla'),
        ],
        'content': [
            r'Joomla!',
            r'joomla\.js',
        ],
        'files': {
            '/administrator/': r'Joomla',
        }
    },
    'Drupal': {
        'headers': [
            ('X-Generator', 'Drupal'),
        ],
        'content': [
            r'drupal\.js',
            r'class="node-',
        ],
        'files': {
            '/user/login': r'Drupal',
        }
    },
    'Discuz': {
        'content': [
            r'discuz\.js',
            r'Powered by Discuz!',
        ],
        'files': {
            '/admin.php': r'Discuz!',
        }
    },
    'Apache': {
        'headers': [
            ('Server', 'Apache'),
        ],
    },
    'Nginx': {
        'headers': [
            ('Server', 'nginx'),
        ],
    },
    'IIS': {
        'headers': [
            ('Server', 'Microsoft-IIS'),
        ],
    }
}


class ServiceDetector:
    def __init__(self, target, timeout=1.0):
        """初始化服务识别器"""
        self.target = target
        self.timeout = timeout
        # 设置requests超时时间
        self.request_timeout = min(5.0, timeout * 3)  # 至少5秒，或超时时间的3倍

    def identify_service(self, port, sock=None):
        """识别端口上运行的具体服务"""
        # 根据端口号初步判断
        for service, info in SERVICE_SIGNATURES.items():
            if port in info['ports']:
                try:
                    if sock:
                        # 使用已连接的socket
                        s = sock.dup()
                        s.settimeout(self.timeout)
                    else:
                        # 创建新的socket连接
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(self.timeout)
                        s.connect((self.target, port))

                    # 对于需要发送探测包的服务
                    if info['probe']:
                        if isinstance(info['probe'], str):
                            s.sendall(info['probe'].encode())
                        else:
                            s.sendall(info['probe'])

                    # 接收响应
                    response = s.recv(1024)
                    if isinstance(response, bytes):
                        response_str = response.decode('utf-8', errors='ignore')
                    else:
                        response_str = response

                    # 检查响应是否匹配服务特征
                    if info['response'] in response_str:
                        # 提取banner信息
                        banner = response_str[info['banner_offset']:].strip()

                        # 对于Web服务，进行更详细的指纹识别
                        if service in ['http', 'https']:
                            web_info = self.identify_web_service(port)
                            return f"{service} ({web_info})" if web_info else service

                        return f"{service} ({banner[:50]}...)" if banner else service

                except Exception as e:
                    # 识别失败，返回基于端口的初步判断
                    return service

        # 如果无法识别，返回基于端口的服务名称
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def identify_web_service(self, port):
        """识别Web服务的详细信息，包括CMS类型和服务器软件"""
        # 构建URL
        scheme = 'https' if port == 443 else 'http'
        base_url = f"{scheme}://{self.target}:{port}"

        try:
            # 发送HEAD请求获取响应头
            head_resp = requests.head(base_url, timeout=self.request_timeout, verify=False)

            # 发送GET请求获取页面内容
            get_resp = requests.get(base_url, timeout=self.request_timeout, verify=False)

            # 检查robots.txt文件
            robots_detected = self.check_robots_txt(base_url)

            # 分析响应，识别CMS和服务器信息
            cms_info = self.analyze_web_fingerprint(head_resp, get_resp)

            # 获取服务器信息
            server_info = head_resp.headers.get('Server', 'Unknown Server')

            # 构建完整的Web服务信息
            web_info = f"Server: {server_info}"
            if cms_info:
                web_info += f", CMS: {cms_info}"
            if robots_detected:
                web_info += ", robots.txt detected"

            return web_info

        except Exception as e:
            return f"Error: {str(e)[:30]}"

    def analyze_web_fingerprint(self, head_resp, get_resp):
        """分析Web指纹，识别CMS类型"""
        matched_cms = []

        # 检查所有已知的CMS指纹
        for cms, rules in CMS_FINGERPRINTS.items():
            score = 0
            total = 0

            # 检查响应头
            if 'headers' in rules:
                for header_name, pattern in rules['headers']:
                    total += 1
                    if header_name.lower() in [h.lower() for h in head_resp.headers]:
                        header_value = head_resp.headers.get(header_name)
                        if header_value and pattern.lower() in header_value.lower():
                            score += 1

            # 检查页面内容
            if 'content' in rules:
                for pattern in rules['content']:
                    total += 1
                    if re.search(pattern, get_resp.text, re.IGNORECASE):
                        score += 1

            # 检查特殊文件(这里只做标记，实际检测在单独的函数中)
            if 'files' in rules:
                total += len(rules['files'])
                # 这里不实际请求，只作为潜在匹配的参考
                score += 0  # 实际检测会在单独的函数中进行

            # 如果匹配度超过50%，认为是该CMS
            if total > 0 and score / total >= 0.5:
                matched_cms.append(cms)

        return ", ".join(matched_cms) if matched_cms else "Unknown"

    def check_robots_txt(self, base_url):
        """检查网站是否存在robots.txt文件"""
        try:
            robots_url = f"{base_url}/robots.txt"
            resp = requests.get(robots_url, timeout=self.request_timeout, verify=False)
            return resp.status_code == 200 and "User-agent" in resp.text
        except:
            return False
