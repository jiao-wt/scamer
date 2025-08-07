import socket
import requests
import re
import time

# 服务识别特征字典（精简版）
SERVICE_SIGNATURES = {
    # 数据库服务
    'mysql': {
        'ports': [3306, 3307],
        'probe': b'',
        'response': b'\x0a',
        'banner_offset': 0,
        'version_re': r'([5-8]\.\d+\.\d+)',
        'decode': 'latin1'
    },
    'postgresql': {
        'ports': [5432],
        'probe': b'\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00',
        'response': b'PostgreSQL',
        'version_re': r'PostgreSQL ([\d.]+)'
    },
    'mongodb': {
        'ports': [27017, 27018],
        'probe': b'\x31\x00\x00\x00\x02\x01\x00\x00\x02\x61\x64\x6d\x69\x6e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'response': b'ismaster',
        'version_re': r'"version"\s*:\s*"([\d.]+)"'
    },
    'mssql': {
        'ports': [1433],
        'probe': b'\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'response': b'TDS',
        'version_re': r'SQL Server ([\d.]+)'
    },
    'oracle': {
        'ports': [1521],
        'probe': b'\x00\x00\x00\x28\x01\x00\x00\x05\x00\x00\x00\x00\x4f\x52\x41\x43\x4c\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'response': b'ORACLE',
        'version_re': r'Oracle Database ([\d.]+)'
    },

    # 缓存/消息队列服务
    'redis': {
        'ports': [6379],
        'probe': '*1\r\n$4\r\nPING\r\n',
        'response': '+PONG',
        'version_re': r'Redis server v=([\d.]+)'
    },
    'memcached': {
        'ports': [11211],
        'probe': 'stats\r\n',
        'response': 'STAT',
        'version_re': r'version ([\d.]+)'
    },
    'rabbitmq': {
        'ports': [5672, 15672],
        'probe': b'\x01\x00\x00\x00\x08\x00\x00\x00',
        'response': b'AMQP',
        'version_re': r'RabbitMQ ([\d.]+)'
    },

    # 网络服务
    'ssh': {
        'ports': [22],
        'probe': '',
        'response': 'SSH-',
        'version_re': r'SSH-([\d.]+)'
    },
    'ftp': {
        'ports': [21],
        'probe': '',
        'response': '220',
        'version_re': r'(\d+\.\d+\.\d+)'
    },
    'smtp': {
        'ports': [25, 465, 587],
        'probe': 'EHLO localhost\r\n',
        'response': '250',
        'version_re': r'SMTP ([\d.]+)'
    },

    # Web服务
    'http': {
        'ports': [80, 8080, 8000, 5000],
        'probe': 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
        'response': 'HTTP/',
        'version_re': r'HTTP/([\d.]+)',
        'web_service': True
    },
    'https': {
        'ports': [443, 8443],
        'probe': '',
        'response': '',
        'web_service': True,
        'tls': True
    }
}

# Web服务器版本提取规则
WEB_SERVER_VERSION = {
    'Apache': r'Apache/([\d.]+)',
    'Nginx': r'nginx/([\d.]+)',
    'IIS': r'Microsoft-IIS/([\d.]+)',
    'Tomcat': r'Apache-Coyote/([\d.]+)|Tomcat/([\d.]+)'
}


class ServiceDetector:
    def __init__(self, target, timeout=1.0):
        self.target = target
        self.timeout = timeout
        self.request_timeout = min(5.0, timeout * 3)

    def identify_service(self, port, sock=None):
        """仅返回服务名/版本号（如 mysql/5.7.26）"""
        for service, info in SERVICE_SIGNATURES.items():
            if port in info['ports']:
                try:
                    # 处理连接
                    s = sock.dup() if sock else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if not sock:
                        s.settimeout(self.timeout * 2)
                        s.connect((self.target, port))

                    # 发送探测包
                    if info.get('probe'):
                        probe = info['probe'].encode() if isinstance(info['probe'], str) else info['probe']
                        s.sendall(probe)
                        time.sleep(0.1)

                    # 接收响应并解码
                    response = s.recv(2048)
                    decode = info.get('decode', 'utf-8')
                    response_str = response.decode(decode, errors='replace')

                    # 匹配服务特征
                    if self._match_response(info['response'], response_str):
                        # 提取版本
                        banner = response_str[info.get('banner_offset', 0):]
                        version = self._extract_version(banner, info['version_re'])

                        # 处理Web服务
                        if info.get('web_service'):
                            return self._identify_web_service(port, service)

                        # 基础服务格式
                        return f"{service}/{version}" if version else service

                except:
                    continue
                finally:
                    if not sock:
                        s.close()

        # 未匹配到特征的默认处理
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def _match_response(self, expected, actual):
        if isinstance(expected, bytes):
            expected = expected.decode('utf-8', errors='ignore')
        return expected in actual

    def _extract_version(self, banner, pattern):
        """提取版本号，无额外输出"""
        if not pattern or not banner:
            return ""

        # 正则匹配
        match = re.search(pattern, banner)
        if match:
            version = match.group(1).strip()
            if re.match(r'^\d+\.\d+\.\d+$', version):
                return version

        # MySQL专用容错
        if 'mysql' in banner.lower():
            candidates = re.findall(r'\b(5|8)\.\d+\.\d+\b', banner)
            return candidates[0] if candidates else ""

        return ""

    def _identify_web_service(self, port, service):
        """识别Web服务（仅返回 服务/版本）"""
        try:
            scheme = 'https' if service == 'https' else 'http'
            head_resp = requests.head(
                f"{scheme}://{self.target}:{port}",
                timeout=self.request_timeout,
                verify=False,
                allow_redirects=True
            )
            server_str = head_resp.headers.get('Server', service)

            # 提取Web服务器版本
            for server, pattern in WEB_SERVER_VERSION.items():
                match = re.search(pattern, server_str, re.IGNORECASE)
                if match:
                    version = next((g for g in match.groups() if g), "")
                    return f"{server}/{version}" if version else server

            # 未匹配到已知服务器时
            parts = server_str.split('/')
            return f"{parts[0]}/{parts[1]}" if len(parts) > 1 else server_str

        except:
            return service

    # 移除所有打印语句，确保无额外输出


if __name__ == "__main__":
    detector = ServiceDetector("127.0.0.1", timeout=2.0)
    print(detector.identify_service(3306))  # 输出示例: mysql/5.7.26
    print(detector.identify_service(80))  # 输出示例: Apache/2.4.39