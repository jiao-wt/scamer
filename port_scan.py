# port_scan.py
import socket
import threading
import concurrent.futures
import time
import ipaddress
from service_detector import ServiceDetector

# 常见端口

COMMON_PORTS = [21, 22, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]


class PortScanner:
    def __init__(self, target, ports=None, timeout=1.0, max_workers=50):
        """初始化扫描端口扫描器"""
        self.target = target
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
        self.lock = threading.Lock()
        self.ip = self.resolve_target()
        self.service_detector = ServiceDetector(target, timeout)

    def resolve_target(self):
        """解析目标为IP地址"""
        try:
            # 检查是否为有效IP地址
            ipaddress.ip_address(self.target)
            return self.target
        except ValueError:
            # 不是有效的IP地址，进行域名解析
            try:
                ip = socket.gethostbyname(self.target)
                print(f"域名 {self.target} 解析为 IP：{ip}")
                return ip
            except socket.gaierror as e:
                print(f"无法解析域名：{self.target}，错误：{e}")
                return None

    def scan_port(self, port):
        """扫描单个端口并获取socket连接"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    with self.lock:
                        self.results.append((port, "open", s.dup()))
                        print(f"端口 {port}：开放")
        except Exception as e:
            with self.lock:
                print(f"扫描端口 {port} 时出错：{e}")

    def run_scan(self):
        """执行多线程端口扫描"""
        if not self.ip:
            print("无法执行扫描，无效目标")
            return []

        print(f"开始扫描 {self.ip} 的端口。。。")
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"端口 {port} 扫描异常：{e}")

        end_time = time.time()
        print(f"扫描完成！耗时：{end_time - start_time:.2f} 秒")
        print(f"共扫描 {len(self.ports)} 个端口，发现 {len(self.results)} 个开放端口")
        self.results.sort(key=lambda x: x[0])

        return self.results

    def identify_services(self, scan_results):
        """调用服务识别模块分析开放端口服务"""
        if not scan_results:
            print("没有开放端口需要识别")
            return []

        print("开始识别服务...")
        identified_results = []
        for port, status, sock in scan_results:
            identified_service = self.service_detector.identify_service(port, sock)
            identified_results.append((port, status, identified_service))
            print(f"端口 {port}: {status} | 服务识别: {identified_service}")
            sock.close()  # 释放socket资源
        return identified_results

if __name__ == '__main__':

    portscan = PortScanner(
        target='127.0.0.1',
        ports=COMMON_PORTS
    )
    scan_results = portscan.run_scan()

    identified_results = portscan.identify_services(scan_results)

    if identified_results:
        print("\n扫描结果汇总：")
        print("端口\t\t状态\t\t服务")
        print("-" * 50)
        for port, status,identified in identified_results:
            print(f"{port}\t\t{status}\t\t{identified}")
    else:
        print("\n未发现开放端口")