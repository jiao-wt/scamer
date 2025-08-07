# port_scan.py
import socket
import threading
import concurrent.futures
import time
import ipaddress
import json
import re
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
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    with self.lock:
                        self.results.append((port, service, "open", s.dup()))
                        print(f"端口 {port}/{service}：开放")
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
        for port, service, status, sock in scan_results:
            identified_service = self.service_detector.identify_service(port, sock)
            identified_results.append({
                "port": port,
                "service": service,
                "status": status,
                "details": identified_service
            })
            print(f"端口 {port}/{service}: {status} | 服务识别: {identified_service}")
            sock.close()  # 释放socket资源
        return identified_results

    def to_json(self, results, output_file=None):
        """将结果转换为JSON格式"""
        json_data = []
        for result in results:
            # 提取服务版本信息（从识别结果中解析）
            version = self._extract_version(result['details'])
            service = self._extract_service(result['details'])

            json_entry = {
                "ip": self.target,
                "port": result['port'],
                "service": service,
                "version": version
            }

            if json_entry["service"] == "unknown":
                json_entry["service"] = result["service"]
            json_data.append(json_entry)

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            print(f"结果已保存到 {output_file}")

        return json_data

    def _extract_version(self, details):
        """从服务识别结果中提取版本信息"""
        # 简单的正则表达式提取版本号（如"nginx/1.18.0"）
        match = re.search(r'([a-zA-Z0-9-]+)/([0-9.]+)', details)
        if match:
            return match.group(2)
        return "unknown"

    def _extract_service(self, details):
        """从服务识别结果中提取版本信息"""
        # 简单的正则表达式提取版本号（如"nginx/1.18.0"）
        match = re.search(r'([a-zA-Z0-9-]+)/([0-9.]+)', details)
        if match:
            return match.group(1)
        return "unknown"


    def scan_targets_from_file(self, file_path, ports=None, timeout=1.0, max_workers=50):
        """从文件读取目标列表并执行扫描"""
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        all_results = []
        for target in targets:
            print(f"\n开始扫描目标: {target}")
            scanner = PortScanner(target, ports, timeout, max_workers)
            scan_results = scanner.run_scan()
            identified_results = scanner.identify_services(scan_results)

            # 转换为JSON格式并添加到总结果
            json_results = scanner.to_json(identified_results)
            all_results.extend(json_results)

        return all_results

    def save_json_results(self, results, output_file=None):
        """保存所有结果到JSON文件"""
        if output_file is None:  # 更规范的 None 比较方式
            current_time = time.strftime("%Y%m%d%H%M%S")
            output_file = current_time + '.json'  # 不再包含 'Assets/'，因为下面会拼接

        # 确保路径正确拼接
        file_path = 'Assets/' + output_file

        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n所有扫描结果已保存到 {file_path}")


if __name__ == '__main__':
    target = 'target.txt'
    scanner = PortScanner(target="")
    result = scanner.scan_targets_from_file(target)
    current_time = time.strftime("%Y%m%d%H%M%S")
    scanner.save_json_results(result)
