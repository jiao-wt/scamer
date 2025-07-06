import argparse
import port_scan
import domain_scan


class Scamer:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="这是一个模块化的漏洞扫描工具, 包括子域名扫描模块、端口扫描服务识别模块等"
        )

        # 创建子解析器，用于不同模块的命令解析
        self.subparsers = self.parser.add_subparsers(dest='mode', required=True, help='模式选择')

        # 创建端口扫描子解析器
        self.setup_portscan_parser()

        # 创建子域名扫描子解析器
        self.setup_domainscan_parser()

        self.args = self.parser.parse_args()

    def setup_portscan_parser(self):
        """设置端口扫描子解析器的参数"""
        parser = self.subparsers.add_parser('portscan', help='端口扫描模式')
        parser.add_argument('target', help='目标IP地址或域名')
        parser.add_argument('-p', '--ports', default=','.join(map(str, port_scan.COMMON_PORTS)),
                            help='扫描的端口范围，默认扫描常见端口，格式为"80,443"或"1-100"')
        parser.add_argument('-t', '--timeout', type=float, default=1.0, help='连接超时时间(秒)')
        parser.add_argument('-w', '--workers', type=int, default=50, help='最大线程数')

    def portscan_run(self):
        """执行端口扫描"""
        # 处理端口参数
        if self.args.ports:
            if '-' in self.args.ports:
                start, end = map(int, self.args.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = list(map(int, self.args.ports.split(',')))
        else:
            ports = port_scan.COMMON_PORTS

        portscan = port_scan.PortScanner(
            target=self.args.target,
            ports=ports,
            timeout=self.args.timeout,
            max_workers=self.args.workers,
        )

        scan_results = portscan.run_scan()

        identified_results = portscan.identify_services(scan_results)

        if identified_results:
            print("\n扫描结果汇总：")
            print("端口\t\t状态\t\t\t服务")
            print("-" * 50)
            for port, status, identified in identified_results:
                print(f"{port}\t\t{status}\t\t{identified}")
        else:
            print("\n未发现开放端口")

    def setup_domainscan_parser(self):
        parser = self.subparsers.add_parser("domainscan", help='子域名扫描模式')
        parser.add_argument('-d', '--domain', required=True, help='指定目标域名')
        parser.add_argument('-o', '--output', help='将结果保存至文件')
        parser.add_argument('-b', '--bruteforce', action='store_true', help='启用子域名暴力破解')
        parser.add_argument('-t', '--threads', help='设置暴力破解的线程数（默认 10）')

    def domainscan_run(self):
        target = self.args.domain
        threads = self.args.threads
        bruteforce = self.args.bruteforce
        sublist3r_path = "Sublist3r-master/sublist3r.py"
        sublist3r = domain_scan.Sublist3rWapper(sublist3r_path)
        sublist3r.scan(target=target, threads=threads, bruteforce=bruteforce)

    def run(self):
        if self.args.mode == 'portscan':
            self.portscan_run()
        elif self.args.mode == 'domainscan':
            self.domainscan_run()

if __name__ == '__main__':
    scamer = Scamer()
    scamer.run()
