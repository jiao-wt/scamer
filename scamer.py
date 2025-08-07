import argparse
import port_scan
import domain_scan
import pocscanner.vuln_scanner


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

        self.setup_vulnscan_parser()


        self.args = self.parser.parse_args()

    def setup_portscan_parser(self):
        """设置端口扫描子解析器的参数"""
        parser = self.subparsers.add_parser('portscan', help='端口扫描模式')
        parser.add_argument('-t', '--target', help='目标IP地址或域名')
        parser.add_argument('-p', '--ports', default=','.join(map(str, port_scan.COMMON_PORTS)),
                            help='扫描的端口范围，默认扫描常见端口，格式为"80,443"或"1-100"')
        parser.add_argument('--timeout', type=float, default=1.0, help='连接超时时间(秒)')
        parser.add_argument('--workers', type=int, default=50, help='最大线程数')
        parser.add_argument('-f', '--file', help='包含目标列表的文件')
        parser.add_argument('-s', '--save', action='store_true', help="保存结果(json格式)")

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
            target='',
            ports=ports,
            timeout=self.args.timeout,
            max_workers=self.args.workers,
        )

        if self.args.file:
            scan_results = portscan.scan_targets_from_file(self.args.file)
            if self.args.save:
                portscan.save_json_results(scan_results, 'Assets/output_file.json')

        elif self.args.target:
            scan_results = portscan.run_scan()
            identified_results = portscan.identify_services(scan_results)

            if self.args.save:
                portscan.save_json_results(identified_results)

        else:
            print("请指定目标(-t)或目标文件(-f)")


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

    def setup_vulnscan_parser(self):
        parser = self.subparsers.add_parser("vulnscan", help='漏洞模式')
        parser.add_argument('-a', '--assets', required=True, help='指定目标资产')
        parser.add_argument('-P', '--path', help='指定poc路径')
        parser.add_argument('--protocol', default='https',help='指定使用协议(http/https)')

    def vulnscan_run(self):
        Asset_file = self.args.assets
        assets = '../Assets/'+Asset_file
        poc_path = self.args.threads
        protocol = self.args.bruteforce
        pocscanner.vuln_scanner.scanner(poc_path=poc_path, assets=assets, protocol=protocol)


    def run(self):
        if self.args.mode == 'portscan':
            self.portscan_run()
        elif self.args.mode == 'domainscan':
            self.domainscan_run()
        elif self.args.mode == 'vulnscan':
            self.vulnscan_run()

if __name__ == '__main__':
    scamer = Scamer()
    scamer.run()
