import argparse


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
        COMMON_PORTS = [21, 80, 3306, 8080]
        parser = self.subparsers.add_parser('portscan', help='端口扫描模式')
        parser.add_argument('target', help='目标IP地址或域名')
        parser.add_argument('-p', '--ports', default=','.join(map(str, COMMON_PORTS)),
                            help='扫描的端口范围，默认扫描常见端口，格式为"80,443"或"1-100"')
        parser.add_argument('-t', '--timeout', type=float, default=1.0, help='连接超时时间(秒)')
        parser.add_argument('-w', '--workers', type=int, default=50, help='最大线程数')
        parser.add_argument('-s', '--save', action='store_true', help='将结果保存到文件')

    def setup_domainscan_parser(self):
        pass
