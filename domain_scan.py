# domain_scan.py
"""封装 Sublist3r 工具"""
import os
import sys
import subprocess
from pathlib import Path


class Sublist3rWapper():
    def __init__(self, sublist3r_path):
        self.sublist3r_path = Path(sublist3r_path)
        if not self.sublist3r_path.exists():
            raise FileNotFoundError(f"Sublist3r工具未找到: {sublist3r_path}")

    def scan(self, target: str,
             output_path: str = 'subdomain_results',
             bruteforce=False,
             threads=10,):
        # 确保输出目录存在
        os.makedirs(output_path, exist_ok=True)

        # 构造输出文件及路径
        output_file = f"{target}_subdomains.txt"
        output_path = os.path.join(output_path, output_file)

        # 构造执行命令
        cmd = [
            sys.executable,  # 当前 python解析器
            str(self.sublist3r_path),
            "-d", target,
            "-o", output_path
        ]

        if bruteforce:
            cmd.append('-b')
            if threads:
                cmd.append(f'-t {threads}')


        print(f"执行命令: {' '.join(cmd)}")

        try:
            results = subprocess.run(cmd, check=True, text=True, encoding='utf-8')
            print(f"命令执行完成, 返回码: {results.returncode}")
            print(f"扫描结果保存至: {output_path}")

        except subprocess.CalledProcessError as e:
            print(f"执行 Sublist3r 时发生错误")


if __name__ == '__main__':
    target = 'google.com'
    sublist3r = Sublist3rWapper("Sublist3r-master/sublist3r.py")
    result_file = sublist3r.scan(target=target)
