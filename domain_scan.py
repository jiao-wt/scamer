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
        print(f"✅ Sublist3r工具初始化成功，路径: {sublist3r_path}")

    def scan(self, target: str,
             output_path: str = 'subdomain_results',
             bruteforce=False,
             threads=10, ):
        # 确保输出目录存在
        os.makedirs(output_path, exist_ok=True)
        print(f"📂 输出目录准备就绪: {output_path}")

        # 构造输出文件及路径
        output_file = f"{target}_subdomains.txt"
        output_full_path = os.path.join(output_path, output_file)

        # 构造执行命令
        cmd = [
            sys.executable,  # 当前python解析器
            str(self.sublist3r_path),
            "-d", target,
            "-o", output_full_path
        ]

        if bruteforce:
            cmd.append('-b')
            print("🔍 启用暴力破解模式")
        if threads:
            cmd.extend(['-t', str(threads)])
            print(f"⚡ 线程数设置为: {threads}")

        # 显示执行的命令
        print(f"\n📝 执行命令: {' '.join(cmd)}")

        try:
            print(f"⏳ 正在使用Sublist3r对 {target} 进行子域名扫描...")
            # 屏蔽工具输出，只保留自定义提示
            with open(os.devnull, 'w', encoding='utf-8') as devnull:
                results = subprocess.run(
                    cmd,
                    check=True,
                    text=True,
                    encoding='utf-8',
                    stdout=devnull,
                    stderr=devnull
                )

            # 统计扫描到的子域名数量
            if os.path.exists(output_full_path) and os.path.getsize(output_full_path) > 0:
                with open(output_full_path, 'r', encoding='utf-8') as f:
                    subdomain_count = len([line for line in f if line.strip()])
                print(f"✅ 子域名扫描完成！共发现 {subdomain_count} 个有效子域名")
            else:
                print("⚠️ 扫描完成，但未发现有效子域名")

            print(f"📊 扫描结果已保存至: {output_full_path}")
            return output_full_path  # 返回结果文件路径，方便后续处理

        except subprocess.CalledProcessError as e:
            print(f"❌ 执行Sublist3r时发生错误，返回码: {e.returncode}")
        except Exception as e:
            print(f"❌ 扫描过程中发生异常: {str(e)}")
        return None


if __name__ == '__main__':
    target = 'google.com'
    try:
        print(f"🚀 开始对目标 {target} 进行子域名扫描流程")
        sublist3r = Sublist3rWapper("Sublist3r-master/sublist3r.py")
        result_file = sublist3r.scan(
            target=target,
            bruteforce=False,
            threads=20
        )
        print("\n🏁 子域名扫描任务已结束")
    except Exception as e:
        print(f"❌ 程序初始化失败: {str(e)}")
