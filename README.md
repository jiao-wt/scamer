# README

工具名称 scamer, 采用模块化设计, 根据不同的模块完成不同的功能
项目地址: https://github.com/jiao-wt/scamer

```shell
pip install -r requirements.txt # 安装第三方库
```

模块

```
domainscan 模块: 进行子域名收集
portscan 模块: 进行端口扫描和服务识别
vulnscan 模块: 利用poc对目标进行漏洞扫描
```

### 子域名收集模块

**子域名收集原理**:

```
分装sublist3r工具实现子域名收集
```

```shell
# 使用示例
python scamer.py vulnscan -h
python scamer.py vulnscan -d baidu.com
python scamer.py vulnscan -d baidu.com -o  #将结果输出为txt文本
python scamer.py vulnscan -d baidu.com -b -t 10 # 使用暴力破解模式可设置暴力破解的线程数
```

### 端口扫描模块

```
完成对目标的端口扫描, 服务识别, 版本识别
-t TARGET, --target TARGET
                        目标IP地址或域名
  -p PORTS, --ports PORTS
                        扫描的端口范围，默认扫描常见端口，格式为"80,443"或"1-100"
  --timeout TIMEOUT     连接超时时间(秒)
  --workers WORKERS     最大线程数
  -f FILE, --file FILE  包含目标列表的文件
  -s, --save            保存结果(json格式)

```

```shell
# 使用示例
python scamer.py portscan -h
python scamer.py portscan -t baidu.com  # 默认扫描常见端口
python scamer.py portscan -t baidu.com -p 80 # 指定端口
python scamer.py portscan -f baidu.com_subdomains.txt # 可对多个目标进行扫描, 可联动域名扫描
python scamer.py portscan -t baidu.com -s # 将结果保存为json文件
```

### 漏洞扫描模块pocscanner

利用网上公开的poc库对资产进行漏洞扫描，目前支持nuclei-template/http

```
功能：
1. 完成对neclei格式的poc模板解析，对变量进行提取和赋值
2. 支持http协议的请求，包括普通http请求和raw请求
3. 支持正则表达式、json、xpath类型的提取器
4. 支持status、size、word、regex、binary、dsl、xpath类型的匹配器
5  支持根据资产自动进行poc匹配
6  支持高级http动态变量替换（例如：CVE-2023-26469.yaml）
```

使用示例

```shell
python scamer.py vulnscan -h # 查看帮助
python scamer.py vulnscan -a asset.json #根据资产信息自动匹配poc进行性漏洞扫描

# 实现对 CVE-2023-26469 poc 的验证
python scamer.py vulnscan -a asset.json -P pocs/cves/2023/CVE-2023-26469.yaml --protocol 'https'
assetjson示例
[
  {
    "ip": "eci-2zef3nsgswrnizep6m1p.cloudeci1.ichunqiu.com",  # 春秋云镜 CVE-2023-26469 靶场
    "port": 80,
    "service": "Chamilo LMS",
    "version": "1.0.0"
  }
]
```

