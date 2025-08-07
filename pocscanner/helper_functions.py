import json
import re
import base64
import hashlib
import hmac
import random
import string
import time
import datetime
import urllib.parse
import zlib
import request_prec
from typing import List, Dict,Set


# 辅助函数映射（复用之前定义）
helper_functions = {
    # 编码/解码函数
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "base64_decode": lambda s: base64.b64decode(s).decode(errors="ignore"),
    "hex_encode": lambda s: s.encode().hex(),
    "hex_decode": lambda s: bytes.fromhex(s).decode(errors="ignore"),
    "url_encode": lambda s: urllib.parse.quote(s),
    "url_decode": lambda s: urllib.parse.unquote(s),
    "gzip": lambda s: zlib.compress(s.encode()),
    "gzip_decode": lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS).decode(errors="ignore"),
    "zlib": lambda s: zlib.compress(s.encode()),
    "zlib_decode": lambda b: zlib.decompress(b).decode(errors="ignore"),

    # 字符串处理函数
    "concat": lambda *args: "".join(map(str, args)),
    "contains": lambda s, substr: substr in s,
    "contains_all": lambda s, *substrs: all(sub in s for sub in substrs),
    "starts_with": lambda s, prefix: s.startswith(prefix),
    "ends_with": lambda s, suffix: s.endswith(suffix),
    "replace": lambda s, old, new: s.replace(old, new),
    "trim": lambda s, cutset="": s.strip(cutset),
    "trim_left": lambda s, cutset="": s.lstrip(cutset),
    "trim_right": lambda s, cutset="": s.rstrip(cutset),
    "to_upper": lambda s: s.upper(),
    "to_lower": lambda s: s.lower(),
    "reverse": lambda s: s[::-1],
    "len": lambda s: len(s),
    "join": lambda sep, *args: sep.join(map(str, args)),

    # 哈希函数
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
    "hmac": lambda algo, data, secret: hmac.new(
        secret.encode(), data.encode(),
        {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}.get(algo, hashlib.sha256)
    ).hexdigest(),

    # 随机生成函数
    "rand_base": lambda length, charset=None: "".join(
        random.choice(charset or string.ascii_letters + string.digits)
        for _ in range(int(length))
    ),
    "rand_int": lambda min_val=0, max_val=2147483647: random.randint(int(min_val), int(max_val)),
    "rand_text_alpha": lambda length, cutset="": "".join(
        c for c in [random.choice(string.ascii_letters) for _ in range(int(length))]
        if c not in cutset
    ),
    "rand_ip": lambda cidr="0.0.0.0/0": ".".join(str(random.randint(0, 255)) for _ in range(4)),

    # 日期时间函数
    "date_time": lambda fmt="%Y-%m-%d", unix_ts=None: datetime.datetime.fromtimestamp(
        float(unix_ts) if unix_ts else time.time()
    ).strftime(fmt.replace("%M", "%m").replace("%D", "%d")),
    "unix_time": lambda add_sec=0: int(time.time()) + int(add_sec),
    "to_unix_time": lambda date_str, layout="%Y-%m-%d": int(
        datetime.datetime.strptime(date_str, layout).timestamp()
    ),

    # 正则与匹配函数
    "contains_any": lambda s, *substrs: any(sub in s for sub in substrs),
    "regex": lambda pattern, s: bool(re.search(pattern, s)),
    "regex_all": lambda pattern, *strs: all(re.search(pattern, s) for s in strs),

    # JSON函数
    "json_minify": lambda json_str: json_str.replace(" ", "").replace("\n", ""),
    "json_prettify": lambda json_str: json_str,

    # 复杂函数简化实现
    "generate_jwt": lambda claims, algo, secret: f"mock_jwt.{claims}.{secret}",
    "generate_java_gadget": lambda gadget_type, url, encoding: f"mock_{gadget_type}_gadget_{url}"
}


def convert_ip_port_to_variables(ip: str, port: int, scheme: str = "http") -> Dict[str, str]:
    """生成HTTP相关变量值"""
    hostname = f"{ip}:{port}"
    root_url = f"{scheme}://{hostname}"
    return {
        "{{Host}}": ip,
        "{{Port}}": str(port),
        "{{Hostname}}": hostname,
        "{{Scheme}}": scheme,
        "{{RootURL}}": root_url,
        "{{BaseURL}}": root_url,
        "{{Path}}": "",
        "{{File}}": ""
    }


def parse_inner_function(expr: str) -> str:
    """解析参数中的函数调用（如rand_base(12)，支持嵌套）"""
    # 匹配函数格式：函数名(参数)，支持参数包含嵌套函数
    pattern = re.compile(r'^(\w+)\(\s*(.*?)\s*\)$', re.DOTALL)
    match = pattern.match(expr.strip())
    if not match:
        return expr  # 非函数格式，直接返回

    func_name, args_str = match.groups()
    func_name = func_name.lower()

    # 解析参数（支持嵌套函数）
    def parse_args(args_str: str) -> list:
        args = []
        in_quote = False
        current_arg = []
        quote_char = None
        bracket_depth = 0  # 跟踪括号深度，处理嵌套函数

        for c in args_str:
            if c in ["'", '"'] and (not quote_char or quote_char == c):
                in_quote = not in_quote
                quote_char = c if in_quote else None
                current_arg.append(c)
            elif c == '(' and not in_quote:
                bracket_depth += 1
                current_arg.append(c)
            elif c == ')' and not in_quote:
                bracket_depth -= 1
                current_arg.append(c)
            elif c == ',' and not in_quote and bracket_depth == 0:
                # 仅在引号外且括号深度为0时分割参数
                args.append(''.join(current_arg).strip())
                current_arg = []
            else:
                current_arg.append(c)

        if current_arg:
            args.append(''.join(current_arg).strip())

        # 递归解析每个参数中的函数
        parsed_args = []
        for arg in args:
            if not arg:
                continue
            # 去除引号
            if arg.startswith(("'", '"')) and arg.endswith(("'", '"')):
                arg = arg[1:-1]
            # 递归解析参数中的函数（如rand_base(5)）
            parsed_arg = parse_inner_function(arg)
            parsed_args.append(parsed_arg)
        return parsed_args

    # 执行函数
    if func_name not in helper_functions:
        return expr  # 不支持的函数，返回原始表达式

    try:
        args = parse_args(args_str)
        # 调用函数时确保参数类型正确（如整数参数）
        converted_args = []
        for arg in args:
            # 尝试转换为整数（如rand_base(12)中的12）
            try:
                converted = int(arg)
            except (ValueError, TypeError):
                converted = arg
            converted_args.append(converted)
        return str(helper_functions[func_name](*converted_args))
    except Exception as e:
        return f"{{error: {str(e)}}}"


def parse_function_call(var_str: str) -> str:
    """解析带{{}}的函数调用（支持嵌套，如{{to_upper(rand_base(12))}}）"""
    # 提取{{}}内的表达式
    pattern = re.compile(r'{{\s*(.*?)\s*}}', re.DOTALL)
    match = pattern.match(var_str.strip())
    if not match:
        return ""

    inner_expr = match.group(1)
    return parse_inner_function(inner_expr)


def get_variable_values(variables_list: List[str], ip: str, port: int) -> Dict[str, str]:
    """获取变量列表中每个变量的值（支持嵌套函数解析）"""
    http_vars = convert_ip_port_to_variables(ip, port)
    result = {}

    for var in variables_list:
        var_clean = var.strip()
        if var_clean in http_vars:
            result[var_clean] = http_vars[var_clean]
        elif re.match(r'^\s*{{.*}}\s*$', var_clean):
            # 处理带{{}}的函数调用（可能包含嵌套）
            result[var_clean] = parse_function_call(var_clean)
        else:
            result[var_clean] = ""  # 未定义变量

    return result


def reporter_variables(poc_report):
    poc_report = json.loads(poc_report)
    variables = {}

    if poc_report.get('variables'):
        for key, value in poc_report['variables'].items():
            if parse_function_call(value):
                variables[key] = parse_function_call(value)
            else:
                variables[key] = value
        return variables
    else:
        return None

def replace_dict_variables(data: Dict[str, str]) -> Dict[str, str]:
    # 复制原始字典避免修改源数据
    processed_data = data.copy()
    # 正则匹配{{变量名}}格式（支持空格，如{{ header }}）
    var_pattern = re.compile(r'{{\s*(\w+)\s*}}')
    # 记录已处理的变量名，避免循环引用导致死循环
    processed_vars: Set[str] = set()

    def replace_recursive(value: str) -> str:
        """递归替换字符串中的变量"""
        # 提取所有变量名
        vars_in_value = var_pattern.findall(value)
        if not vars_in_value:
            return value  # 无变量则直接返回

        # 替换每个变量
        new_value = value
        for var_name in vars_in_value:
            # 检查变量是否存在于字典中
            if var_name not in processed_data:
                continue  # 变量不存在则不替换

            # 避免循环引用（如a="{{b}}", b="{{a}}"）
            if var_name in processed_vars:
                continue

            # 递归处理变量值（解决嵌套变量，如a="{{b}}", b="{{c}}", c="123"）
            processed_vars.add(var_name)
            var_value = replace_recursive(processed_data[var_name])
            processed_vars.remove(var_name)

            # 替换当前变量
            new_value = new_value.replace(f'{{{{{var_name}}}}}', var_value)
            new_value = new_value.replace(f'{{{{ {var_name} }}}}', var_value)  # 处理带空格的变量

        return new_value

    # 遍历字典所有值进行替换
    for key in processed_data:
        processed_data[key] = replace_recursive(processed_data[key])

    return processed_data


def variable_out(variables_list, variables):
    for A_key, A_value in variables_list.items():
        for a in variables.keys():
            if A_value == a:
                variables_list[A_key] = variables[a]

    return variables_list

# 使用示例
if __name__ == "__main__":
    variables = [
        "{{csrf}}",
        "{{date_time(\"%Y-%m-%d\")}}",
        "{{header}}",
        "{{Hostname}}",
        "{{payload}}",
        "{{to_upper(rand_base(12))}}",  # 嵌套函数
        "{{to_upper(concat(rand_base(5), \"_\", rand_int(100, 200)))}}"  # 多层嵌套
    ]
    target_ip = "192.168.1.100"
    target_port = 8080

    # 完成对各类辅助函数变量的替换
    variable_values = get_variable_values(variables, target_ip, target_port)
    print(variable_values)


    poc_path = "pocs/http/cves/2023/CVE-2023-26469.yaml"  # 替换为你的POC路径
    try:
        processor = request_prec.RequestPreprocessor(poc_path)
        request_report = processor.generate_json()

        # 完成对variables字段变量的替换
        test = reporter_variables(request_report)
        print(test)
    except Exception as e:
        print(f"处理失败：{str(e)}")