import requests
import re
from typing import Dict, Any, List
from urllib.parse import parse_qs
from requests.structures import CaseInsensitiveDict

# 禁用SSL证书验证警告（仅测试用）
requests.packages.urllib3.disable_warnings()

# 全局会话对象：所有请求共享同一个会话，保持Cookie和会话状态
session = requests.Session()


# ------------------------------
# 通用工具函数
# ------------------------------
def get_request_type(request_template: Dict[str, Any]) -> str:
    """根据模板的type字段判断请求类型（raw/normal）"""
    try:
        if isinstance(request_template.get('request'), list) and len(request_template['request']) > 0:
            return request_template['request'][0].get('type', 'unknown').lower()
        return 'unknown'
    except Exception as e:
        print(f"解析请求类型失败: {e}")
        return 'unknown'


def validate_step(steps: List[Dict], step: int) -> bool:
    """验证步骤编号的有效性"""
    if not isinstance(step, int) or step < 1 or step > len(steps):
        raise ValueError(f"无效的步骤编号（有效范围：1-{len(steps)}）")
    return True


def remove_existing_protocol(url: str) -> str:
    """移除URL中已有的http://或https://协议前缀"""
    if not url:
        return url
    return re.sub(r'^https?://', '', url, flags=re.IGNORECASE)


def add_protocol(url: str, protocol: str) -> str:
    """为URL添加指定协议（确保协议唯一）"""
    cleaned_url = remove_existing_protocol(url)
    return f"{protocol}://{cleaned_url}"


# ------------------------------
# Raw类型请求处理（原始HTTP报文）
# ------------------------------
def send_raw_request(raw_body: str, protocol: str = 'http') -> requests.Response:
    """发送raw类型请求（解析原始HTTP报文）"""
    # 1. 按行分割原始请求
    lines = [line.strip() for line in raw_body.split('\n') if line.strip() is not None]
    if not lines:
        raise ValueError("原始请求体为空")

    # 2. 解析请求行（方法和路径）
    request_line = lines[0]
    method, path, *_ = request_line.split()
    method = method.upper()

    # 3. 解析Host头（主机和端口）
    host_line = lines[1]
    if not host_line.startswith('Host:'):
        raise ValueError("第二行不是Host头，请检查模板格式")
    host_info = host_line.split(':', 1)[1].strip()
    host, port = host_info.split(':', 1) if ':' in host_info else (host_info, None)

    # 4. 解析请求头和请求体
    headers = CaseInsensitiveDict()
    body_lines = []
    is_body = False  # 标记是否进入请求体

    for line in lines[2:]:
        if not is_body:
            if line == '':  # 空行后为请求体
                is_body = True
                continue
            if ':' in line:  # 解析请求头
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:  # 收集请求体
            body_lines.append(line)

    # 5. 解析请求体（表单格式）
    data = None
    if method in ['POST', 'PUT', 'PATCH'] and body_lines:
        body_str = '\n'.join(body_lines)
        if headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            data = parse_qs(body_str)
            data = {k: v[0] for k, v in data.items()}  # 去除列表嵌套

    # 6. 构造URL并发送请求
    port_str = f":{port}" if port else ""
    url = f"{protocol}://{host}{port_str}{path}"

    try:
        if method == 'GET':
            return session.get(url, headers=headers, verify=False, timeout=10)
        elif method == 'POST':
            return session.post(url, headers=headers, data=data, verify=False, timeout=10)
        else:
            return session.request(method, url, headers=headers, data=data, verify=False, timeout=10)
    except Exception as e:
        raise RuntimeError(f"发送{method}请求失败: {e}")


# ------------------------------
# Normal类型请求处理（结构化请求）
# ------------------------------
def send_normal_request(request_data: Dict[str, Any], protocol: str = 'http') -> requests.Response:
    """发送normal类型请求（结构化参数）"""
    # 1. 解析请求方法
    method = request_data.get('method', 'GET').upper()
    if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
        raise ValueError(f"不支持的请求方法: {method}")

    # 2. 解析路径并处理协议
    paths = request_data.get('path', [])
    if not paths or not isinstance(paths, list):
        raise ValueError("path字段无效或为空")
    original_url = paths[0].strip()
    if not original_url:
        raise ValueError("路径不能为空")
    url = add_protocol(original_url, protocol)

    # 3. 解析请求头
    headers = CaseInsensitiveDict()
    raw_headers = request_data.get('headers', {})
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            headers[k.strip()] = str(v).strip()

    # 4. 解析URL参数和请求体
    params = request_data.get('params', {})
    if not isinstance(params, dict):
        params = {}
    body = request_data.get('body', '')
    if not isinstance(body, str):
        body = str(body)

    # 5. 解析Cookie（合并到会话）
    cookie_str = request_data.get('cookie', '')
    if cookie_str:
        cookie_dict = {}
        for item in cookie_str.split(';'):
            item = item.strip()
            if '=' in item:
                k, v = item.split('=', 1)
                cookie_dict[k.strip()] = v.strip()
        session.cookies.update(cookie_dict)

    # 6. 发送请求
    try:
        return session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=body,
            verify=False,
            timeout=10
        )
    except Exception as e:
        raise RuntimeError(f"发送{method}请求失败: {e}")


# ------------------------------
# 统一请求发送接口
# ------------------------------
def send_request_from_template(
        request_template: Dict[str, Any],
        step: int = 1,
        protocol: str = 'http'
) -> requests.Response:
    """
    根据模板发送指定步骤的请求（自动适配raw/normal类型）
    :param request_template: 请求模板字典
    :param step: 步骤编号（1基索引）
    :param protocol: 协议（http/https）
    :return: 响应对象
    """
    req_type = get_request_type(request_template)
    protocol = protocol.lower()
    if protocol not in ['http', 'https']:
        raise ValueError(f"不支持的协议: {protocol}，仅支持http/https")

    # 提取步骤列表（跳过第一个type字段）
    steps = request_template.get('request', [])[1:]
    if not steps:
        raise ValueError("模板中无有效步骤")
    validate_step(steps, step)
    target_step = steps[step - 1]

    # 根据类型发送请求
    if req_type == 'raw':
        print(f"\n===== 执行Raw请求（步骤{step}，协议: {protocol}） =====")
        raw_body = target_step['body'][0] if isinstance(target_step.get('body'), list) and target_step['body'] else ''
        print(f"原始请求体:\n{raw_body[:500]}...\n")  # 打印前500字符
        return send_raw_request(raw_body, protocol)

    elif req_type == 'normal':
        print(f"\n===== 执行Normal请求（步骤{step}，协议: {protocol}） =====")
        print(f"请求方法: {target_step.get('method', 'GET')}，路径: {target_step.get('path', [''])[0]}")
        return send_normal_request(target_step, protocol)

    else:
        raise ValueError(f"不支持的请求类型: {req_type}（仅支持raw/normal）")


def close_session():
    """关闭全局会话，释放资源"""
    global session
    if session:
        session.close()
        print("\n会话已关闭")
    session = None


# ------------------------------
# 示例使用
# ------------------------------
if __name__ == '__main__':
    try:
        # 示例1：Raw类型请求模板（包含3个步骤）
        raw_template = {
            'request': [
                {'type': 'raw'},  # 类型标记
                # 步骤1：GET获取CSRF
                {'step': 1,
                 'body': [
                     'GET /session/login HTTP/1.1\nHost: eci-2zeenli6forycwqfadxv.cloudeci1.ichunqiu.com:80\nUser-Agent: Mozilla/5.0']},
                # 步骤2：POST提交数据
                {'step': 2,
                 'body': [
                     "POST /session/login HTTP/1.1\nHost: eci-2zeenli6forycwqfadxv.cloudeci1.ichunqiu.com:80\nContent-Type: application/x-www-form-urlencoded\n\ncsrf_test_jorani={{csrf}}&login=test&password=123"]},
                # 步骤3：GET验证结果
                {'step': 3,
                 'body': [
                     'GET /dashboard HTTP/1.1\nHost: eci-2zeenli6forycwqfadxv.cloudeci1.ichunqiu.com:80\nX-Requested-With: XMLHttpRequest']}
            ]
        }

        # 发送Raw类型请求（步骤1）
        print("----- 测试Raw类型请求 -----")
        raw_response1 = send_request_from_template(raw_template, step=1, protocol='https')
        print(f"步骤1响应状态码: {raw_response1.status_code}")
        print(f"步骤1响应体预览: {raw_response1.text[:300]}")

        # 示例2：Normal类型请求模板（包含2个步骤）
        normal_template = {
            'request': [
                {'type': 'normal'},  # 类型标记
                # 步骤1：POST登录
                {
                    'step': 1,
                    'method': 'POST',
                    'path': ['eci-2zeargnmo682gipquy0t.cloudeci1.ichunqiu.com:80/login'],
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'params': {},
                    'body': 'username=test&password=123456',
                    'cookie': ''
                },
                # 步骤2：GET用户信息
                {
                    'step': 2,
                    'method': 'GET',
                    'path': ['eci-2zeargnmo682gipquy0t.cloudeci1.ichunqiu.com:80/userinfo'],
                    'headers': {'Accept': 'application/json'},
                    'params': {'detail': 'true'},
                    'body': '',
                    'cookie': ''
                }
            ]
        }

        # 发送Normal类型请求（步骤1和步骤2，共享会话）
        print("\n----- 测试Normal类型请求 -----")
        normal_response1 = send_request_from_template(normal_template, step=1, protocol='http')
        print(f"步骤1响应状态码: {normal_response1.status_code}")

        normal_response2 = send_request_from_template(normal_template, step=2, protocol='http')
        print(f"步骤2响应状态码: {normal_response2.status_code}")
        print(f"步骤2响应体预览: {normal_response2.text[:300]}")

    except Exception as e:
        print(f"请求失败: {e}")
    finally:
        close_session()