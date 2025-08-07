import re
import json
from jsonpath_ng import parse  # 需安装：pip install jsonpath-ng
from lxml import etree  # 需安装：pip install lxml
from typing import Dict, Any, Optional, List, Union


class Extractor:
    """通用提取器，支持regex/kval/json/xpath/dsl五种类型"""

    def __init__(self, extractor_config: Dict[str, Any]):
        """
        初始化提取器，解析配置
        :param extractor_config: 包含extractors列表的完整配置
        """
        self.extractors = extractor_config.get("extractors", [])  # 所有提取器配置
        self.results: Dict[str, Optional[str]] = {}  # 最终提取结果（{名称: 值}）

    def _get_response_content(self, response, part: str = "body") -> Union[str, Dict, int]:
        """获取响应中指定部分的内容（通用工具方法）"""
        if part == "body":
            return response.text or ""  # 响应体文本
        elif part == "header":
            return dict(response.headers)  # 响应头（字典形式）
        elif part == "status":
            return response.status_code  # 状态码（整数）
        else:
            return ""  # 不支持的部分

    # ------------------------------
    # 1. 正则提取器（regex）
    # ------------------------------
    def _extract_regex(self, config: Dict[str, Any], response) -> Optional[str]:
        name = config.get("name")
        part = config.get("part", "body")
        group = config.get("group", 1)
        patterns = config.get("config", {}).get("regex_patterns", [])

        content = str(self._get_response_content(response, part))  # 转为字符串处理
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and len(match.groups()) >= group:
                return match.group(group)
        return None

    # ------------------------------
    # 2. 键值提取器（kval）- 从键值对中提取值
    # ------------------------------
    def _extract_kval(self, config: Dict[str, Any], response) -> Optional[str]:
        name = config.get("name")
        part = config.get("part", "header")  # 通常从header提取，支持body（键值对字符串）
        key = config.get("config", {}).get("key")  # 目标键名

        if not key:
            return None

        content = self._get_response_content(response, part)
        # 从响应头（字典）中提取
        if part == "header" and isinstance(content, dict):
            return content.get(key)
        # 从body（键值对字符串，如a=1&b=2）中提取
        elif part == "body" and isinstance(content, str):
            for pair in content.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k == key:
                        return v
        return None

    # ------------------------------
    # 3. JSON提取器（json）- 通过JSONPath提取
    # ------------------------------
    def _extract_json(self, config: Dict[str, Any], response) -> Optional[str]:
        name = config.get("name")
        part = config.get("part", "body")  # 仅支持body（JSON格式）
        json_paths = config.get("config", {}).get("json_path", [])  # JSONPath表达式

        content = self._get_response_content(response, part)
        try:
            json_data = json.loads(content) if isinstance(content, str) else content
        except (json.JSONDecodeError, TypeError):
            return None  # 非JSON格式

        for path in json_paths:
            try:
                jsonpath_expr = parse(path)
                matches = [match.value for match in jsonpath_expr.find(json_data)]
                if matches:
                    return str(matches[0])  # 返回第一个匹配结果
            except Exception:
                continue  # 忽略无效表达式
        return None

    # ------------------------------
    # 4. XPath提取器（xpath）- 从XML/HTML中提取
    # ------------------------------
    def _extract_xpath(self, config: Dict[str, Any], response) -> Optional[str]:
        name = config.get("name")
        part = config.get("part", "body")  # 仅支持body（XML/HTML）
        xpaths = config.get("config", {}).get("xpath", [])  # XPath表达式

        content = self._get_response_content(response, part)
        if not isinstance(content, str):
            return None

        try:
            # 解析XML/HTML（自动修复HTML）
            parser = etree.HTMLParser() if "<html>" in content.lower() else etree.XMLParser()
            tree = etree.fromstring(content.encode("utf-8"), parser=parser)
        except etree.XMLSyntaxError:
            return None  # 解析失败

        for xpath in xpaths:
            try:
                results = tree.xpath(xpath)
                if results:
                    return str(results[0])  # 返回第一个匹配结果
            except etree.XPathError:
                continue  # 忽略无效表达式
        return None

    # ------------------------------
    # 5. DSL提取器（dsl）- 复杂逻辑提取
    # ------------------------------
    def _extract_dsl(self, config: Dict[str, Any], response) -> Optional[str]:
        name = config.get("name")
        expressions = config.get("config", {}).get("dsl", [])  # DSL表达式

        # 支持的DSL函数（扩展可添加更多）
        dsl_functions = {
            "status_code": lambda: response.status_code,
            "len": lambda part: len(str(self._get_response_content(response, part))),
            "header": lambda key: response.headers.get(key),
            "regex": lambda part, pattern: self._extract_regex(
                {"config": {"regex_patterns": [pattern]}, "part": part}, response
            )
        }

        for expr in expressions:
            try:
                # 解析简单表达式（如"status_code() == 200 ? header('X-Token') : ''"）
                # 此处简化实现，仅支持提取类表达式（如"header('X-Token')"、"regex(body, 'pattern')"）
                if "header(" in expr:
                    key = expr.split("'", 2)[1]  # 提取header('key')中的key
                    return dsl_functions["header"](key)
                elif "regex(" in expr:
                    part, pattern = expr.split(", ", 1)
                    part = part.split("(", 1)[1].strip("'")  # 提取part
                    pattern = pattern.strip("')")  # 提取pattern
                    return dsl_functions["regex"](part, pattern)
                elif "status_code()" in expr:
                    return str(dsl_functions["status_code"]())
                elif "len(" in expr:
                    part = expr.split("(", 1)[1].strip(")")  # 提取len(part)中的part
                    return str(dsl_functions["len"](part))
            except Exception:
                continue  # 忽略表达式错误
        return None

    # ------------------------------
    # 主提取方法
    # ------------------------------
    def extract(self, response) -> Dict[str, Optional[str]]:
        """
        对单个响应执行所有提取器
        :param response: requests.Response对象
        :return: {提取器名称: 提取结果}
        """
        self.results = {}
        for ext in self.extractors:
            ext_type = ext.get("type")
            name = ext.get("name")
            if not ext_type or not name:
                continue  # 跳过无效配置

            # 根据类型调用对应提取方法
            if ext_type == "regex":
                self.results[name] = self._extract_regex(ext, response)
            elif ext_type == "kval":
                self.results[name] = self._extract_kval(ext, response)
            elif ext_type == "json":
                self.results[name] = self._extract_json(ext, response)
            elif ext_type == "xpath":
                self.results[name] = self._extract_xpath(ext, response)
            elif ext_type == "dsl":
                self.results[name] = self._extract_dsl(ext, response)
            else:
                self.results[name] = None  # 不支持的类型

        return self.results


# ------------------------------
# 使用示例
# ------------------------------
if __name__ == "__main__":
    # 模拟响应对象（模拟requests.Response）
    class MockResponse:
        def __init__(self, text, headers=None, status_code=200):
            self.text = text  # 响应体
            self.headers = headers or {}  # 响应头
            self.status_code = status_code  # 状态码

    # 1. 测试数据准备
    # 包含XML/HTML/JSON/键值对的混合响应示例
    test_response = MockResponse(
        text='''
            <html>
                <form>
                    <input type="hidden" name="csrf_token" value="csrf_123">
                </form>
            </html>
            {"user": {"id": 100, "name": "test"}, "token": "json_token_456"}
        ''',
        headers={
            "X-Token": "header_token_789",
            "Content-Length": "200",
            "Set-Cookie": "session=abc; Path=/"
        },
        status_code=200
    )

    # 2. 提取器配置（包含所有类型）
    extractor_config = {
        "extractors": [
            # 正则提取器：从HTML中提取csrf_token
            {
                "type": "regex",
                "name": "regex_csrf",
                "part": "body",
                "group": 1,
                "config": {
                    "regex_patterns": ['name="csrf_token" value="(.*?)"']
                }
            },
            # kval提取器：从响应头提取X-Token
            {
                "type": "kval",
                "name": "kval_header_token",
                "part": "header",
                "config": {"key": "X-Token"}
            },
            # JSON提取器：从JSON中提取user.id
            {
                "type": "json",
                "name": "json_user_id",
                "part": "body",
                "config": {"json_path": ["$.user.id", "$.user.name"]}
            },
            # XPath提取器：从HTML中提取input标签的value
            {
                "type": "xpath",
                "name": "xpath_input_value",
                "part": "body",
                "config": {"xpath": ["//input[@name='csrf_token']/@value"]}
            },
            # DSL提取器：复杂逻辑提取（状态码、响应头、正则组合）
            {
                "type": "dsl",
                "name": "dsl_combined",
                "config": {
                    "dsl": [
                        "status_code()",  # 提取状态码
                        "header('Content-Length')",  # 提取响应头长度
                        "regex(body, 'token: (.*?)')"  # 从body正则提取
                    ]
                }
            }
        ]
    }

    # 3. 执行提取
    extractor = Extractor(extractor_config)
    results = extractor.extract(test_response)

    # 4. 打印结果
    print("提取结果汇总：")
    for name, value in results.items():
        print(f"{name}: {value}")