import re
import math
from typing import Dict, List, Any, Union, Callable
from requests import Response
from lxml import etree  # 需安装lxml库：pip install lxml


class Matcher:
    def __init__(self, matchers_config: Dict[str, Any]):
        """初始化匹配器，支持word/status/regex/dsl/xpath/size类型"""
        self.matchers = matchers_config.get("matchers", [])
        self.matchers_condition = matchers_config.get("matchers_condition", "or")
        self.global_matchers = matchers_config.get("global_matchers", False)
        self.internal_matchers_count = matchers_config.get("internal_matchers_count", 0)

        # 注册DSL函数（扩展可添加更多函数）
        self.dsl_functions = {
            "len": self._dsl_len,
            "status_code": self._dsl_status_code,
            "contains": self._dsl_contains,
            "regex": self._dsl_regex,
            "to_int": self._dsl_to_int,
        }

    def _parse_part(self, part: str) -> (str, int):
        """解析part字段（如header_3 → (header, 2)，索引0开始）"""
        part = part.lower()
        if "_" in part:
            part_type, idx_str = part.split("_", 1)
            try:
                req_index = int(idx_str) - 1  # 转为0基索引
                return part_type, max(0, req_index)  # 避免负索引
            except ValueError:
                return part, 0
        return part, 0

    def _get_response_part(self, responses: List[Response], part: str, request_index: int = None) -> Union[
        str, int, Dict, bytes]:
        """
        获取响应指定部分内容（支持多请求响应）
        :param responses: 所有请求的响应列表
        :param part: 匹配部分（如body_3、header、interactsh_protocol）
        :param request_index: 强制指定请求索引（覆盖part中的索引）
        """
        # 解析part中的索引（如header_3）
        part_type, parsed_idx = self._parse_part(part)
        # 优先使用外部指定的request_index，否则使用part中的索引
        req_index = request_index if request_index is not None else parsed_idx
        # 索引越界保护（取最后一个响应）
        req_index = min(req_index, len(responses) - 1) if responses and req_index >= 0 else 0
        response = responses[req_index] if responses else None

        if not response:
            return ""

        # 扩展支持interactsh_protocol（模拟交互协议字段）
        if part_type == "interactsh_protocol":
            return "http"  # 示例默认值

        if part_type == "body":
            return response.text
        elif part_type == "header":
            return dict(response.headers)
        elif part_type == "status":
            return response.status_code
        elif part_type == "content_length":
            return int(response.headers.get("Content-Length", len(response.content)))
        elif part_type == "raw":
            return response.content  # 原始字节
        elif part_type == "duration":
            return response.elapsed.total_seconds()  # 响应时间（秒）
        else:
            return ""  # 未知part返回空

    # ------------------------------
    # 基础匹配器类型（已实现）
    # ------------------------------
    def _check_word(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        part = matcher.get("part", "body")
        condition = matcher.get("condition", "or")
        words = matcher["config"].get("words", [])
        content = str(self._get_response_part(responses, part, request_index))
        matches = [word in content for word in words]
        result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: word | 匹配部分: {part} | 条件: {condition}")
        print(f"  预期关键词: {words}")
        print(f"  实际内容: {content[:100]}...")  # 截断长内容
        print(f"  单匹配结果: {result}\n")
        return result

    def _check_status(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        part = matcher.get("part", "status")
        condition = matcher.get("condition", "or")
        # 兼容status和status_codes两种配置键
        status_list = matcher["config"].get("status", []) or matcher["config"].get("status_codes", [])
        target_status = self._get_response_part(responses, part, request_index)
        matches = [target_status == status for status in status_list]
        result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: status | 匹配部分: {part} | 条件: {condition}")
        print(f"  预期状态码: {status_list}")
        print(f"  实际状态码: {target_status}")
        print(f"  单匹配结果: {result}\n")
        return result

    def _check_regex(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        part = matcher.get("part", "body")
        condition = matcher.get("condition", "or")
        regex_list = matcher["config"].get("regex", [])
        content = str(self._get_response_part(responses, part, request_index))
        matches = []
        for regex in regex_list:
            try:
                matches.append(bool(re.search(regex, content, re.IGNORECASE)))
            except re.error:
                matches.append(False)
        result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: regex | 匹配部分: {part} | 条件: {condition}")
        print(f"  预期正则: {regex_list}")
        print(f"  实际内容: {content[:100]}...")  # 截断长内容
        print(f"  单匹配结果: {result}\n")
        return result

    # ------------------------------
    # 新增匹配器类型：size（响应大小匹配）
    # ------------------------------
    def _check_size(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        """检查响应大小（支持精确值或范围，如1024、500-2000）"""
        part = matcher.get("part", "content_length")
        condition = matcher.get("condition", "or")
        size_config = matcher["config"].get("size", [])
        target_size = self._get_response_part(responses, part, request_index)

        if not isinstance(target_size, (int, float)):
            result = False
        else:
            matches = []
            for size_str in size_config:
                if "-" in size_str:
                    try:
                        min_s, max_s = map(int, size_str.split("-", 1))
                        matches.append(min_s <= target_size <= max_s)
                    except ValueError:
                        continue
                else:
                    try:
                        size = int(size_str)
                        matches.append(target_size == size)
                    except ValueError:
                        continue
            result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: size | 匹配部分: {part} | 条件: {condition}")
        print(f"  预期大小: {size_config}")
        print(f"  实际大小: {target_size}")
        print(f"  单匹配结果: {result}\n")
        return result

    # ------------------------------
    # 新增匹配器类型：xpath（XML内容匹配）
    # ------------------------------
    def _check_xpath(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        """从XML响应中执行xpath查询，检查结果是否匹配预期"""
        part = matcher.get("part", "body")
        condition = matcher.get("condition", "or")
        xpath_queries = matcher["config"].get("query", [])  # xpath查询列表
        expected_words = matcher["config"].get("words", [])  # 预期结果

        content = self._get_response_part(responses, part, request_index)
        if not isinstance(content, str):
            result = False
        else:
            try:
                tree = etree.fromstring(content.encode("utf-8"))
            except etree.XMLSyntaxError:
                result = False
            else:
                xpath_results = []
                for query in xpath_queries:
                    try:
                        results = tree.xpath(query)
                        xpath_results.extend([str(res) for res in results])
                    except etree.XPathError:
                        continue
                matches = [any(word in res for res in xpath_results) for word in expected_words]
                result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: xpath | 匹配部分: {part} | 条件: {condition}")
        print(f"  预期结果: {expected_words}")
        print(f"  XPath查询: {xpath_queries}")
        print(f"  实际结果: {xpath_results[:3]}...")  # 显示前3个结果
        print(f"  单匹配结果: {result}\n")
        return result

    # ------------------------------
    # 新增匹配器类型：dsl（表达式匹配）
    # ------------------------------
    def _dsl_len(self, args: List[Any]) -> int:
        """DSL函数：计算长度（如len(body)）"""
        if not args:
            return 0
        return len(str(args[0]))

    def _dsl_status_code(self, args: List[Any]) -> int:
        """DSL函数：获取状态码（如status_code()）"""
        return args[0] if args else 0  # args[0]传入响应状态码

    def _dsl_contains(self, args: List[Any]) -> bool:
        """DSL函数：检查包含关系（如contains(body, "error")）"""
        if len(args) < 2:
            return False
        return str(args[1]) in str(args[0])

    def _dsl_regex(self, args: List[Any]) -> bool:
        """DSL函数：正则匹配（如regex(body, "error.*")）"""
        if len(args) < 2:
            return False
        try:
            return bool(re.search(str(args[1]), str(args[0])))
        except re.error:
            return False

    def _dsl_to_int(self, args: List[Any]) -> int:
        """DSL函数：转为整数（如to_int(content_length)）"""
        if not args:
            return 0
        try:
            return int(args[0])
        except (ValueError, TypeError):
            return 0

    def _parse_dsl_expression(self, expr: str, request_index: int = None) -> Callable[[List[Response]], bool]:
        """解析DSL表达式（如"len(body) > 100 && status_code() == 200"）"""
        op_pattern = re.compile(r"(\S+)\s*(==|!=|>|<|>=|<=)\s*(\S+)")
        match = op_pattern.match(expr.strip())
        if not match:
            return lambda _: False  # 表达式无效

        left_expr, op, right_val = match.groups()

        func_pattern = re.compile(r"(\w+)\(([^)]*)\)")
        func_match = func_pattern.match(left_expr)
        if not func_match:
            return lambda _: False

        func_name, func_arg = func_match.groups()
        func = self.dsl_functions.get(func_name)
        if not func:
            return lambda _: False

        def evaluate(responses: List[Response]) -> bool:
            arg_part = func_arg.strip()
            arg_value = self._get_response_part(responses, arg_part, request_index)
            if func_name == "status_code":
                arg_value = self._get_response_part(responses, "status", request_index)
            left_val = func([arg_value])
            try:
                right_val_parsed = int(right_val)
            except ValueError:
                right_val_parsed = right_val.strip("'\"")
            ops = {
                "==": lambda a, b: a == b,
                "!=": lambda a, b: a != b,
                ">": lambda a, b: a > b,
                "<": lambda a, b: a < b,
                ">=": lambda a, b: a >= b,
                "<=": lambda a, b: a <= b,
            }
            return ops.get(op, lambda a, b: False)(left_val, right_val_parsed)

        return evaluate

    def _check_dsl(self, responses: List[Response], matcher: Dict[str, Any], request_index: int = None) -> bool:
        """检查DSL表达式是否成立（如"len(body) > 1024"）"""
        condition = matcher.get("condition", "or")
        dsl_expressions = matcher["config"].get("dsl", [])  # DSL表达式列表

        matches = []
        for expr in dsl_expressions:
            evaluator = self._parse_dsl_expression(expr, request_index)
            matches.append(evaluator(responses))
        result = self._condition_check(matches, condition)

        # 打印当前匹配器详情
        print(f"  匹配器类型: dsl | 条件: {condition}")
        print(f"  预期表达式: {dsl_expressions}")
        print(f"  单匹配结果: {result}\n")
        return result

    # ------------------------------
    # 通用逻辑
    # ------------------------------
    def _condition_check(self, matches: List[bool], condition: str) -> bool:
        """处理AND/OR条件判断"""
        return all(matches) if condition == "and" else any(matches)

    def match(self, responses: List[Response], request_index: int = None) -> bool:
        """
        执行所有匹配器逻辑，打印每个匹配结果和最终结果
        :param responses: 所有请求的响应列表
        :param request_index: 强制指定匹配的请求索引（None则使用part中的索引）
        :return: 是否满足匹配条件
        """
        if not responses:
            print("无响应数据，匹配失败")
            return False

        # 打印匹配上下文
        target_idx = request_index if request_index is not None else "自动"
        print(f"\n===== 开始匹配（目标请求索引: {target_idx}）=====")
        matcher_results = []

        for i, matcher in enumerate(self.matchers, 1):
            print(f"----- 匹配器 {i}/{len(self.matchers)} -----")
            matcher_type = matcher.get("type")
            negative = matcher.get("negative", False)
            match_result = False

            # 调用对应类型的匹配方法
            if matcher_type == "word":
                match_result = self._check_word(responses, matcher, request_index)
            elif matcher_type == "status":
                match_result = self._check_status(responses, matcher, request_index)
            elif matcher_type == "regex":
                match_result = self._check_regex(responses, matcher, request_index)
            elif matcher_type == "size":
                match_result = self._check_size(responses, matcher, request_index)
            elif matcher_type == "xpath":
                match_result = self._check_xpath(responses, matcher, request_index)
            elif matcher_type == "dsl":
                match_result = self._check_dsl(responses, matcher, request_index)
            else:
                print(f"  未知匹配器类型: {matcher_type}，跳过\n")
                continue

            # 处理反向匹配
            if negative:
                match_result = not match_result
                print(f"  反向匹配后结果: {match_result}")

            matcher_results.append(match_result)

        # 计算最终结果
        final_result = all(matcher_results) if self.matchers_condition == "and" else any(matcher_results)

        # 打印最终结果
        print("\n===== 匹配总结 =====")
        print(f"匹配器组合条件: {self.matchers_condition}")
        print(f"各匹配器结果: {matcher_results}")
        print(f"最终匹配结果: {final_result}\n")
        return final_result


# ------------------------------
# 测试用例
# ------------------------------
if __name__ == "__main__":
    class MockResponse:
        """模拟requests.Response对象"""

        def __init__(self, status_code, text, headers=None, duration=0.5):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.elapsed = type('obj', (object,), {'total_seconds': lambda: duration})()
            self.content = text.encode("utf-8")


    # 准备多请求响应列表
    multi_responses = [
        # 第0个请求
        MockResponse(200, "first response: hello wsConvertPptResponse", {"Content-Length": "100"}),
        # 第1个请求
        MockResponse(404, "not found", {"Content-Length": "50"}),
        # 第2个请求
        MockResponse(200, "third response: http interaction", {"Content-Length": "200"})
    ]

    # 匹配器配置
    test_config = {
        'matchers': [
            # 状态码匹配
            {'type': 'status', 'part': 'status', 'condition': 'or', 'negative': False,
             'config': {'status_codes': [200]}},

            # 关键词匹配
            {'type': 'word', 'part': 'body', 'condition': 'or', 'negative': False,
             'config': {'words': ['wsConvertPptResponse'], 'case_sensitive': False}},

            # interactsh协议匹配
            {'type': 'word', 'part': 'interactsh_protocol', 'condition': 'or', 'negative': False,
             'config': {'words': ['http'], 'case_sensitive': False}},

            # 大小匹配（100-300）
            {'type': 'size', 'part': 'content_length', 'condition': 'or', 'negative': False,
             'config': {'size': ['100-300']}}
        ],
        'matchers_condition': 'and',  # 所有条件需同时满足
        'global_matchers': False,
        'internal_matchers_count': 0
    }

    # 测试匹配第0个请求
    print("=== 测试场景1：匹配第0个请求 ===")
    Matcher(test_config).match(multi_responses, request_index=0)

    # 测试匹配第2个请求
    print("=== 测试场景2：匹配第2个请求 ===")
    Matcher(test_config).match(multi_responses, request_index=2)