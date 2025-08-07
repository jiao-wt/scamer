import yaml
import json
from typing import Dict, Any,List
import poc_variable


class RequestPreprocessor:
    """POC预处理工具，完善对HTTP请求字段的提取（支持raw和normal类型）"""

    def __init__(self, poc_path: str):
        self.poc_path = poc_path
        self.poc_data = self._load_poc()
        self.processed_data = {
            "request": []  # 保留请求流程，不含variables字段
        }

    def _load_poc(self) -> Dict[str, Any]:
        """加载YAML格式POC"""
        try:
            with open(self.poc_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"POC加载失败: {str(e)}")

    def _parse_raw_requests(self, raw_requests: List[str]) -> None:
        """解析raw类型请求（保持原始报文结构，特别处理请求头与体之间的两个空行）"""
        self.processed_data["request"].append({"type": "raw"})  # 标记类型
        for step, raw in enumerate(raw_requests, 1):
            # 保留原始报文的空行结构，仅去除每行首尾多余空格
            cleaned_lines = [line.rstrip() for line in raw.splitlines()]
            # 重新拼接以保留原始空行布局（包括请求头与体之间的两个空行）
            cleaned_raw = "\n".join(cleaned_lines).strip('\n')
            self.processed_data["request"].append({
                "step": step,
                "body": [cleaned_raw]  # 以列表形式保留原始报文
            })

    def _parse_normal_requests(self, normal_sections: List[Dict[str, Any]]) -> None:
        """解析normal类型请求（提取headers、body、params等字段）"""
        self.processed_data["request"].append({"type": "normal"})  # 标记类型
        for step, section in enumerate(normal_sections, 1):
            # 基础字段：方法和路径
            method = section.get("method", "GET").upper()
            path = section.get("path", "/")
            # 确保path为列表（兼容多路径场景）
            if isinstance(path, str):
                path = [path]
            elif not isinstance(path, list):
                path = ["/"]

            # 提取headers（默认空字典）
            headers = section.get("headers", {})
            # 确保headers为字典（兼容YAML中的列表形式，如["Key: Value"]）
            if isinstance(headers, list):
                headers = {
                    k.strip(): v.strip()
                    for line in headers
                    if isinstance(line, str) and ":" in line
                    for k, v in [line.split(":", 1)]
                }

            # 提取查询参数（params）
            params = section.get("params", {})
            # 确保params为字典（兼容查询字符串形式）
            if isinstance(params, str):
                params = dict(
                    param.split("=", 1)
                    for param in params.split("&")
                    if "=" in param
                )

            # 提取请求体（body）
            body = section.get("body", "")
            # 处理表单类型body（如果是字典，转为urlencoded格式）
            if isinstance(body, dict):
                body = "&".join([f"{k}={v}" for k, v in body.items()])

            # 提取cookie（优先从headers取，其次单独字段）
            cookie = section.get("cookie", "")
            if not cookie and "Cookie" in headers:
                cookie = headers["Cookie"]

            # 整合normal类型请求结构
            self.processed_data["request"].append({
                "step": step,
                "method": method,
                "path": path,
                "headers": headers,
                "params": params,
                "body": body,
                "cookie": cookie
            })

    def _parse_requests(self) -> None:
        """区分解析raw和normal类型HTTP请求，完善字段提取"""
        http_sections = self.poc_data.get("http", [])
        if not isinstance(http_sections, list):
            http_sections = [http_sections]  # 兼容单请求场景

        # 分离raw和normal类型请求
        raw_requests = []
        normal_sections = []
        for section in http_sections:
            if not isinstance(section, dict):
                continue  # 跳过无效结构
            if "raw" in section:
                # 收集raw请求（支持单条或多条）
                raw = section["raw"]
                if isinstance(raw, list):
                    raw_requests.extend(raw)
                else:
                    raw_requests.append(str(raw))
            else:
                # 收集normal请求
                normal_sections.append(section)

        # 解析raw类型请求
        if raw_requests:
            self._parse_raw_requests(raw_requests)

        # 解析normal类型请求
        if normal_sections:
            self._parse_normal_requests(normal_sections)

    def generate_json(self) -> str:
        """生成包含完整HTTP字段的JSON结果"""
        self._parse_requests()
        return json.dumps(self.processed_data, indent=2, ensure_ascii=False)



class MatcherPreprocessor:
    """匹配器预处理工具, 处理matcher字段"""

    def __init__(self, poc_path: str):
        self.poc_path = poc_path
        self.poc_data = self._load_poc()
        self.processed_matchers = {
            "matchers": [],  # 所有匹配器配置
            "matchers_condition": "or",  # 匹配器间条件（默认or）
            "global_matchers": False,  # 是否为全局匹配器
            "internal_matchers_count": 0,  # 内部匹配器数量
            "types_distribution": {}  # 匹配器类型分布统计
        }
        # 初始化时自动解析匹配器
        self._parse_matchers()

    def _load_poc(self) -> Dict[str, Any]:
        """加载YAML格式POC"""
        try:
            with open(self.poc_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"POC加载失败: {str(e)}")

    def _parse_single_matcher(self, matcher: Dict[str, Any]) -> Dict[str, Any]:
        """解析单个匹配器的详细配置"""
        matcher_type = matcher.get("type")
        parsed = {
            "type": matcher_type,
            "part": matcher.get("part", "status"),  # 默认匹配body
            "condition": matcher.get("condition", "or"),  # 单个匹配器内部条件
            "negative": matcher.get("negative", False),  # 负匹配标记
            "internal": matcher.get("internal", False),  # 内部匹配器标记
            "name": matcher.get("name"),  # 匹配器名称（可选）
            "config": {}  # 匹配器具体配置
        }

        # 根据匹配器类型提取专属配置
        if matcher_type == "status":
            parsed["config"]["status_codes"] = matcher.get("status", [])
        elif matcher_type == "word":
            parsed["config"]["words"] = matcher.get("words", [])
            parsed["config"]["case_sensitive"] = matcher.get("case_sensitive", False)
        elif matcher_type == "regex":
            parsed["config"]["regex_patterns"] = matcher.get("regex", [])
            parsed["config"]["case_sensitive"] = matcher.get("case_sensitive", False)
        elif matcher_type == "binary":
            parsed["config"]["binary_patterns"] = matcher.get("binary", [])
            parsed["config"]["encoding"] = matcher.get("encoding", "hex")  # 支持hex/base64
        elif matcher_type == "xpath":
            parsed["config"]["xpath_queries"] = matcher.get("xpath", [])
            parsed["config"]["words"] = matcher.get("words", [])  # xpath结果需包含的词
        elif matcher_type == "dsl":
            parsed["config"]["expressions"] = matcher.get("dsl", [])
        elif matcher_type == "size":
            parsed["config"]["size"] = matcher.get("size")  # 支持精确值或范围（如1024-2048）
        elif matcher_type == "header":
            parsed["config"]["header_names"] = matcher.get("name", [])
            parsed["config"]["values"] = matcher.get("value", [])

        return parsed

    def _parse_matchers(self) -> None:
        """解析POC中所有匹配器并统计信息"""
        http_sections = self.poc_data.get("http", [])
        # 确保http_sections是列表（兼容单条目情况）
        if not isinstance(http_sections, list):
            http_sections = [http_sections]

        for section in http_sections:
            # 处理全局匹配器标记
            if section.get("global_matchers", False):
                self.processed_matchers["global_matchers"] = True

            # 提取匹配器间组合条件（and/or）
            self.processed_matchers["matchers_condition"] = section.get("matchers-condition", "or")

            # 解析每个匹配器
            matchers = section.get("matchers", [])
            if not isinstance(matchers, list):
                matchers = [matchers]

            for matcher in matchers:
                parsed_matcher = self._parse_single_matcher(matcher)
                self.processed_matchers["matchers"].append(parsed_matcher)

                # 更新统计信息
                matcher_type = parsed_matcher["type"]
                self.processed_matchers["types_distribution"][matcher_type] = (
                    self.processed_matchers["types_distribution"].get(matcher_type, 0) + 1
                )

                # 统计内部匹配器数量
                if parsed_matcher["internal"]:
                    self.processed_matchers["internal_matchers_count"] += 1

    def get_processed_result(self) -> Dict[str, Any]:
        """返回预处理后的字典结果"""
        return self.processed_matchers

    def generate_json(self) -> str:
        """基于字典结果生成JSON字符串"""
        return json.dumps(self.get_processed_result(), indent=2, ensure_ascii=False)



class ExtractorPreprocessor:
    """Nuclei POC提取器预处理工具, 处理extractor字段"""

    def __init__(self, poc_path: str):
        self.poc_path = poc_path
        self.poc_data = self._load_poc()
        self.processed_extractors = {
            "extractors": [],  # 所有提取器配置
            "dynamic_extractors_count": 0,  # 动态提取器（internal: true）数量
            "types_distribution": {}  # 提取器类型分布统计
        }
        # 初始化时自动解析提取器
        self._parse_extractors()

    def _load_poc(self) -> Dict[str, Any]:
        """加载YAML格式POC"""
        try:
            with open(self.poc_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"POC加载失败: {str(e)}")

    def _parse_single_extractor(self, extractor: Dict[str, Any]) -> Dict[str, Any]:
        """解析单个提取器的详细配置"""
        extractor_type = extractor.get("type")
        parsed = {
            "type": extractor_type,
            "name": extractor.get("name"),  # 提取后变量名（动态提取器必需）
            "part": extractor.get("part", "body"),  # 提取的响应部分（body/header/all）
            "internal": extractor.get("internal", False),  # 是否为动态提取器（内部使用）
            "group": extractor.get("group", 0),  # 正则分组（默认0取完整匹配）
            "config": {}  # 提取器类型专属配置
        }

        # 根据提取器类型解析专属配置
        if extractor_type == "regex":
            parsed["config"]["regex_patterns"] = extractor.get("regex", [])
        elif extractor_type == "kval":
            parsed["config"]["keys"] = extractor.get("kval", [])  # 键值对中的键（需替换-为_）
        elif extractor_type == "json":
            parsed["config"]["jq_expressions"] = extractor.get("json", [])  # JQ风格表达式
        elif extractor_type == "xpath":
            parsed["config"]["xpath_queries"] = extractor.get("xpath", [])
            parsed["config"]["attribute"] = extractor.get("attribute")  # 可选：提取节点属性
        elif extractor_type == "dsl":
            parsed["config"]["dsl_expressions"] = extractor.get("dsl", [])  # DSL表达式
        # 新增常见提取器类型支持
        elif extractor_type == "header":
            parsed["config"]["header_names"] = extractor.get("name", [])  # 提取指定响应头
        elif extractor_type == "cookie":
            parsed["config"]["cookie_names"] = extractor.get("name", [])  # 提取指定Cookie

        return parsed

    def _parse_extractors(self) -> None:
        """解析POC中的所有提取器"""
        # 处理HTTP部分的提取器
        http_sections = self.poc_data.get("http", [])
        # 确保http_sections是列表（兼容单条目情况）
        if not isinstance(http_sections, list):
            http_sections = [http_sections]

        for section in http_sections:
            extractors = section.get("extractors", [])
            # 确保extractors是列表
            if not isinstance(extractors, list):
                extractors = [extractors]

            for ext in extractors:
                parsed_ext = self._parse_single_extractor(ext)
                self.processed_extractors["extractors"].append(parsed_ext)

                # 更新类型分布统计
                ext_type = parsed_ext["type"]
                self.processed_extractors["types_distribution"][ext_type] = (
                        self.processed_extractors["types_distribution"].get(ext_type, 0) + 1
                )

                # 统计动态提取器数量（internal: true）
                if parsed_ext["internal"]:
                    self.processed_extractors["dynamic_extractors_count"] += 1

    def get_processed_result(self) -> Dict[str, Any]:
        """返回预处理后的字典结果"""
        return self.processed_extractors

    def generate_json(self) -> str:
        """生成JSON格式的结果（基于字典结果）"""
        return json.dumps(self.get_processed_result(), indent=2, ensure_ascii=False)



# 使用示例
if __name__ == "__main__":
    poc_path = "http/cves/2023/CVE-2023-26469.yaml"  # 替换为你的POC路径
    variable_values = {'{{csrf}}': 'csrf',
                       '{{date_time("%Y-%M-%D")}}': '2025-08-02',
                       '{{header}}': '5UPVYRITOYEN', '{{Hostname}}': 'example.com:80',
                       '{{payload}}': "<?php if(isset($_SERVER['HTTP_5UPVYRITOYEN'])){echo md5('CVE-2023-26469');unlink(__FILE__);} ?>",
                       '{{to_upper(rand_base(12))}}': 'FSMEGTXYJQQJ'}
    try:
        # http字段解析
        request_processor = RequestPreprocessor(poc_path)
        request_report = request_processor.generate_json()
        print(request_report)

        # 对http字段中的变量进行替换
        poc_request = poc_variable.replace_poc_variables(request_report, variable_values)
        print(type(poc_request))

        # mathcer字段解析
        matcher_processor = MatcherPreprocessor(poc_path)
        matcher_report = matcher_processor.get_processed_result()
        print(matcher_report)

        # extractor字段解析
        extractor_processor = ExtractorPreprocessor(poc_path)
        extractor_report = extractor_processor.get_processed_result()
        print(extractor_report)

    except Exception as e:
        print(f"处理失败：{str(e)}")
