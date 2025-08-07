import yaml
import re
import json
from typing import Dict, List, Any


class RequestPreprocessor:
    """POC预处理工具，区分raw和normal类型HTTP请求，移除request中的variable字段"""

    def __init__(self, poc_path: str):
        self.poc_path = poc_path
        self.poc_data = self._load_poc()
        self.processed_data = {
            "variables": {},  # 保留variables字段（变量键值对）
            "request": []  # 请求流程（移除variable字段）
        }

    def _load_poc(self) -> Dict[str, Any]:
        """加载YAML格式POC"""
        try:
            with open(self.poc_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"POC加载失败: {str(e)}")

    def _parse_variables(self) -> None:
        """解析变量为原始字符串格式（保留variables字段）"""
        # 解析variables字段
        variables = self.poc_data.get("variables", {})
        for var_name, var_value in variables.items():
            self.processed_data["variables"][var_name] = var_value

        # 解析payloads字段
        payloads = self.poc_data.get("payloads", {})
        for payload_name, payload_value in payloads.items():
            if isinstance(payload_value, list) and payload_value:
                self.processed_data["variables"][payload_name] = payload_value[0]
            else:
                self.processed_data["variables"][payload_name] = payload_value

    def _parse_requests(self) -> None:
        """区分解析raw和normal类型的HTTP请求，移除variable字段"""
        http_sections = self.poc_data.get("http", [])
        for section in http_sections:
            # 1. 处理raw类型请求
            if "raw" in section:
                self.processed_data["request"].append({"type": "raw"})
                raw_requests = section["raw"]
                raw_requests = [raw_requests] if not isinstance(raw_requests, list) else raw_requests

                for step, raw in enumerate(raw_requests, 1):
                    # 清理raw请求内容（不提取variable字段）
                    cleaned_raw = "\n".join([line.strip() for line in raw.strip().split("\n")]).strip()
                    self.processed_data["request"].append({
                        "step": step,
                        "body": [cleaned_raw]  # 仅保留body，移除variable
                    })

            # 2. 处理normal类型请求
            else:
                self.processed_data["request"].append({"type": "normal"})
                # 提取请求方法（默认GET）
                method = section.get("method", "GET").upper()

                # 提取路径（确保为数组格式）
                path = section.get("path", ["/"])
                if isinstance(path, str):
                    path = [path]  # 转为数组格式
                elif not isinstance(path, list):
                    path = ["/"]  # 兜底默认值

                # 添加normal类型请求结构（不包含variable字段）
                self.processed_data["request"].append({
                    "method": method,
                    "path": path  # 仅保留method和path，移除variable
                })

    def generate_json(self) -> str:
        """生成最终JSON结果（不含variable字段）"""
        self._parse_variables()
        self._parse_requests()

        json_str = json.dumps(self.processed_data, indent=2, ensure_ascii=False)
        return json_str


# 使用示例
if __name__ == "__main__":
    poc_path = "pocs/http/cves/2023/CVE-2023-26469.yaml"  # 替换为你的POC路径
    try:
        processor = RequestPreprocessor(poc_path)
        json_path = "output_without_variable.json"
        request_report = processor.generate_json()
        print(request_report)
    except Exception as e:
        print(f"处理失败：{str(e)}")