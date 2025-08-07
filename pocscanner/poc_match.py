import json
import re
import yaml
import os
from packaging import version


class PocInfoParser:
    """解析单个POC的信息（含版本提取）"""

    def __init__(self, poc_path):
        self.poc_path = poc_path  # 保存POC文件路径
        self.poc_data = self._load_poc()
        self.info = {}
        self.versions = []

        if self.poc_data:
            self.info = self._parse_info()
            self.versions = self._extract_versions()

    def _load_poc(self):
        try:
            with open(self.poc_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            # 忽略格式错误的POC
            return None

    def _parse_info(self):
        info = self.poc_data.get("info", {})
        return {
            "id": self.poc_data.get("id", "unknown"),
            "name": info.get("name", "Unknown Vulnerability"),
            "description": info.get("description", "Unknown"),
            "severity": info.get("severity", "unknown"),
            "reference": info.get("reference", []),
            "classification": info.get("classification", {})  # 用于CPE提取
        }

    def _extract_versions(self):
        """从name和description中提取版本范围"""
        content = f"{self.info['name']} {self.info['description']}".lower()

        # 正则匹配常见版本格式
        patterns = [
            # 基础比较符（<=1.0.0、>=2.3.4）
            r"(<=|>=|<|>|==|=)\s*v?([\d\.]+)",
            # 版本范围（v1.0.0 - v2.0.0）
            r"v?([\d\.]+)\s*-\s*v?([\d\.]+)",
            # 模糊描述（up to 3.0、version 2.1 and prior）
            r"(up\s+to|version)\s*v?([\d\.]+)\s*(?:and\s+prior)?",
            # 软件名+版本（如Jorani 1.0.0）
            r"([a-z0-9\-_]+)\s+v?(\d+\.\d+\.\d+)"
        ]

        versions = []
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    # 处理不同格式的匹配结果
                    if len(match) == 2:
                        # 处理 <=1.0.0 或 Jorani 1.0.0
                        if match[0] in ["up to", "version"]:
                            versions.append(f"<= {match[1]}")
                        elif match[0].replace("-", "").isalpha():  # 软件名匹配（如Jorani）
                            versions.append(f"== {match[1]}")
                        else:  # 比较符（如<=、>=）
                            versions.append(f"{match[0]} {match[1]}")
                    elif len(match) == 3:
                        # 处理范围（如1.0.0 - 2.0.0）
                        versions.append(f">= {match[0]} <= {match[2]}")

        # 去重并标准化
        return list(set(versions)) if versions else ["unknown"]

    def get_info(self):
        return self.info

    def get_version(self):
        return self.versions

    def is_version_affected(self, target_version):
        """判断目标版本是否受影响"""
        if not self.versions or "unknown" in self.versions:
            return None  # 无法判断

        try:
            target = version.parse(target_version)
            for constraint in self.versions:
                op, ver_str = constraint.split(' ', 1)
                ver = version.parse(ver_str)

                if (op == "==" and target == ver) or \
                        (op == ">=" and target >= ver) or \
                        (op == "<=" and target <= ver) or \
                        (op == ">" and target > ver) or \
                        (op == "<" and target < ver):
                    return True
            return False
        except:
            return None  # 版本格式错误


class PocMatcher:
    """匹配资产与多级目录中的POC"""

    def __init__(self, assets, poc_root_dir):
        self.assets = assets  # 资产列表
        self.poc_root_dir = poc_root_dir  # POC根目录
        self.poc_parsers = self._load_all_pocs()  # 加载所有POC

    def _load_all_pocs(self):
        """递归加载所有子目录中的POC"""
        poc_parsers = []
        # 遍历根目录及所有子目录
        for root, _, files in os.walk(self.poc_root_dir):
            for file in files:
                if file.endswith(".yaml"):
                    poc_path = os.path.join(root, file)
                    parser = PocInfoParser(poc_path)
                    if parser.poc_data:  # 仅保留有效POC
                        poc_parsers.append(parser)
        return poc_parsers

    def match_assets(self):
        """为每个资产匹配相关POC"""
        results = []
        for asset in self.assets:
            matched_pocs = []
            for parser in self.poc_parsers:
                score = self._calculate_score(asset, parser)
                if score > 0:  # 仅保留有匹配度的POC
                    matched_pocs.append({
                        "poc_id": parser.get_info()["id"],
                        "poc_name": parser.get_info()["name"],
                        "severity": parser.get_info()["severity"],
                        "version_constraint": parser.get_version(),
                        "match_score": score,
                        "poc_path": parser.poc_path  # 添加POC文件路径
                    })
            # 按匹配度排序
            matched_pocs.sort(key=lambda x: x["match_score"], reverse=True)
            results.append({
                "asset": asset,
                "matched_pocs": matched_pocs[:5]  # 取前5个高匹配度POC
            })
        return results

    def _calculate_score(self, asset, parser):
        """计算资产与POC的匹配度（0-100分）"""
        score = 0
        asset_service = asset["service"].lower()
        poc_name = parser.get_info()["name"].lower()

        # 1. 服务名匹配（权重60%）
        if asset_service in poc_name:
            score += 60
            # 2. 版本匹配（权重30%）
            if asset["version"] != "unknown":
                version_check = parser.is_version_affected(asset["version"])
                if version_check is True:
                    score += 30
                elif version_check is False:
                    score -= 20  # 版本不匹配扣分
            # 3. CPE匹配（权重10%，从classification提取）
            cpe = parser.get_info()["classification"].get("cpe", "")
            if asset_service in cpe.lower():
                score += 10

        return max(score, 0)  # 确保分数非负


# 使用示例
if __name__ == "__main__":
    # 示例资产（可从文件加载）
    assets = [
        {
            "ip": "example.com",
            "port": 80,
            "service": "Chamilo LMS",
            "version": "1.11.11"
        }
    ]
    print(type(assets))

    # 初始化匹配器（POC根目录为"pocs"，支持多级子目录）
    matcher = PocMatcher(assets, poc_root_dir="pocs/http/cves")
    # 执行匹配
    results = matcher.match_assets()
    # 输出结果（包含poc_path）
    print(json.dumps(results, indent=2, ensure_ascii=False))