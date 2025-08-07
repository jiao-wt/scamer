import re
import json
import request_prec
#import pocs.poc_prec
from typing import Set, List, Any, Dict
import helper_functions


def extract_variables_from_yaml(content: str) -> Set[str]:
    """从YAML内容中提取所有变量，包括{{interactsh-url}}"""
    # 基础变量：{{变量名}}
    basic_pattern = r'{{([a-zA-Z0-9_]+)}}'
    # 函数变量：{{函数名(参数)}}
    function_pattern = r'{{[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)}}'
    # 嵌套变量：{{...}} 结构
    nested_pattern = r'{{(?:[^{}]+|{{[^}]*}})*}}'
    # 新增：明确匹配interactsh-url变量
    interactsh_pattern = r'{{interactsh-url}}'

    variables = set()

    # 提取基础变量
    basic_matches = re.findall(basic_pattern, content)
    variables.update([f"{{{{{var}}}}}" for var in basic_matches])

    # 提取函数变量
    function_matches = re.findall(function_pattern, content)
    variables.update(function_matches)

    # 提取嵌套变量
    nested_matches = re.findall(nested_pattern, content)
    variables.update(nested_matches)

    # 新增：提取interactsh-url变量
    interactsh_matches = re.findall(interactsh_pattern, content)
    variables.update(interactsh_matches)

    return variables


def process_poc_file(file_path: str) -> List[str]:
    """处理单个POC文件，提取变量并返回列表（包含{{interactsh-url}}）"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            variables_set = extract_variables_from_yaml(content)
            # 转换为排序后的列表
            return sorted(variables_set, key=lambda x: x.lower())
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
        return []


def variables_colect(poc_yaml, asset):
    POC_FILE = "pocs/CVE-2023-26469.yaml"  # 单个POC文件路径

    print(f"开始处理单个POC文件: {poc_yaml}...")
    variables_list = process_poc_file(poc_yaml)

    # 新增：如果包含{{interactsh-url}}，提示输入域名并替换
    if '{{interactsh-url}}' in variables_list:
        print("\n检测到{{interactsh-url}}变量，需要手动输入替换的域名")
        interactsh_domain = input("请输入用于替换{{interactsh-url}}的域名: ").strip()
        # 确保输入有效
        while not interactsh_domain:
            print("域名不能为空，请重新输入")
            interactsh_domain = input("请输入用于替换{{interactsh-url}}的域名: ").strip()

    print(f"提取到的变量（共 {len(variables_list)} 个）:")

    with open(asset, encoding='utf-8') as f:
        Asset = json.load(f)

    target_ip = Asset[0]['ip']
    target_port = Asset[0]['port']
    variable_values = helper_functions.get_variable_values(variables_list, target_ip, target_port)

    # 新增：将输入的域名添加到变量映射中
    if '{{interactsh-url}}' in variables_list:
        variable_values['{{interactsh-url}}'] = interactsh_domain

    #processor = pocs.poc_prec.RequestPreprocessor(POC_FILE)
    processor = request_prec.RequestPreprocessor(POC_FILE)
    request_report = processor.generate_json()

    # 完成对variables字段变量的替换
    test = helper_functions.reporter_variables(request_report)
    test = helper_functions.replace_dict_variables(test)

    # 补充poc中variables字段的变量
    variables_values = helper_functions.variable_out(variable_values, test)
    return variables_values


def replace_poc_variables(poc_str: str, var_mapping: Dict[str, str]) -> Dict[str, Any]:
    """
    处理字符串格式的POC数据，替换其中的变量（包括{{interactsh-url}}）后返回字典类型
    """
    # 尝试解析为JSON
    try:
        poc_data = json.loads(poc_str)
        is_json = True
    except json.JSONDecodeError:
        poc_data = poc_str
        is_json = False

    # 匹配变量名的正则（提取{{}}中的内容，忽略前后空格）
    var_name_pattern = re.compile(r'{{\s*(.*?)\s*}}')

    def replace_in_data(data: Any) -> Any:
        """递归处理数据中的变量替换，包括{{interactsh-url}}"""
        if isinstance(data, str):
            processed_str = data
            for var, value in var_mapping.items():
                # 提取变量名（如从{{csrf}}中提取csrf）
                var_match = var_name_pattern.match(var)
                if not var_match:
                    continue  # 非标准变量格式，跳过
                var_name = var_match.group(1)

                # 变量名与值相同时不替换
                if var_name == value:
                    continue

                # 替换字符串中的变量（转义特殊字符确保精确匹配）
                processed_str = re.sub(re.escape(var), str(value), processed_str)
            return processed_str

        elif isinstance(data, dict):
            return {k: replace_in_data(v) for k, v in data.items()}

        elif isinstance(data, list):
            return [replace_in_data(item) for item in data]

        else:
            return data  # 其他类型（数字、布尔等）不处理

    # 执行替换
    replaced_data = replace_in_data(poc_data)

    # 确保返回字典类型
    if isinstance(replaced_data, dict):
        return replaced_data
    elif isinstance(replaced_data, list):
        return {"data": replaced_data}  # 列表类型包装为字典
    else:
        # 普通字符串包装为字典
        return {"content": replaced_data}


def replace_variable(variables_dict, variable):
    """替换变量字典中的值，支持{{interactsh-url}}"""
    for key1, value1 in variables_dict.items():
        for key2, value2 in variable.items():
            if variables_dict.get(key1) == key2:
                variables_dict[key1] = variable[key2]

    return variables_dict


if __name__ == "__main__":
    POC_FILE = "pocs/http/cves/2023/CVE-2023-3368.yaml"  # 单个POC文件路径
    Asset_file = 'asset.json'
    variable_values = variables_colect(POC_FILE, Asset_file)
    print(variable_values)

    # 测试包含{{interactsh-url}}的替换
    a = {
        '{{csrf}}': 'csrf',
        '{{interactsh-url}}': 'original-interactsh.com',
        '{{date_time("%Y-%M-%D")}}': '2025-08-05'
    }
    b = {'csrf': '7a8c43be6da3d151cb76e0a526e7212e'}
    a = replace_variable(a, b)
    print("\n替换后的变量字典:")
    print(a)