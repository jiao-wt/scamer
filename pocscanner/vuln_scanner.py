import json
import sys
import os

# 获取当前脚本所在目录（即 pocscanner/）
current_dir = os.path.dirname(__file__)  # 例如：E:\PyCharm\scamer\pocscanner\
# 将该目录加入 Python 的模块搜索路径

sys.path.append(current_dir)
import poc_variable
import matcher
import extractor
import request_sender
import pocs.poc_prec
import poc_match



def pocscanner(poc_path, Asset_file, protocol='https'):
    # 完成变量的提取与解析
    variable_values = poc_variable.variables_colect(poc_path, Asset_file)
    #print(variable_values)

    # poc请求字段解析
    request_processor = pocs.poc_prec.RequestPreprocessor(poc_path)
    request_report = request_processor.generate_json()
    #print(request_report)

    #对http字段中的变量进行替换
    request_template = poc_variable.replace_poc_variables(request_report, variable_values)
    print(request_template)


    # mathcer字段解析
    matcher_processor = pocs.poc_prec.MatcherPreprocessor(poc_path)
    matchers_config = matcher_processor.get_processed_result()
    #print(matchers_config)


    # extractor字段解析
    extractor_processor = pocs.poc_prec.ExtractorPreprocessor(poc_path)
    extractor_config = extractor_processor.get_processed_result()
    #print(extractor_config)

    responses_list = []


    """ ========== 开始执行扫描 =========="""

    for i in range(1, len(request_template['request'])):
        step_response = request_sender.send_request_from_template(request_template, protocol=protocol, step=i)

        #print(f"请求请求头: {step1_response.request.headers}\n")
        #print(f"请求请求体: {step1_response.request.body}\n")
        #print(f"请求url: {step1_response.request.url}\n")
        #print(f"响应状态码: {step1_response.status_code}\n")
        #print(f"响应头:{step1_response.headers}")

        # 提取器
        # 初始化提取器并执行提取

        extract1 = extractor.Extractor(extractor_config)
        extracted = extract1.extract(step_response)

        # 输出提取结果
        print(f"提取结果: {extracted}")

        variable_values = poc_variable.replace_variable(variable_values, extracted)
        request_template = poc_variable.replace_poc_variables(request_report, variable_values)

        # 存储每个响应
        responses_list.append(step_response)



# 使用匹配器进行对响应进行匹配
    for step in range(len(responses_list)):
        mactcher = matcher.Matcher(matchers_config)
        mactched = mactcher.match(responses_list, step)
        print(f"匹配结果: {mactched}")

def get_poc(assets: str):
    with open(assets, 'r', encoding='utf-8') as f:
        asset = f.read()
        asset = json.loads(asset)
        print(f"根据资产{assets}.json进行poc匹配")
        poc_matcher = poc_match.PocMatcher(asset, poc_root_dir="pocs/http/cves")
    # 执行匹配
        results = poc_matcher.match_assets()
        print(results[0]['matched_pocs'][0]['poc_path'])
        return results
    # 输出结果（包含poc_path）
    #print(json.dumps(results, indent=2, ensure_ascii=False))

def scanner(assets, protocol='https', poc_path=None):
    if poc_path:
        print(f"\n{poc_path}进行扫描\n")
        pocscanner(poc_path, assets, protocol=protocol)

    else:
        print('获取poc')
        pocs = get_poc(assets)
        print(f'共匹配到{len(pocs[0].get('matched_pocs'))}个poc')
        for num in range(len(pocs[0].get('matched_pocs'))):
            if pocs[0].get('matched_pocs')[num]:
                print(f"\n开始根据{pocs[0].get('matched_pocs')[num]['poc_path']}进行扫描\n")
                pocscanner(pocs[0].get('matched_pocs')[num]['poc_path'], assets, protocol=protocol)


if __name__ == "__main__":
    poc_path = 'pocs/http/cves/2023/CVE-2023-3368.yaml'
    Asset_file = '../Assets/asset.json'
    scanner(poc_path=poc_path, assets=Asset_file)

