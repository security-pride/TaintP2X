import json
import os
from openai import OpenAI
from zhipuai import ZhipuAI
import requests
import sys

# 全局变量
LOG_DIR = ''

def get_project_names_starting_with_a(log_dir):
    project_names = []
    if os.path.exists(log_dir):
        for item in os.listdir(log_dir):
            item_path = os.path.join(log_dir, item)
            if os.path.isdir(item_path):
                project_names.append(item)
    return project_names

PROJECT_NAMES = get_project_names_starting_with_a(LOG_DIR)
PROJECT_BASE_PATH = ''
LOG_BASE_PATH = ''

def extract_method_by_line(file_path: str, target_line: int) -> str:
    """根据指定行号提取整个方法内容"""
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            
        # 确保目标行在文件范围内
        if target_line < 1 or target_line > len(lines):
            return "目标行号超出文件范围"
            
        # 检查目标行是否为空行
        if not lines[target_line - 1].strip():
            return "目标行是空行"
            
        # 向上查找方法开始
        start_line = target_line - 1
        method_found = False
        while start_line >= 0:
            if lines[start_line].strip().startswith('def '):
                method_found = True
                break
            start_line -= 1
            
        # 如果没有找到方法定义，返回上下文各5行
        if not method_found:
            context_start = max(0, target_line - 6)  # -6是因为行号从1开始
            context_end = min(len(lines), target_line + 5)  # +5是为了包含目标行后的5行
            return f"目标行不在任何方法内部，显示上下文：\n" + ''.join(lines[context_start:context_end])
            
        # 向下查找方法结束（通过缩进判断）
        method_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
        end_line = target_line
        
        # 检查目标行的缩进是否属于该方法
        target_line_content = lines[target_line - 1].rstrip()
        if not target_line_content:  # 空行
            context_start = max(0, target_line - 6)
            context_end = min(len(lines), target_line + 5)
            return f"目标行是空行，显示上下文：\n" + ''.join(lines[context_start:context_end])
            
        target_indent = len(lines[target_line - 1]) - len(lines[target_line - 1].lstrip())
        if target_indent <= method_indent:
            # 如果目标行不在方法内部，返回上下文各5行
            context_start = max(0, target_line - 6)
            context_end = min(len(lines), target_line + 5)
            return f"目标行不在任何方法内部，显示上下文：\n" + ''.join(lines[context_start:context_end])
            
        while end_line < len(lines):
            # 跳过空行
            if not lines[end_line].strip():
                end_line += 1
                continue
            # 如果遇到同级或更低级的缩进，说明方法结束
            current_indent = len(lines[end_line]) - len(lines[end_line].lstrip())
            if current_indent <= method_indent:
                break
            end_line += 1
            
        # 提取方法内容
        method_content = ''.join(lines[start_line:end_line])
        return method_content
        
    except FileNotFoundError:
        return "文件不存在"
    except Exception as e:
        return f"提取方法时出错：{str(e)}"


def extract_vulnerable_issues(base_path: str) -> list:
    """
    提取所有response_output.json中标记为漏洞的issue
    
    Args:
        base_path: 基础路径，例如 'log/CodeFuse-muAgent'
        
    Returns:
        list: 包含所有漏洞issue的列表
    """
    vulnerable_issues = []
    
    try:
        # 遍历目录
        for issue_dir in os.listdir(base_path):
            json_path = os.path.join(base_path, issue_dir, 'response_output.json')
            
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        if data.get('is_vulnerability') == True:
                            vulnerable_issues.append({
                                'issue_number': issue_dir,
                                'file_path': json_path,
                                'data': data
                            })
                    except json.JSONDecodeError:
                        print(f"解析JSON文件失败: {json_path}")
                        continue
    
    except Exception as e:
        print(f"提取漏洞issue时出错: {str(e)}")
    
    return vulnerable_issues


def parse_trace_chain(log_file: str) -> list:
    """
    解析调用链日志文件，提取每个函数调用的详细信息
    
    Args:
        log_file: 日志文件路径
    
    Returns:
        list: 包含每个函数调用信息的列表
    """
    trace_chain = []
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            # 跳过非调用链相关的行
            if not line.strip() or line.startswith('issue') or line.startswith('trace') or line.startswith('quit'):
                continue
                
            # 跳过缺失的trace frame
            if '[Missing trace frame' in line:
                continue
                
            # 分割并清理行
            parts = line.strip().split()
            if len(parts) >= 4:
                # 处理行号和前缀
                start_idx = 0
                for i, part in enumerate(parts):
                    # 跳过行号、+号和箭头
                    if part.isdigit() or part.startswith('+') or part == '-->':
                        start_idx = i + 1
                    else:
                        break
                
                # 提取函数名和参数信息
                func_name = parts[start_idx]
                
                # 提取参数信息（位于函数名和文件路径之间）
                param_start = start_idx + 1
                param_end = len(parts) - 1
                param_info = ' '.join(parts[param_start:param_end]).strip()
                
                location = parts[-1]
                
                # 解析位置信息
                if ':' in location:
                    file_path, line_info = location.rsplit(':', 1)
                    line_nums = line_info.split('|')
                    if len(line_nums) >= 3:
                        start_line, start_col, end_col = line_nums
                else:
                    file_path, start_line, start_col, end_col = location, "unknown", "unknown", "unknown"
                
                trace_chain.append({
                    'function': func_name,
                    'params': param_info,
                    'file_path': file_path,
                    'start_line': start_line,
                    'start_column': start_col,
                    'end_column': end_col
                })
                
    except Exception as e:
        print(f"解析调用链时出错: {str(e)}")
        
    return trace_chain


def get_function_name(full_name: str) -> str:
    """
    从完整的函数名中提取出纯函数名
    """
    return full_name.split('.')[-1]

def find_function_implementation(function_name: str, project_path: str) -> list:
    """
    在项目中查找函数的具体实现
    """
    results = []
    
    for root, _, files in os.walk(project_path):
        for file in files:
            if not file.endswith('.py'):
                continue
                
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for i, line in enumerate(lines):
                    if line.strip().startswith(f'def {function_name}') or \
                       line.strip().startswith(f'async def {function_name}'):
                        method_indent = len(line) - len(line.lstrip())
                        end_line = i + 1
                        
                        while end_line < len(lines):
                            if not lines[end_line].strip():
                                end_line += 1
                                continue
                            current_indent = len(lines[end_line]) - len(lines[end_line].lstrip())
                            if current_indent <= method_indent:
                                break
                            end_line += 1
                        
                        results.append({
                            'file_path': file_path,
                            'content': ''.join(lines[i:end_line]),
                            'line_number': i + 1
                        })
                        
            except Exception as e:
                print(f"读取文件 {file_path} 时出错: {str(e)}")
    
    return results

def get_sanitizer_implementations( analysis_results, trace_chain) -> dict:
    """
    获取分析中提到但未在调用链中出现的过滤函数的具体实现
    
    Args:
        analysis_results: 分析结果列表
        trace_chain: 调用链列表
    
    Returns:
        dict: 过滤函数名称及其实现的字典
    """
    # 收集所有提到的过滤函数，但排除已经在调用链中的函数
    sanitizer_functions = set()
    existing_functions = {get_function_name(call['function']) for call in trace_chain}
    
    for result in analysis_results:
        if result['analysis'].get('has_sanitizer') and result['analysis'].get('sanitizer_functions'):
            sanitizer_functions.update(
                func for func in result['analysis']['sanitizer_functions'] 
                if func not in existing_functions
            )
    
    # 查找过滤函数的具体实现
    sanitizer_implementations = {}
    if sanitizer_functions:
        print(f"\n发现以下过滤函数：{sanitizer_functions}")
        project_path = os.path.join(PROJECT_BASE_PATH, PROJECT_NAME)
        
        for func_name in sanitizer_functions:
            impls = find_function_implementation(func_name, project_path)
            if impls:
                # 如果找到多个实现，使用第一个
                sanitizer_implementations[func_name] = impls[0]['content']
                if len(impls) > 1:
                    print(f"警告：函数 {func_name} 找到多个实现，使用第一个实现")
                    for i, impl in enumerate(impls, 1):
                        print(f"实现 #{i} 位于: {impl['file_path']}:{impl['line_number']}")
            else:
                print(f"未找到函数 {func_name} 的实现")
    
    return sanitizer_implementations

def analyze_trace_with_deepseek(trace_chain: list, log_file: str) -> dict:
    """
    使用DeepSeek分析调用链并评估污点传播可靠性
    
    Args:
        trace_chain: 调用链列表
        log_file: 原始调用链日志文件路径
    """
    # 检查 analysis_results.json 是否已存在
    analysis_results_file = os.path.join(os.path.dirname(log_file), 'analysis_results.json')
    if os.path.exists(analysis_results_file) and os.path.getsize(analysis_results_file) > 0:
        print(f"文件 {analysis_results_file} 已存在且有内容，跳过分析。")
        try:
            with open(analysis_results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"读取已存在的分析结果时出错: {str(e)}")
            # 如果读取出错，继续进行新的分析
    
    # 读取原始调用链日志
    with open(log_file, 'r') as f:
        output_log_content = f.read()
    
    # client = ZhipuAI(api_key="8093042fbe2c4b25b89c2dcc3c76bfdd.PSrV0dJhWQcrbohR")
    
    analysis_results = []
    print(f"\n开始分析调用链，共 {len(trace_chain)} 个函数...")
    
    # 提取漏洞类型
    vuln_type = None
    response_json = os.path.join(os.path.dirname(log_file), 'response_output.json')
    if os.path.exists(response_json):
        try:
            with open(response_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'vulnerability_types' in data:
                    vuln_type = data['vulnerability_types']
        except Exception as e:
            print(f"读取漏洞类型时出错: {str(e)}")

    # 根据漏洞类型添加特定提示
    type_specific_prompts = {
        "Code_Execution": """
请特别关注以下几点：
1. 是否存在命令拼接或eval类执行函数
2. 命令参数是否经过严格过滤
3. 是否使用了安全的命令执行方式
4. 是否限制了可执行的命令范围
5. 如果通过eval实现的命令执行，污点是否被限制为正确的json格式
6. 污点可以控制的内容是否能影响命令或代码的执行，有些污点即使能传播到sink函数，也不能影响执行何种命令或代码的执行
7. 对于sink点为subprocess.Popen时，要注意shell的值是否为True""",
        
        "SQL_Injection": """
请特别关注以下几点：
1. SQL语句是否使用参数化查询
2. 是否存在直接字符串拼接
3. 是否对特殊字符进行转义
4. 是否限制了SQL语句的类型""",
        
        "File_Operation": """
请特别关注以下几点：
1. 文件路径是否进行了规范化处理
2. 是否限制了文件操作的目录范围
3. 是否存在路径穿越的可能

然后你需要分析文件操作的类型是读取文件还是写入文件，这点很重要。

对于写入文件的sink：
1. 污点是否能同时控制文件路径和写入内容
2. 如果污点只能控制其中一个（路径或内容），则不构成有效的漏洞利用
3. 即使其他条件都满足，只要不满足同时控制路径和内容的条件，也必须判定为无效

对于读取文件的sink：
1. 污点是否能控制文件路径，导致任意文件读取
2. 是否对读取的文件路径进行了白名单校验
3. 是否限制了可读取的文件类型和目录范围""",
        
        "XSS": """
请特别关注以下几点：
1. 输出是否进行了HTML编码
2. 是否使用了安全的模板引擎
3. 是否对大模型的输出进行了严格的过滤""",

        "SSRF": """
1. 检查这些请求的目标地址是否可控，例如是否从用户输入、配置文件或环境变量中获取。
2. 确认是否存在对内部网络资源（如内网IP、本地文件、内部服务）的访问。
3. 评估是否存在绕过URL白名单或黑名单的技巧，例如使用特殊协议（file://, gopher://）、重定向或DNS重绑定。
4. 检查是否存在对请求返回内容的处理，以判断是否可能导致信息泄露或进一步的攻击。
"""
    }

    # 在函数开始处添加已分析函数集合
    analyzed_functions = set()
    
    for i, call in enumerate(trace_chain, 1):
        # 只使用函数实现内容作为唯一标识
        func_content = call.get('content', '函数实现不可见')
        
        # 如果已经分析过相同的函数实现，则跳过
        if func_content in analyzed_functions:
            print(f"\n[{i}/{len(trace_chain)}] 跳过重复函数: {call['function']}")
            continue
            
        print(f"\n[{i}/{len(trace_chain)}] 正在分析函数: {call['function']}")
        analyzed_functions.add(func_content)
        
        # 构建基础提示信息
        base_prompt = f"""请分析以下调用链中的片段里的污点传播是否有效，请注意，污点源是由用户可控的大模型输出，
        在污点传播到sink函数的过程中，可能有过滤函数对污点进行消毒，对于这种过滤函数请你仔细判断污点是否能被消毒成功。
        对于污点流，你要分析流入sink函数的污点是否是source的大模型输出可控的，并且还要考虑污点是否有能力触发sink函数导致的漏洞。
注意只需要具体分析片段中的内容。
"""

        # 添加漏洞类型特定的提示
        if vuln_type and isinstance(vuln_type, list):
            for vtype in vuln_type:
                if vtype in type_specific_prompts:
                    base_prompt += "\n" + type_specific_prompts[vtype]

        # 完整提示信息
        prompt = base_prompt + f"""
请详细分析以下几点：
1. 污点经过的每个函数的具体功能和调用意图
2. 每个函数是如何处理和传递污点数据的
3. 函数之间的调用关系和数据流转过程
4. 是否存在对污点数据的校验或过滤

完整调用链信息：
{output_log_content}

具体调用链片段：

函数名: {call['function']}
参数信息: {call['params']}
函数实现:
{call['content'] if 'content' in call else '函数实现不可见'}

请以JSON格式返回分析结果：
{{
    "issue_number": <调用链编号>,
    "is_taint_valid": true/false,
    "has_sanitizer": true/false,
    "sanitizer_functions": [<过滤函数名称列表>],
    "function_analysis": [
        {{
            "function_name": <函数名>,
            "purpose": <函数调用意图和功能（中文）>,
            "taint_handling": <污点处理方式（中文）>
        }}
    ],
    "analysis_reason": <有效或无效的原因（中文）>
}}
"""
        
        # 调用DeepSeek进行分析
        try:
            # print(f"  正在等待智谱AI响应...")
            # response = client.chat.completions.create(
            #     model="glm-4-air",
            #     messages=[{"role": "user", "content": prompt}],
            #     temperature=0,
            #     max_tokens=1024
            # )
            url = "https://api.siliconflow.cn/v1/chat/completions"

            payload = {
                "model": "Pro/deepseek-ai/DeepSeek-V3",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0,
                "max_tokens": 1024,
                "response_format": {"type": "json_object"}
            }

            headers = {
                "Authorization": "Bearer sk-123",
                "Content-Type": "application/json"
            }

            response = requests.request("POST", url, json=payload, headers=headers)

            # 检查响应状态码
            if response.status_code != 200:
                print(f"DeepSeek API调用出错，状态码：{response.status_code}")
                print(f"错误信息：{response.text}")
                sys.exit(1)
            
            # 解析响应JSON
            response_data = response.json()
            if 'choices' not in response_data or not response_data['choices']:
                print("DeepSeek API返回数据格式错误")
                sys.exit(1)
                
            # 提取内容
            json_content = response_data['choices'][0]['message']['content']
            analysis = json.loads(json_content)
            print(f"  分析完成: {'存在' if analysis.get('is_taint_valid') else '不存在'}污点传播")
            
            analysis_results.append({
                'function': call['function'],
                'analysis': analysis
            })
        except Exception as e:
            print(f"分析函数 {call['function']} 时出错: {str(e)}")
            sys.exit(1)  # 遇到任何错误都直接退出程序

    print("\n开始综合分析整个调用链...")
    
    # 获取过滤函数实现
    sanitizer_implementations = get_sanitizer_implementations(analysis_results, trace_chain)

    # 构建最终的分析提示
    chain_prompt = (f"""基于以下调用链的分析结果和过滤函数的具体实现，请评估整体的污点传播可靠性：
    
    调用链分析结果：
    {json.dumps(analysis_results, indent=2, ensure_ascii=False)}
    
    对于调用链的分析结果，你应该注重分析"analysis_reason"部分。特别注意：
    1. 如果任何局部分析中断了污点传播，全局分析必须考虑这一点
    2. 即使污点传播到sink函数，也要评估sink函数是否真的会执行危险操作
    3. 对于静态分析工具（如flake8）的执行点，即使接收了污点数据，也不会实际执行代码
    
    {"发现以下过滤函数的具体实现：" if sanitizer_implementations else "未发现过滤函数"}
    """ + 
    '\n'.join(f"函数名: {name}\n具体实现:\n{impl}" for name, impl in sanitizer_implementations.items()))
    
    # 添加漏洞类型特定的提示
    if vuln_type and isinstance(vuln_type, list):
        for vtype in vuln_type:
            if vtype in type_specific_prompts:
                chain_prompt += "\n" + type_specific_prompts[vtype]
    
    chain_prompt += """

请详细分析以下几点：
1. 过滤函数的实现是否完整有效
2. 过滤函数是否能完全消除污点
3. 污点是否能绕过过滤函数的限制
4. 结合完整调用链判断漏洞是否能被触发
5. 如果在前面的分析中某一个函数中断污点传播被判断为不存在，那么要仔细考虑整个污点传播的有效性
6. 如果分析最后一个函数的结果是就算污点能正确传播到sink函数也不能被触发漏洞，那么要着重考虑最后一个分析的结果

请以JSON格式返回分析结果：
{
    "issue_number": <调用链编号>,
    "is_vulnerability": true/false,
    "reason": <判断原因（中文）>,
    "triggering_conditions": <触发条件（中文）>,
    "poc": <PoC示例>
}
"""
    
    try:
        # final_response = client.chat.completions.create(
        #     model="glm-4-air",
        #     messages=[{
        #         "role": "user", 
        #         "content": chain_prompt + "\n请务必以严格的JSON格式返回结果，不要包含任何其他文本或Markdown标记。确保JSON格式正确且可解析。"
        #     }],
        #     temperature=0,
        #     max_tokens=1024,
        #     response_format={"type": "json_object"}  # 指定返回JSON格式
        # )

        payload = {
                "model": "Pro/deepseek-ai/DeepSeek-V3",
                "messages": [
                    {
                        "role": "user",
                        "content": chain_prompt
                    }
                ],
                "temperature": 0,
                "max_tokens": 1024,
                "response_format": {"type": "json_object"}
        }

        final_response = requests.request("POST", url, json=payload, headers=headers)

        # 检查响应状态码
        if final_response.status_code != 200:
            print(f"DeepSeek API调用出错，状态码：{final_response.status_code}")
            print(f"错误信息：{final_response.text}")
            sys.exit(1)
        
        # 解析响应JSON
        response_data = final_response.json()
        if 'choices' not in response_data or not response_data['choices']:
            print("DeepSeek API返回数据格式错误")
            sys.exit(1)
            
        # 提取内容
        json_content = response_data['choices'][0]['message']['content']
        try:
            final_analysis = json.loads(json_content)
        except json.JSONDecodeError as je:
            print(f"JSON解析错误，原始内容：\n{json_content}")
            print(f"错误详情：{str(je)}")
            final_analysis = {
                "issue_number": log_file.split('/')[-2],
                "is_vulnerability": False,
                "reason": "JSON解析错误，无法完成分析",
                "triggering_conditions": "无法确定",
                "poc": "无法生成"
            }
            sys.exit(1)  # JSON解析错误也直接退出
        
    except Exception as e:
        print(f"调用 DeepSeek 时出错: {str(e)}")
        sys.exit(1)  # 遇到任何错误都直接退出程序
    
    # 构建输出JSON
    output_json = {
        'issue_id': log_file.split('/')[-2],  # 从log_file路径提取issue_id
        'trace_chain': trace_chain,
        'analysis': {
            'individual_analysis': analysis_results,
            'chain_analysis': final_analysis
        }
    }
    
    # 输出JSON结果
    output_file = os.path.join(os.path.dirname(log_file), 'analysis_results.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_json, f, ensure_ascii=False, indent=2)
    
    print(f"分析结果已保存到: {output_file}")
    
    return {
        'individual_analysis': analysis_results,
        'chain_analysis': final_analysis
    }

if __name__ == "__main__":
    # 遍历所有项目
    for project_name in PROJECT_NAMES:
        print(f"\n正在处理项目: {project_name}")
        # 设置当前项目名
        PROJECT_NAME = project_name
        
        project_log_dir = os.path.join(LOG_BASE_PATH, PROJECT_NAME)

        # 提取所有标记为漏洞的issue
        vulnerable_issues = extract_vulnerable_issues(project_log_dir)
        print(f"发现 {len(vulnerable_issues)} 个漏洞issue")
        
        # 只遍历漏洞issue
        for issue in vulnerable_issues:
            issue_dir = issue['issue_number']
            issue_path = os.path.join(project_log_dir, issue_dir)
                
            log_file = os.path.join(issue_path, 'output.log')
            if not os.path.exists(log_file):
                print(f"跳过 {issue_dir}: 未找到output.log")
                continue
                
            print(f"\n开始分析 {PROJECT_NAME} 项目的漏洞 issue {issue_dir}")
            trace_chain = parse_trace_chain(log_file)
            
            # 提取函数内容
            for call in trace_chain:
                file_path = call['file_path']
                if file_path.startswith(('servers1/', 'servers/', 'servers2/')):
                    file_path = os.path.join('', file_path)
                
                if os.path.exists(file_path):
                    call['content'] = extract_method_by_line(file_path, int(call['start_line']))
                else:
                    print(f"警告：找不到文件 {file_path}")
            
            # 使用DeepSeek分析调用链
            analyze_trace_with_deepseek(trace_chain, log_file)
            print(f"完成漏洞 issue {issue_dir} 的分析\n{'='*50}")


