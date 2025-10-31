import re
import json
import subprocess
import os
from openai import OpenAI
from zhipuai import ZhipuAI
import requests
import sys

# 定义目标
# dir = "ShortGPT"

system_prompt = """
您是一位专门识别代码中污点源函数的软件安全专家。为了进行精确分析，您需要具备扎实的Python编程能力和污点流分析技能。
现在，您的任务是检查一个开源项目（使用Python编写）中的函数是否是请求大模型对话API的函数。判断标准如下：

1. 直接调用大模型API的函数：
   - OpenAI API (openai.OpenAI.chat.completions.create)
   - Anthropic API (anthropic.Anthropic.messages.create)
   - DeepSeek API
   - 其他类似的大模型API调用

2. 间接请求大模型API的函数：
   - 使用requests.post/get请求大模型API端点
   - URL包含明显的大模型API特征（如openai.com, api.anthropic.com, api.deepseek.com等）
   - 请求头包含API密钥（Authorization: Bearer sk-...）
   - 请求体包含模型名称、messages等典型大模型API参数
   - 特别要注意区分是请求大模型对话服务还是大模型生成图像服务，如果是大模型生成图像服务则舍弃

3. 使用第三方封装库调用大模型API：
   - LiteLLM (litellm.completion, litellm.completion_with_retries)
   - LangChain (LLMChain, ChatOpenAI等)
   - 其他类似的API封装库（如transformers, autotrain等）

您只需要判断给定的函数是否符合以上标准。
您要判断的函数为调用链中的第一个函数。

请以以下JSON格式返回您的分析：
{
    "issue_number": <问题编号>,
    "is_vulnerability": <true或false>,
    "reason": "<为什么是或不是大模型请求函数的原因>",
    "triggering_conditions": "<如果是大模型请求函数，描述其调用方式和参数>"
}
返回的"reason"和"triggering_conditions"内容需要使用中文。
以下是您需要分析的可疑代码片段和调用链：
"""

# 统计 "kind":"issue" 的出现次数
def count_issues(taint_output_file):
    try:
        with open(taint_output_file, "r") as file:
            content = file.read()
        target_string = '"kind":"issue"'
        issue_count = content.count(target_string)
        print(f"检测到 {issue_count} 个 'kind':'issue'。")
        return issue_count
    except FileNotFoundError:
        print(f"错误：文件 {taint_output_file} 未找到。")
        return 0
    except Exception as e:
        print(f"未知错误：{e}")
        return 0

# 创建文件夹
def create_folder(folder_path):
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
        print(f"文件夹已创建：{folder_path}")
    else:
        print(f"文件夹已存在，跳过创建：{folder_path}")

# 运行 test.sh 脚本
def run_test_script(test_script_path, test_script_arg1, test_script_arg2, project_name):
    try:
        print(f"正在运行 test_zhipu.sh 脚本，检测 issue {test_script_arg2}...")
        
        # 确保目标目录存在
        output_dir = f"{project_name}/{test_script_arg2}"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # 运行脚本
        result = subprocess.run(
            [test_script_path, test_script_arg1, test_script_arg2, project_name], 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        
        # 检查输出文件
        output_file = f"{output_dir}/output.log"
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"成功生成输出文件：{output_file}")
        else:
            print(f"警告：输出文件不存在或为空：{output_file}")
            
        print(f"test.sh 脚本运行成功！")
        
    except subprocess.CalledProcessError as e:
        print(f"test.sh 脚本运行失败！错误信息：{e.stderr.decode().strip()}")
    except Exception as e:
        print(f"运行脚本时发生错误：{str(e)}")

# 提取文件路径和行号
def extract_file_paths_and_lines(input_file, output_file):
    try:
        with open(input_file, "r") as file:
            content = file.read()
    except FileNotFoundError:
        print(f"错误：文件 {input_file} 未找到。")
        return []

    # 使用正则表达式匹配文件路径、行号和函数名
    # 匹配格式：servers1/sweep/sweepai/utils/github_utils.py:76|24|23 这样的格式
    pattern = r'([^\s]+\.py):(\d+)\|(\d+)\|(\d+)\s*'
    matches = re.findall(pattern, content)
    results = []
    
    # 使用另一个正则表达式匹配函数名
    func_pattern = r'(\S+)\s+(?:formal|result|leaf|root)'
    func_matches = re.findall(func_pattern, content)
    
    # 合并结果
    for i, (file_path, line_num, _, _) in enumerate(matches):
        func_name = func_matches[i] if i < len(func_matches) else "unknown"
        # 去除函数名中的前缀路径
        func_name = func_name.split('.')[-1] if '.' in func_name else func_name
        
        results.append({
            "file_path": file_path, 
            "line_number": int(line_num),
            "function_name": func_name
        })

    with open(output_file, "w") as file:
        json.dump(results, file, indent=4)

    print(f"提取结果已写入 {output_file}")
    return results

def extract_method_by_line(file_path: str, target_line: int) -> str:
    """根据指定行号提取整个方法内容"""
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            
        # 确保目标行在文件范围内
        if target_line < 1 or target_line > len(lines):
            return "目标行号超出文件范围"
            
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
            return "目标行是空行"
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

# 提取行号附近的上下文内容
def extract_context_content(results, base_path, context_output_file):
    if not results:
        print("未找到匹配项以提取上下文。")
        return

    first_result = results[0]
    target_file = first_result["file_path"]
    target_line = first_result["line_number"]

    full_target_file = f"{base_path}/{target_file.lstrip('/')}"

    try:
        # 使用extract_method_by_line函数提取完整方法
        method_content = extract_method_by_line(full_target_file, target_line)

        with open(context_output_file, "w") as file:
            file.write(f"File: {full_target_file}, Line: {target_line}\n")
            file.write("方法内容：\n")
            file.write(method_content)

        print(f"方法内容已写入 {context_output_file}")
    except Exception as e:
        print(f"提取方法内容时出错：{e}")

def count_checked_issues(project_name):
    """
    统计已经检查过的 issue 个数。
    :param project_name: 项目名称。
    :return: 已检查过的 issue 个数。
    """
    base_dir = f"{project_name}"
    issue_count = 0

    # 检查目标目录是否存在
    if not os.path.exists(base_dir):
        print(f"目录 {base_dir} 不存在。")
        return issue_count

    # 遍历目录下的所有文件夹
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        if os.path.isdir(item_path):
            issue_count += 1

    print(f"已检查过的 issue 个数：{issue_count}")
    return issue_count

def is_file_path_checked(file_path, project_name):
    """
    检查 file_path 是否已经检查过。
    :param file_path: 需要检查的文件路径。
    :param project_name: 当前项目名称。
    :return: 如果已检查过，返回对应的 response_output.json 文件路径；否则返回 None。
    """
    base_dir = f"{project_name}"

    issue_checked = count_checked_issues(project_name)
    
    # 遍历所有 issue 文件夹
    for issue_number in range(1, issue_checked + 1):  
        paths_and_lines_file = f"{base_dir}/{issue_number}/file_paths_and_lines.json"
        
        # 检查 file_paths_and_lines.json 文件是否存在
        if not os.path.exists(paths_and_lines_file):
            continue
        
        # 读取 file_paths_and_lines.json 文件
        with open(paths_and_lines_file, "r") as file:
            try:
                data = json.load(file)
                if data and data[0]["file_path"] == file_path:
                    # 如果 file_path 匹配，返回对应的 response_output.json 文件路径
                    response_file = f"{base_dir}/{issue_number}/response_output.json"
                    if os.path.exists(response_file):
                        return response_file
            except json.JSONDecodeError as e:
                print(f"解析 {paths_and_lines_file} 时出错：{e}")
    
    # 如果未找到匹配的 file_path，返回 None
    return None

def check_and_merge_duplicate_issues(project_name):
    """检查并合并重复的issues"""
    base_dir = f"/log_zhipu/{project_name}"
    issue_count = count_checked_issues(project_name)
    issue_info = {}  # 存储每个issue的首尾信息
    duplicates = {}  # 用于存储重复的issues

    # 首先收集所有issue的首尾信息
    for i in range(1, issue_count + 1):
        paths_file = f"{base_dir}/{i}/file_paths_and_lines.json"
        if not os.path.exists(paths_file):
            continue

        try:
            with open(paths_file, 'r') as f:
                data = json.load(f)
                if not data:  # 跳过空文件
                    continue
                
                # 获取第一个和最后一个记录
                first_record = data[0]
                last_record = data[-1]
                issue_info[i] = {
                    'first': f"{first_record['file_path']}:{first_record['line_number']}:{first_record['function_name']}",
                    'last': f"{last_record['file_path']}:{last_record['line_number']}:{last_record['function_name']}"
                }
                
        except Exception as e:
            print(f"处理文件 {paths_file} 时出错: {e}")

    # 比较不同issue之间的首尾记录
    for i in range(1, issue_count + 1):
        if i not in issue_info:
            continue
        
        for j in range(i + 1, issue_count + 1):
            if j not in issue_info:
                continue
                
            # 如果两个issue的首尾记录相同
            if (issue_info[i]['first'] == issue_info[j]['first'] and 
                issue_info[i]['last'] == issue_info[j]['last']):
                # 使用首尾特征组合作为key
                key = f"{issue_info[i]['first']}|{issue_info[i]['last']}"
                if key not in duplicates:
                    duplicates[key] = []
                if i not in duplicates[key]:
                    duplicates[key].append(i)
                if j not in duplicates[key]:
                    duplicates[key].append(j)

    # 合并重复的issues
    for key, issue_numbers in duplicates.items():
        if len(issue_numbers) > 1:
            # 保留编号最小的issue
            keep_issue = min(issue_numbers)
            remove_issues = [i for i in issue_numbers if i != keep_issue]
            print(f"发现重复issues {issue_numbers}，保留编号最小的 {keep_issue}")
            
            # 删除其他重复的issue文件夹
            for remove_issue in remove_issues:
                remove_dir = f"{base_dir}/{remove_issue}"
                try:
                    if os.path.exists(remove_dir):
                        import shutil
                        shutil.rmtree(remove_dir)
                        print(f"已删除重复issue目录: {remove_dir}")
                except Exception as e:
                    print(f"删除目录 {remove_dir} 时出错: {e}")

    return duplicates

def interact_with_deepseek(issue_number, context_output_file, input_file, project_name, i):
    try:
        # 构造目标文件路径
        response_file = f"/llm_web_serve/LLM_determine/log_zhipu/{project_name}/{i}/response_output.json"

        # 检查目标文件是否存在且有内容
        if os.path.exists(response_file) and os.path.getsize(response_file) > 0:
            print(f"文件 {response_file} 已存在且有内容，跳过分析。")
            return

        # 读取 file_paths_and_lines.json 文件，获取第一个 file_path
        paths_and_lines_file = f"/llm_web_serve/LLM_determine/log_zhipu/{project_name}/{i}/file_paths_and_lines.json"
        with open(paths_and_lines_file, "r") as file:
            file_path_data = json.load(file)
            first_file_path = file_path_data[0]["file_path"] if file_path_data else None
            first_function_name = file_path_data[0]["function_name"] if file_path_data else None

            # 检查 file_paths_and_lines 文件中最后一个函数的 file_path 是否有效
            # 读取 output.log 文件内容
            output_log_path = f"/llm_web_serve/LLM_determine/log_zhipu/{project_name}/{i}/output.log"
            output_log_content = ""
            if os.path.exists(output_log_path):
                with open(output_log_path, 'r') as f:
                    output_log_content = f.read()

            # 检查 output.log 中最后一个函数的文件路径是否无效
            # 假设无效路径的模式是 "*:" 或 "leaf:*" 出现在 output.log 的最后几行
            # 这里需要根据实际 output.log 的格式进行调整
            # 暂时使用一个简单的字符串匹配作为示例
            if "*:" in output_log_content or "leaf:*" in output_log_content:
                # 进一步细化，检查是否是最后一个函数的位置无效
                # 这需要更复杂的解析逻辑，例如查找最后一个函数调用的模式
                # 暂时简化为只要包含这些字符串就认为是无效
                print(f"Issue {i} 的 output.log 中检测到无效函数位置，跳过分析。")
                default_response = {
                    "issue_number": i,
                    "is_vulnerability": False,
                    "reason": "调用链最后一个函数位置无效，无法准确判断",
                    "triggering_conditions": ""
                }
                with open(response_file, 'w') as f:
                    json.dump(default_response, f, indent=2, ensure_ascii=False)
                return

            # 检查第一个函数是否是 post 或 request
            if first_function_name not in ["post", "request"]:
                print(f"Issue {i} 的第一个函数不是 post 或 request，跳过对话。")
                default_response = {
                    "issue_number": i,
                    "is_vulnerability": True,
                    "reason": "不是request.post",
                    "triggering_conditions": ""
                }
                with open(response_file, 'w') as f:
                    json.dump(default_response, f, indent=2, ensure_ascii=False)
                return

        # 检查 first_file_path 是否已经检查过
        if first_file_path:
            checked_response_file = is_file_path_checked(first_file_path, project_name)
            if checked_response_file:
                # 如果已检查过，直接复制 response_output.json 文件
                with open(checked_response_file, "r") as src, open(response_file, "w") as dst:
                    dst.write(src.read())
                print(f"文件 {first_file_path} 已检查过，直接复制 {checked_response_file} 到 {response_file}。")
                return

        # 读取 context_output_file 和 input_file 的内容
        with open(context_output_file, "r") as file:
            context_content = file.read()

        with open(input_file, "r") as file:
            output_log_content = file.read()

        # 构造发送给 DeepSeek 的内容
        deepseek_input = f"Issue {issue_number}\n{system_prompt}\n\ncode snippet:\n {context_content}\n"

        # 初始化 OpenAI 客户端
        # client = ZhipuAI(api_key="8093042fbe2c4b25b89c2dcc3c76bfdd.PSrV0dJhWQcrbohR")

        try:
            # 发送请求到 DeepSeek
            # response = client.chat.completions.create(
            #     model="glm-4-air",  
            #     messages=[
            #         {
            #             "role": "user",
            #             "content": deepseek_input  
            #         }
            #     ],
            #     temperature=0,        
            #     max_tokens=1024,    
            #     stream=False,
            #     response_format={"type": "json_object"}
            # )

            url = "https://api.siliconflow.cn/v1/chat/completions"

            payload = {
                "model": "Pro/deepseek-ai/DeepSeek-V3",
                "messages": [
                    {
                        "role": "user",
                        "content": deepseek_input
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

            # 去掉内容中的 Markdown 格式（```json```）和换行符
            json_content = response_data['choices'][0]['message']['content']

            # 将响应内容写入文件
            with open(response_file, "w") as file:
                file.write(json_content)

            print(f"DeepSeek 的响应已保存到 {response_file}")

        except Exception as api_error:
            error_message = str(api_error).lower()
            raise api_error

    except FileNotFoundError as e:
        print(f"错误：文件未找到。{e}")
    except Exception as e:
        print(f"与 DeepSeek 交互时出错：{e}")

def extract_vulnerable_issues(project_name,issue_count):
    # 获取所有 issue 的文件夹
    base_dir = f"/llm_web_serve/LLM_determine/log_zhipu/{project_name}"
    vulnerable_issues = []

    # 遍历实际存在的文件夹
    for item in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, item)
        if not os.path.isdir(folder_path):
            continue
            
        issue_number = int(item)
        response_file = f"{folder_path}/response_output.json"
        
        # 检查文件是否存在
        if not os.path.exists(response_file):
            continue

        # 读取文件内容
        with open(response_file, "r") as file:
            try:
                data = json.load(file)
                # 检查 is_vulnerability 是否为 true
                if data.get("is_vulnerability", False):
                    vulnerable_issues.append(issue_number)
            except json.JSONDecodeError as e:
                print(f"解析 {response_file} 时出错：{e}")

    # 输出结果
    if vulnerable_issues:
        print("以下 issue 的 is_vulnerability 为 true：")
        for issue in vulnerable_issues:
            print(f"Issue {issue}")
    else:
        print("未找到 is_vulnerability 为 true 的 issue。")

    return vulnerable_issues


def classify_vulnerability(sink_info):
    """根据sink信息对漏洞进行分类"""
    sink_info = sink_info.lower()
    
    # 代码执行类
    code_execution_sinks = [
        'remotecodeexecution',
        'execimportsink',
        'execdeserializationsink',
        'filecontentdeserializationsink',
        'execargsink',
        'execenvsink'
    ]
    
    # SQL注入类
    sql_injection_sinks = ['sql']
    
    # XSS类
    xss_sinks = ['xss']
    
    # 文件操作类
    file_operation_sinks = ['filesystem_readwrite', 'filesystem_other']

    # SSRF

    ssrf_sink = ['ssrfsink']
    
    # 判断漏洞类型
    if any(sink in sink_info for sink in code_execution_sinks):
        return 'Code_Execution'
    elif any(sink in sink_info for sink in sql_injection_sinks):
        return 'SQL_Injection'
    elif any(sink in sink_info for sink in xss_sinks):
        return 'XSS'
    elif any(sink in sink_info for sink in file_operation_sinks):
        return 'File_Operation'
    elif any(sink in sink_info for sink in ssrf_sink):
        return 'SSRF'
    
    return 'other'  # 其他类型的sink（如EmailSend, FormatString等）

def extract_vulnerability_info(dir, issue_number):
    """提取sapp_session.log中的漏洞信息并进行分类"""
    log_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{issue_number}/sapp_session.log"
    response_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{issue_number}/response_output.json"
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        # 查找包含"Issue"的行的索引
        for i, line in enumerate(lines):
            if line.strip().startswith('Issue'):
                # 提取接下来的信息，直到遇到空行
                info_lines = []
                j = i
                while j < len(lines) and lines[j].strip():
                    info_lines.append(lines[j].strip())
                    j += 1
                    
                # 解析信息
                info = {}
                for line in info_lines:
                    if ':' in line:
                        key, value = [x.strip() for x in line.split(':', 1)]
                        info[key] = value
                
                # 根据Sinks确定漏洞类型
                if 'Sinks' in info:
                    vuln_type = classify_vulnerability(info['Sinks'])
                    
                    # 更新response_output.json
                    try:
                        with open(response_file, 'r') as f:
                            response_data = json.load(f)
                        
                        response_data['vulnerability_types'] = [vuln_type]
                        
                        with open(response_file, 'w') as f:
                            json.dump(response_data, f, indent=2, ensure_ascii=False)
                            
                        print(f"Issue {issue_number} 的漏洞类型已更新：{vuln_type}")
                    except Exception as e:
                        print(f"更新response_output.json时出错：{str(e)}")
                
                return info
                
        return None
        
    except Exception as e:
        print(f"提取漏洞信息时出错：{str(e)}")
        return None

def process_pysa_results(dir):
    """
    从pysa_result_with_bug目录中提取项目名并返回
    目录结构示例: /llm_web_serve/pysa_result_with_bug/pysa-runs_AutoGPT-0.3.1
    返回: ['AutoGPT-0.3.1', ...]
    """
    
    project_names = []
    if not os.path.exists(dir):
        return project_names
    
    for item in os.listdir(dir):
        if item.startswith('pysa-runs_'):
            # 提取项目名部分
            project_name = item.split('_', 1)[1]
            project_names.append(project_name)
    
    return project_names

def load_projects_from_json(file_path):
    """从 JSON 文件加载项目名数组（不带作者）"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            projects_data = json.load(f)
            # 提取项目名（去掉作者部分）
            return [project["nameWithOwner"].split('/')[-1] for project in projects_data]
    except FileNotFoundError:
        print(f"错误：文件 {file_path} 不存在")
        return []
    except json.JSONDecodeError:
        print(f"错误：文件 {file_path} 不是有效的 JSON 格式")
        return []
    except KeyError:
        print(f"错误：JSON 文件中缺少 'nameWithOwner' 字段")
        return []
    except Exception as e:
        print(f"读取文件时发生错误: {str(e)}")
        return []


# 在主函数中调用
def main():
    # print("开始")
    # projects = process_pysa_results("/llm_web_serve/pysa_result_without_debug4")
    # print(projects)

    pysa_findings_file = "/llm_web_serve/pysa_findings2.json"
    if not os.path.exists(pysa_findings_file):
        print(f"错误：未找到 {pysa_findings_file} 文件。请先运行 find_pysa_files.py 脚本。")
        return

    with open(pysa_findings_file, 'r') as f:
        pysa_findings = json.load(f)

    # 遍历每个找到的项目信息
    check_initial = 'a' # 可以根据需要修改为其他字母 abcdefghijklmnopqrstuvwxyz
    for finding in pysa_findings:
        project_name = finding['project_name']
        # if check_initial and not project_name.lower().startswith(check_initial.lower()):
        #     continue
        dir = finding['developer']+"__"+project_name
        # dir = "agno-agi__phidata"
        project_path = finding['project_path']
        # pysa_file_path = finding['pysa_file_path'] # 如果需要，可以启用此行
        taint_output_file = f"/llm_web_serve/pysa_result_source/pysa-runs_{dir}/taint-output.json"
        issue_count = count_issues(taint_output_file)
        # issue_count = 20

        test_script_path = "/llm_web_serve/LLM_determine/test_zhipu.sh"
        create_folder(f"/llm_web_serve/LLM_determine/log_zhipu/{dir}")

        # 第一阶段：记录所有issue
        for i in range(1, issue_count + 1):
            paths_and_lines_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}/file_paths_and_lines.json"
            context_output_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}/line_context.txt"
            folder_path = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}"
            # output_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}/output.log"
            input_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}/output.log"
            response_file = f"/llm_web_serve/LLM_determine/log_zhipu/{dir}/{i}/response_output.json"
            taint_output = f"/llm_web_serve/pysa_result_source/pysa-runs_{dir}"

            create_folder(folder_path)
            run_test_script(test_script_path, taint_output, str(i), dir)

            results = extract_file_paths_and_lines(input_file, paths_and_lines_file)
            extract_context_content(results, "llm_web_serve", context_output_file)

        project_name = dir
        # 第二阶段：查重和合并
        duplicates = check_and_merge_duplicate_issues(project_name)
        
        # 第三阶段：统一向大模型提问
        # 只遍历实际存在的文件夹
        # for item in os.listdir(f"/llm_web_serve/LLM_determine/log_zhipu/{dir}"):
        #     folder_path = os.path.join(f"llm_web_serve/LLM_determine/log_zhipu/{dir}", item)
        #     if os.path.isdir(folder_path):
        #         i = int(item)
        #         context_output_file = f"{folder_path}/line_context.txt"
        #         input_file = f"{folder_path}/output.log"
        #         if os.path.exists(context_output_file):
        #             interact_with_deepseek(i, context_output_file, taint_output_file, dir, i)

        # 最后提取漏洞结果
        actual_issue_count = count_checked_issues(dir)
        vulnerable_issues = extract_vulnerable_issues(project_name, issue_count)
        
        # 为每个漏洞issue提取和更新漏洞类型
        for issue_number in vulnerable_issues:
            vuln_info = extract_vulnerability_info(dir, issue_number)
            if vuln_info and 'Sinks' in vuln_info:
                print(f"Issue {issue_number} 的漏洞信息已提取完成")

if __name__ == "__main__":
    main()


