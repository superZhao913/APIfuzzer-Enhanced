#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Fuzzer - 红队API模糊测试工具
主要功能：
1. 使用AI分析API文档并生成潜在的越权接口
2. 执行未授权漏洞测试
3. 智能分析测试结果
"""

import os
import json
import asyncio
from pathlib import Path
from datetime import datetime

from modules.ai_analyzer import AIAnalyzer
from modules.fuzzer import APIFuzzer
from modules.result_analyzer import ResultAnalyzer
from modules.utils import setup_logging, create_result_directory


def main():
    """
    主函数 - 执行完整的API Fuzz测试流程
    """
    print("[+] API Fuzzer 启动")
    
    # 设置日志
    logger = setup_logging()
    
    # 创建结果目录
    result_dir = create_result_directory()
    logger.info(f"结果目录创建: {result_dir}")
    
    # 读取API文档
    api_doc_path = "/Users/superxiaoshu/tanweai/project/APIfuzzer/final_api_analysis_副本.json"
    with open(api_doc_path, 'r', encoding='utf-8') as f:
        original_apis = json.load(f)
    
    logger.info(f"原始API数量: {original_apis['total_apis']}")
    
    # 目标网站
    target_url = "http://8.219.197.28:9998"
    
    # 步骤1: AI分析并生成潜在越权接口
    print("\n[+] 步骤1: AI分析API文档并生成潜在越权接口")
    ai_analyzer = AIAnalyzer()
    enhanced_apis, ai_reasoning = ai_analyzer.analyze_and_generate_apis(original_apis)
    
    # 保存AI推理过程
    reasoning_file = os.path.join(result_dir, "ai_reasoning.txt")
    with open(reasoning_file, 'w', encoding='utf-8') as f:
        f.write(f"AI推理过程:\n{ai_reasoning}\n")
    
    # 保存增强后的API文档
    enhanced_api_path = os.path.join(result_dir, "enhanced_apis.json")
    with open(enhanced_api_path, 'w', encoding='utf-8') as f:
        json.dump(enhanced_apis, f, ensure_ascii=False, indent=2)
    
    logger.info(f"增强后API数量: {enhanced_apis['total_apis']}")
    print(f"[+] 增强API文档已保存: {enhanced_api_path}")
    
    # 限制只测试前两个接口以加快开发速度
    test_apis = enhanced_apis['apis'][:2]
    logger.info(f"为加快开发速度，只测试前{len(test_apis)}个接口")
    
    # 步骤2: 执行Fuzz测试
    print("\n[+] 步骤2: 执行API Fuzz测试")
    fuzzer = APIFuzzer(target_url, result_dir)
    test_results = fuzzer.fuzz_all_apis(test_apis)
    
    # 保存测试结果
    results_path = os.path.join(result_dir, "fuzz_results.json")
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(test_results, f, ensure_ascii=False, indent=2)
    
    print(f"[+] Fuzz测试完成，结果已保存: {results_path}")
    
    # 步骤3: AI分析测试结果
    print("\n[+] 步骤3: AI分析测试结果")
    result_analyzer = ResultAnalyzer()
    
    # 构建文件路径
    enhanced_apis_file = os.path.join(result_dir, "enhanced_apis.json")
    test_results_file = os.path.join(result_dir, "fuzz_results.json")
    
    vulnerability_report = result_analyzer.analyze_results(enhanced_apis, test_results, enhanced_apis_file, test_results_file)
    
    # 保存漏洞报告
    report_path = os.path.join(result_dir, "vulnerability_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(vulnerability_report, f, ensure_ascii=False, indent=2)
    
    print(f"[+] 漏洞分析报告已保存: {report_path}")
    
    # 输出总结
    print("\n" + "="*60)
    print("API Fuzz测试完成总结:")
    print(f"原始API数量: {original_apis['total_apis']}")
    print(f"增强API数量: {enhanced_apis['total_apis']}")
    print(f"测试请求数量: {len(test_results)}")
    # 从正确的字段获取漏洞数量
    vulnerability_analysis = vulnerability_report.get('vulnerability_analysis', {})
    vulnerabilities = vulnerability_analysis.get('vulnerabilities', [])
    total_vulnerabilities = vulnerability_analysis.get('summary', {}).get('total_vulnerabilities', len(vulnerabilities))
    print(f"发现潜在漏洞: {total_vulnerabilities}")
    print(f"结果目录: {result_dir}")
    print("="*60)


if __name__ == "__main__":
    main()