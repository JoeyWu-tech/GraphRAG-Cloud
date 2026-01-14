#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据脱敏工具 (高级版)
- 自动识别并脱敏复杂字符串中嵌入的IP地址
- IP地址将被脱敏为无格式的乱码（非IP格式）
- 保持跨文件一致性 (相同原文 -> 相同密文)
"""

import os
import re
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Set

class FormatPreservingMasker:
    """格式保持的数据脱敏器"""
    
    def __init__(self, salt: str = "huawei_nl2api_masking_salt_2026"):
        self.salt = salt
        self.mapping: Dict[str, str] = {}  # 原值 -> 脱敏值
        self.reverse_mapping: Dict[str, str] = {}  # 脱敏值 -> 原值
        self.file_index: Dict[str, Set[str]] = {}  # 文件名 -> 涉及的脱敏值
        
        # 统计字段，完全跳过处理
        self.skip_fields = {"totalNum", "pageSize", "totalPageNo", "currentPage"}

        # ---------------------------------------------------------
        # 核心正则：匹配 IPv4 地址
        # 使用严格模式，避免匹配到版本号 (如 2.0.1) 或超大数字
        # ---------------------------------------------------------
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

    def _get_hash_bytes(self, original: str) -> bytes:
        """获取原值的哈希字节"""
        return hashlib.sha256((original + self.salt).encode()).digest()
    
    def _hash_to_hex_chars(self, original: str, length: int) -> str:
        """将原值映射到十六进制字符，保持指定长度"""
        hex_chars = "0123456789abcdef"
        h = self._get_hash_bytes(original)
        result = []
        for i in range(length):
            idx = h[i % len(h)] % len(hex_chars)
            result.append(hex_chars[idx])
        return ''.join(result)
    
    def _is_uuid_like(self, value: str) -> bool:
        """判断是否是UUID格式"""
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        return bool(re.match(uuid_pattern, value))
    
    def _mask_uuid_like(self, original: str) -> str:
        """脱敏UUID格式的值，保持格式和长度"""
        clean = original.replace("-", "")
        masked_clean = self._hash_to_hex_chars(original, len(clean))
        
        if "-" in original:
            parts = original.split("-")
            pos = 0
            masked_parts = []
            for part in parts:
                masked_parts.append(masked_clean[pos:pos+len(part)])
                pos += len(part)
            return "-".join(masked_parts)
        else:
            return masked_clean
    
    def _mask_generic(self, original: str) -> str:
        """通用脱敏，生成等长的乱码"""
        length = len(original)
        return self._hash_to_hex_chars(original, length)

    def _replace_ip_match(self, match) -> str:
        """
        正则替换的回调函数
        输入: 正则匹配对象 (包含一个IP)
        输出: 脱敏后的乱码字符串 (非IP格式)
        """
        original_ip = match.group(0)
        
        # 查缓存
        if original_ip in self.mapping:
            return self.mapping[original_ip]
        
        # 生成脱敏值：使用十六进制字符，破坏IP的点分十进制格式
        # 例如: 192.168.1.1 (11 chars) -> a1b2c3d4e5f
        masked_ip = self._hash_to_hex_chars(original_ip, len(original_ip))
        
        # 缓存
        self.mapping[original_ip] = masked_ip
        self.reverse_mapping[masked_ip] = original_ip
        
        return masked_ip

    def process_string_content(self, text: str) -> str:
        """
        处理字符串内容：扫描并替换其中所有的 IP 地址
        无论这个字符串是 JSON、日志还是普通文本
        """
        if not text:
            return text
        # 使用 regex.sub 自动查找所有匹配项并调用 _replace_ip_match
        return self.ip_pattern.sub(self._replace_ip_match, text)
    
    def should_mask_entire_field(self, field_name: str) -> bool:
        """
        判断字段是否需要【整字段】完全脱敏
        """
        # 1. 统计字段跳过
        if field_name in self.skip_fields:
            return False
        
        # 2. 如果包含 "IP" 字样，通常也应该全脱敏（双重保险）
        if "ip" in field_name.lower():
            return True
            
        # 3. 特定后缀和名称
        if field_name.endswith("Id") or field_name == "id":
            return True
        if field_name == "Image":
            return True
            
        return False
    
    def process_value(self, value: Any, field_name: str, file_name: str) -> Any:
        """
        处理单个值的入口逻辑
        """
        # 非字符串不处理
        if not isinstance(value, str):
            return value
            
        original_value = value
        
        # --- 步骤 1: 优先处理内容中的 IP ---
        # 无论字段名是什么，只要内容里有IP，先把它挖掉
        # 这解决了 {"config": "host=192.168.1.1"} 这种嵌入式 IP
        current_value = self.process_string_content(original_value)
        
        # --- 步骤 2: 判断是否需要整字段脱敏 ---
        # 如果字段名是敏感的（如 user_id），则把整个字符串（可能已经不含IP了）变成乱码
        if self.should_mask_entire_field(field_name):
            # 检查是否是 UUID
            if self._is_uuid_like(current_value):
                current_value = self._mask_uuid_like(current_value)
            else:
                # 已经是部分脱敏的字符串，或者普通字符串，进行全量通用脱敏
                current_value = self._mask_generic(current_value)
        
        # --- 步骤 3: 记录文件索引 ---
        # 如果值发生了变化（说明进行了脱敏），记录下来
        if current_value != original_value:
            if file_name not in self.file_index:
                self.file_index[file_name] = set()
            # 简单记录 "masked" 标记，或者记录具体改了什么
            # 这里为了节省内存，只记录发生过脱敏的文件名即可，或者记录原值
            self.file_index[file_name].add("processed")
            
        return current_value
    
    def process_dict(self, data: Dict, file_name: str, is_root: bool = True) -> Dict:
        """递归处理字典"""
        result = {}
        for key, value in data.items():
            if is_root and key in self.skip_fields:
                result[key] = value
                continue
            
            if isinstance(value, dict):
                result[key] = self.process_dict(value, file_name, is_root=False)
            elif isinstance(value, list):
                result[key] = self.process_list(value, key, file_name)
            else:
                result[key] = self.process_value(value, key, file_name)
        return result
    
    def process_list(self, data: list, parent_key: str, file_name: str) -> list:
        """递归处理列表"""
        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(self.process_dict(item, file_name, is_root=False))
            elif isinstance(item, list):
                result.append(self.process_list(item, parent_key, file_name))
            else:
                result.append(self.process_value(item, parent_key, file_name))
        return result
    
    def get_mapping_report(self) -> Dict:
        return {
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "total_mappings": len(self.mapping),
                "salt_hint": self.salt[:10] + "..."
            },
            "mappings": self.mapping,
            "reverse_mappings": self.reverse_mapping
        }
    
    def get_file_index_report(self) -> Dict:
        return {k: list(v) for k, v in self.file_index.items()}


def parse_file_num(filename: str) -> int:
    """从文件名解析实例数量"""
    match = re.search(r'_[Nn]um(\d+)\.json$', filename)
    if match:
        return int(match.group(1))
    return -1


def process_folder(input_folder: str, output_folder: str = None, salt: str = None):
    """处理文件夹入口"""
    input_path = Path(input_folder)
    
    if not input_path.exists():
        print(f"错误: 输入文件夹不存在: {input_folder}")
        return
    
    if output_folder is None:
        output_path = input_path / "masked_output"
    else:
        output_path = Path(output_folder)
    
    output_data_path = output_path / "masked_data"
    output_data_path.mkdir(parents=True, exist_ok=True)
    
    masker = FormatPreservingMasker(salt=salt) if salt else FormatPreservingMasker()
    
    stats = {"total": 0, "processed": 0, "skipped": 0}
    json_files = list(input_path.glob("*.json"))
    stats["total"] = len(json_files)
    
    print(f"找到 {len(json_files)} 个JSON文件，开始处理...")
    print("-" * 50)
    
    for json_file in sorted(json_files):
        filename = json_file.name
        num = parse_file_num(filename)
        
        if num == 0:
            stats["skipped"] += 1
            continue
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            masked_data = masker.process_dict(data, filename)
            
            with open(output_data_path / filename, 'w', encoding='utf-8') as f:
                json.dump(masked_data, f, ensure_ascii=False, indent=2)
            
            print(f"OK: {filename}")
            stats["processed"] += 1
            
        except Exception as e:
            print(f"ERROR {filename}: {e}")
            stats["skipped"] += 1
    
    # 保存报告
    with open(output_path / "global_mapping.json", 'w', encoding='utf-8') as f:
        json.dump(masker.get_mapping_report(), f, ensure_ascii=False, indent=2)
        
    print("-" * 50)
    print(f"处理完成。输出目录: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="高级数据脱敏工具 (支持嵌入式IP识别)")
    parser.add_argument("input_folder", help="输入文件夹路径")
    parser.add_argument("-o", "--output", dest="output_folder", default=None, help="输出文件夹")
    parser.add_argument("--salt", default=None, help="自定义混淆盐值")
    
    args = parser.parse_args()
    process_folder(args.input_folder, args.output_folder, args.salt)

if __name__ == "__main__":
    # 默认运行模式：直接修改下面的路径即可运行
    # 如果要使用命令行模式，请注释掉下面这行，取消注释 main()
    
    # process_folder("./sample_data")
    
    my_input_folder = r"/Users/yinwu/research/data/raw_json"  # <--- 把这里的路径改成您的输入文件夹路径
        my_output_folder = r"/Users/yinwu/research/data/masked_out" # <--- (可选) 输出路径，设为 None 则默认生成在原目录下
        my_salt = "custom_salt_value" # <--- (可选) 固定盐值，保证每次运行结果一致
    
        # ================= 开始运行 =================
        print(f"正在处理文件夹: {my_input_folder}")
        
        process_folder(
            input_folder=my_input_folder,
            output_folder=my_output_folder,
            salt=my_salt
        )
