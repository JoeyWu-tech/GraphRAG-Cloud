#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据脱敏工具
- 对JSON文件中的敏感字段进行脱敏
- 保持脱敏后的值与原值长度一致
- 保持UUID和IP的格式
- 全局映射表保证跨文件一致性
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
        self.file_index: Dict[str, Set[str]] = {}  # 文件名 -> 使用的原值集合
        
        # 统计字段，不进行脱敏
        self.skip_fields = {"totalNum", "pageSize", "totalPageNo", "currentPage"}
    
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
    
    def _hash_to_digits(self, original: str, length: int) -> str:
        """将原值映射到数字字符，保持指定长度"""
        digits = "0123456789"
        h = self._get_hash_bytes(original)
        result = []
        for i in range(length):
            idx = h[i % len(h)] % len(digits)
            result.append(digits[idx])
        return ''.join(result)
    
    def _is_uuid_like(self, value: str) -> bool:
        """判断是否是UUID格式"""
        # UUID格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        return bool(re.match(uuid_pattern, value))
    
    def _is_ip_like(self, value: str) -> bool:
        """判断是否是IP地址格式"""
        # IP格式: 数字.数字.数字.数字
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))
    
    def _mask_uuid_like(self, original: str) -> str:
        """脱敏UUID格式的值，保持格式和长度"""
        # 去掉横杠
        clean = original.replace("-", "")
        # 生成相同长度的十六进制字符
        masked_clean = self._hash_to_hex_chars(original, len(clean))
        
        # 还原横杠位置
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
    
    def _mask_ip_like(self, original: str) -> str:
        """脱敏IP格式的值，保持格式和长度"""
        parts = original.split(".")
        masked_parts = []
        for i, part in enumerate(parts):
            # 为每个部分生成相同长度的数字
            part_hash = self._hash_to_digits(original + str(i), len(part))
            # 确保第一位不是0（除非原值就是单个0）
            if len(part) > 1 and part_hash[0] == '0':
                # 用哈希的下一个非零数字替换
                for j in range(len(part_hash)):
                    if part_hash[j] != '0':
                        part_hash = part_hash[j] + part_hash[1:]
                        break
                else:
                    part_hash = '1' + part_hash[1:]
            masked_parts.append(part_hash)
        
        return ".".join(masked_parts)
    
    def _mask_generic(self, original: str) -> str:
        """通用脱敏，保持长度"""
        length = len(original)
        # 使用十六进制字符
        return self._hash_to_hex_chars(original, length)
    
    def mask_value(self, original: str, field_name: str = "") -> str:
        """
        对值进行脱敏
        - 空值保持不变
        - 已脱敏的值直接返回缓存结果
        - 根据值的格式选择合适的脱敏方式
        """
        # 空值处理
        if original is None or (isinstance(original, str) and original.strip() == ""):
            return original
        
        # 非字符串类型不处理
        if not isinstance(original, str):
            return original
        
        # 已经脱敏过的值，直接返回
        if original in self.mapping:
            return self.mapping[original]
        
        # 根据格式选择脱敏方式
        if self._is_uuid_like(original):
            masked = self._mask_uuid_like(original)
        elif self._is_ip_like(original):
            masked = self._mask_ip_like(original)
        else:
            masked = self._mask_generic(original)
        
        # 保存映射
        self.mapping[original] = masked
        self.reverse_mapping[masked] = original
        
        return masked
    
    def should_mask_field(self, field_name: str) -> bool:
        """
        判断字段是否需要脱敏
        规则：
        1. 属性名包含"IP"（不区分大小写）
        2. 以"Id"结尾（区分大小写）
        3. 名字是"id"（区分大小写）
        4. 名字是"Image"（区分大小写）
        """
        # 跳过统计字段
        if field_name in self.skip_fields:
            return False
        
        # 规则1: 包含"IP"（不区分大小写）
        if "ip" in field_name.lower():
            return True
        
        # 规则2: 以"Id"结尾（区分大小写）
        if field_name.endswith("Id"):
            return True
        
        # 规则3: 名字是"id"（区分大小写）
        if field_name == "id":
            return True
        
        # 规则4: 名字是"Image"（区分大小写）
        if field_name == "Image":
            return True
        
        return False
    
    def process_value(self, value: Any, field_name: str, file_name: str) -> Any:
        """处理单个值"""
        if not self.should_mask_field(field_name):
            return value
        
        if isinstance(value, str):
            masked = self.mask_value(value, field_name)
            # 记录文件索引
            if file_name not in self.file_index:
                self.file_index[file_name] = set()
            self.file_index[file_name].add(value)
            return masked
        elif isinstance(value, list):
            return [self.process_value(item, field_name, file_name) for item in value]
        else:
            return value
    
    def process_dict(self, data: Dict, file_name: str, is_root: bool = True) -> Dict:
        """递归处理字典"""
        result = {}
        for key, value in data.items():
            # 跳过根级别的统计字段
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
        """生成映射报告"""
        return {
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "total_mappings": len(self.mapping),
                "salt_hint": self.salt[:10] + "..."  # 只显示部分salt作为提示
            },
            "mappings": self.mapping,
            "reverse_mappings": self.reverse_mapping
        }
    
    def get_file_index_report(self) -> Dict:
        """生成文件索引报告"""
        # 将set转换为list以便JSON序列化
        return {
            file_name: list(values) 
            for file_name, values in self.file_index.items()
        }


def parse_file_num(filename: str) -> int:
    """
    从文件名解析实例数量
    文件名格式: xxx_NumN.json，其中N是数字
    返回: 实例数量，如果解析失败返回-1
    """
    # 匹配 _NumN 或 _numN 格式
    match = re.search(r'_[Nn]um(\d+)\.json$', filename)
    if match:
        return int(match.group(1))
    return -1


def process_folder(input_folder: str, output_folder: str = None, salt: str = None):
    """
    处理文件夹中的所有JSON文件
    
    Args:
        input_folder: 输入文件夹路径
        output_folder: 输出文件夹路径（默认在输入文件夹下创建 masked_output）
        salt: 自定义salt值
    """
    input_path = Path(input_folder)
    
    if not input_path.exists():
        print(f"错误: 输入文件夹不存在: {input_folder}")
        return
    
    # 设置输出文件夹
    if output_folder is None:
        output_path = input_path / "masked_output"
    else:
        output_path = Path(output_folder)
    
    # 创建输出目录
    output_data_path = output_path / "masked_data"
    output_data_path.mkdir(parents=True, exist_ok=True)
    
    # 初始化脱敏器
    masker = FormatPreservingMasker(salt=salt) if salt else FormatPreservingMasker()
    
    # 统计信息
    stats = {
        "total_files": 0,
        "processed_files": 0,
        "skipped_files": 0,
        "skipped_reasons": []
    }
    
    # 获取所有JSON文件
    json_files = list(input_path.glob("*.json"))
    stats["total_files"] = len(json_files)
    
    print(f"找到 {len(json_files)} 个JSON文件")
    print("-" * 50)
    
    for json_file in sorted(json_files):
        filename = json_file.name
        
        # 解析文件中的实例数量
        num = parse_file_num(filename)
        
        if num == 0:
            print(f"跳过 (实例数为0): {filename}")
            stats["skipped_files"] += 1
            stats["skipped_reasons"].append(f"{filename}: 实例数为0")
            continue
        
        if num == -1:
            print(f"警告: 无法解析文件名中的实例数量: {filename}，将正常处理")
        
        try:
            # 读取JSON文件
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 处理数据
            masked_data = masker.process_dict(data, filename)
            
            # 写入输出文件
            output_file = output_data_path / filename
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(masked_data, f, ensure_ascii=False, indent=2)
            
            print(f"处理完成: {filename}")
            stats["processed_files"] += 1
            
        except json.JSONDecodeError as e:
            print(f"错误: JSON解析失败 {filename}: {e}")
            stats["skipped_files"] += 1
            stats["skipped_reasons"].append(f"{filename}: JSON解析失败")
        except Exception as e:
            print(f"错误: 处理失败 {filename}: {e}")
            stats["skipped_files"] += 1
            stats["skipped_reasons"].append(f"{filename}: {str(e)}")
    
    print("-" * 50)
    
    # 保存全局映射表
    mapping_file = output_path / "global_mapping.json"
    with open(mapping_file, 'w', encoding='utf-8') as f:
        json.dump(masker.get_mapping_report(), f, ensure_ascii=False, indent=2)
    print(f"映射表已保存: {mapping_file}")
    
    # 保存文件索引
    index_file = output_path / "file_index.json"
    with open(index_file, 'w', encoding='utf-8') as f:
        json.dump(masker.get_file_index_report(), f, ensure_ascii=False, indent=2)
    print(f"文件索引已保存: {index_file}")
    
    # 打印统计信息
    print("-" * 50)
    print("处理统计:")
    print(f"  总文件数: {stats['total_files']}")
    print(f"  已处理: {stats['processed_files']}")
    print(f"  已跳过: {stats['skipped_files']}")
    print(f"  总映射数: {len(masker.mapping)}")
    
    if stats["skipped_reasons"]:
        print("\n跳过原因:")
        for reason in stats["skipped_reasons"]:
            print(f"  - {reason}")
    
    print(f"\n输出目录: {output_path}")
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="数据脱敏工具 - 对JSON文件中的敏感字段进行脱敏",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python data_masker.py ./sample_data
  python data_masker.py ./sample_data -o ./output
  python data_masker.py ./sample_data --salt "my_custom_salt"

脱敏规则:
  1. 属性名包含"IP"（不区分大小写）
  2. 以"Id"结尾（区分大小写）
  3. 名字是"id"（区分大小写）
  4. 名字是"Image"（区分大小写）

文件命名规则:
  文件名格式: xxx_NumN.json
  其中N代表实例数量，N=0时不处理该文件
        """
    )
    
    parser.add_argument(
        "input_folder",
        help="包含JSON文件的输入文件夹路径"
    )
    
    parser.add_argument(
        "-o", "--output",
        dest="output_folder",
        default=None,
        help="输出文件夹路径（默认在输入文件夹下创建 masked_output）"
    )
    
    parser.add_argument(
        "--salt",
        default=None,
        help="自定义salt值用于哈希计算（用于控制脱敏结果的随机性）"
    )
    
    args = parser.parse_args()
    
    process_folder(
        input_folder=args.input_folder,
        output_folder=args.output_folder,
        salt=args.salt
    )


if __name__ == "__main__":
    # 直接在这里设置参数
    process_folder(
        input_folder="./sample_data",      # 输入文件夹路径
        output_folder=None,                 # 输出文件夹（None表示默认在输入文件夹下创建 masked_output）
        salt=None                           # 自定义salt（None表示使用默认值）
    )
    
    # 如果需要命令行方式运行，注释上面的代码，取消下面这行的注释
    # main()

