# vtd_bypass.py
# 修复并增强后的 VTD-Bypass 脚本
# 依赖: leechcorepyc, cryptography.fernet

import leechcorepyc
import struct
import binascii
import json
import time
import os
import mmap
import tempfile
import traceback
from cryptography.fernet import Fernet

# ================= DMAR表配置 =================
DEFAULT_DMAR_ADDRESS = "0x749b5000"
DMAR_CONTENT_HEX = "444D415250000000013F494E54454C2045444B322020202002000000494E544C1707202026030000000000000000000000002000010000000010D9FE000000000308000002001E070408000000001E06"

# ================= 路径设置（脚本目录下） =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_KEY_FILE = os.path.join(BASE_DIR, "config.key")

def get_config_path(filename):
    """获取脚本目录下的配置文件路径"""
    return os.path.join(BASE_DIR, filename)

# ================= 加密密钥管理 =================
def get_or_create_config_key():
    """获取或生成持久化的加密密钥 (Fernet)"""
    try:
        if os.path.exists(CONFIG_KEY_FILE):
            with open(CONFIG_KEY_FILE, "rb") as f:
                key = f.read()
            Fernet(key)  # 验证
            return key
        else:
            key = Fernet.generate_key()
            with open(CONFIG_KEY_FILE, "wb") as f:
                f.write(key)
            return key
    except Exception as e:
        print(f"无法读取或生成配置密钥: {e}")
        raise

CONFIG_KEY = get_or_create_config_key()

def save_config(config_data, filename="mod.config"):
    """加密保存配置"""
    try:
        fernet = Fernet(CONFIG_KEY)
        data = json.dumps(config_data, ensure_ascii=False, indent=2).encode('utf-8')
        encrypted = fernet.encrypt(data)
        path = get_config_path(filename)
        with open(path, 'wb') as f:
            f.write(encrypted)
        print(f"配置已保存到 {path}")
    except Exception as e:
        print(f"保存配置失败: {e}")

def load_config(filename="mod.config"):
    """解密加载配置"""
    try:
        fernet = Fernet(CONFIG_KEY)
        path = get_config_path(filename)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        return None

def load_config_from_path(file_path):
    """从指定路径加载配置"""
    try:
        fernet = Fernet(CONFIG_KEY)
        with open(file_path, 'rb') as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        return None

# ================= LeechCore 初始化 =================
def init_leechcore_with_retry():
    """初始化LeechCore连接，失败时最多重连20次"""
    max_attempts = 20
    for attempt in range(1, max_attempts + 1):
        lc = None
        try:
            print(f"初始化LeechCore连接... (尝试 {attempt}/{max_attempts})")
            lc = leechcorepyc.LeechCore("fpga")
            print("成功初始化LeechCore连接")
            return lc
        except Exception as e:
            print(f"LeechCore连接失败: {e}")
            if lc:
                try: lc.close()
                except: pass
            if attempt < max_attempts:
                time.sleep(1)
            else:
                raise
                
# ================= 内存转储与搜索工具 =================
def dump_memory_region(lc, start_addr, end_addr, dump_file="memory_region.bin"):
    """将指定内存区域转储到文件（分块读取）。"""
    size = end_addr - start_addr
    if size <= 0:
        print("错误：start_addr >= end_addr")
        return False

    # 询问是否覆盖已存在文件
    if os.path.exists(dump_file):
        response = input(f"文件 {dump_file} 已存在，是否覆盖? (y/n): ")
        if response.lower() != 'y':
            print("使用现有转储文件")
            return True

    chunk_size = 10 * 1024 * 1024  # 10MB
    total_chunks = (size + chunk_size - 1) // chunk_size
    start_time = time.time()

    try:
        with open(dump_file, 'wb') as f:
            for i in range(total_chunks):
                chunk_start = start_addr + i * chunk_size
                chunk_end = min(chunk_start + chunk_size, end_addr)
                chunk_size_actual = chunk_end - chunk_start
                print(f"读取块 {i+1}/{total_chunks} (0x{chunk_start:X} - 0x{chunk_end:X})")
                try:
                    chunk_data = lc.read(chunk_start, chunk_size_actual)
                    if not isinstance(chunk_data, (bytes, bytearray)):
                        # 尽量将可能类型转换为 bytes
                        chunk_data = bytes(chunk_data)
                    f.write(chunk_data)
                except Exception as e:
                    print(f"读取块失败: {e} — 用零填充该块")
                    f.write(b'\x00' * chunk_size_actual)

                elapsed = time.time() - start_time
                read_bytes = min((i+1)*chunk_size, size)
                rate = (read_bytes / (1024*1024)) / elapsed if elapsed > 0 else 0
                progress = (read_bytes / size) * 100
                print(f"进度: {progress:.2f}% (速率: {rate:.2f} MB/s)")

        print(f"内存转储完成: {dump_file} (用时 {time.time()-start_time:.2f}s)")
        return True
    except Exception as e:
        print(f"转储内存失败: {e}")
        return False

def search_in_dump(dump_file, signature_bytes):
    """在转储文件中搜索签名（返回匹配的文件偏移列表）"""
    if isinstance(signature_bytes, str):
        signature_bytes = signature_bytes.encode()
    try:
        file_size = os.path.getsize(dump_file)
        print(f"在 {dump_file} 中搜索签名（文件大小 {file_size/(1024*1024):.2f} MB）...")
        with open(dump_file, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                matches = []
                offset = 0
                while True:
                    pos = mm.find(signature_bytes, offset)
                    if pos == -1:
                        break
                    matches.append(pos)
                    offset = pos + 1
                print(f"搜索完成，找到 {len(matches)} 个匹配")
                return matches
    except Exception as e:
        print(f"搜索失败: {e}")
        return []

def read_table_from_dump(dump_file, offset, length=None):
    """从转储文件中读取表数据（offset 为文件偏移）"""
    try:
        with open(dump_file, 'rb') as f:
            f.seek(offset)
            if length is None:
                header = f.read(8)
                if len(header) < 8:
                    return None
                _, table_length = struct.unpack("<4sI", header)
                f.seek(offset)
                data = f.read(table_length)
            else:
                data = f.read(length)
            return data
    except Exception as e:
        print(f"从转储读取失败: {e}")
        return None

# ================= 校验和工具 =================
def calculate_checksum(data):
    """计算 ACPI 表校验和（返回单字节校验和）"""
    # 校验和定义为使整个表的字节和为 0 mod 256
    return (-sum(data)) & 0xFF

def update_table_checksum(table_data):
    """更新表的校验和字段（偏移 9）并返回更新后的 bytes"""
    tbl = bytearray(table_data)
    if len(tbl) > 9:
        tbl[9] = 0
        tbl[9] = calculate_checksum(tbl)
    return bytes(tbl)

# ================= 验证内存函数 =================
def verify_memory(lc, address, expected_data):
    """验证内存中的数据是否与预期一致"""
    try:
        actual_data = lc.read(address, len(expected_data))
        if not isinstance(actual_data, (bytes, bytearray)):
            actual_data = bytes(actual_data)
        if actual_data == expected_data:
            print(f"验证成功: 地址 0x{address:X} 数据一致")
            return True
        else:
            print(f"验证失败: 地址 0x{address:X} 数据不一致")
            mismatch_count = 0
            for i in range(min(len(actual_data), len(expected_data))):
                if actual_data[i] != expected_data[i]:
                    mismatch_count += 1
                    if mismatch_count <= 10:
                        print(f"  偏移 {i}: 实际={actual_data[i]:02X}, 期望={expected_data[i]:02X}")
            if mismatch_count > 10:
                print(f"  ... 还有 {mismatch_count-10} 个不匹配字节")
            return False
    except Exception as e:
        print(f"读取内存失败: {e}")
        return False

# ================= 自动寻找表地址 =================
def auto_find_table_in_range(lc, start_addr, end_addr, signature_str, dump_file=None):
    """
    在给定物理地址范围内自动转储并搜索签名（如 'XSDT' 或 'DMAR'）。
    返回找到的物理地址（第一个匹配）或 None。
    """
    if dump_file is None:
        dump_file = tempfile.gettempdir() + os.sep + f"dump_{signature_str}.bin"
    print(f"尝试在 0x{start_addr:X}-0x{end_addr:X} 范围内查找 '{signature_str}'，转储文件: {dump_file}")
    if not dump_memory_region(lc, start_addr, end_addr, dump_file):
        print("转储失败，无法搜索")
        return None

    matches = search_in_dump(dump_file, signature_str.encode())
    if not matches:
        return None

    # 选择第一个匹配（可根据需求改为选择最靠前/靠后的或人工选择）
    offset = matches[0]
    phys_addr = start_addr + offset
    print(f"检测到 {signature_str}，文件偏移 0x{offset:X}，物理地址 0x{phys_addr:X}")
    return phys_addr

# ================= 读取并修改 XSDT (自动插入 DMAR) =================
def read_and_modify_xsdt(auto_search=True, scan_start=0x70000000, scan_end=0x80000000):
    """
    读取在 VT-d 关闭情况下的 XSDT，向末尾插入 DMAR 基址，并保存到 mod.config。
    如果 auto_search=True，则尝试自动搜索 XSDT 与 DMAR。
    """
    print("===== 读取并修改 XSDT（插入 DMAR） =====")
    print("请确保系统处于 VT-d 关闭 / 或按照指示准备好内存读取环境。")

    # 询问用户是否手动输入 DMAR 地址
    use_default = input(f"是否使用默认 DMAR 地址 {DEFAULT_DMAR_ADDRESS}? (Y/n): ").strip().lower()
    if use_default in ['', 'y', 'yes', '是']:
        dmar_address = DEFAULT_DMAR_ADDRESS
    else:
        # 允许自动搜索或手动输入
        manual = input("是否手动输入 DMAR 地址? (y=手动 / n=自动搜索): ").strip().lower()
        if manual in ['y', 'yes', '是']:
            while True:
                dab = input("请输入 DMAR 表地址 (格式 0xXXXXXXXX): ").strip()
                try:
                    if dab.startswith('0x'):
                        int(dab, 16)
                        dmar_address = dab
                        break
                    else:
                        print("地址需以 0x 开头")
                except:
                    print("无效地址，请重试")
        else:
            dmar_address = None  # 交由自动搜索

    # 询问 XSDT 地址是否手动提供
    manual_xsdt = input("是否手动输入 XSDT 表物理地址? (y=手动 / n=自动搜索): ").strip().lower()
    if manual_xsdt in ['y', 'yes', '是']:
        while True:
            xsdt_input = input("请输入 XSDT 表地址 (格式 0xXXXXXXXX): ").strip()
            try:
                if xsdt_input.startswith('0x'):
                    xsdt_addr = int(xsdt_input, 16)
                    break
                else:
                    print("地址需以 0x 开头")
            except:
                print("无效地址，请重试")
    else:
        xsdt_addr = None

    # 配置保存结构
    config = {
        "vtd_mode": "disable",
        "xsdt_address": None,
        "xsdt_content_hex": None,
        "dmar_address": dmar_address if dmar_address else None,
        "dmar_content_hex": DMAR_CONTENT_HEX
    }

    lc = None
    dump_file = tempfile.gettempdir() + os.sep + "memory_region_disable.bin"

    try:
        lc = init_leechcore_with_retry()

        # 自动搜索 XSDT 与 DMAR（若未手动提供）
        if xsdt_addr is None or dmar_address is None:
            # 先尝试在一段地址范围内自动搜索 XSDT 与 DMAR
            print(f"开始自动扫描内存范围 0x{scan_start:X}-0x{scan_end:X} ...")
            # 如果需要分两段扫描可以在此扩展
            if xsdt_addr is None:
                xsdt_addr = auto_find_table_in_range(lc, scan_start, scan_end, "XSDT", dump_file=dump_file)
            if dmar_address is None:
                dmar_found = auto_find_table_in_range(lc, scan_start, scan_end, "DMAR", dump_file=tempfile.gettempdir()+os.sep+"dump_DMAR.bin")
                if dmar_found:
                    dmar_address = hex(dmar_found)

        if xsdt_addr is None:
            print("未能找到 XSDT（自动或手动）。请确认范围或选择手动提供地址。")
            lc.close()
            return 1

        config["xsdt_address"] = hex(xsdt_addr)
        if dmar_address:
            config["dmar_address"] = dmar_address

        # 读取 XSDT 表头并完整表
        print(f"读取 XSDT 表 - 地址: 0x{xsdt_addr:X}")
        xsdt_header = lc.read(xsdt_addr, 36)
        if not isinstance(xsdt_header, (bytes, bytearray)) or len(xsdt_header) < 8:
            print("读取 XSDT 表头失败或数据不足，尝试从转储文件读取...")
            # 如果之前转储了内存，可以尝试从文件读取
            if os.path.exists(dump_file):
                xsdt_offset = xsdt_addr - scan_start
                xsdt_full = read_table_from_dump(dump_file, xsdt_offset, None)
            else:
                print("无法读取 XSDT")
                lc.close()
                return 1
        else:
            # 解析长度字段并读取完整表
            length = struct.unpack("<I", xsdt_header[4:8])[0]
            if length < 36 or length > 0x100000:
                print(f"警告：XSDT 长度异常 ({length})，使用默认 256 字节读取")
                length = 256
            xsdt_full = lc.read(xsdt_addr, length)
            if not isinstance(xsdt_full, (bytes, bytearray)) or len(xsdt_full) < length:
                print("警告：从内存读取到的 XSDT 长度小于预期，尝试从转储文件补齐...")
                if os.path.exists(dump_file):
                    xsdt_offset = xsdt_addr - scan_start
                    xsdt_full_file = read_table_from_dump(dump_file, xsdt_offset, length)
                    if xsdt_full_file:
                        xsdt_full = xsdt_full_file

        if not xsdt_full:
            print("无法获取完整 XSDT 表")
            lc.close()
            return 1

        # 解析条目数
        length = len(xsdt_full)
        entry_count = (length - 36) // 8 if length > 36 else 0
        print(f"原始 XSDT 长度: {length} 字节, 条目数: {entry_count}")

        # 将 XSDT 转为可修改的 bytearray
        xsdt_list = bytearray(xsdt_full)

        # DMAR 地址可能是字符串或 hex; 处理为整数
        if config.get("dmar_address"):
            if isinstance(config["dmar_address"], str):
                dmar_addr_int = int(config["dmar_address"], 16)
            else:
                dmar_addr_int = int(config["dmar_address"])
        else:
            # 如果没有 DMAR 地址（非常不常见），尝试使用默认或停止
            print("未提供 DMAR 地址，无法插入 DMAR 项")
            lc.close()
            return 1

        # 在表尾追加 DMAR 表地址（8 字节小端）
        print(f"向 XSDT 尾部追加 DMAR 地址 0x{dmar_addr_int:X}")
        xsdt_list.extend(struct.pack("<Q", dmar_addr_int))

        # 更新长度字段及校验和字段
        new_length = len(xsdt_list)
        xsdt_list[4:8] = struct.pack("<I", new_length)
        xsdt_list[9] = 0
        xsdt_list[9] = calculate_checksum(xsdt_list)

        modified_xsdt = bytes(xsdt_list)
        config["xsdt_content_hex"] = binascii.hexlify(modified_xsdt).decode('utf-8').upper()
        config["dmar_content_hex"] = DMAR_CONTENT_HEX  # 保持默认 DMAR 内容（可由 customized.config 覆盖）

        # 保存配置
        save_config(config, "mod.config")

        print("已生成并保存修改后的 XSDT（mod.config）:")
        print(f"  XSDT 地址: 0x{xsdt_addr:X}")
        print(f"  DMAR 地址: 0x{dmar_addr_int:X}")
        print(f"  修改后 XSDT 长度: {len(modified_xsdt)} 字节")
        lc.close()
        return 0

    except Exception as e:
        print("处理 XSDT 时发生错误:")
        traceback.print_exc()
        try:
            if lc:
                lc.close()
        except:
            pass
        return 1

# ================= 写入 ACPI 表 =================
def write_acpi_tables():
    """从 mod.config 读取并写入 XSDT 与 DMAR 表（多次尝试与验证）。"""
    try:
        config = load_config("mod.config")
        if not config:
            print("未找到 mod.config，请先运行选项1以创建修改后的配置")
            return 1

        xsdt_addr = int(config.get("xsdt_address", "0x0"), 16)
        dmar_addr = int(config.get("dmar_address", "0x0"), 16)
        dmar_content_hex = config.get("dmar_content_hex", "")
        xsdt_content_hex = config.get("xsdt_content_hex", "")

        if xsdt_addr == 0 or dmar_addr == 0 or not dmar_content_hex or not xsdt_content_hex:
            print("配置文件中缺少必要信息 (xsdt_addr/dmar_addr/xsdt_content/dmar_content)")
            return 1

        xsdt_data = binascii.unhexlify(xsdt_content_hex)
        dmar_data = binascii.unhexlify(dmar_content_hex)

        print(f"准备写入 XSDT 到 0x{xsdt_addr:X}（{len(xsdt_data)} 字节）")
        print(f"准备写入 DMAR 到 0x{dmar_addr:X}（{len(dmar_data)} 字节）")

        attempts = 10
        for attempt in range(1, attempts + 1):
            print(f"\n===== 写入尝试 {attempt}/{attempts} =====")
            lc = None
            try:
                lc = init_leechcore_with_retry()

                # 写入 XSDT
                try:
                    lc.write(xsdt_addr, xsdt_data)
                    print("已写入 XSDT，校验中...")
                    if not verify_memory(lc, xsdt_addr, xsdt_data):
                        print("XSDT 校验失败，跳过本次尝试")
                        lc.close()
                        continue
                except Exception as e:
                    print(f"写入 XSDT 失败: {e}")
                    lc.close()
                    continue

                # 写入 DMAR
                try:
                    lc.write(dmar_addr, dmar_data)
                    print("已写入 DMAR，校验中...")
                    if not verify_memory(lc, dmar_addr, dmar_data):
                        print("DMAR 校验失败")
                    else:
                        print("DMAR 校验成功 —— 写入完成")
                        lc.close()
                        return 0  # 成功则退出
                except Exception as e:
                    print(f"写入 DMAR 失败: {e}")

                lc.close()
            except Exception as e:
                print(f"连接或写入过程出错: {e}")
            finally:
                try:
                    if lc:
                        lc.close()
                except:
                    pass

            if attempt < attempts:
                time.sleep(1)

        print("所有写入尝试完成，未能确认成功写入")
        return 1

    except Exception as e:
        print(f"写入过程发生错误: {e}")
        traceback.print_exc()
        return 1

# ================= 读取定制 customized.config 并写入 mod.config =================
def load_dingzhi_config():
    """读取 customized.config（默认放在脚本目录下），从中取 dmar_address 与 dmar_content_hex 并写入 mod.config（保留已有 XSDT）。"""

    print("===== 加载定制 DMAR 表 (customized.config) =====")
    dingzhi_path = "C:\\customized.config"
    if not os.path.exists(dingzhi_path):
        print(f"未找到 {dingzhi_path}，请将定制文件放置于 C:\\ 并确保格式正确（加密后的 JSON）")
        return 1

    try:
        dingzhi_config = load_config_from_path(dingzhi_path)
        if not dingzhi_config:
            print("解析 customized.config 失败")
            return 1

        dmar_address = dingzhi_config.get("dmar_address")
        dmar_content_hex = dingzhi_config.get("dmar_content_hex")
        if not dmar_address or not dmar_content_hex:
            print("customized.config 中缺少 dmar_address 或 dmar_content_hex")
            return 1

        existing = load_config("mod.config")
        if existing:
            config = {
                "vtd_mode": "custom",
                "xsdt_address": existing.get("xsdt_address"),
                "xsdt_content_hex": existing.get("xsdt_content_hex"),
                "dmar_address": dmar_address,
                "dmar_content_hex": dmar_content_hex
            }
            print("保留现有 XSDT 信息，仅替换 DMAR 信息")
        else:
            config = {
                "vtd_mode": "custom",
                "xsdt_address": None,
                "xsdt_content_hex": None,
                "dmar_address": dmar_address,
                "dmar_content_hex": dmar_content_hex
            }
            print("已写入 DMAR 信息，请使用选项1创建/填充 XSDT 信息")

        save_config(config, "mod.config")
        print("已保存到 mod.config")
        return 0
    except Exception as e:
        print(f"读取或处理 customized.config 时出错: {e}")
        traceback.print_exc()
        return 1

# ================= 简化的登录示例（替代未定义的logonwarning） =================
def logonwarning():
    """
    原脚本引用了一个未定义的函数。这里提供一个增强版替代：
    在继续前向用户明确提示风险，避免误操作。
    """
    print("\n================= 风险提示 =================")
    print("⚠️  本工具会修改 ACPI/XSDT/DMAR 等关键系统表")
    print("⚠️  不正确的使用可能导致：")
    print("    - 系统崩溃 / 蓝屏")
    print("    - 启动失败 / 数据丢失")
    print("    - 硬件不兼容 / 永久损坏风险")
    print("⚠️  请仅在测试/研究环境中使用，不要在生产或重要设备上操作！")
    print("⚠️  使用前请务必做好完整数据备份，并确保你理解其中的原理与风险。")
    print("============================================\n")

    ok = input("是否已阅读并接受以上风险？继续请输入 Y，否则请输入 N: ").strip().lower()
    return ok in ['y', 'yes', '是']


# ================= 主菜单 =================
def main():
    if not logonwarning():
        print("登录/确认未通过，程序退出。")
        return

    while True:
        print("\n===== 主菜单 =====")
        print("1. 读取并修改 XSDT（自动插入 DMAR）")
        print("2. 写入 VTD-Bypass（从 mod.config）")
        print("3. 加载定制 DMAR 表 (customized.config -> mod.config)")
        print("0. 退出")

        choice = input("请选择操作 (0-3): ").strip()
        if choice == "1":
            read_and_modify_xsdt(auto_search=True)
        elif choice == "2":
            print("\n写入操作很危险：请确保主机处于预期状态（例如关机/开机时机按说明）。")
            confirm = input("确认继续写入？ (Y/n): ").strip().lower()
            if confirm in ['', 'y', 'yes', '是']:
                write_acpi_tables()
            else:
                print("操作已取消")
        elif choice == "3":
            load_dingzhi_config()
        elif choice == "0":
            print("退出程序")
            break
        else:
            print("无效选择，请重试")

if __name__ == "__main__":
    main()
