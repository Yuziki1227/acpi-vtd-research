# VTD-Bypass 工具

## 📌 简介
本工具 (`bypass.py` / `vtd_bypass.py`) 用于 **ACPI 表修改与 VT-d Bypass 实验**。  
它可以在关闭 VT-d 的情况下读取 **XSDT 表**，向其中插入 **DMAR 表基址**，并将修改后的表写回系统内存，从而实现 VT-d 的旁路/绕过。  

⚠️ **注意**：此工具仅供研究与学习 ACPI / VT-d 相关机制使用，切勿在生产环境或无关系统上使用。  
错误操作可能导致 **系统崩溃 / 蓝屏 / 数据损坏**。请确保你有足够的背景知识和测试环境。  

---

## 📦 依赖
运行前需要安装以下依赖：

- Python 3.8+  
- `leechcorepyc`（用于与目标设备/FPGA 通信）  
- `cryptography`（用于加密配置文件）  

安装示例：
```bash
pip install cryptography
pip install leechcorepyc
```

> 注意：`leechcorepyc` 可能需要特定的硬件或驱动（如 PCILeech/FPGA）。请确保你的运行环境具备相应硬件支持。

---

## 🚀 功能
脚本提供以下主要功能：

1. **读取并修改 XSDT 表**  
   - 自动或手动输入 XSDT 与 DMAR 地址。  
   - 自动扫描并搜索内存中的 XSDT / DMAR 表。  
   - 将 DMAR 地址插入 XSDT 表尾，并修复校验和。  
   - 保存结果到 `mod.config`（加密存储）。

2. **写入 ACPI 表**  
   - 从 `mod.config` 读取 XSDT/DMAR 内容。  
   - 多次尝试写入目标地址并验证写入结果。  

3. **加载定制 DMAR 表**  
   - 从 `customized.config` 加载自定义 DMAR 表和基址（可选）。  
   - 与现有 `mod.config` 合并（保留 XSDT 信息）。

---

## 📂 文件说明
- `bypass.py` / `vtd_bypass.py`：主程序。  
- `config.key`：自动生成的加密密钥（存放在脚本同目录）。  
- `mod.config`：加密保存的修改后 ACPI 配置文件（存放在脚本同目录）。  
- `customized.config`：可选的自定义 DMAR 配置（加密，放在脚本同目录）。  
- `memory_region_disable.bin`：内存转储文件（调试/搜索用，生成于运行目录或系统临时目录）。

---

## ⚡ 使用方法
将 `bypass.py` 放在一个文件夹内，进入该目录并运行：

```bash
python bypass.py
```

运行后会出现交互菜单，常见选项如下：

```
1. 读取并修改 XSDT（自动插入 DMAR）
2. 写入 VTD-Bypass（从 mod.config）
3. 加载定制 DMAR 表 (customized.config -> mod.config)
0. 退出
```

推荐流程：
1. 选择 1 读取并修改 XSDT（脚本会尝试自动搜索 XSDT 与 DMAR）。  
2. 查看并确认生成的 `mod.config`。  
3. 在安全的测试环境下，选择 2 将修改写回内存（写入存在风险，请谨慎）。

---

## 📑 customized.config 示例
`customized.config` 是一个 **加密** 的 JSON 文件。如果你需要手动创建或在其他地方生成其明文样例（仅用于演示），解密后的 JSON 结构如下：

```json
{
  "dmar_address": "0x749b5000",
  "dmar_content_hex": "444D415250000000013F494E54..."
}
```

- `dmar_address`：DMAR 表物理地址（十六进制字符串，必须以 `0x` 开头）。  
- `dmar_content_hex`：DMAR 表内容（十六进制字符串，不包含空格）。

> 实际使用时请通过脚本或受信任工具将明文加密为 `customized.config`，并放在脚本同目录以便加载。

---

## ⚠️ 风险与注意事项
- 本脚本可能导致系统不稳定或不可启动，请仅在**隔离的测试环境**中运行（如测试机、虚拟机或可恢复备份的系统）。  
- 写入内存和修改 ACPI 表是一项高风险操作：错误地址或错误数据会导致系统崩溃或数据损坏。  
- 确保在操作前做好完整备份，并对操作步骤有充分理解。  
- 若要在物理机上运行写入操作，通常需要管理员权限并正确连接 LeechCore 支持的硬件设备（例如 FPGA/PCILeech）。  

---

## 🛠️ 故障排查
- **无法连接 LeechCore**：确认硬件连接、驱动、FPGA 固件及 `leechcorepyc` 配置。  
- **权限错误（无法写入 config.key）**：请以拥有写权限的用户运行脚本，或将脚本放在有写权限的目录。  
- **未找到 XSDT/DMAR**：尝试扩大扫描范围或手动提供物理地址。  
- **写入后系统异常**：请立即停止后续操作，并使用硬件恢复或系统备份进行恢复。

---

## 📝 免责声明
本工具仅用于 **安全研究与教育目的**，若用于非法目的或在生产环境造成任何损害，作者不承担任何责任。使用本工具即表示你已阅读并接受本免责声明。

---

## 📬 联系与贡献
欢迎在合规且合法的前提下对本工具提出问题或贡献改进（通过你自己的代码仓库/渠道）。