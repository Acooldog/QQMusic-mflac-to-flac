# QQ音乐解密工具 - 控制台版本

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![GitHub stars](https://img.shields.io/github/stars/Acooldog/QQMusic-mflac-to-flac?style=social)

![Star History Chart](https://api.star-history.com/svg?repos=Acooldog/QQMusic-mflac-to-flac&type=Date)

自动解密QQ音乐下载的加密音频文件，将mflac转换为flac，mgg转换为ogg。

---

本项目是[qqmusic_decrypt](https://github.com/luyikk/qqmusic_decrypt)的python重写版本，感谢原作者提供的动态插桩思路以及导出函数

## ⚠️ 重要声明

**本项目仅供学习交流使用，严禁商用！**

- 本工具仅用于技术研究和个人学习目的
- 请勿将本工具用于任何商业用途
- 使用本工具解密的音频文件仅供个人欣赏
- 请尊重版权，支持正版音乐
  
如果帮助到了你，可以去[github](https://github.com/Acooldog/QQMusic-mflac-to-flac)帮我点一个star吗？万分感谢！

## 分支说明
- master-console: 命令行分支，采用[MIT](https://github.com/Acooldog/QQMusic-mflac-to-flac/blob/master-console/LICENSE)开源协议
- master: PyQt5图形化界面分支，采用[GPLv3](https://github.com/Acooldog/QQMusic-mflac-to-flac/blob/master/LICENSE)开源协议
- develop: 开发分支，用于新功能开发, 采用[GPLv3](https://github.com/Acooldog/QQMusic-mflac-to-flac/blob/master/LICENSE)开源协议

## 用户指南
- 要使用PyQt5图形化界面，请在发行版下载QQMusic-mflac-to-flac.zip
- 要使用命令行，请在发行版下载QQMusic-mflac-to-flac-console.zip

## 功能特性

- 自动搜索QQ音乐下载目录下的加密文件
- 使用Frida动态插桩技术调用QQ音乐官方解密函数 优点: QQ音乐官方修改静态密钥，无需维护
- 支持mflac（加密FLAC）和mgg（加密OGG）格式
- 自动转换为标准flac和ogg格式
- 支持交互式模式和命令行模式
- 支持循环监控模式，自动解密新下载的文件
- 配置自动保存，下次启动可快速加载

## 环境要求

- Python 3.11.x
- QQ音乐客户端（Windows版本）必须处于运行状态
- Frida工具包


## 部署指南

### 基本部署

1. **克隆项目**
   ```bash
   git clone https://github.com/Acooldog/QQMusic-mflac-to-flac
   cd QQMusic-mflac-to-flac
   ```
 - **国内用户可以使用国内镜像**：
   ```bash
   git clone https://gitee.com/daoges_x/QQMusic-mflac-to-flac.git
   cd QQMusic-mflac-to-flac
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **启动 QQ 音乐**
   - 确保已安装 Windows 版 QQ 音乐客户端
   - 启动 QQ 音乐并登录账号

4. **运行程序**
   ```bash
   # 交互式模式（推荐首次使用）
   python main.py

   # 命令行模式
   python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output"

   # 解密后删除原文件
   python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output" -d

   # 循环监控模式（自动解密新下载的文件）
   python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output" -l
   ```



## 使用方法

### 方式一：交互式模式（推荐首次使用）

1. **确保QQ音乐正在运行**
   - 启动QQ音乐客户端
   - 下载一些VIP歌曲到默认下载目录

2. **运行解密程序**
   ```bash
   python main.py
   ```

3. **按照提示输入**
   - 输入QQ音乐下载目录路径
   - 输入输出目录路径
   - 选择是否删除原文件
   - 选择是否开启循环监控模式

4. **查看输出**
   - 解密后的文件会保存在指定的输出目录
   - mflac文件 → flac格式
   - mgg文件 → ogg格式

### 方式二：命令行模式

```bash
# 基本用法
python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output"

# 解密后删除原文件
python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output" -d

# 循环监控模式（自动解密新下载的文件）
python main.py -i "C:\Users\你的用户名\Music\VipSongsDownload" -o "output" -l

# 查看帮助
python main.py --help
```

### 命令行参数说明

| 参数 | 简写 | 说明 |
|------|------|------|
| --input | -i | QQ音乐下载目录路径 |
| --output | -o | 解密文件输出目录路径 |
| --delete | -d | 解密后删除原音频文件 |
| --loop | -l | 循环监控模式 |
| --help | -h | 显示帮助信息 |

## 目录结构

```
qqmusic_decrypt_python/
├── main.py                 # Python主程序（入口）
├── src/                   # 源代码目录
│   ├── Manager/           # 核心逻辑模块
│   │   └── qqmusic_decrypt.py  # QQ音乐解密器类
│   ├── UI/                # UI模块（已废弃，保留用于参考）
│   │   └── MainWindow/
│   │       └── MainWindow.py
│   ├── Helper/            # 辅助工具
│   ├── backupFuc/         # 备份功能
│   └── upRequirements/    # 依赖更新工具
├── requirements.txt       # Python依赖
├── plugins/               # 配置文件目录（自动创建）
│   └── plugins.json       # 用户配置文件
├── README.md             # 说明文档
├── js/                   # JavaScript参考代码（仅作参考）
│   └── hook_qq_music.js  # JavaScript Hook脚本
└── output/               # 输出目录（程序自动创建）
    ├── 歌曲1.flac
    ├── 歌曲2.ogg
    └── ...
```

## 架构说明

### 核心类：QQMusicDecryptor

`qqmusic_decrypt.py` 中的 `QQMusicDecryptor` 类封装了所有解密逻辑：

```python
from src.Manager.qqmusic_decrypt import QQMusicDecryptor

# 初始化解密器
decryptor = QQMusicDecryptor(session)

# 解密文件
success = decryptor.decrypt(src_file, dest_file)
```

### 工作流程

1. **初始化阶段**（Python主导）
   - 附加到QQ音乐进程
   - 使用JavaScript动态查找QQMusicCommon.dll模块
   - 枚举并定位5个关键函数地址
   - **Python动态生成解密JavaScript代码**并加载

2. **解密阶段**
   - Python调用 `decrypt()` 方法
   - 通过RPC调用**动态生成的**JavaScript代码
   - 调用EncAndDesMediaFile类的成员函数
   - 将解密后的数据写入文件

**重要**: 整个流程完全由Python代码控制，JavaScript代码在运行时动态生成，不需要任何外部JavaScript文件。

### 关键函数

| 函数名 | 作用 | 调用约定 |
|--------|------|----------|
| 构造函数 `??0EncAndDesMediaFile@@QAE@XZ` | 初始化对象 | thiscall |
| 析构函数 `??1EncAndDesMediaFile@@QAE@XZ` | 释放对象 | thiscall |
| Open `?Open@EncAndDesMediaFile@@QAE_NPB_W_N1@Z` | 打开加密文件 | thiscall |
| GetSize `?GetSize@EncAndDesMediaFile@@QAEKXZ` | 获取文件大小 | thiscall |
| Read `?Read@EncAndDesMediaFile@@QAEKPAEK_J@Z` | 读取解密数据 | thiscall |

## QQ音乐下载目录

默认路径：`C:\Users\你的用户名\Music\VipSongsDownload\`

包含加密文件：
- `歌手-歌名.mflac`  # 加密的FLAC文件（VIP歌曲）
- `歌手-歌名.mgg`    # 加密的OGG文件

## 技术栈

- **Python 3.7+**: 主程序逻辑和类封装
- **Frida 16.0+**: 动态插桩框架
- **JavaScript**: Hook脚本（通过Frida注入到QQ音乐进程）

## 代码示例

### 基本使用

```python
import frida
from src.Manager.qqmusic_decrypt import QQMusicDecryptor

# 附加到QQ音乐进程
device = frida.get_local_device()
session = device.attach(qqmusic_pid)

# 创建解密器
decryptor = QQMusicDecryptor(session)

# 解密文件
decryptor.decrypt("C:/Users/xxx/Music/VipSongsDownload/歌曲.mflac", "output/歌曲.flac")
```

### 自定义集成

```python
from src.Manager.qqmusic_decrypt import QQMusicDecryptor
from pathlib import Path

# ... Frida初始化代码 ...

decryptor = QQMusicDecryptor(session)

# 批量处理
qq_music_dir = Path.home() / "Music" / "VipSongsDownload"
for file in qq_music_dir.glob("*.mflac"):
    output_file = "output" / file.with_suffix(".flac").name
    if decryptor.decrypt(str(file), str(output_file)):
        print(f"解密成功: {file}")
```

## 注意事项

- 确保QQ音乐正在运行
- **严禁商用！仅供学习交流使用**
- 解密后的音频文件仅限个人欣赏
- 请尊重版权，支持正版音乐
- 不同版本的QQ音乐可能使用不同的DLL导出函数名

---

## 免责声明

本工具仅供学习交流使用，不得用于任何商业用途。使用者需自行承担使用本工具的一切后果，开发者不承担任何责任。

## 常见问题

**Q: 提示"请先启动QQ音乐"？**
A: 确保QQ音乐客户端已启动并且进程名包含"qqmusic"

**Q: 解密后的文件无法播放？**
A: 确保你的播放器支持flac/ogg格式

**Q: 找不到QQMusicCommon.dll？**
A: 确保使用的是Windows版本的QQ音乐客户端

**Q: 提示"未找到所有必要的函数"？**
A: 可能是QQ音乐版本更新了DLL，程序会列出所有相关导出函数，需要更新函数名

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## Star History

如果觉得这个项目有帮助，请给个 ⭐️ Star 支持一下！

## 贡献

欢迎提交 Issue 和 Pull Request！