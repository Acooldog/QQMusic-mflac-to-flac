# QQ音乐解密工具 - PyQt5版本

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-GPLv3-blue)
![GitHub stars](https://img.shields.io/github/stars/Acooldog/QQMusic-mflac-to-flac?style=social)

![Star History Chart](https://api.star-history.com/svg?repos=Acooldog/QQMusic-mflac-to-flac&type=Date)

自动解密QQ音乐下载的加密音频文件，将mflac转换为flac，mgg转换为ogg。

---

## ⚠️ 重要声明

**本项目仅供学习交流使用，严禁商用！**

- 本工具仅用于技术研究和个人学习目的
- 请勿将本工具用于任何商业用途
- 使用本工具解密的音频文件仅供个人欣赏
- 请尊重版权，支持正版音乐
- 本分支使用 PyQt5，请注意 PyQt5 采用 **GPLv3** 或商业许可证双重授权
- 如果想不受限制分发代码，请前往[master-console](https://github.com/Acooldog/QQMusic-mflac-to-flac/blob/master-console)分支
- 如果您希望闭源或商业使用，需要购买 PyQt5 的商业许可证
- 更多信息请参考 [PyQt5 官方许可证页面](https://www.riverbankcomputing.com/commercial/license)
  
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
- 输出到当前目录的output文件夹
- Python封装类，易于使用和维护

## 环境要求

- Python 3.7+
- QQ音乐客户端（Windows版本）必须处于运行状态
- Frida工具包

## 安装依赖

```bash
pip install -r requirements.txt
```

或手动安装：

```bash
pip install frida>=16.0.0
```

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
   python src/UI/MainWindow/mainWindow.py
   ```

### 设置保存问题解决方案

**已知问题**：在某些环境下，GUI 程序的设置可能无法保存到 `plugins/plugins.json`。

**临时解决方案**：

如果遇到设置无法保存的情况，可以在项目根目录下手动创建 `plugins/plugins.json` 文件，内容如下：

```json
{
    "input": "",
    "output": "",
    "del": false,
    "wheel": false
}
```

参数说明：
- `input`: QQ 音乐下载目录路径（如：`C:\Users\你的用户名\Music\VipSongsDownload`）
- `output`: 解密文件输出目录路径
- `del`: 是否在解密后删除原始加密文件（`true` 或 `false`）
- `wheel`: 是否循环运行（`true` 或 `false`）

**提示**：该问题将在后续版本中修复，届时设置将能正常保存。

---

## 使用方法

1. **确保QQ音乐正在运行**
   - 启动QQ音乐客户端
   - 下载一些VIP歌曲到默认下载目录

2. **运行解密程序**
   ```bash
   python main.py
   ```

3. **查看输出**
   - 解密后的文件会保存在 `output` 目录下
   - mflac文件 → flac格式
   - mgg文件 → ogg格式

## 目录结构

```
qqmusic_decrypt_python/
├── main.py                 # Python主程序（入口）
├── qqmusic_decrypt.py      # QQ音乐解密器类（核心逻辑）
├── requirements.txt        # Python依赖
├── README.md              # 说明文档
├── js/                    # JavaScript参考代码（仅作参考，不会被Python调用）
│   └── hook_qq_music.js   # JavaScript Hook脚本（原始版本，供调试参考）
└── output/                # 输出目录（程序自动创建）
    ├── 歌曲1.flac
    ├── 歌曲2.ogg
    └── ...
```

## 架构说明

### 核心类：QQMusicDecryptor

`qqmusic_decrypt.py` 中的 `QQMusicDecryptor` 类封装了所有解密逻辑：

```python
from qqmusic_decrypt import QQMusicDecryptor

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
from qqmusic_decrypt import QQMusicDecryptor

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
from qqmusic_decrypt import QQMusicDecryptor
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

## 📄 许可证

本项目采用 **GPLv3** 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

### PyQt5 依赖说明
本软件依赖于 PyQt5 库，该库采用双重授权：
- **GPLv3**：适用于开源项目
- **商业许可证**：适用于闭源商业项目

使用本软件即表示您同意遵守上述许可证条款。

## Star History

如果觉得这个项目有帮助，请给个 ⭐️ Star 支持一下！

## 贡献

欢迎提交 Issue 和 Pull Request！

