# QQMusic-mflac-to-flac

QQ 音乐加密文件解密工具。

## 项目说明
- 当前本地工作树分支：`master`
- 入口：`main.py`
- 桌面界面：`PyQt5`
- 打包形态：`onefile`
- 运行期自动生成目录：`plugins`、`_log`、`output`
- 转码只使用包内 `assets/ffmpeg-win-x86_64-v7.1.exe`

## 支持的输入
- `mflac`
- `mgg`
- `mmp4`

## 最终输出格式
本项目不再提供 `ogg` 作为最终输出格式。

默认映射：
- `mflac -> flac`
- `mgg -> m4a`
- `mmp4 -> m4a`

允许的最终输出格式：
- `flac`
- `m4a`
- `mp3`
- `wav`

## 封面处理
QQ 平台已接入自动补封面流程：
- 优先使用源文件目录中的本地图片
- 其次使用 `plugins/cover_cache` 本地缓存
- 最后才使用 QQ 网络封面兜底

说明：
- 不改核心解密算法
- 只在解密后的媒体处理与转码阶段补封面

## 运行
```powershell
O:\A_python\A_QQd\.venv\Scripts\python.exe O:\A_python\A_QQd\main.py
```

## 打包
```powershell
cd O:\A_python\A_QQd
npm run package
```

打包结果：
- `release/QQMusic-mflac-to-flac.exe`

说明：
- 代码和非自动生成依赖会打进单个 exe
- `plugins`、`_log`、`output` 会在 exe 同级外部自动创建

## 注意事项
- 仅供学习交流使用
- 请仅处理你本人拥有合法访问权限的本地文件
- 请遵守版权、平台协议与适用法律
