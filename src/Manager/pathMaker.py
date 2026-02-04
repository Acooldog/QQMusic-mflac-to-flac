import os
import sys

def get_resource_path(relative_path):
    """获取资源文件的绝对路径"""
    try:
        # PyInstaller创建的临时文件夹
        base_path = sys._MEIPASS
    except Exception:
        # 开发模式
        base_path = os.path.abspath(".")
    
    # 先尝试从临时文件夹（exe内）获取
    internal_path = os.path.join(base_path, relative_path)
    if os.path.exists(internal_path):
        return internal_path
    
    # 如果不在exe内，尝试从外部文件夹获取
    if getattr(sys, 'frozen', False):
        # 打包后模式，尝试从exe所在目录获取
        external_base = os.path.dirname(sys.executable)
        external_path = os.path.join(external_base, relative_path)
        if os.path.exists(external_path):
            return external_path
    
    # 都没找到，返回路径（可能会引发文件不存在异常）
    return os.path.join(base_path, relative_path)

# 使用示例
# plugin_path = get_resource_path('plugins/my_plugin.py')