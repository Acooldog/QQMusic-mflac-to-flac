import subprocess
import sys

def generate_requirements():
    try:
        # 运行 pip freeze
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'freeze'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'  # 忽略无法解码的字符
        )
        
        # 写入文件
        with open('requirements.txt', 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        
        print("✅ requirements.txt 已成功生成！")
        
    except Exception as e:
        print(f"❌ 生成失败: {e}")

if __name__ == '__main__':
    generate_requirements()