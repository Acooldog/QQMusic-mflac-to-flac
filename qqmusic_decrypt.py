"""QQ音乐解密器 - Python版本

使用Frida调用QQMusicCommon.dll中的EncAndDesMediaFile类来解密加密音频文件
"""

import frida


class QQMusicDecryptor:
    """QQ音乐解密器"""
    
    def __init__(self, session):
        """初始化解密器
        
        Args:
            session: Frida session对象
        """
        self.session = session
        self.target_dll = "QQMusicCommon.dll"
        self.functions = {}
        self._initialize_functions()
    
    def _initialize_functions(self):
        """查找并初始化QQMusicCommon.dll中的解密函数"""
        print("[*] 正在查找QQMusicCommon.dll...")
        
        # 由于Session对象没有get_module_by_name方法，我们需要在JavaScript中查找模块
        # 创建一个临时脚本来枚举模块和导出函数
        script_code = """
        var targetModule = Process.findModuleByName("QQMusicCommon.dll");
        if (!targetModule) {
          send({ type: "error", message: "未找到QQMusicCommon.dll" });
        } else {
          send({ type: "found_module", base: targetModule.base.toString(), size: targetModule.size });
          
          // 枚举导出函数
          var exports = targetModule.enumerateExports();
          var exportList = [];
          exports.forEach(function(exp) {
            if (exp.name.indexOf("EncAndDesMediaFile") !== -1) {
              exportList.push({ name: exp.name, address: exp.address.toString() });
            }
          });
          send({ type: "exports", data: exportList });
        }
        """
        
        script = self.session.create_script(script_code)
        
        # 用于接收JavaScript消息的变量
        module_info = {}
        export_functions = []
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'found_module':
                    module_info['base'] = int(payload['base'], 16)
                    module_info['size'] = payload['size']
                elif payload['type'] == 'exports':
                    for exp in payload['data']:
                        exp['address'] = int(exp['address'], 16)
                        export_functions.append(exp)
        
        script.on('message', on_message)
        script.load()
        
        # 等待脚本执行
        import time
        time.sleep(0.5)
        
        if not module_info:
            raise RuntimeError(f"未找到{self.target_dll}")
        
        print(f"[*] 找到{self.target_dll} @ {hex(module_info['base'])}")
        print(f"[*] 正在查找相关导出函数...")
        
        if not export_functions:
            raise RuntimeError("未找到任何EncAndDesMediaFile相关函数")
        
        print(f"[*] 找到 {len(export_functions)} 个相关函数")
        
        # 可能的函数名列表（考虑不同编译器版本）
        possible_names = {
            'constructor': [
                "??0EncAndDesMediaFile@@QAE@XZ",
                "??0EncAndDesMediaFile@@QEAA@XZ",
                "??0EncAndDesMediaFile@@IAAE@XZ"
            ],
            'destructor': [
                "??1EncAndDesMediaFile@@QAE@XZ",
                "??1EncAndDesMediaFile@@QEAA@XZ",
                "??1EncAndDesMediaFile@@IAAE@XZ"
            ],
            'open': [
                "?Open@EncAndDesMediaFile@@QAE_NPB_W_N1@Z",
                "?Open@EncAndDesMediaFile@@QEAA_NPEB_W_N1@Z"
            ],
            'getSize': [
                "?GetSize@EncAndDesMediaFile@@QAEKXZ",
                "?GetSize@EncAndDesMediaFile@@QEAAKXZ"
            ],
            'read': [
                "?Read@EncAndDesMediaFile@@QAEKPAEK_J@Z",
                "?Read@EncAndDesMediaFile@@QEAAKPEAEK_J@Z"
            ]
        }
        
        # 遍历从JavaScript获取的导出函数，查找目标函数
        for exp in export_functions:
            name = exp['name']
            address = exp['address']
            
            # 检查构造函数
            if 'constructor' not in self.functions:
                for possible_name in possible_names['constructor']:
                    if name == possible_name:
                        self.functions['constructor'] = address
                        print(f"[*] 找到构造函数: {name} @ {hex(address)}")
                        break
            
            # 检查析构函数
            if 'destructor' not in self.functions:
                for possible_name in possible_names['destructor']:
                    if name == possible_name:
                        self.functions['destructor'] = address
                        print(f"[*] 找到析构函数: {name} @ {hex(address)}")
                        break
            
            # 检查Open函数
            if 'open' not in self.functions:
                for possible_name in possible_names['open']:
                    if name == possible_name:
                        self.functions['open'] = address
                        print(f"[*] 找到Open函数: {name} @ {hex(address)}")
                        break
            
            # 检查GetSize函数
            if 'getSize' not in self.functions:
                for possible_name in possible_names['getSize']:
                    if name == possible_name:
                        self.functions['getSize'] = address
                        print(f"[*] 找到GetSize函数: {name} @ {hex(address)}")
                        break
            
            # 检查Read函数
            if 'read' not in self.functions:
                for possible_name in possible_names['read']:
                    if name == possible_name:
                        self.functions['read'] = address
                        print(f"[*] 找到Read函数: {name} @ {hex(address)}")
                        break
        
        # 检查是否所有函数都找到了
        required = ['constructor', 'destructor', 'open', 'getSize', 'read']
        missing = [f for f in required if f not in self.functions]
        
        if missing:
            raise RuntimeError(f"未找到所有必要的函数: {', '.join(missing)}")
        
        print("[*] 所有函数都已找到！")
        print("[*] 创建解密脚本...")
        
        # 创建解密脚本
        self._create_decrypt_script()
    
    def _create_decrypt_script(self):
        """创建并加载解密脚本"""
        script_code = f"""
        // 目标函数地址
        var constructorAddr = ptr("{hex(self.functions['constructor'])}");
        var destructorAddr = ptr("{hex(self.functions['destructor'])}");
        var openAddr = ptr("{hex(self.functions['open'])}");
        var getSizeAddr = ptr("{hex(self.functions['getSize'])}");
        var readAddr = ptr("{hex(self.functions['read'])}");
        
        // 创建NativeFunction包装器
        var Constructor = new NativeFunction(constructorAddr, "pointer", ["pointer"], "thiscall");
        var Destructor = new NativeFunction(destructorAddr, "void", ["pointer"], "thiscall");
        var Open = new NativeFunction(openAddr, "bool", ["pointer", "pointer", "bool", "bool"], "thiscall");
        var GetSize = new NativeFunction(getSizeAddr, "uint32", ["pointer"], "thiscall");
        var Read = new NativeFunction(readAddr, "uint", ["pointer", "pointer", "uint32", "uint64"], "thiscall");
        
        // 导出解密函数
        rpc.exports = {{
          decrypt: function (srcFileName, tmpFileName) {{
            try {{
              console.log("开始解密: " + srcFileName);
              
              // 1. 分配对象内存（0x28字节）
              var obj = Memory.alloc(0x28);
              
              // 2. 调用构造函数
              Constructor(obj);
              
              // 3. 转换路径为UTF-16
              var fileNameUtf16 = Memory.allocUtf16String(srcFileName);
              
              // 4. 打开加密文件
              var openResult = Open(obj, fileNameUtf16, 1, 0);
              console.log("打开文件结果: " + openResult);
              
              // 5. 获取文件大小
              var fileSize = GetSize(obj);
              console.log("文件大小: " + fileSize + " 字节");
              
              // 6. 分配缓冲区
              var buffer = Memory.alloc(fileSize);
              
              // 7. 读取解密后的数据
              var readResult = Read(obj, buffer, fileSize, 0);
              console.log("读取字节数: " + readResult);
              
              // 8. 转换为字节数组
              var data = buffer.readByteArray(fileSize);
              
              // 9. 释放对象资源
              Destructor(obj);
              
              // 10. 写入临时文件
              var tmpFile = new File(tmpFileName, "wb");
              tmpFile.write(data);
              tmpFile.close();
              
              console.log("解密完成: " + tmpFileName);
              return true;
            }} catch (e) {{
              console.log("解密出错: " + e);
              console.log("错误堆栈: " + e.stack);
              return false;
            }}
          }}
        }};
        
        console.log("解密脚本已加载");
        """
        
        # 创建并加载脚本
        self.decrypt_script = self.session.create_script(script_code)
        
        # 定义消息处理器
        def on_message(message, data):
            if message["type"] == "send":
                print(f"- {message['payload']}")
        
        self.decrypt_script.on("message", on_message)
        self.decrypt_script.load()
        print("[*] 解密脚本加载成功！")
    
    def decrypt(self, src_file, dest_file):
        """解密QQ音乐加密文件
        
        Args:
            src_file: 源文件路径（加密文件）
            dest_file: 目标文件路径（解密后文件）
        
        Returns:
            bool: 解密是否成功
        """
        try:
            # 调用解密函数
            result = self.decrypt_script.exports_sync.decrypt(src_file, dest_file)
            return result
        except Exception as e:
            print(f"[!] 解密出错: {e}")
            import traceback
            traceback.print_exc()
            return False
