const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');

// 读取当前版本号
const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const version = packageJson.version;

// 配置变量
const APP_NAME = 'QQMusic-mflac-to-flac-console';  // EXE名称变量
const APP_VERSION = version;                // 版本号
const SOURCE_DIR = 'src';                   // Python 源码目录
const DIST_DIR = 'dist';                    // PyInstaller 输出目录
const RELEASE_DIR = 'release';             // 发布目录
const EXE_NAME = `${APP_NAME}.exe`;        // 最终exe名称
// const ZIP_NAME = `${APP_NAME}-v${APP_VERSION}.zip`;  // 压缩包名称
const ZIP_NAME = `${APP_NAME}.zip`;  // 压缩包名称

// 获取虚拟环境路径
const isWindows = process.platform === 'win32';
const venvDir = '.venv';
const venvPython = isWindows 
    ? path.join(venvDir, 'Scripts', 'python.exe')
    : path.join(venvDir, 'bin', 'python');
const venvPip = isWindows 
    ? path.join(venvDir, 'Scripts', 'pip.exe')
    : path.join(venvDir, 'bin', 'pip');

// 检查虚拟环境是否存在
function checkVenv() {
    if (!fs.existsSync(venvDir)) {
        console.error(`❌ 虚拟环境不存在: ${venvDir}`);
        console.log('💡 请先创建虚拟环境: python -m venv .venv');
        process.exit(1);
    }
    
    if (!fs.existsSync(venvPython)) {
        console.error(`❌ 虚拟环境Python不存在: ${venvPython}`);
        process.exit(1);
    }
    
    console.log(`✅ 使用虚拟环境: ${venvDir}`);
    return true;
}

// 在虚拟环境中执行命令
function execInVenv(command, options = {}) {
    const fullCommand = isWindows 
        ? `"${venvPython}" -c "${command}"`
        : `${venvPython} -c "${command}"`;
    
    return execSync(fullCommand, { 
        stdio: 'inherit',
        ...options 
    });
}

// 在虚拟环境中运行脚本
function runScriptInVenv(script, options = {}) {
    const fullCommand = `"${venvPython}" ${script}`;
    return execSync(fullCommand, { 
        stdio: 'inherit',
        ...options 
    });
}

// 主构建函数
async function build() {
    console.log(`🚀 开始构建: ${APP_NAME} v${APP_VERSION}`);
    console.log(`📁 EXE名称: ${EXE_NAME}`);
    
    // 1. 检查虚拟环境
    checkVenv();
    
    // 2. 安装/更新 PyInstaller
    console.log('📦 检查 PyInstaller...');
    try {
        execInVenv('import pyinstaller');
        console.log('✅ PyInstaller 已安装');
    } catch (error) {
        console.log('📦 安装 PyInstaller...');
        const pipCmd = isWindows ? `"${venvPip}" install pyinstaller` : `${venvPip} install pyinstaller`;
        execSync(pipCmd, { stdio: 'inherit' });
    }
    
    // 3. 安装项目依赖
    console.log('📦 安装项目依赖...');
    if (fs.existsSync('requirements.txt')) {
        const pipCmd = isWindows ? `"${venvPip}" install -r requirements.txt` : `${venvPip} install -r requirements.txt`;
        execSync(pipCmd, { stdio: 'inherit' });
    } else if (fs.existsSync('pyproject.toml')) {
        const pipCmd = isWindows ? `"${venvPip}" install -e .` : `${venvPip} install -e .`;
        execSync(pipCmd, { stdio: 'inherit' });
    } else {
        console.log('📝 未找到依赖文件，跳过依赖安装');
    }
    
    // 4. 确定入口文件
    console.log('🔍 查找入口文件...');
    let entryFile = 'main.py';
    const possibleEntryFiles = ['main.py', 'app.py', 'run.py', 'gui.py'];
    
    for (const file of possibleEntryFiles) {
        if (fs.existsSync(file)) {
            entryFile = file;
            break;
        }
    }
    
    if (!fs.existsSync(entryFile)) {
        const pyFiles = fs.readdirSync('.').filter(file => file.endsWith('.py'));
        if (pyFiles.length > 0) {
            entryFile = pyFiles[0];
        } else {
            console.error('❌ 错误: 未找到 Python 入口文件');
            process.exit(1);
        }
    }
    
    console.log(`📄 使用入口文件: ${entryFile}`);
    
    // 5. 清理旧的构建文件
    console.log('🧹 清理旧构建文件...');
    if (fs.existsSync('build')) {
        fs.rmSync('build', { recursive: true });
    }
    if (fs.existsSync(DIST_DIR)) {
        fs.rmSync(DIST_DIR, { recursive: true });
    }
    if (fs.existsSync(`${APP_NAME}.spec`)) {
        fs.unlinkSync(`${APP_NAME}.spec`);
    }
    
    // 6. 使用 PyInstaller 打包
    console.log('🔨 使用 PyInstaller 打包...');
    
    // 检查 plugins 目录是否存在
    const pluginsDir = 'plugins';
    const pluginsExist = fs.existsSync(pluginsDir);
    
    // 构建 PyInstaller 命令
    let pyinstallerCmd = `"${venvPython}" -m PyInstaller --onefile --name "${APP_NAME}"`;
    
    // 添加 plugins 文件夹（如果存在）
    if (pluginsExist) {
        console.log(`📁 包含 plugins 目录: ${pluginsDir}`);
        pyinstallerCmd += ` --add-data "${pluginsDir};plugins"`;
    }
    
    // 添加其他必要资源
    const additionalResources = ['./plugins'];
    additionalResources.forEach(resource => {
        if (fs.existsSync(resource)) {
            if (fs.statSync(resource).isDirectory()) {
                pyinstallerCmd += ` --add-data "${resource}/*;${resource}"`;
            } else {
                pyinstallerCmd += ` --add-data "${resource};."`;
            }
        }
    });
    
    // 添加 hidden-imports 用于常见库
    // const hiddenImports = [
    //     'PyQt5.QtCore',
    //     'PyQt5.QtGui',
    //     'PyQt5.QtWidgets',
    //     'PyQt5.sip',
    //     'numpy',
    //     'pandas',
    //     'PIL',
    //     'PIL._imaging'
    // ];
    
    // hiddenImports.forEach(module => {
    //     pyinstallerCmd += ` --hidden-import ${module}`;
    // });
    
    // 添加入口文件
    pyinstallerCmd += ` "${entryFile}"`;
    
    console.log(`📦 执行打包命令: ${pyinstallerCmd}`);
    
    try {
        execSync(pyinstallerCmd, { stdio: 'inherit' });
        console.log('✅ PyInstaller 打包完成！');
    } catch (buildError) {
        console.error('❌ PyInstaller 打包失败:');
        console.error(buildError.message);
        process.exit(1);
    }
    
    // 7. 检查输出文件
    const exePath = path.join(DIST_DIR, EXE_NAME);
    if (!fs.existsSync(exePath)) {
        console.error(`❌ 错误: PyInstaller 输出文件不存在: ${exePath}`);
        process.exit(1);
    }
    
    // 8. 验证 plugins 是否包含
    if (pluginsExist) {
        console.log('🔍 验证资源包含...');
        // 可以在这里添加验证逻辑，比如检查exe大小等
    }
    
    // 9. 创建发布包
    console.log(`📦 创建发布压缩包: ${ZIP_NAME}`);
    await createReleasePackage(exePath);
    
    // 10. 完成
    console.log('✨ 构建完成！');
    console.log(`📁 输出文件: ${path.join(DIST_DIR, EXE_NAME)}`);
    console.log(`📦 发布包: ${path.join(RELEASE_DIR, ZIP_NAME)}`);
}

// 创建发布包
async function createReleasePackage(exePath) {
    // 清理旧版本文件
    if (fs.existsSync(RELEASE_DIR)) {
        const files = fs.readdirSync(RELEASE_DIR);
        files.forEach(file => {
            if (file.endsWith('.zip') && file.startsWith(APP_NAME)) {
                const filePath = path.join(RELEASE_DIR, file);
                fs.unlinkSync(filePath);
                console.log(`🗑️  删除旧文件: ${file}`);
            }
        });
    } else {
        fs.mkdirSync(RELEASE_DIR, { recursive: true });
    }
    
    // 创建临时目录
    const tempDir = 'temp_release';
    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });
    
    // 复制可执行文件
    fs.copyFileSync(exePath, path.join(tempDir, EXE_NAME));
    
    // 复制 README.md
    if (fs.existsSync('README.md')) {
        fs.copyFileSync('README.md', path.join(tempDir, 'README.md'));
    }
    
    // 创建配置文件说明
    const configText = `# ${APP_NAME} v${APP_VERSION}

    ## 使用说明
    1. 直接运行 ${EXE_NAME} 即可
    2. 如果需要配置文件，请查看同目录下的 config.ini（如有）

    ## 构建信息
    - 构建时间: ${new Date().toLocaleString()}
    - 程序名称: ${APP_NAME}
    - 版本: v${APP_VERSION}
    - 打包方式: PyInstaller (无控制台窗口)
    `;
    
    fs.writeFileSync(path.join(tempDir, 'BUILD_INFO.txt'), configText);
    
    // 创建压缩包
    try {
        // 尝试使用 7z
        execSync(`7z a -tzip "${path.join(RELEASE_DIR, ZIP_NAME)}" "${tempDir}\\*"`, { 
            stdio: 'inherit',
            cwd: process.cwd()
        });
        console.log(`✅ 使用 7z 创建压缩包`);
    } catch (error) {
        try {
            // 回退到 PowerShell
            const psCommand = `powershell -Command "Compress-Archive -Path '${tempDir}\\*' -DestinationPath '${path.join(RELEASE_DIR, ZIP_NAME)}' -Force"`;
            execSync(psCommand, { 
                stdio: 'inherit',
                cwd: process.cwd()
            });
            console.log(`✅ 使用 PowerShell 创建压缩包`);
        } catch (psError) {
            console.error('❌ 压缩失败');
            console.error(psError.message);
        }
    }
    
    // 清理临时目录
    fs.rmSync(tempDir, { recursive: true });
    
    // 验证压缩包
    if (fs.existsSync(path.join(RELEASE_DIR, ZIP_NAME))) {
        const stats = fs.statSync(path.join(RELEASE_DIR, ZIP_NAME));
        console.log(`📦 压缩包大小: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);
        return true;
    } else {
        console.error('❌ 压缩包创建失败');
        return false;
    }
}

// 运行构建
build().catch(error => {
    console.error('❌ 构建过程中发生错误:');
    console.error(error);
    process.exit(1);
});