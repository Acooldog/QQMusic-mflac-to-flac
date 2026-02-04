const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 读取当前版本号
const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const version = packageJson.version;

// 目录配置
const sourceDir = 'src';  // Python 源码目录
const distDir = 'dist';   // PyInstaller 输出目录
const releaseDir = 'release';
const zipName = `QQMusic-mflac-to-flac.zip`;

// 1. 自动运行 Python 构建
console.log('🚀 开始使用 PyInstaller 打包 Python 项目...');
try {
    console.log('📋 检查 Python 环境...');
    
    // 检查 PyInstaller 是否安装
    try {
        execSync('pyinstaller --version', { stdio: 'inherit' });
        console.log('✅ PyInstaller 已安装');
    } catch (error) {
        console.log('📦 安装 PyInstaller...');
        execSync('pip install pyinstaller', { stdio: 'inherit' });
    }
    
    // 安装项目依赖
    console.log('📦 安装项目依赖...');
    if (fs.existsSync('requirements.txt')) {
        execSync('pip install -r requirements.txt', { stdio: 'inherit' });
    } else if (fs.existsSync('pyproject.toml')) {
        execSync('pip install -e .', { stdio: 'inherit' });
    } else {
        console.log('📝 未找到依赖文件，跳过依赖安装');
    }
    
    // 2. 使用 PyInstaller 打包（无控制台窗口）
    console.log('🔨 使用 PyInstaller 打包...');
    
    // 确定入口文件
    let entryFile = 'main.py';
    const possibleEntryFiles = ['main.py', 'app.py', 'run.py', 'gui.py'];
    
    for (const file of possibleEntryFiles) {
        if (fs.existsSync(file)) {
            entryFile = file;
            break;
        }
    }
    
    if (!fs.existsSync(entryFile)) {
        // 如果没有找到入口文件，查找 .py 文件
        const pyFiles = fs.readdirSync('.').filter(file => file.endsWith('.py'));
        if (pyFiles.length > 0) {
            entryFile = pyFiles[0];
            console.log(`📄 使用入口文件: ${entryFile}`);
        } else {
            console.error('❌ 错误: 未找到 Python 入口文件');
            process.exit(1);
        }
    }
    
    // PyInstaller 打包命令 - 无控制台窗口
    const pyinstallerCmd = `pyinstaller --onefile --noconsole --name "QQMusic-mflac-to-flac" "${entryFile}"`;
    
    console.log(`📦 执行打包命令: ${pyinstallerCmd}`);
    execSync(pyinstallerCmd, { stdio: 'inherit' });
    
    console.log('✅ PyInstaller 打包完成！');
    
} catch (buildError) {
    console.error('❌ PyInstaller 打包失败:');
    console.error(buildError.message);
    process.exit(1);
}

// 3. 清理旧版本文件
console.log('🧹 清理旧版本文件...');
if (fs.existsSync(releaseDir)) {
    const files = fs.readdirSync(releaseDir);
    files.forEach(file => {
        if (file.endsWith('.zip') && file.startsWith('QQMusic-mflac-to-flac-')) {
            const filePath = path.join(releaseDir, file);
            fs.unlinkSync(filePath);
            console.log(`🗑️  删除旧文件: ${file}`);
        }
    });
} else {
    // 创建 release 目录（如果不存在）
    fs.mkdirSync(releaseDir, { recursive: true });
}

// 4. 检查 PyInstaller 输出文件
const exePath = path.join(distDir, 'QQMusic-mflac-to-flac.exe');
if (!fs.existsSync(exePath)) {
    console.error(`❌ 错误: PyInstaller 输出文件不存在: ${exePath}`);
    console.error('💡 请检查 PyInstaller 构建日志');
    process.exit(1);
}

// 5. 创建包含可执行文件的发布包
console.log(`📦 创建发布压缩包: ${zipName}`);
try {
    // 创建临时目录用于打包
    const tempDir = 'temp_release';
    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });
    
    // 复制可执行文件到临时目录
    fs.copyFileSync(exePath, path.join(tempDir, 'QQMusic-mflac-to-flac.exe'));
    
    // 复制其他必要文件
    const filesToInclude = ['README.md', 'LICENSE.txt', 'requirements.txt'];
    filesToInclude.forEach(file => {
        if (fs.existsSync(file)) {
            fs.copyFileSync(file, path.join(tempDir, file));
            console.log(`📄 包含文件: ${file}`);
        }
    });
    
    // 创建压缩包
    try {
        execSync(`7z a -tzip "${path.join(releaseDir, zipName)}" "${tempDir}/*"`, { stdio: 'inherit' });
        console.log(`✅ 使用 7z 创建压缩包: ${zipName}`);
    } catch (error) {
        // 回退到 PowerShell
        try {
            execSync(`powershell -Command "Compress-Archive -Path '${tempDir}/*' -DestinationPath '${path.join(releaseDir, zipName)}' -Force"`, { stdio: 'inherit' });
            console.log(`✅ 使用 PowerShell 创建压缩包: ${zipName}`);
        } catch (psError) {
            console.error('❌ 压缩失败');
            process.exit(1);
        }
    }
    
    // 清理临时目录
    fs.rmSync(tempDir, { recursive: true });
    
} catch (error) {
    console.error('❌ 创建发布包失败:');
    console.error(error.message);
    process.exit(1);
}

// 6. 验证压缩包
if (fs.existsSync(path.join(releaseDir, zipName))) {
    const stats = fs.statSync(path.join(releaseDir, zipName));
    console.log(`🎉 打包完成: ${zipName} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);
    
    // 显示可执行文件信息
    const exeStats = fs.statSync(exePath);
    console.log(`📁 生成的可执行文件: QQMusic-mflac-to-flac.exe (${(exeStats.size / 1024 / 1024).toFixed(2)} MB)`);
    console.log('💡 特性: 无控制台窗口的单文件可执行程序');
} else {
    console.error('❌ 压缩包创建失败');
    process.exit(1);
}

console.log('✨ 所有步骤完成！');