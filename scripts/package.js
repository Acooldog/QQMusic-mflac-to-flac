const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const APP_NAME = 'QQMusic-mflac-to-flac';
const rootDir = path.resolve(__dirname, '..');
const venvDir = path.join(rootDir, '.venv');
const pythonExe = process.platform === 'win32'
  ? path.join(venvDir, 'Scripts', 'python.exe')
  : path.join(venvDir, 'bin', 'python');
const pipExe = process.platform === 'win32'
  ? path.join(venvDir, 'Scripts', 'pip.exe')
  : path.join(venvDir, 'bin', 'pip');
const distDir = path.join(rootDir, 'dist');
const buildDir = path.join(rootDir, 'build');
const releaseDir = path.join(rootDir, 'release');
const specDir = path.join(buildDir, 'spec');
const mainPy = path.join(rootDir, 'main.py');
const assetsDir = path.join(rootDir, 'assets');

function ensureFile(target, label) {
  if (!fs.existsSync(target)) {
    throw new Error(`${label} not found: ${target}`);
  }
}

function ensureDir(target, label) {
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
    throw new Error(`${label} not found: ${target}`);
  }
}

function cleanDir(target) {
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
}

function run(file, args, options = {}) {
  console.log(`> ${file} ${args.join(' ')}`);
  execFileSync(file, args, {
    cwd: rootDir,
    stdio: 'inherit',
    ...options,
  });
}

function checkEnvironment() {
  ensureDir(venvDir, 'virtual environment');
  ensureFile(pythonExe, 'venv python');
  ensureFile(mainPy, 'main entry');
  ensureDir(assetsDir, 'assets directory');
  ensureFile(path.join(assetsDir, 'ffmpeg-win-x86_64-v7.1.exe'), 'bundled ffmpeg');
}

function ensureDependencies() {
  try {
    run(pythonExe, ['-c', 'import PyInstaller'], { stdio: 'ignore' });
  } catch {
    run(pipExe, ['install', 'pyinstaller']);
  }
}

function buildOnefile() {
  cleanDir(distDir);
  cleanDir(buildDir);
  cleanDir(releaseDir);

  const args = [
    '-m', 'PyInstaller',
    '--noconfirm',
    '--clean',
    '--onefile',
    '--windowed',
    '--name', APP_NAME,
    '--distpath', distDir,
    '--workpath', path.join(buildDir, 'work'),
    '--specpath', specDir,
    '--paths', rootDir,
    '--collect-submodules', 'src',
    '--collect-all', 'PyQt5',
    '--add-data', `${assetsDir};assets`,
    mainPy,
  ];

  run(pythonExe, args);

  const exePath = path.join(distDir, `${APP_NAME}.exe`);
  ensureFile(exePath, 'onefile executable');
  fs.copyFileSync(exePath, path.join(releaseDir, `${APP_NAME}.exe`));
}

function main() {
  console.log(`Building ${APP_NAME} (onefile)`);
  checkEnvironment();
  ensureDependencies();
  buildOnefile();
  console.log(`Release ready: ${path.join(releaseDir, `${APP_NAME}.exe`)}`);
  console.log('plugins, _log, output 等运行期目录会在 exe 同级外部自动生成。');
}

main();
