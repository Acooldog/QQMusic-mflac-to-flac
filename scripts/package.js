const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const version = packageJson.version;

const APP_NAME = 'QQMusic-mflac-to-flac';
const APP_VERSION = version;
const DIST_DIR = 'dist';
const RELEASE_DIR = 'release';
const EXE_NAME = `${APP_NAME}.exe`;
const DIST_APP_DIR = path.join(DIST_DIR, APP_NAME);
const ZIP_NAME = `${APP_NAME}.zip`;

const isWindows = process.platform === 'win32';
const venvDir = '.venv';
const venvPython = isWindows
  ? path.join(venvDir, 'Scripts', 'python.exe')
  : path.join(venvDir, 'bin', 'python');
const venvPip = isWindows
  ? path.join(venvDir, 'Scripts', 'pip.exe')
  : path.join(venvDir, 'bin', 'pip');

function checkVenv() {
  if (!fs.existsSync(venvDir)) {
    console.error(`Virtual env not found: ${venvDir}`);
    process.exit(1);
  }
  if (!fs.existsSync(venvPython)) {
    console.error(`Python not found in venv: ${venvPython}`);
    process.exit(1);
  }
}

function installDependencies() {
  console.log('Installing dependencies...');
  if (fs.existsSync('requirements.txt')) {
    execSync(`"${venvPip}" install -r requirements.txt`, { stdio: 'inherit' });
  }

  try {
    execSync(`"${venvPython}" -c "import PyInstaller"`, { stdio: 'ignore' });
  } catch {
    execSync(`"${venvPip}" install pyinstaller`, { stdio: 'inherit' });
  }
}

function pickEntryFile() {
  const candidates = ['main.py', 'app.py', 'run.py', 'gui.py'];
  for (const file of candidates) {
    if (fs.existsSync(file)) {
      return file;
    }
  }

  const pyFiles = fs.readdirSync('.').filter((file) => file.endsWith('.py'));
  if (!pyFiles.length) {
    throw new Error('No Python entry file found.');
  }
  return pyFiles[0];
}

function cleanBuildArtifacts() {
  if (fs.existsSync('build')) {
    fs.rmSync('build', { recursive: true, force: true });
  }
  if (fs.existsSync(DIST_DIR)) {
    fs.rmSync(DIST_DIR, { recursive: true, force: true });
  }
  const specPath = `${APP_NAME}.spec`;
  if (fs.existsSync(specPath)) {
    fs.rmSync(specPath, { force: true });
  }
}

function buildPyInstaller(entryFile) {
  const cmd = [
    `"${venvPython}"`,
    '-m',
    'PyInstaller',
    '--clean',
    '--noconfirm',
    '--onedir',
    '--noconsole',
    '--name',
    `"${APP_NAME}"`,
    `"${entryFile}"`,
  ].join(' ');

  console.log(`Running: ${cmd}`);
  execSync(cmd, { stdio: 'inherit' });
}

function createReleaseZip() {
  const exePath = path.join(DIST_APP_DIR, EXE_NAME);
  if (!fs.existsSync(exePath)) {
    throw new Error(`Executable not found: ${exePath}`);
  }

  if (fs.existsSync(RELEASE_DIR)) {
    fs.rmSync(RELEASE_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(RELEASE_DIR, { recursive: true });

  const tempDir = 'temp_release';
  if (fs.existsSync(tempDir)) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  fs.mkdirSync(tempDir, { recursive: true });

  const releaseAppDir = path.join(tempDir, APP_NAME);
  fs.cpSync(DIST_APP_DIR, releaseAppDir, { recursive: true });

  if (fs.existsSync('README.md')) {
    fs.copyFileSync('README.md', path.join(tempDir, 'README.md'));
  }
  if (fs.existsSync('LICENSE')) {
    fs.copyFileSync('LICENSE', path.join(tempDir, 'LICENSE'));
  }

  const buildInfo = [
    `${APP_NAME} v${APP_VERSION}`,
    '',
    `Build time: ${new Date().toLocaleString()}`,
    'Packaging mode: PyInstaller onedir + noconsole',
    `Executable: ${APP_NAME}\\${EXE_NAME}`,
  ].join('\n');
  fs.writeFileSync(path.join(tempDir, 'BUILD_INFO.txt'), buildInfo, 'utf8');

  const zipPath = path.join(RELEASE_DIR, ZIP_NAME);

  try {
    execSync(`7z a -tzip "${zipPath}" "${tempDir}\\*"`, { stdio: 'inherit' });
  } catch {
    const psCmd = `powershell -Command "Compress-Archive -Path '${tempDir}\\*' -DestinationPath '${zipPath}' -Force"`;
    execSync(psCmd, { stdio: 'inherit' });
  }

  fs.rmSync(tempDir, { recursive: true, force: true });
  console.log(`Release package created: ${zipPath}`);
}

function main() {
  console.log(`Building ${APP_NAME} v${APP_VERSION}`);
  checkVenv();
  installDependencies();
  const entryFile = pickEntryFile();
  console.log(`Entry file: ${entryFile}`);
  cleanBuildArtifacts();
  buildPyInstaller(entryFile);
  createReleaseZip();
}

main();
