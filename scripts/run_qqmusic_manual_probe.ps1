[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Sample,

    [int]$Duration = 120,

    [switch]$OpenSample
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$probeScript = Join-Path $scriptDir "qqmusic_manual_probe.py"

if (-not (Test-Path $python)) {
    throw "未找到虚拟环境 Python: $python"
}
if (-not (Test-Path $probeScript)) {
    throw "未找到探针脚本: $probeScript"
}

$argsList = @(
    $probeScript,
    "--sample", $Sample,
    "--duration", "$Duration"
)

if ($OpenSample) {
    $argsList += "--open-sample"
}

Write-Host "启动 QQMusic 手动探针..." -ForegroundColor Cyan
Write-Host "样本: $Sample"
Write-Host "时长: $Duration 秒"
if ($OpenSample) {
    Write-Host "模式: 启动后自动打开样本" -ForegroundColor Yellow
} else {
    Write-Host "模式: 你手动在 QQ 音乐里操作" -ForegroundColor Yellow
}

& $python @argsList
