[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Sample,

    [int]$Duration = 60,

    [switch]$AttemptReinvoke
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$replayScript = Join-Path $scriptDir 'qqmusic_internal_export_replay.py'

if (-not (Test-Path $python)) {
    throw "未找到虚拟环境 Python: $python"
}
if (-not (Test-Path $replayScript)) {
    throw "未找到内部重放脚本: $replayScript"
}

$argsList = @(
    $replayScript,
    '--sample', $Sample,
    '--duration', "$Duration"
)

if ($AttemptReinvoke) {
    Write-Host '警告: --attempt-reinvoke 目前属于高风险实验，可能导致 QQ 音乐崩溃。' -ForegroundColor Yellow
    $argsList += '--attempt-reinvoke'
}

Write-Host '启动 QQMusic 内部重放候选捕获...' -ForegroundColor Cyan
Write-Host "样本: $Sample"
Write-Host "时长: $Duration 秒"
if ($AttemptReinvoke) {
    Write-Host '模式: 实验性重放' -ForegroundColor Yellow
} else {
    Write-Host '模式: 仅安全捕获候选调用现场' -ForegroundColor Yellow
}

& $python @argsList
