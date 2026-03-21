[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Sample,

    [int]$Duration = 60
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$probeScript = Join-Path $scriptDir 'qqmusic_internal_export_probe.py'

if (-not (Test-Path $python)) {
    throw "未找到虚拟环境 Python: $python"
}
if (-not (Test-Path $probeScript)) {
    throw "未找到内部探针脚本: $probeScript"
}

Write-Host '启动 QQMusic 内部导出探针...' -ForegroundColor Cyan
Write-Host "样本: $Sample"
Write-Host "时长: $Duration 秒"

& $python $probeScript --sample $Sample --duration $Duration
