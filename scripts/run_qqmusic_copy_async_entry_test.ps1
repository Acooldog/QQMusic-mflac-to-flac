[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManagerThis,

    [Parameter(Mandatory = $true)]
    [string]$SourceUrlPrimary,

    [Parameter(Mandatory = $true)]
    [string]$SourceUrlSecondary,

    [Parameter(Mandatory = $true)]
    [string]$SourceCachePath,

    [Parameter(Mandatory = $true)]
    [string]$StreamUrl,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$scriptPath = Join-Path $scriptDir 'qqmusic_copy_async_entry_test.py'

if (-not (Test-Path $python)) {
    throw "未找到虚拟环境 Python: $python"
}
if (-not (Test-Path $scriptPath)) {
    throw "未找到 copy_async_entry 测试脚本: $scriptPath"
}

Write-Host '启动 QQMusic 高层内部导出实验...' -ForegroundColor Cyan
Write-Host "ManagerThis: $ManagerThis"
Write-Host "SourceCache: $SourceCachePath"
Write-Host "OutputPath : $OutputPath"

& $python $scriptPath `
    --manager-this $ManagerThis `
    --source-url-primary $SourceUrlPrimary `
    --source-url-secondary $SourceUrlSecondary `
    --source-cache-path $SourceCachePath `
    --stream-url $StreamUrl `
    --output-path $OutputPath
