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
$probeScript = Join-Path $scriptDir 'qqmusic_parser_experiment.py'

if (-not (Test-Path $python)) {
    throw "未找到虚拟环境 Python: $python"
}
if (-not (Test-Path $probeScript)) {
    throw "未找到 parser 实验脚本: $probeScript"
}

Write-Host 'Starting QQMusic parser-level chain experiment...' -ForegroundColor Cyan
Write-Host "Sample: $Sample"
Write-Host "Duration: $Duration sec"
Write-Host 'While the probe is running, trigger one QQMusic "convert to common audio format" action for the target song.' -ForegroundColor Yellow

& $python $probeScript --sample $Sample --duration $Duration
