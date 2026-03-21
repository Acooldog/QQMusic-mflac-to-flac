param(
    [string]$CandidateLog = "O:\A_python\A_QQd\_log\probe_qqmusic_play\probe_internal_1774084699.jsonl",
    [string]$OutputPath = "O:\A_python\A_QQd\output\direct-call-test\auto.flac"
)

$cache = Get-ChildItem "K:\QQMusicCache\QMDL" | Select-Object -First 1 -ExpandProperty FullName
$cover = Get-ChildItem "K:\QQMusicCache\QQMusicPicture" | Select-Object -First 1 -ExpandProperty FullName

if (-not $cache -or -not (Test-Path $cache)) {
    throw "source cache file not found"
}
if (-not $cover -or -not (Test-Path $cover)) {
    throw "cover file not found"
}

if (Test-Path $OutputPath) {
    Remove-Item -Force $OutputPath
}

& "O:\A_python\A_QQd\.venv\Scripts\python.exe" `
  "O:\A_python\A_QQd\scripts\qqmusic_direct_decrypt_call_test.py" `
  --candidate-log $CandidateLog `
  --source-cache-path $cache `
  --output-path $OutputPath `
  --cover-path $cover
