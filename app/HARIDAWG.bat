@echo off
title HARIDAWG APP
set "HBAT=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:HBAT); Invoke-Expression $t.Substring($t.IndexOf('#PS'+'START'))"
exit /b

#PSSTART
$ErrorActionPreference = 'SilentlyContinue'
$dir  = Split-Path -Parent $env:HBAT
$html = Join-Path $dir 'haridawg_app.html'

# ---- read real system info ----
$cs  = Get-CimInstance Win32_ComputerSystem
$os  = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$threads = 0; $cores = 0
Get-CimInstance Win32_Processor | ForEach-Object { $threads += [int]$_.NumberOfLogicalProcessors; $cores += [int]$_.NumberOfCores }

$disks = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | ForEach-Object {
  [ordered]@{ name = $_.DeviceID; label = [string]$_.VolumeName; total = [double]$_.Size; free = [double]$_.FreeSpace }
})

$info = [ordered]@{
  user  = $env:USERNAME
  home  = $env:USERPROFILE
  ram   = [ordered]@{ total = [double]$cs.TotalPhysicalMemory; free = [double]$os.FreePhysicalMemory * 1024 }
  cpu   = [ordered]@{ name = ([string]$cpu.Name).Trim(); cores = $cores; threads = $threads; maxMHz = [int]$cpu.MaxClockSpeed; load = [int]$cpu.LoadPercentage }
  disks = $disks
}
$json = $info | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText((Join-Path $dir 'sysinfo.js'), 'window.HARIDAWG_SYSINFO=' + $json + ';', (New-Object Text.UTF8Encoding $false))

# ---- open as an app window (Edge / Chrome), else default browser ----
if (-not (Test-Path -LiteralPath $html)) { Write-Host 'haridawg_app.html not found next to this file.'; Start-Sleep 4; exit }
$uri = ([System.Uri]$html).AbsoluteUri
$cands = @(
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
  "$env:LocalAppData\Google\Chrome\Application\chrome.exe"
)
$b = $cands | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if ($b) { Start-Process -FilePath $b -ArgumentList @("--app=$uri", '--window-size=980,860') }
else    { Start-Process $html }
