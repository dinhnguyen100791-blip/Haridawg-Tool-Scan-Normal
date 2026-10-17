@echo off
title HARIDAWG APP
set "HBAT=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:HBAT); Invoke-Expression $t.Substring($t.IndexOf('#PS'+'START'))"
exit /b

#PSSTART
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Web
$dir  = Split-Path -Parent $env:HBAT
$html = Join-Path $dir 'haridawg_app.html'
if (-not (Test-Path -LiteralPath $html)) { Write-Host 'haridawg_app.html not found next to this file.'; Start-Sleep 4; exit }
$token = [guid]::NewGuid().ToString('N')
$qdir  = Join-Path $env:LOCALAPPDATA 'HARIDAWG\Quarantine'
$S = [hashtable]::Synchronized(@{ pct=0; stage='idle'; done=$true; running=$false
  logs  = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
  finds = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) })

# ---------------- scan job (runs in its own runspace) ----------------
$scan = {
  param($S, $folder)
  $ErrorActionPreference = 'SilentlyContinue'
  function L($m) { [void]$S.logs.Add('[' + (Get-Date -Format HH:mm:ss) + '] ' + $m) }
  $mp = @("$env:ProgramFiles\Windows Defender\MpCmdRun.exe") +
        @(Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" -Directory | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' }) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
  $S.logs.Clear(); $S.finds.Clear(); $S.done = $false; $S.running = $true; $start = Get-Date
  if ($folder -and -not (Test-Path -LiteralPath $folder -PathType Container)) { L("Folder not found, using all drives"); $folder = '' }

  # 1) every running program (background ones included)
  $S.stage = 'Running programs'; $S.pct = 5
  $groups = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Group-Object ExecutablePath)
  L("Programs: $($groups.Count) running programs (all background processes) found")
  $i = 0; $win = $env:windir
  foreach ($g in $groups) {
    $i++; $S.pct = 5 + [int](35 * $i / [math]::Max(1, $groups.Count)); $p = $g.Name; $sc = 0; $why = @()
    if (-not $p.StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) {
      $sig = Get-AuthenticodeSignature -LiteralPath $p
      if ($sig.Status -ne 'Valid') { $sc++; $why += 'no valid signature' }
      if ($p -match '\\(Temp|Downloads)\\') { $sc++; $why += 'runs from Temp/Downloads' }
      if ($p -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com)$') { $sc += 2; $why += 'double extension' }
    }
    if ($sc -ge 2) { [void]$S.finds.Add(@{ path = $p; reason = ($why -join ', '); src = 'process' }) }
  }
  L("Programs: $($S.finds.Count) suspicious")

  # 2) Windows Defender (same engine as Windows Security)
  $S.stage = 'Windows Defender'; $S.pct = 45
  if ($mp) {
    foreach ($f in @($S.finds)) {
      & $mp -Scan -ScanType 3 -File $f.path -DisableRemediation | Out-Null
      if ($LASTEXITCODE -eq 2) { $f.reason = $f.reason + ' + CONFIRMED by Windows Defender' }
    }
    if ($folder) { L("Defender: scanning $folder"); & $mp -Scan -ScanType 3 -File $folder -DisableRemediation | Out-Null }
    else         { L('Defender: quick scan'); & $mp -Scan -ScanType 1 -DisableRemediation | Out-Null }
    $n = 0
    Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $start } | ForEach-Object {
      $tid = $_.ThreatID
      foreach ($r in $_.Resources) {
        $pp = $r -replace '^file:_', ''
        if (-not ($S.finds | Where-Object { $_.path -eq $pp })) { [void]$S.finds.Add(@{ path = $pp; reason = "Windows Defender detection (threat $tid)"; src = 'defender' }); $n++ }
      }
    }
    L("Defender: $n threat(s) reported")
  } else { L('Windows Defender not found - heuristic checks only') }

  # 3) quick file heuristic in chosen folder
  if ($folder) {
    $S.stage = 'Files'; $S.pct = 90; $c = 0
    Get-ChildItem -LiteralPath $folder -Recurse -File -Force | Where-Object { $_.Name -match '\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com|bat|cmd|js|vbs)$' } | ForEach-Object {
      [void]$S.finds.Add(@{ path = $_.FullName; reason = 'double extension'; src = 'file' }); $c++ }
    L("Files: $c with double extension")
  }
  $S.pct = 100; $S.stage = 'Done'
  L("Result: $($S.finds.Count) item(s) need attention")
  $S.done = $true; $S.running = $false
}

# ---------------- local server (127.0.0.1 only, token protected) ----------------
function Send($ctx, [string]$body, [string]$type = 'application/json') {
  $b = [Text.Encoding]::UTF8.GetBytes($body)
  $ctx.Response.ContentType = "$type; charset=utf-8"; $ctx.Response.ContentLength64 = $b.Length
  $ctx.Response.OutputStream.Write($b, 0, $b.Length); $ctx.Response.Close()
}
function Deny($ctx) { $ctx.Response.StatusCode = 403; $ctx.Response.Close() }
function SysInfo {
  $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  $th = 0; $co = 0; Get-CimInstance Win32_Processor | ForEach-Object { $th += [int]$_.NumberOfLogicalProcessors; $co += [int]$_.NumberOfCores }
  $d = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | ForEach-Object {
    [ordered]@{ name = $_.DeviceID; label = [string]$_.VolumeName; total = [double]$_.Size; free = [double]$_.FreeSpace } })
  $o = [ordered]@{ user = $env:USERNAME; home = $env:USERPROFILE
    ram = [ordered]@{ total = [double]$cs.TotalPhysicalMemory; free = [double]$os.FreePhysicalMemory * 1024 }
    cpu = [ordered]@{ name = ([string]$cpu.Name).Trim(); cores = $co; threads = $th; maxMHz = [int]$cpu.MaxClockSpeed; load = [int]$cpu.LoadPercentage }
    disks = $d }
  'window.HARIDAWG_SYSINFO=' + ($o | ConvertTo-Json -Depth 5 -Compress) + ';'
}

$l = $null; $port = 0
foreach ($pt in (@(17321) + @(20000..40000 | Get-Random -Count 20))) {
  $x = New-Object Net.HttpListener; $x.Prefixes.Add("http://127.0.0.1:$pt/")
  try { $x.Start(); $l = $x; $port = $pt; break } catch {}
}
if (-not $l) { Write-Host 'Could not start local server.'; Start-Sleep 4; exit }

$url = "http://127.0.0.1:$port/?t=$token"
$cands = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LocalAppData\Google\Chrome\Application\chrome.exe")
$b = $cands | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if ($b) { Start-Process -FilePath $b -ArgumentList @("--app=$url", '--window-size=980,860') } else { Start-Process $url }

$last = Get-Date; $seen = $false
while ($l.IsListening) {
  $task = $l.GetContextAsync()
  while (-not $task.AsyncWaitHandle.WaitOne(1000)) { if ($seen -and ((Get-Date) - $last).TotalSeconds -gt 25) { $l.Stop(); break } }
  if (-not $l.IsListening) { break }
  $ctx = $task.Result
  try {
    $u = $ctx.Request.Url; $path = $u.AbsolutePath; $q = [Web.HttpUtility]::ParseQueryString($u.Query)
    if ($ctx.Request.UserHostName -ne "127.0.0.1:$port" -or $q['t'] -ne $token) { Deny $ctx; continue }
    $last = Get-Date
    switch ($path) {
      '/'            { Send $ctx ([IO.File]::ReadAllText($html)) 'text/html' }
      '/sysinfo.js'  { Send $ctx (SysInfo) 'application/javascript' }
      '/api/ping'    { $seen = $true; Send $ctx '{}' }
      '/api/state'   { Send $ctx (@{ pct = $S.pct; stage = $S.stage; done = $S.done; logs = [object[]]@($S.logs); findings = [object[]]@($S.finds) } | ConvertTo-Json -Depth 4 -Compress) }
      '/api/scan'    {
        if (-not $S.running) { $S.running = $true; $S.done = $false
          $script:ps = [powershell]::Create(); [void]$script:ps.AddScript($scan).AddArgument($S).AddArgument([string]$q['folder']); [void]$script:ps.BeginInvoke() }
        Send $ctx '{"ok":true}' }
      '/api/quarantine' {
        $req = @((New-Object IO.StreamReader($ctx.Request.InputStream)).ReadToEnd() | ConvertFrom-Json)
        $out = New-Object System.Collections.ArrayList
        New-Item -ItemType Directory -Force -Path $qdir | Out-Null
        foreach ($p in $req) {
          if (-not ($S.finds | Where-Object { $_.path -eq $p })) { [void]$out.Add("Skipped (not from this scan): $p"); continue }
          try { Move-Item -LiteralPath $p -Destination (Join-Path $qdir ((Get-Date -Format yyyyMMddHHmmss) + '_' + [IO.Path]::GetFileName($p) + '.quar')) -ErrorAction Stop; [void]$out.Add("Quarantined: $p") }
          catch { [void]$out.Add("Failed (in use or no permission - close the program first): $p") }
        }
        Send $ctx (@{ logs = [object[]]@($out) } | ConvertTo-Json -Compress) }
      default        { $ctx.Response.StatusCode = 404; $ctx.Response.Close() }
    }
  } catch { try { $ctx.Response.Abort() } catch {} }
}
