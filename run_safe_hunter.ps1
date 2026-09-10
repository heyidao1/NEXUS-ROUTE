$ErrorActionPreference = 'Stop'
$root = 'C:\Users\hexiaohan\bugbounty-safe-runner'
$state = Join-Path $root 'state'
$logs = Join-Path $state 'logs'
$lock = Join-Path $state 'runner.lock'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
if (Test-Path $lock) {
  $age = (Get-Date) - (Get-Item $lock).LastWriteTime
  if ($age.TotalHours -lt 2) { exit 0 }
  Remove-Item $lock -Force
}
New-Item -ItemType File -Force -Path $lock | Out-Null
try {
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $log = Join-Path $logs ("run-$stamp.log")
  Set-Location $root
  $env:PYTHONUTF8 = '1'
  python .\bounty\safe_hunter.py *>&1 | Tee-Object -FilePath $log
  python .\bounty\triage_queue.py *>&1 | Tee-Object -FilePath $log -Append
  Get-Date -Format o | Set-Content -Encoding UTF8 (Join-Path $state 'last-success.txt')
} catch {
  $_ | Out-File -Append -Encoding UTF8 (Join-Path $logs 'runner-errors.log')
  throw
} finally {
  Remove-Item $lock -Force -ErrorAction SilentlyContinue
}
