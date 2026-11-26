$ErrorActionPreference = 'Stop'
$processes = @(Get-Process -ErrorAction Stop | Where-Object { ($_.ProcessName + '.exe') -like $image })
if ($processes.Count -eq 0) {
    Write-Output 'SOFTWARE_MANAGER_NO_PROCESS'
    exit 0
}
foreach ($process in $processes) {
    Stop-Process -InputObject $process -Force -ErrorAction Stop
}
exit 0
