$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Get-Content -LiteralPath (Join-Path $root 'scripts/package_process.cs') -Raw
$runner = Join-Path $root 'scripts/package_execute.ps1'
Add-Type -TypeDefinition $source -Language CSharp
$directory = Join-Path ([IO.Path]::GetTempPath()) ('software-manager-test-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $directory
$exe = Join-Path $directory 'test installer.exe'
$tree = Join-Path $directory 'tree.txt'
$registry = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\software-manager-test-' + [guid]::NewGuid()
$sentinel = $null
$tracked = @()
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Test-Alive([int]$Id) {
    return $null -ne (Get-Process -Id $Id -ErrorAction SilentlyContinue)
}
try {
    Add-Type -OutputAssembly $exe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
public static class TestInstaller {
    public static int Main(string[] args) {
        switch (args[0]) {
            case "exit": return Int32.Parse(args[1]);
            case "sleep": Thread.Sleep(60000); return 0;
            case "write": File.WriteAllLines(args[1], new string[] { args[2], args[3], args[4] }); return 0;
            case "tree":
                File.AppendAllText(args[1], Process.GetCurrentProcess().Id + Environment.NewLine);
                Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "branch \"" + args[1] + "\"") { UseShellExecute = false });
                Thread.Sleep(60000); return 0;
            case "branch":
                File.AppendAllText(args[1], Process.GetCurrentProcess().Id + Environment.NewLine);
                Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "leaf \"" + args[1] + "\"") { UseShellExecute = false });
                Thread.Sleep(60000); return 0;
            case "leaf":
                File.AppendAllText(args[1], Process.GetCurrentProcess().Id + Environment.NewLine);
                Thread.Sleep(60000); return 0;
            case "orphan":
                Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "leaf \"" + args[1] + "\"") { UseShellExecute = false });
                return 0;
            default: return 1;
        }
    }
}
'@
    $sentinel = Start-Process -FilePath $exe -ArgumentList 'sleep' -PassThru
    $result = [SoftwareManager.PackageProcess]::Run($exe, 'exit 23', $directory, 5, $true)
    Assert-True (-not $result.TimedOut -and $result.ExitCode -eq 23) 'Unexpected exit code'
    foreach ($wait in @($true, $false)) {
        Remove-Item -LiteralPath $tree -ErrorAction SilentlyContinue
        $result = [SoftwareManager.PackageProcess]::Run($exe, ('tree ' + [SoftwareManager.PackageProcess]::Quote($tree)), $directory, 5, $wait)
        Assert-True ($result.TimedOut -and $result.CleanupConfirmed) 'Tree termination was not confirmed'
        $tracked = @(Get-Content -LiteralPath $tree | ForEach-Object { [int]$_ })
        Assert-True ($tracked.Count -eq 3) 'The test did not create the full process tree'
        foreach ($id in $tracked) { Assert-True (-not (Test-Alive $id)) 'Installer descendant survived timeout' }
        Assert-True (Test-Alive $sentinel.Id) 'Unrelated process was terminated'
    }
    Remove-Item -LiteralPath $tree -ErrorAction SilentlyContinue
    $result = [SoftwareManager.PackageProcess]::Run($exe, ('orphan ' + [SoftwareManager.PackageProcess]::Quote($tree)), $directory, 5, $true)
    Assert-True ($result.TimedOut -and $result.CleanupConfirmed) 'Exited parent did not wait for its child'
    $tracked = @(Get-Content -LiteralPath $tree | ForEach-Object { [int]$_ })
    Assert-True ($tracked.Count -eq 1 -and -not (Test-Alive $tracked[0])) 'Child survived parent exit and timeout'
    Remove-Item -LiteralPath $tree -ErrorAction SilentlyContinue
    $result = [SoftwareManager.PackageProcess]::Run($exe, ('orphan ' + [SoftwareManager.PackageProcess]::Quote($tree)), $directory, 5, $false)
    Assert-True (-not $result.TimedOut -and $result.ExitCode -eq 0) 'wait_for_children=false did not return on parent exit'
    for ($attempt = 0; $attempt -lt 50 -and -not (Test-Path -LiteralPath $tree); $attempt++) { Start-Sleep -Milliseconds 100 }
    $tracked = @(Get-Content -LiteralPath $tree | ForEach-Object { [int]$_ })
    Assert-True ($tracked.Count -eq 1 -and (Test-Alive $tracked[0])) 'Child was killed after successful root exit'
    Stop-Process -Id $tracked[0] -Force
    $tracked = @()
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    & $runner -ProcessSource $source -Operation install -Provider registry -TimeoutSeconds 5 -Path $exe -Checksum ('0' * 64) -Arguments @('exit', '0')
    Assert-True ($Ansible.Failed -and $Ansible.Result.error_code -eq 'checksum' -and -not $Ansible.Changed) 'Checksum failure was not rejected'
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    $output = Join-Path $directory 'arguments.txt'
    $expected = @('value with spaces', 'trailing\', 'a"b')
    & $runner -ProcessSource $source -Operation install -Provider registry -TimeoutSeconds 5 -Path $exe -Checksum $hash -Arguments (@('write', $output) + $expected)
    Assert-True (-not $Ansible.Failed -and $Ansible.Changed -and $Ansible.Result.rc -eq 0) 'EXE installation result was invalid'
    $actual = @(Get-Content -LiteralPath $output)
    Assert-True (($actual -join '|') -ceq ($expected -join '|')) 'Argument list quoting changed values'
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    & $runner -ProcessSource $source -Operation install -Provider registry -TimeoutSeconds 5 -Path $exe -Checksum $hash -Arguments 'exit 3010'
    Assert-True (-not $Ansible.Failed -and $Ansible.Result.rc -eq 3010 -and $Ansible.Result.reboot_required) 'Reboot code not preserved'
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    & $runner -ProcessSource $source -Operation install -Provider registry -TimeoutSeconds 5 -Path $exe -Checksum $hash -Arguments @('sleep')
    Assert-True ($Ansible.Failed -and $Ansible.Result.timed_out -and $Ansible.Result.cleanup_confirmed) 'PowerShell timeout receipt invalid'
    $null = New-Item -Path $registry
    $null = New-ItemProperty -LiteralPath $registry -Name QuietUninstallString -Value ('"' + $exe + '" exit 0')
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    & $runner -ProcessSource $source -Operation remove -Provider registry -TimeoutSeconds 5 -ProductId (Split-Path -Leaf $registry)
    Assert-True (-not $Ansible.Failed -and $Ansible.Changed -and $Ansible.Result.rc -eq 0) 'Registry uninstall failed'
    $Ansible = @{ Changed = $false; Failed = $false; Result = @{} }
    & $runner -ProcessSource $source -Operation remove -Provider msi -TimeoutSeconds 5 -ProductId ([guid]::NewGuid().ToString('B'))
    Assert-True (-not $Ansible.Failed -and -not $Ansible.Changed -and $Ansible.Result.rc -eq 0) 'Absent MSI removal is not idempotent'
    Write-Output 'Installer process tests passed.'
} finally {
    foreach ($id in $tracked) {
        $process = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($null -ne $process -and $process.Path -eq $exe) { Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue }
    }
    if ($null -ne $sentinel) { Stop-Process -InputObject $sentinel -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $registry -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
}
