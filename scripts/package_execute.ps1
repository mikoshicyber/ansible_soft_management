param(
    [Parameter(Mandatory = $true)][string]$ProcessSource,
    [Parameter(Mandatory = $true)][ValidateSet('install', 'reapply', 'remove')][string]$Operation,
    [Parameter(Mandatory = $true)][ValidateSet('msi', 'registry')][string]$Provider,
    [Parameter(Mandatory = $true)][ValidateRange(5, 86400)][int]$TimeoutSeconds,
    [string]$Path,
    [string]$Checksum,
    [string]$ProductId,
    [object]$Arguments,
    [bool]$WaitForChildren = $true,
    [bool]$VerifySignature = $false
)
$ErrorActionPreference = 'Stop'
$Ansible.Changed = $false
$Ansible.Result = @{ reboot_required = $false }

function Resolve-Uninstall([string]$Command) {
    $Command = $Command.Trim()
    if ($Command.StartsWith('%') -or $Command.StartsWith('"%')) { $Command = [Environment]::ExpandEnvironmentVariables($Command) }
    if ($Command -match '^"([^\"]+)"(?:\s+(.*))?$') {
        $file = $Matches[1]
        $tail = if ($Matches.ContainsKey(2)) { $Matches[2] } else { '' }
    } elseif ($Command -match '^(.+?\.exe)(?:\s+(.*))?$') {
        $file = $Matches[1]
        $tail = if ($Matches.ContainsKey(2)) { $Matches[2] } else { '' }
    } elseif ($Command -match '^([^\s]+)(?:\s+(.*))?$') {
        $file = $Matches[1]
        $tail = if ($Matches.ContainsKey(2)) { $Matches[2] } else { '' }
    } else { throw 'Invalid uninstall command' }
    if ([IO.Path]::IsPathRooted($file)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Uninstall executable not found' }
    } elseif ($file -match '^[a-zA-Z0-9_.-]+$') {
        $file = (Get-Command -Name $file -CommandType Application -ErrorAction Stop | Select-Object -First 1).Path
    } else { throw 'Invalid uninstall executable' }
    return @{ executable = $file; arguments = $tail }
}

$stage = 'initialize'
try {
    if (-not ('SoftwareManager.PackageProcess' -as [type])) { Add-Type -TypeDefinition $ProcessSource -Language CSharp }
    $stage = 'arguments'
    $extra = if ($Arguments -is [string]) { $Arguments } elseif ($null -ne $Arguments) {
        @($Arguments | ForEach-Object { [SoftwareManager.PackageProcess]::Quote([string]$_) }) -join ' '
    } else { '' }
    $directory = $null
    $commandArguments = ''
    if ($Operation -ne 'remove') {
        $stage = 'checksum'
        if (-not $Path -or $Checksum -notmatch '^[0-9a-fA-F]{64}$' -or
            (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Checksum) { throw 'Installer SHA-256 mismatch' }
        $stage = 'signature'
        if ($VerifySignature -and (Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'Valid') { throw 'Invalid Authenticode signature' }
        $directory = [IO.Path]::GetDirectoryName($Path)
    }
    $stage = 'identity'
    if ($Provider -eq 'msi') {
        $executable = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        if ($ProductId -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') { throw 'Invalid MSI product ID' }
        $installed = [SoftwareManager.PackageProcess]::MsiQueryProductState($ProductId) -eq 5
        if (($Operation -eq 'install' -and $installed) -or ($Operation -eq 'remove' -and -not $installed)) {
            $Ansible.Result.rc = 0
            return
        }
        if ($Operation -eq 'remove') { $commandArguments = '/x ' + $ProductId + ' /qn /norestart' }
        else {
            try {
                $acl = Get-Acl -LiteralPath $Path
                $system = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
                $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($system, 'Read', 'Allow')
                $acl.AddAccessRule($rule)
                Set-Acl -LiteralPath $Path -AclObject $acl
            } catch {
                $Ansible.Result.acl_warning = $true
            }
            $commandArguments = '/i ' + [SoftwareManager.PackageProcess]::Quote($Path) + ' /qn /norestart'
            if ($Operation -eq 'reapply') { $commandArguments += ' REINSTALL=ALL REINSTALLMODE=vomus' }
        }
    } elseif ($Operation -eq 'remove') {
        if (-not $ProductId -or $ProductId -match '[\\/]') { throw 'Invalid registry product ID' }
        $entry = $null
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $key = Join-Path $root $ProductId
            if (Test-Path -LiteralPath $key) { $entry = Get-ItemProperty -LiteralPath $key; break }
        }
        if ($null -eq $entry) { $Ansible.Result.rc = 0; return }
        $stage = 'uninstall_command'
        $uninstall = if ($entry.QuietUninstallString) { [string]$entry.QuietUninstallString } elseif ($extra -and $entry.UninstallString) { [string]$entry.UninstallString } else { throw 'Silent uninstall command not available' }
        $resolved = Resolve-Uninstall $uninstall
        $executable = $resolved.executable
        $commandArguments = $resolved.arguments
    } else {
        if ($Operation -ne 'install') { throw 'Invalid EXE operation' }
        $executable = $Path
    }
    if ($extra) { $commandArguments = ($commandArguments + ' ' + $extra).TrimStart() }
    $stage = 'process'
    $result = [SoftwareManager.PackageProcess]::Run($executable, $commandArguments, $directory, $TimeoutSeconds, $WaitForChildren)
    if ($result.TimedOut) {
        $Ansible.Result.timed_out = $true
        $Ansible.Result.cleanup_confirmed = $result.CleanupConfirmed
        $Ansible.Failed = $true
        return
    }
    $Ansible.Result.rc = $result.ExitCode
    $Ansible.Result.reboot_required = ($result.ExitCode -eq 3010 -or ($Operation -eq 'reapply' -and $result.ExitCode -eq 1641))
    $Ansible.Changed = $true
} catch {
    $Ansible.Result.error_code = $stage
    $exception = $_.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.ComponentModel.Win32Exception]) {
            $Ansible.Result.native_error = $exception.NativeErrorCode
            break
        }
        $exception = $exception.InnerException
    }
    $Ansible.Failed = $true
}
