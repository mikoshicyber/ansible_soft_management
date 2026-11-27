param(
    [Parameter(Mandatory=$true)][ValidateSet('inspect','inspect_batch','read','write','remove','guard','template','prune_cache','cleanup_package','cleanup_packages')][string]$Operation,
    [string[]]$Paths = @(),
    [string]$StatePath,
    [string]$Content,
    [string]$ExpectedContent,
    [bool]$ExpectedExists = $false,
    [hashtable]$ExpectedHashes = @{},
    [string]$ManagedRoot
)
$ErrorActionPreference = 'Stop'
$Ansible.Changed = $false

function Get-SafePath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\[^\\]' -or $Path.Substring(2) -match '[:<>"|?*\x00-\x1f]' -or $Path -match '(?:^|\\)\.{1,2}(?:\\|$)') {
        throw 'Unsafe local Windows path'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ne $Path -or $full -eq [IO.Path]::GetPathRoot($full)) { throw 'Noncanonical path' }
    $current = [IO.Path]::GetPathRoot($full)
    foreach ($component in $full.Substring($current.Length).Split('\')) {
        if ($component.EndsWith('.') -or $component.EndsWith(' ') -or $component -match '^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)') { throw 'Unsafe path component' }
        $current = [IO.Path]::Combine($current, $component)
        try { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { $item = $null }
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse point: $current" }
        if ($current -ne $full -and $null -ne $item -and -not $item.PSIsContainer) { throw 'Parent is not a directory' }
    }
    return $full
}

function Get-SafeFile([string]$Path) {
    $full = Get-SafePath $Path
    if ([IO.Directory]::Exists($full)) { throw "Expected a file, found a directory: $full" }
    return $full
}

function Remove-EmptyCacheDirectories([string]$ManagedRoot, [string[]]$Paths) {
    $managed = Get-SafePath ($ManagedRoot.Replace('/', '\').TrimEnd('\'))
    $root = Get-SafePath ([IO.Path]::Combine($managed, '_src'))
    $systemRoot = $env:SystemRoot.TrimEnd('\')
    if ($root.Equals($systemRoot, [StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($systemRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Deletion inside Windows system directory is forbidden' }
    if ([IO.File]::Exists($root)) { throw 'Cache root is not a directory' }
    if (-not [IO.Directory]::Exists($root)) { return }
    $directories = @()
    if ($Paths.Count -gt 0) {
        foreach ($path in $Paths) {
            $file = Get-SafeFile $path
            $directory = [IO.Path]::GetDirectoryName($file)
            if (-not ([IO.Path]::GetDirectoryName($directory)).Equals($root, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($directory) -notmatch '^[0-9a-f]{64}$') { throw 'Expected a file in a SHA-256 cache directory' }
            $directories += $directory
        }
    } else {
        $directories = @([IO.Directory]::GetDirectories($root))
    }
    foreach ($directory in $directories) {
        if ([IO.Path]::GetFileName($directory) -notmatch '^[0-9a-f]{64}$') { continue }
        try { $item = Get-Item -LiteralPath $directory -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { continue }
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
        $full = Get-SafePath $directory
        if ([IO.Directory]::GetFileSystemEntries($full).Length -ne 0) { continue }
        $null = Get-SafePath $full
        try {
            [IO.Directory]::Delete($full, $false)
            $Ansible.Changed = $true
        } catch [System.IO.IOException] {
            if (-not [IO.Directory]::Exists($full)) { continue }
            if ([IO.Directory]::GetFileSystemEntries($full).Length -ne 0) { continue }
            throw
        }
    }
}

function Remove-CachedInstaller([string]$Path) {
    $managed = Get-SafePath ($ManagedRoot.Replace('/', '\').TrimEnd('\'))
    $root = Get-SafePath ([IO.Path]::Combine($managed, '_src'))
    $full = Get-SafeFile $Path
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not ([IO.Path]::GetDirectoryName($directory)).Equals($root, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($directory) -notmatch '^[0-9a-f]{64}$') { throw 'Expected a file in a SHA-256 cache directory' }
    if ($full.StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Deletion inside Windows system directory is forbidden' }
    if (-not $ExpectedHashes.ContainsKey($Path) -or $ExpectedHashes[$Path] -ne [IO.Path]::GetFileName($directory)) { throw 'Expected installer hash does not match cache directory' }
    $log = if ([IO.Path]::GetExtension($full) -eq '.msi') { Get-SafeFile ($full + '.log') } else { $null }
    if ([IO.File]::Exists($full)) {
        if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $ExpectedHashes[$Path]) { throw 'Cached installer has changed' }
        [IO.File]::Delete($full)
        $Ansible.Changed = $true
    }
    if ($null -ne $log -and [IO.File]::Exists($log)) { [IO.File]::Delete($log); $Ansible.Changed = $true }
}

switch ($Operation) {
    'guard' {
        foreach ($path in $Paths) { $null = Get-SafeFile $path }
    }
    'inspect' {
        $result = @{}
        foreach ($path in $Paths) {
            $full = Get-SafeFile $path
            if ([IO.File]::Exists($full)) {
                $result[$path] = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
            } else { $result[$path] = $null }
        }
        $Ansible.Result = $result
    }
    'inspect_batch' {
        $result = @{}
        foreach ($path in $Paths) {
            try {
                $full = Get-SafeFile $path
                if ([IO.File]::Exists($full)) {
                    $result[$path] = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
                } else { $result[$path] = $null }
            } catch { $result[$path] = @{ error = $_.Exception.Message } }
        }
        $Ansible.Result = $result
    }
    'read' {
        $full = Get-SafeFile $StatePath
        $exists = [IO.File]::Exists($full)
        $text = if ($exists) { [IO.File]::ReadAllText($full) } else { '{}' }
        $Ansible.Result = @{ exists = $exists; content_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)) }
    }
    'write' {
        $full = Get-SafeFile $StatePath
        $exists = [IO.File]::Exists($full)
        if ($exists -ne $ExpectedExists) { throw 'State database changed concurrently' }
        $expectedText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ExpectedContent))
        $newText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Content))
        if ($exists -and [IO.File]::ReadAllText($full) -cne $expectedText) { throw 'State database changed concurrently' }
        if ($exists -and $newText -ceq $expectedText) { return }
        $parent = [IO.Path]::GetDirectoryName($full)
        $null = [IO.Directory]::CreateDirectory($parent)
        $null = Get-SafeFile $full
        $temp = [IO.Path]::Combine($parent, [IO.Path]::GetRandomFileName())
        try {
            $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes($newText)
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            } finally { $stream.Dispose() }
            if ($exists) { [IO.File]::Replace($temp, $full, [System.Management.Automation.Language.NullString]::Value) } else { [IO.File]::Move($temp, $full) }
            $Ansible.Changed = $true
        } finally {
            if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
        }
    }
    'template' {
        $full = Get-SafeFile $Paths[0]
        $bytes = [Convert]::FromBase64String($Content)
        $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        if ([IO.File]::Exists($full) -and (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -eq $hash) { return }
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
        $null = Get-SafeFile $full
        $temp = [IO.Path]::Combine([IO.Path]::GetDirectoryName($full), [IO.Path]::GetRandomFileName())
        try {
            $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
            if ([IO.File]::Exists($full)) { [IO.File]::Replace($temp, $full, [System.Management.Automation.Language.NullString]::Value) } else { [IO.File]::Move($temp, $full) }
            $Ansible.Changed = $true
        } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
    }
    'remove' {
        foreach ($path in $Paths) {
            $full = Get-SafeFile $path
            if ($full.StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Deletion inside Windows system directory is forbidden' }
            if ([IO.File]::Exists($full) -and $ExpectedHashes.ContainsKey($path)) {
                if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $ExpectedHashes[$path]) { throw "Managed file changed: $full" }
            }
        }
        foreach ($path in $Paths) {
            $full = Get-SafeFile $path
            if ([IO.File]::Exists($full)) {
                [IO.File]::Delete($full)
                $Ansible.Changed = $true
            }
        }
    }
    'prune_cache' { Remove-EmptyCacheDirectories $ManagedRoot $Paths }
    'cleanup_package' {
        if ($Paths.Count -ne 1) { throw 'Expected one cached installer' }
        Remove-CachedInstaller $Paths[0]
        Remove-EmptyCacheDirectories $ManagedRoot $Paths
    }
    'cleanup_packages' {
        foreach ($path in $Paths) {
            try { Remove-CachedInstaller $path }
            catch { Write-Warning ("$path : " + $_.Exception.Message) }
        }
        try { Remove-EmptyCacheDirectories $ManagedRoot @() }
        catch { Write-Warning $_.Exception.Message }
    }
}
