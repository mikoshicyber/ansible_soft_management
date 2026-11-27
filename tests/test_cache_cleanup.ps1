$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\filesystem.ps1'
$managed = Join-Path ([IO.Path]::GetTempPath()) ('software-cache-test-' + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $managed '_src'
$first = Join-Path $root ('a' * 64)
$old = Join-Path $root ('b' * 64)
$failed = Join-Path $root ('c' * 64)
$nested = Join-Path $root ('d' * 64)
$other = Join-Path $root 'unmanaged'
$Ansible = @{ Changed = $false }
try {
    & $scriptPath -Operation prune_cache -ManagedRoot $managed
    if ($Ansible.Changed -or [IO.Directory]::Exists($managed)) { throw 'Missing root was modified' }
    foreach ($directory in @($first, $old, $failed, $nested, $other)) { $null = [IO.Directory]::CreateDirectory($directory) }
    $installer = Join-Path $failed 'installer.exe'
    [IO.File]::WriteAllText($installer, 'keep')
    $null = [IO.Directory]::CreateDirectory((Join-Path $nested 'empty'))
    & $scriptPath -Operation prune_cache -ManagedRoot $managed -Paths @((Join-Path $first 'installer.exe'))
    if (-not $Ansible.Changed -or [IO.Directory]::Exists($first) -or -not [IO.Directory]::Exists($old)) { throw 'Targeted cleanup failed' }
    & $scriptPath -Operation prune_cache -ManagedRoot $managed
    if (-not $Ansible.Changed -or [IO.Directory]::Exists($old)) { throw 'Final cleanup failed' }
    if (-not [IO.Directory]::Exists($root) -or -not [IO.Directory]::Exists($nested) -or -not [IO.Directory]::Exists($other) -or -not [IO.File]::Exists($installer)) { throw 'Protected content was deleted' }
    & $scriptPath -Operation prune_cache -ManagedRoot $managed
    if ($Ansible.Changed) { throw 'Cleanup is not idempotent' }
    $blocked = $false
    try { & $scriptPath -Operation prune_cache -ManagedRoot $managed -Paths @((Join-Path $other 'installer.exe')) }
    catch { $blocked = $true }
    if (-not $blocked) { throw 'Unmanaged path was accepted' }
    $goodContent = 'confirmed installer'
    $goodHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($goodContent))).Replace('-', '').ToLowerInvariant()
    $goodDir = Join-Path $root $goodHash
    $null = [IO.Directory]::CreateDirectory($goodDir)
    $good = Join-Path $goodDir 'installer.msi'
    [IO.File]::WriteAllText($good, $goodContent, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(($good + '.log'), 'log')
    & $scriptPath -Operation inspect_batch -Paths @($good, $nested, (Join-Path $goodDir 'missing'))
    if ($Ansible.Result[$good] -ne $goodHash -or -not $Ansible.Result[$nested].error -or $null -ne $Ansible.Result[(Join-Path $goodDir 'missing')]) { throw 'Batch inspection failed' }
    $hashes = @{}
    $hashes[$installer] = 'c' * 64
    $hashes[$good] = $goodHash
    & $scriptPath -Operation cleanup_packages -ManagedRoot $managed -Paths @($installer, $good) -ExpectedHashes $hashes
    if (-not $Ansible.Changed -or [IO.File]::Exists($good) -or [IO.File]::Exists($good + '.log') -or [IO.Directory]::Exists($goodDir) -or -not [IO.File]::Exists($installer)) { throw 'Batch cleanup failed or deleted an unconfirmed installer' }
    & $scriptPath -Operation cleanup_packages -ManagedRoot $managed -Paths @() -ExpectedHashes @{}
    if ($Ansible.Changed) { throw 'Batch cleanup is not idempotent' }

} finally {
    if ([IO.Directory]::Exists($managed)) { [IO.Directory]::Delete($managed, $true) }
}
