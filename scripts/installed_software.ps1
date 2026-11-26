param(
    [string[]]$ProbePaths = @(),
    [hashtable]$MsiMetadata = @{},
    [hashtable]$MsiIdentities = @{},
    [string[]]$ProductIds = @(),
    [bool]$NativeOnly = $false
)
$ErrorActionPreference = 'Stop'
$Ansible.Changed = $false
$apps = @()
$roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
function Invoke-MsiCom($Object, [string]$Member, [string]$Kind, [object[]]$Arguments = @()) {
    $value = $Object.GetType().InvokeMember($Member, $Kind, $null, $Object, $Arguments)
    if ($null -ne $value) { return ,$value }
}
function Release-MsiCom($Object) {
    if ($null -ne $Object -and [Runtime.InteropServices.Marshal]::IsComObject($Object)) {
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object)
    }
}
if (-not $NativeOnly) {
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $keys = if ($ProductIds.Count -gt 0) {
            foreach ($id in $ProductIds) {
                if ($id -match '[\\/]') { throw 'Invalid registry product ID' }
                $path = Join-Path $root $id
                if (Test-Path -LiteralPath $path) { Get-Item -LiteralPath $path }
            }
        } else { Get-ChildItem -LiteralPath $root }
        foreach ($key in $keys) {
            $meta = Get-ItemProperty -LiteralPath $key.PSPath
            if (-not $meta.DisplayName -or $meta.SystemComponent) { continue }
            $provider = if ($meta.WindowsInstaller -eq 1 -and $key.PSChildName -match '^\{[0-9a-fA-F-]{36}\}$') { 'msi' } else { 'registry' }
            $apps += @{
                name = [string]$meta.DisplayName
                version = [string]$meta.DisplayVersion
                publisher = [string]$meta.Publisher
                product_id = [string]$key.PSChildName
                provider = $provider
                registry_key = [string]$key.Name
                quiet_uninstall_string = [string]$meta.QuietUninstallString
            }
        }
    }
}
$errors = @{}
$related = @{}
$states = @{}
$installer = $null
try {
    if ($MsiMetadata.Count -gt 0 -or $MsiIdentities.Count -gt 0) {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $codes = @{}
        foreach ($meta in @($MsiMetadata.Values) + @($MsiIdentities.Values)) {
            if ($meta.product_id -match '^\{[0-9a-fA-F-]{36}\}$') { $codes[$meta.product_id] = $true }
            $upgrade = ([string]$meta.upgrade_code).ToLowerInvariant()
            if (-not $upgrade -or $related.ContainsKey($upgrade)) { continue }
            $list = $null
            try {
                $list = Invoke-MsiCom $installer 'RelatedProducts' 'GetProperty' @($upgrade.ToUpperInvariant())
                $count = [int](Invoke-MsiCom $list 'Count' 'GetProperty')
                $members = @()
                for ($i = 0; $i -lt $count; $i++) {
                    $code = [string](Invoke-MsiCom $list 'Item' 'GetProperty' @($i))
                    $members += $code
                    $codes[$code] = $true
                }
                $related[$upgrade] = $members
            } catch { $errors[$upgrade] = $_.Exception.Message } finally { Release-MsiCom $list }
        }
        foreach ($rawCode in $codes.Keys) {
            $code = $rawCode.ToUpperInvariant()
            try {
                $state = [int](Invoke-MsiCom $installer 'ProductState' 'GetProperty' @($code))
                $states[$code.ToLowerInvariant()] = $state
                if ($state -ne 5) { continue }
                $version = [string](Invoke-MsiCom $installer 'ProductInfo' 'GetProperty' @($code, 'VersionString'))
                if (-not $version) { throw 'MSI version not available' }
                $language = ''
                $platform = ''
                $summary = $null
                try { $language = [string](Invoke-MsiCom $installer 'ProductInfo' 'GetProperty' @($code, 'Language')) } catch { $errors[$code + ':language'] = $_.Exception.Message }
                try {
                    $localPackage = [string](Invoke-MsiCom $installer 'ProductInfo' 'GetProperty' @($code, 'LocalPackage'))
                    if ($localPackage -and [IO.File]::Exists($localPackage)) {
                        $summary = Invoke-MsiCom $installer 'SummaryInformation' 'GetProperty' @($localPackage, 0)
                        $platform = (([string](Invoke-MsiCom $summary 'Property' 'GetProperty' @(7))) -split ';')[0]
                    }
                } catch { $errors[$code + ':platform'] = $_.Exception.Message } finally { Release-MsiCom $summary }
                $existing = @($apps | Where-Object { $_.provider -eq 'msi' -and $_.product_id -eq $code })
                if ($existing.Count -gt 0) {
                    foreach ($app in $existing) { $app.version = $version; $app.language = $language; $app.platform = $platform }
                } else {
                    $name = [string]$code
                    $publisher = ''
                    try { $name = [string](Invoke-MsiCom $installer 'ProductInfo' 'GetProperty' @($code, 'InstalledProductName')) } catch { $errors[$code + ':name'] = $_.Exception.Message }
                    try { $publisher = [string](Invoke-MsiCom $installer 'ProductInfo' 'GetProperty' @($code, 'Publisher')) } catch { $errors[$code + ':publisher'] = $_.Exception.Message }
                    $apps += @{
                        name = $name
                        publisher = $publisher
                        version = $version
                        language = $language
                        platform = $platform
                        product_id = [string]$code
                        provider = 'msi'
                    }
                }
            } catch {
                $null = $states.Remove($code.ToLowerInvariant())
                $errors[$code.ToLowerInvariant()] = $_.Exception.Message
            }
        }
    }
} catch { $errors['native'] = $_.Exception.Message } finally { Release-MsiCom $installer }
$probes = @{}
foreach ($path in $ProbePaths) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    $version = if ($null -ne $item -and -not $item.PSIsContainer) { [string]$item.VersionInfo.ProductVersion } else { '' }
    $probes[$path] = @{ exists = ($null -ne $item); version = $version }
}
$Ansible.Result = @{ installed = @($apps); probes = $probes; msi_errors = $errors; msi_related = $related; msi_states = $states }
