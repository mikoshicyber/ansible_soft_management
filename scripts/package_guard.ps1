param([string]$Path, [string]$Checksum, [bool]$VerifySignature = $false)
$ErrorActionPreference = 'Stop'
$Ansible.Changed = $false
if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Checksum) { throw 'Installer SHA-256 mismatch' }
if ($VerifySignature -and (Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'Valid') { throw 'Invalid Authenticode signature' }
