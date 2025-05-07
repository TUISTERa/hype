# Multi-Secret Encryptor Helper for PowerShell cross-machine use

function Get-AesKeyFromPassword {
    param([Parameter(Mandatory)][System.Security.SecureString]$Password)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
    return [System.Text.Encoding]::UTF8.GetBytes($plainPassword.PadRight(32, '0').Substring(0,32))
}

function Encrypt-Secret {
    param(
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][byte[]]$Key
    )
    $secure = $Secret | ConvertTo-SecureString -AsPlainText -Force
    return $secure | ConvertFrom-SecureString -Key $Key
}

Write-Host "=== PowerShell Multi-Secret Encryptor (Cross-Machine Compatible) ===" -ForegroundColor Cyan
$password = Read-Host "Enter the script password (same as used at runtime)" -AsSecureString
$key = Get-AesKeyFromPassword -Password $password

$results = @()

do {
    do {
        $name = Read-Host "Enter a variable name for this secret (e.g., anydeskUrlEnc, apiTokenEnc)"
        $name = $name.Trim()
        if ($name.StartsWith('$')) { $name = $name.Substring(1) }
        if (-not $name) {
            Write-Host "Variable name cannot be empty. Please enter a valid name (without $)." -ForegroundColor Red
        }
    } while (-not $name)
    $secret = Read-Host "Enter the secret value to encrypt"
    $encrypted = Encrypt-Secret -Secret $secret -Key $key
    $results += [PSCustomObject]@{
        Name = $name
        EncryptedValue = $encrypted
    }
    $again = Read-Host "Encrypt another secret? (y/n)"
} while ($again -eq 'y' -or $again -eq 'Y')

Write-Host "`n=== Encrypted Secrets (copy these lines into your CONFIG section) ===" -ForegroundColor Green
foreach ($item in $results) {
    Write-Host ('$' + $item.Name + ' = "' + $item.EncryptedValue + '"') -ForegroundColor Yellow
}