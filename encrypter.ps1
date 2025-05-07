# =========================
#  Secret Encryption Helper
# =========================
# Run this section ONCE to generate encrypted secrets with your password.
# Copy the output strings into the CONFIG section below.

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

function Decrypt-Secret {
    param(
        [Parameter(Mandatory)][string]$Encrypted,
        [Parameter(Mandatory)][byte[]]$Key
    )
    $secure = $Encrypted | ConvertTo-SecureString -Key $Key
    return [System.Net.NetworkCredential]::new("", $secure).Password
}

$password = Read-Host "Enter password for encryption" -AsSecureString
$key = Get-AesKeyFromPassword -Password $password

Write-Host "Paste each value when prompted. Copy the output for use in the script."
$anydeskUrlEnc      = Encrypt-Secret -Secret (Read-Host "AnyDesk URL") -Key $key
$anydeskPasswordEnc = Encrypt-Secret -Secret (Read-Host "AnyDesk Password") -Key $key
$telegramBotTokenEnc= Encrypt-Secret -Secret (Read-Host "Telegram Bot Token") -Key $key
$telegramChatIdEnc  = Encrypt-Secret -Secret (Read-Host "Telegram Chat ID") -Key $key
$vcredistUrlEnc     = Encrypt-Secret -Secret (Read-Host "vcredist URL") -Key $key
$vboxUrlEnc         = Encrypt-Secret -Secret (Read-Host "VirtualBox URL") -Key $key
$vboxExtUrlEnc      = Encrypt-Secret -Secret (Read-Host "VBox Extension Pack URL") -Key $key

Write-Host "`nCopy these lines into the CONFIG section:"
Write-Host "`$anydeskUrlEnc      = `"$anydeskUrlEnc`""
Write-Host "`$anydeskPasswordEnc = `"$anydeskPasswordEnc`""
Write-Host "`$telegramBotTokenEnc= `"$telegramBotTokenEnc`""
Write-Host "`$telegramChatIdEnc  = `"$telegramChatIdEnc`""
Write-Host "`$vcredistUrlEnc     = `"$vcredistUrlEnc`""
Write-Host "`$vboxUrlEnc         = `"$vboxUrlEnc`""
Write-Host "`$vboxExtUrlEnc      = `"$vboxExtUrlEnc`""
