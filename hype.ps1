
# =========================
#   DECRYPTION HELPERS
# =========================

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

function Decrypt-Secret {
    param(
        [Parameter(Mandatory)][string]$Encrypted,
        [Parameter(Mandatory)][byte[]]$Key
    )
    $secure = $Encrypted | ConvertTo-SecureString -Key $Key
    return [System.Net.NetworkCredential]::new("", $secure).Password
}

# =========================
#      CONFIG (ENCRYPTED)
# =========================

# -- Paste your encrypted values here (generated above) --
$anydeskUrlEnc      = "76492d1116743f0423413b16050a5345MgB8ADkAdgBhAFQAQQBpAC8ATQBLAGYASQA5AGkAWQBJADUAVgBhAGkARwBXAFEAPQA9AHwAMgA5AGIAMQBmADgAYgBjAGQAZQA0AGIAMgBhAGEANgAxAGMAMAA4ADQANAA3ADgAZAA3ADgANwAyAGUANgA4AGUAOABmADcAMgBjADAAOQAzADEAZABmADIAOAA3ADgAOABmADAAMQBkAGMAZgA0AGMAZAAxAGUAYgBmADgANAAyADUAOQAxADYANwBlAGIANgA4AGMAZgBiAGIAZQBiADEANQA3ADUANQA4ADMAYgA4ADQANABmADUAYgA4ADAAZABkADEAZQAxAGIAZQA5AGEAMAA4ADgAOQAwAGQAZQA3ADUANgA3AGMAMQAyADUAYQA5ADEAOABjAGYANQA2ADAAZgA4ADAAYQA2AGQANQA2ADgAYgAyAGMAZABiADQAYwA1ADIAZgAxADAAZABkADMAMgBmAGQAZABkADEANwA="
$anydeskPasswordEnc = "76492d1116743f0423413b16050a5345MgB8AGoASwAzADYAYQA1AFMAbgAzAC8AVABDAGgAawBKAEcAcgA1AHQAUgBtAGcAPQA9AHwAZAAwAGIANABjADYANQA4ADEAMgBjAGMAYwBlAGMAOQBhADkAZABiADUAYgBjADEAOABlAGMAOQBlAGQAYwBmADgAMwA2ADQANgBkAGIAYgAxAGYAYQAwAGQANwA1AGYAOABmADEAZQA4ADIANgA3ADcAYQBjAG8AZQBmADMAMAA="
$telegramBotTokenEnc= "76492d1116743f0423413b16050a5345MgB8ADgAdABBADMAUwBRADAAawB3AE4ASAAvAGgAUQBHAFUANgBqAFgATwBpAFEAPQA9AHwAZAA1AGYAZgBiADUAZQBkAGUAMQAzADgAMQBkADAAZQA3AGMAYQA1AGQAZgBiAGMAMQAxADEAZAA0ADkAOABiAGIANQBiADIAZQA5ADAAZQAyADcANgBjAGQAMwA3ADYAMgA5AGIAMwAwAGMAOQA4ADYAYwA3ADgAZQA4ADgAOABjADUAZgBjADYAMQA1AGEAOABjAGUAOAA0ADYANgBjADkANwA3ADAAMQA2ADQAOAA5AGMAZgA5ADIAOAA5AGEAMQBhAGYAMABhAGIAZQBiAGUAMABjADQAOQAzAGUAYwA4ADgANQBlADcAZAAxADgAMgA3ADYAOQBhADAAZABlAGYANgA0ADgANwAwADUAZQA1ADUAMAA3AGMAYQBjADMANQBiADQANgA3AGMAYQBlAGMAOAA1AGYAOAA0ADAAMQAwADAANQA2ADcANwAzADUAMgBiADAANAAyADEAZAAzAGIAYQBmAGYAMQBhADUAZgBjAGIAOAAyAGMANAA5ADYA"
$telegramChatIdEnc  = "76492d1116743f0423413b16050a5345MgB8AFoALwBqAFgARgAwAHEAdwA4AEgAWQBjAEMAWQB2ADEALwBiAGgATgA5AEEAPQA9AHwAZQBjADcAMgAyADQAZQAzAGEAMQA3AGIANQBlAGIANQBmADkAYwA2ADcANwBjAGUANgA2ADQANwBlADgAYQBhAGUAYwBlAGUANwBhADkAMwAzADAANwAwADMAZAAwAGYAMQAxADcANABkADYANAA1ADYANwBhADIAZgA1AGIAYwA="
$vcredistUrlEnc     = "76492d1116743f0423413b16050a5345MgB8AGgAbgBqADEAZwBpAEMAcABCAEUAYQBvAFEASABrAEcAVQBXAEQAQgBNAGcAPQA9AHwAZABhAGUANwAyAGMANgA1ADAAMAA4AGMAZgA0AGEAZQBlADAAYQAxAGYAMgA1ADEAMwA5ADAAZQBiADgANwAwADkAMQBhADEANgAzAGIAZQBkAGYAMAA2ADIAMQA2AGYAMABmADMAOAA4ADkAYgAwADgAMgA2ADIAMwA5AGQAYQBkAGIAZAAzADcANgBkADAANgA1AGYANAAzADUAOAA2ADgAMwBiADEANwBjAGQANAA1AGMAOABkAGUAMAA0AGIANgBjAGYANgA4ADMANQA2ADIAYgA2ADQAZAAxADYAOQBiAGMANwAyAGUAYQA4ADkAYgBiADIAMgBiAGUAMgA4AGUANABlAGYAYwA0AGEANgAyADQAYwA3AGMANgAyAGMAYgA3AGIANwBiAGYAZQA2ADUAZgAyAGUANgBhAGQANwA="
$vboxUrlEnc         = "76492d1116743f0423413b16050a5345MgB8AG8AUwBoAC8AUgBrAEYAUQBtAG8ATgBkADYAbgB1ADkAYwBUAHIAMQBIAFEAPQA9AHwANABmADgAYgAwADUANwA4ADgAMAA1AGEAYgBiAGIAYgAyADEAYQA5AGYANQA4AGMANgAzADIAZgAzADIAMABhAGMAZgAyADIAYgAwAGIANgBmAGMAMQAwADEAYwAzADkAMQAwADAAMwBiAGMAMAA2AGQAZgBhADYAMgA4AGIANAA1ADgAZgAyAGQANABhAGYAZgAyADMAYwBkAGYANQAyAGYANgBlADcAYwBhAGMAOABiAGgAMgA5AGUAMQA2AGIANAA3ADMAYgAzAGYANQAzADIANQA3AGYANgBlADkAZgBiADAAMQAwADUAMwA4ADgANwAwAGUAMgA0ADQAMQBkADIAMAAwADEANwBlADYAMQA0ADUAYQA2ADYAMAA5AGIANQA5ADYANwBiADMANABhADAANAAzADUAMwBkADAAZQA="
$vboxExtUrlEnc      = "76492d1116743f0423413b16050a5345MgB8AGgANgAyAG8AYQB4AE0AYgBSAFoAYQBuAHgAeQBEAG0AMQB0AEUATABUAEEAPQA9AHwAMQA3AGQAMgBmAGQAOQBmAGMAZABlADMANQBhADQANgAwAGQAMwA0ADEAMwA5ADgAOQBkAGYAMAA5AGEANgBjADEAMwA1AGIANgAwADkANwA2AGUAMgAwADUANQA2ADkANQBhAGIAMgBmAGMAYwBhADcAMwAzAGMAYQA1AGQAMABiAGIANQA1ADEAMAA3ADUAYgAyADMAZgBmADcAZAA1ADcAZQA5ADgAMQA3ADEAZgAwAGUANQA1ADcAOQAzADgANwA1ADMAMABhAGEAMgBhADYAMgA0ADcAYQA1ADIAZgBiADQANAA0ADQAYQA5ADIAOABhADEANABhADAAYgBiADMANgAxADcANwAyADIAZgBjADUAZAA1AGUAMgBhADMAYwAxADcAOQBlADQAOQA2ADYAOQAzADcANgBhAGQAZABkADEAYgBmAGIANwBiADMAMQAyAGQAYwAxADMAYwBiADIAOQBmADkAOQA3ADgAMQA2AGMAYQA0AGEANAAzAGYAMwAwADgANgA4AGYAMgA4ADIAZgA0ADIAMgAyADcAOAA4ADYAZQBkADQAZgAzADAAMgA0AGMAYQA2ADMAYwA4AGIAZABmADUAOQA1ADkAMQAzADgANAA1AGMANQA0AGYAMgA4AGUAZQA2ADUAYgA4ADYAMgBmADQAZQA3ADAAZgBlADgAOQAwAGEAOQBhADcANAAwADYANAA5ADQAYwAwADMAMQBiAGYANQA1AGMAZQBjADUAZAAzAGQAOQA3AGQAYgA3AGIANAA0AGYANwBhADIAZQBhADMANAAxADcAZQA1AGMAOAA1ADUANwA2ADQAMQBlADMAZAA2ADIAOQBlAA=="
$debugMode = $false

# =========================
#   PASSWORD PROMPT & DECRYPT
# =========================

# Prompt for password at script start
$password = Read-Host "Enter script password" -AsSecureString
$key = Get-AesKeyFromPassword -Password $password

function Get-DecryptedSecret {
    param([string]$enc)
    return Decrypt-Secret -Encrypted $enc -Key $key
}

# Decrypt secrets at runtime with error handling
try {
    $anydeskUrl      = Get-DecryptedSecret $anydeskUrlEnc
    $anydeskPassword = Get-DecryptedSecret $anydeskPasswordEnc
    $telegramBotToken= Get-DecryptedSecret $telegramBotTokenEnc
    $telegramChatId  = Get-DecryptedSecret $telegramChatIdEnc
    $vcredistUrl     = Get-DecryptedSecret $vcredistUrlEnc
    $vboxUrl         = Get-DecryptedSecret $vboxUrlEnc
    $vboxExtUrl      = Get-DecryptedSecret $vboxExtUrlEnc
} catch {
    Write-Host "`n[ERROR] Failed to decrypt secrets. Wrong password or corrupted data." -ForegroundColor Red
    Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nPress Enter to exit..."
    Read-Host
    exit 1
}

# =========================
#      MAIN SCRIPT LOGIC
# =========================

function Write-DebugMsg($msg) {
    if ($debugMode) { Write-Host "[DEBUG] $msg" -ForegroundColor Yellow }
}

function New-DownloadTempFolder {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $folder = Join-Path $env:TEMP "hypd_download_$timestamp"
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force
    }
    New-Item -Path $folder -ItemType Directory | Out-Null
    Write-Host "[*] Download folder: $folder" -ForegroundColor Cyan
    return $folder
}

function Get-AnyDeskPassword {
    return $anydeskPassword
}

function Set-BulgariaLocaleAndTime {
    Write-Host "[*] Setting region to Bulgaria (BG)..."
    Set-WinSystemLocale -SystemLocale bg-BG
    Set-Culture bg-BG

    Write-Host "[*] Setting time zone to Bulgaria (FLE Standard Time)..."
    Set-TimeZone -Id "FLE Standard Time"

    Write-Host "[*] Setting keyboard layouts: Bulgarian Traditional Phonetic and US..."

    # Create Bulgarian with only Traditional Phonetic
    $bgList = New-WinUserLanguageList bg-BG
    if ($bgList.Count -ge 1) {
        $bgList[0].InputMethodTips.Clear()
        $bgList[0].InputMethodTips.Add("0402:00040402") # Bulgarian Traditional Phonetic
    } else {
        Write-Host "[!] Could not create Bulgarian language list."
        return
    }

    # Create US English with only US layout
    $usList = New-WinUserLanguageList en-US
    if ($usList.Count -ge 1) {
        $usList[0].InputMethodTips.Clear()
        $usList[0].InputMethodTips.Add("0409:00000409") # US
    } else {
        Write-Host "[!] Could not create US English language list."
        return
    }

    # Combine into a single list
    $langList = @($bgList[0], $usList[0])
    Set-WinUserLanguageList $langList -Force

    Write-Host "[*] Syncing system time with NTP server..."
    try {
        w32tm /resync | Out-Null
        Write-Host "[✓] Time synchronized."
    } catch {
        Write-Host "[!] Failed to sync time: $_"
    }
}

function Set-AnyDeskPassword {
    Write-Host "[*] Setting AnyDesk password using CLI..."
    $exePaths = @(
        "C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
        "C:\Program Files\AnyDesk\AnyDesk.exe"
    )
    $anydeskExe = $null
    foreach ($path in $exePaths) {
        if (Test-Path $path) {
            $anydeskExe = $path
            break
        }
    }
    if (-not $anydeskExe) {
        Write-Host "[!] AnyDesk.exe not found in standard locations. Password not set."
        return
    }
    $anydeskPassword = Get-AnyDeskPassword
    $cmd = "echo $anydeskPassword | `"$anydeskExe`" --set-password"
    Write-DebugMsg "Running: $cmd"
    cmd.exe /c $cmd | Out-Null
    Write-Host "[✓] Password set via AnyDesk CLI."
}

function Get-AnyDeskID {
    $idPath = "$env:ProgramData\AnyDesk\system.conf"
    Write-DebugMsg "Looking for AnyDesk ID in $idPath"
    if (Test-Path $idPath) {
        $lines = Get-Content $idPath
        foreach ($line in $lines) {
            if ($line -like "ad.anynet.id=*") {
                $parts = $line.Split('=')
                if ($parts[0].Trim() -eq "ad.anynet.id" -and $parts.Count -ge 2) {
                    Write-DebugMsg "Found AnyDesk ID line: $line"
                    return $parts[1].Trim()
                }
            }
        }
        return $null
    } else {
        return $null
    }
}

function Wait-ForAnyDeskID {
    param(
        [int]$TimeoutSeconds = 60,
        [int]$PollIntervalSeconds = 2
    )
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $id = Get-AnyDeskID
        if ($id -and $id -notmatch "not found|Could not locate") {
            return $id
        }
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
        Write-DebugMsg "Waiting for AnyDesk ID... ($elapsed/$TimeoutSeconds seconds)"
    }
    return "AnyDesk ID not found after waiting $TimeoutSeconds seconds."
}

function Send-TelegramMessage($message) {
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage"
    $params = @{
        chat_id = $telegramChatId
        text    = $message
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $params
        Write-DebugMsg "Telegram API response: $($response | ConvertTo-Json)"
        Write-Host "[✓] Sent AnyDesk ID to Telegram."
    } catch {
        Write-Host "[!] Failed to send message to Telegram: $_"
    }
}

function Is-AnyDeskInstalled {
    $paths = @(
        "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
        "$env:ProgramFiles(x86)\AnyDesk\AnyDesk.exe"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-DebugMsg "AnyDesk found at $path"
            return $true
        }
    }
    $confPath = "$env:ProgramData\AnyDesk\system.conf"
    if (Test-Path $confPath) {
        Write-DebugMsg "AnyDesk config found at $confPath"
        return $true
    }
    Write-DebugMsg "AnyDesk not found."
    return $false
}

function PrintAndSend-AnyDeskID {
    param(
        [string]$Comment = "",
        [string]$Id = $null
    )
    if (-not $Id) {
        $Id = Wait-ForAnyDeskID
    }
    Write-Host "`n[*] AnyDesk ID: $Id`n"
    $dateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $msg = if ($Comment -ne "") { "$Comment - AnyDesk ID: $Id ($dateTime)" } else { "AnyDesk ID: $Id ($dateTime)" }
    Send-TelegramMessage $msg
}

function Start-AnyDesk {
    $exePaths = @(
        "C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
        "C:\Program Files\AnyDesk\AnyDesk.exe"
    )
    foreach ($path in $exePaths) {
        if (Test-Path $path) {
            Write-Host "[*] Starting AnyDesk minimized..."
            Start-Process -FilePath $path -ArgumentList "--minimized" -WindowStyle Hidden
            return
        }
    }
    Write-Host "[!] AnyDesk.exe not found to start."
}

function Install-AnyDesk {
    $downloadFolder = New-DownloadTempFolder
    $anydeskInstaller = Join-Path $downloadFolder "anydesk_installer.exe"
    Set-BulgariaLocaleAndTime

    if (Is-AnyDeskInstalled) {
        Write-Host "[!] AnyDesk is already installed."
        Start-AnyDesk
        $comment = Read-Host "Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.)"
        PrintAndSend-AnyDeskID -Comment $comment
        return
    }

    Write-Host "[+] Downloading AnyDesk..."
    Invoke-WebRequest -Uri $anydeskUrl -OutFile $anydeskInstaller

    Write-Host "[+] Installing AnyDesk with full arguments..."
    $installArgs = '--install "C:\Program Files (x86)\AnyDesk" --start-with-win --create-shortcuts --create-desktop-icon --silent'
    Write-DebugMsg "Installer arguments: $installArgs"
    Start-Process -FilePath $anydeskInstaller -ArgumentList $installArgs -Wait

    # Start AnyDesk to ensure config and ID are generated
    Start-AnyDesk

    # Wait for the ID to become available
    $id = Wait-ForAnyDeskID
    Write-Host "[*] AnyDesk ID: $id"

    Set-AnyDeskPassword

    Write-Host "[✓] AnyDesk installed."

    $comment = Read-Host "Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.)"
    PrintAndSend-AnyDeskID -Comment $comment -Id $id
}

function Scan-NetworkUsedIPs {
    Write-Host "`n[*] Detecting available IPv4 networks...`n"
    $adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -notlike '169.254*' -and
        $_.IPAddress -ne '127.0.0.1' -and
        $_.PrefixOrigin -ne 'WellKnown'
    }
    if (-not $adapters) {
        Write-Host "[!] No suitable network adapters found."
        return
    }
    $choices = @()
    $i = 1
    foreach ($adapter in $adapters) {
        $subnet = ($adapter.IPAddress -replace '\d+$','')
        $choices += [PSCustomObject]@{
            Index = $i
            InterfaceAlias = $adapter.InterfaceAlias
            IPAddress = $adapter.IPAddress
            PrefixLength = $adapter.PrefixLength
            Subnet = $subnet
        }
        Write-Host ("[{0}] {1} - {2}/{3}" -f $i, $adapter.InterfaceAlias, $adapter.IPAddress, $adapter.PrefixLength)
        $i++
    }
    $sel = Read-Host "Select network to scan (enter number)"
    if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $choices.Count) {
        Write-Host "[!] Invalid selection."
        return
    }
    $selected = $choices[[int]$sel - 1]
    $base = $selected.Subnet
    $ip = $selected.IPAddress
    Write-Host "`n[*] Scanning subnet: $base"0" - $base"255" (selected: $ip)`n"

    $results = @()
    $maxConcurrentJobs = 32
    $jobs = @()
    foreach ($i in 1..254) {
        $target = "$base$i"
        while (@(Get-Job -State "Running").Count -ge $maxConcurrentJobs) {
            Start-Sleep -Milliseconds 100
        }
        $jobs += Start-Job -ScriptBlock {
            param($target)
            $ping = "$env:SystemRoot\System32\ping.exe"
            $null = & $ping -n 1 -w 500 $target
            if ($LASTEXITCODE -eq 0) {
                # Get hostname
                try {
                    $hostname = ([System.Net.Dns]::GetHostEntry($target)).HostName
                } catch { $hostname = "" }
                # Get MAC from ARP
                $arp = arp -a $target | Select-String $target
                if ($arp) {
                    $mac = ($arp -split '\s+')[-2]
                } else {
                    $mac = ""
                }
                [PSCustomObject]@{
                    IP = $target
                    Hostname = $hostname
                    MAC = $mac
                }
            }
        } -ArgumentList $target
    }
    Wait-Job -Job $jobs | Out-Null
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job
        if ($result) { $results += $result }
        Remove-Job -Job $job
    }
    Write-Host "`n[*] Used IP addresses found:`n"
    if ($results.Count -eq 0) {
        Write-Host "No active hosts found."
    } else {
        $results | Sort-Object IP | Format-Table -AutoSize
    }
    Write-Host "`n[*] Scan complete.`n"
}

function Set-PowerSettingsNever {
    Write-Host "[*] Setting power settings to 'Never' for sleep, monitor, hard disk, and USB selective suspend..." -ForegroundColor Cyan

    # Set monitor timeout to never (0)
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0

    # Set standby (sleep) timeout to never (0)
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0

    # Get the active power scheme GUID robustly
    $schemeLine = powercfg /getactivescheme
    if ($schemeLine -match '([a-fA-F0-9\-]{36})') {
        $scheme = $matches[1]
    } else {
        Write-Host "[!] Could not determine active power scheme GUID."
        return
    }

    # Set hard disk timeout to never (0) using GUIDs for reliability
    $diskSubGroup = "0012ee47-9041-4b5d-9b77-535fba8b1442"
    $diskSetting = "6738e2c4-e8a5-4a42-b16a-e040e769756e"
    powercfg /setacvalueindex $scheme $diskSubGroup $diskSetting 0
    powercfg /setdcvalueindex $scheme $diskSubGroup $diskSetting 0

    # Disable USB selective suspend (set to 0) using GUIDs from your system
    $usbSubGroup = "2a737441-1930-4402-8d77-b2bebba308a3"
    $usbSetting = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
    powercfg /setacvalueindex $scheme $usbSubGroup $usbSetting 0
    powercfg /setdcvalueindex $scheme $usbSubGroup $usbSetting 0

    # Apply the changes
    powercfg /S $scheme

    # Verification output
    Write-Host "`n[Verification] Current Hard Disk Timeout (AC):"
    powercfg /query $scheme $diskSubGroup $diskSetting
    Write-Host "`n[Verification] Current USB Selective Suspend (AC):"
    powercfg /query $scheme $usbSubGroup $usbSetting

    Write-Host "[✓] Power settings updated: No sleep, no monitor off, no HDD spin-down, USB selective suspend disabled."
}

function Open-DeviceManager {
    Write-Host "[*] Opening Device Manager..."
    Start-Process devmgmt.msc
}

function Send-CustomTelegramMessage {
    Write-Host "[*] Enter your Telegram message. Type a single dot (.) on a new line to finish."
    $lines = @()
    while ($true) {
        $line = Read-Host
        if ($line -eq ".") { break }
        $lines += $line
    }
    $message = $lines -join "`n"
    if (-not $message.Trim()) {
        Write-Host "[!] No message entered. Aborting."
        return
    }
    Send-TelegramMessage $message
    Write-Host "[✓] Message sent to Telegram."
}

# --- VirtualBox Modular Install Functions and Submenu ---

function Install-Vcredist {
    $downloadFolder = New-DownloadTempFolder
    $vcredistPath = Join-Path $downloadFolder "vc_redist.x64.exe"
    Write-Host "[*] Downloading Visual C++ Redistributable..."
    try {
        Invoke-WebRequest -Uri $vcredistUrl -OutFile $vcredistPath -UseBasicParsing
        Write-Host "[✓] Downloaded vcredist."
        Write-Host "[*] Installing vcredist..."
        Start-Process -FilePath $vcredistPath -ArgumentList "/install /quiet /norestart" -Wait
        Write-Host "[✓] vcredist installed."
    } catch {
        Write-Host "[!] Failed to download or install vcredist: $_"
        return
    }
}

function Install-VirtualBoxOnly {
    $downloadFolder = New-DownloadTempFolder
    $vboxPath = Join-Path $downloadFolder "VirtualBox-Installer.exe"
    Write-Host "[*] Downloading VirtualBox installer..."
    try {
        Invoke-WebRequest -Uri $vboxUrl -OutFile $vboxPath -UseBasicParsing
        Write-Host "[✓] Downloaded VirtualBox."
        Write-Host "[*] Installing VirtualBox..."
        Start-Process -FilePath $vboxPath -ArgumentList "--silent --ignore-reboot" -Wait
        Write-Host "[✓] VirtualBox installed."
    } catch {
        Write-Host "[!] Failed to download or install VirtualBox: $_"
        return
    }
}

function Install-VBoxExtPack {
    $downloadFolder = New-DownloadTempFolder
    $vboxExtFileName = "Oracle_VirtualBox_Extension_Pack-7.1.6.vbox-extpack"
    $vboxExtPath = Join-Path $downloadFolder $vboxExtFileName
    Write-Host "[*] Downloading VirtualBox Extension Pack..."
    try {
        Invoke-WebRequest -Uri $vboxExtUrl -OutFile $vboxExtPath -UseBasicParsing
        Write-Host "[✓] Downloaded Extension Pack."
        # Find VBoxManage.exe
        $vboxManage = "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe"
        if (-not (Test-Path $vboxManage)) {
            $vboxManage = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
        }
        if (-not (Test-Path $vboxManage)) {
            Write-Host "[!] VBoxManage.exe not found. Please ensure VirtualBox is installed."
            return
        }
        Write-Host "[*] Importing Extension Pack..."
        Start-Process -FilePath $vboxManage -ArgumentList "extpack", "install", "--replace", "`"$vboxExtPath`"","--accept-license=eb31505e56e9b4d0fbca139104da41ac6f6b98f8e78968bdf01b1f3da3c4f9ae" -Wait -NoNewWindow
        Write-Host "[✓] Extension Pack imported."
    } catch {
        Write-Host "[!] Failed to download or import Extension Pack: $_"
        return
    }
}

function Install-VirtualBox-Menu {
    while ($true) {
        Write-Host ""
        Write-Host "---- VirtualBox Installation Menu ----" -ForegroundColor Cyan
        Write-Host "[1] Install ALL (vcredist, VirtualBox, Extension Pack) [default]"
        Write-Host "[2] Install Visual C++ Redistributable (vcredist)"
        Write-Host "[3] Install VirtualBox"
        Write-Host "[4] Install VirtualBox Extension Pack"
        Write-Host "[b] Back to main menu"
        Write-Host "--------------------------------------"
        $subChoice = Read-Host "Select an option (Enter for ALL)"
        switch ($subChoice.ToLower()) {
            "" {
                # Default: Install ALL
                Install-Vcredist
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VirtualBoxOnly
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VBoxExtPack
                Write-Host "[✓] All VirtualBox components installed."
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host
            }
            "1" {
                Install-Vcredist
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VirtualBoxOnly
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VBoxExtPack
                Write-Host "[✓] All VirtualBox components installed."
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host
            }
            "2" {
                Install-Vcredist
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host
            }
            "3" {
                Install-VirtualBoxOnly
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host
            }
            "4" {
                Install-VBoxExtPack
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid selection."
            }
        }
    }
}

# --- End VirtualBox Modular Install Section ---

function Check-VTDStatus {
    Write-Host "========== VT-d (Intel Virtualization Technology for Directed I/O) Status ==========" -ForegroundColor Cyan

    # Try WMI first
    $vtdWmi = Get-WmiObject -Namespace "root\CIMV2" -Class Win32_Processor | Select-Object -ExpandProperty VirtualizationFirmwareEnabled -ErrorAction SilentlyContinue
    if ($vtdWmi -ne $null -and $vtdWmi -ne "") {
        Write-Host "[*] VT-d/VirtualizationFirmwareEnabled: $vtdWmi" -ForegroundColor Green
    } else {
        # Fallback: Try systeminfo
        $sysinfo = systeminfo | Select-String "Virtualization Enabled In Firmware"
        if ($sysinfo) {
            Write-Host "[*] VT-d/Virtualization status (systeminfo): $($sysinfo.ToString())" -ForegroundColor Green
        } else {
            Write-Host "[!] Could not determine VT-d status automatically. Please check BIOS/UEFI settings manually." -ForegroundColor Yellow
        }
    }
    Write-Host "===================================================================================="
}

# =========================
#   FIREWALL & REGISTRY FIXES
# =========================

function Apply-HypeFirewallRules {
    Write-Host "[*] Adding Hype firewall rules for ports 8001 and 8002..." -ForegroundColor Cyan

    $rule1 = 'netsh advfirewall firewall add rule name="Hype 8001" dir=in action=allow protocol=TCP localport=8001 remoteip=87.121.112.82,LocalSubnet profile=public,private,domain'
    $rule2 = 'netsh advfirewall firewall add rule name="Hype 8002" dir=in action=allow protocol=TCP localport=8002 remoteip=87.121.112.82,LocalSubnet profile=public,private,domain'

    Write-Host "  - Adding rule for port 8001..."
    Invoke-Expression $rule1

    Write-Host "  - Adding rule for port 8002..."
    Invoke-Expression $rule2

    Write-Host "[✓] Hype firewall rules applied."
}

function Apply-RegFixes {
    Write-Host "[*] Applying registry fixes..." -ForegroundColor Cyan

    # Set AutoEndTasks = 1
    Write-Host "  - Setting AutoEndTasks=1 for all users..."
    reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f | Out-Null

    # Set HungAppTimeout = 10000
    Write-Host "  - Setting HungAppTimeout=10000 for all users..."
    reg.exe add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 10000 /f | Out-Null

    Write-Host "[✓] Registry fixes applied."
}

# =========================
#      FIXES SUBMENU
# =========================

function Show-FixesMenu {
#    Clear-Host
    Write-Host "========== Fixes & Configuration ==========" -ForegroundColor Cyan
    Write-Host "[1] Set Bulgaria Locale/Time/Keyboard"
    Write-Host "[2] Set Power Settings to Never Sleep/Standby/Spin Down"
    Write-Host "[3] Apply Firewall Rules"
    Write-Host "[4] Apply Registry Fixes"
    Write-Host "[5] Open Device Manager"
    Write-Host "[b] Back to main menu"
    Write-Host "==========================================="
}

function Fixes-Menu-Loop {
    while ($true) {
        Show-FixesMenu
        $fixChoice = Read-Host "Enter choice"
        switch ($fixChoice.ToLower()) {
            "1" {
                Set-BulgariaLocaleAndTime
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
            "2" {
                Set-PowerSettingsNever
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
            "3" {
                Apply-HypeFirewallRules
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
            "4" {
                Apply-RegFixes
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
            "5" {
                Open-DeviceManager
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid choice."
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host
            }
        }
    }
}

# =========================
#      MAIN MENU (UPDATED)
# =========================

function Show-Menu {
#    Clear-Host
    Write-Host "========== Remote Tool Setup ==========" -ForegroundColor Cyan
    Write-Host "[1] Fixes & Configuration"
    Write-Host "[2] Install AnyDesk"
    Write-Host "[3] Scan Network for Used IP Addresses"
    Write-Host "[4] Send Custom Telegram Message"
    Write-Host "[5] Install VirtualBox (vcredist, VirtualBox, Extension Pack)"
    Write-Host "[x] Exit"
    Write-Host "======================================="
    Check-VTDStatus
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Enter choice"

    switch ($choice.ToLower()) {
        "1" {
            Fixes-Menu-Loop
        }
        "2" {
            Install-AnyDesk
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host
        }
        "3" {
            Scan-NetworkUsedIPs
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host
        }
        "4" {
            Send-CustomTelegramMessage
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host
        }
        "5" {
            Install-VirtualBox-Menu
        }
        "x" {
            Write-Host "Exiting..."
            break
        }
        default {
            Write-Host "Invalid choice."
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host
        }
    }
}
exit
