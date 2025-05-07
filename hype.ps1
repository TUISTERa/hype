# =========================
#      CONFIG (PLAINTEXT)
# =========================

# -- IMPORTANT: Replace these placeholders with your ACTUAL plaintext values --
$anydeskUrl = "http://sh.itpcloud.biz/anydesk.exe"
$anydeskPassword = "hype1234"
$telegramBotToken = "5713387645:AAEnE0skfvLy5FmTRs0RwX9gLz9avFj72Wk"
$telegramChatId = "456050407"
$vcredistUrl = "http://sh.itpcloud.biz/vcredistx64.exe"
$vboxUrl = "http://sh.itpcloud.biz/virtualbox.exe"
$vboxExtUrl = "http://sh.itpcloud.biz/Oracle_VirtualBox_Extension_Pack-7.1.6.vbox-extpack"

$debugMode = $false
$scriptVersion = "1.0.2" # Updated version due to encryption removal

# =========================
#   WELCOME MESSAGE
# =========================
Write-Host "========================================="
Write-Host " Welcome to the Remote Tool Setup Script"
Write-Host "  For support or questions, contact IT. v$scriptVersion "
Write-Host "  WARNING: This version uses plaintext secrets."
Write-Host "=========================================" -ForegroundColor Cyan

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
    # Returns the plaintext password directly
    if (-not $anydeskPassword -or $anydeskPassword -eq "REPLACE_WITH_ACTUAL_ANYDESK_PASSWORD") {
        Write-Warning "[!] AnyDesk password is not set or is still a placeholder. Please update the script."
        return $null
    }
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
    $adPass = Get-AnyDeskPassword # Gets the plaintext password
    if (-not $adPass) {
        Write-Warning "[!] AnyDesk password is not available (likely not set in script). Skipping password set."
        return
    }
    $cmd = "echo $adPass | `"$anydeskExe`" --set-password"
    Write-DebugMsg "Running: $cmd"
    try {
        Invoke-Expression $cmd | Out-Null # Using Invoke-Expression for commands with pipes
        Write-Host "[✓] Password set via AnyDesk CLI."
    } catch {
        Write-Host "[!] Failed to set AnyDesk password: $_"
    }
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
    if (-not $telegramBotToken -or $telegramBotToken -eq "REPLACE_WITH_ACTUAL_TELEGRAM_BOT_TOKEN" -or `
        -not $telegramChatId -or $telegramChatId -eq "REPLACE_WITH_ACTUAL_TELEGRAM_CHAT_ID") {
        Write-Warning "[!] Telegram Bot Token or Chat ID is not available or is a placeholder. Skipping message send."
        return
    }
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage" # Uses plaintext token
    $params = @{
        chat_id = $telegramChatId # Uses plaintext chat ID
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
    if (-not $anydeskUrl -or $anydeskUrl -eq "REPLACE_WITH_ACTUAL_ANYDESK_URL") {
        Write-Warning "[!] AnyDesk URL is not available or is a placeholder. Skipping AnyDesk installation."
        return
    }
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
    Invoke-WebRequest -Uri $anydeskUrl -OutFile $anydeskInstaller # Uses plaintext URL

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
    $idx = 1 
    foreach ($adapter in $adapters) {
        $subnet = ($adapter.IPAddress -replace '\d+$','')
        $choices += [PSCustomObject]@{
            Index = $idx
            InterfaceAlias = $adapter.InterfaceAlias
            IPAddress = $adapter.IPAddress
            PrefixLength = $adapter.PrefixLength
            Subnet = $subnet
        }
        Write-Host ("[{0}] {1} - {2}/{3}" -f $idx, $adapter.InterfaceAlias, $adapter.IPAddress, $adapter.PrefixLength)
        $idx++
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
    foreach ($i_scan in 1..254) { 
        $target = "$base$i_scan"
        while (@(Get-Job -State "Running").Count -ge $maxConcurrentJobs) {
            Start-Sleep -Milliseconds 100
        }
        $jobs += Start-Job -ScriptBlock {
            param($targetToPing) 
            $pingExe = "$env:SystemRoot\System32\ping.exe" 
            $null = & $pingExe -n 1 -w 500 $targetToPing
            if ($LASTEXITCODE -eq 0) {
                try {
                    $hostname = ([System.Net.Dns]::GetHostEntry($targetToPing)).HostName
                } catch { $hostname = "" }
                $arpOutput = arp -a $targetToPing | Select-String $targetToPing
                $macAddress = "" 
                if ($arpOutput) {
                    if ($arpOutput -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                        $macAddress = $Matches[0]
                    }
                }
                [PSCustomObject]@{
                    IP = $targetToPing
                    Hostname = $hostname
                    MAC = $macAddress
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
        $results | Sort-Object {[version]$_.IP} | Format-Table -AutoSize 
    }
    Write-Host "`n[*] Scan complete.`n"
}

function Set-PowerSettingsNever {
    Write-Host "[*] Setting power settings to 'Never' for sleep, monitor, hard disk, and USB selective suspend..." -ForegroundColor Cyan
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    $schemeLine = powercfg /getactivescheme
    $scheme = $null
    if ($schemeLine -match '([a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})') { 
        $scheme = $matches[1]
    } else {
        Write-Host "[!] Could not determine active power scheme GUID."
        return
    }
    $diskSubGroup = "0012ee47-9041-4b5d-9b77-535fba8b1442"
    $diskSetting = "6738e2c4-e8a5-4a42-b16a-e040e769756e"
    powercfg /setacvalueindex $scheme $diskSubGroup $diskSetting 0
    powercfg /setdcvalueindex $scheme $diskSubGroup $diskSetting 0
    $usbSubGroup = "2a737441-1930-4402-8d77-b2bebba308a3"
    $usbSetting = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
    powercfg /setacvalueindex $scheme $usbSubGroup $usbSetting 0
    powercfg /setdcvalueindex $scheme $usbSubGroup $usbSetting 0
    powercfg /hibernate off
    powercfg /S $scheme
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
}

function Install-Vcredist {
    if (-not $vcredistUrl -or $vcredistUrl -eq "REPLACE_WITH_ACTUAL_VCREDIST_URL") {
        Write-Warning "[!] VC Redist URL is not available or is a placeholder. Skipping VC Redist installation."
        return
    }
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
     if (-not $vboxUrl -or $vboxUrl -eq "REPLACE_WITH_ACTUAL_VBOX_URL") {
        Write-Warning "[!] VirtualBox URL is not available or is a placeholder. Skipping VirtualBox installation."
        return
    }
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
    if (-not $vboxExtUrl -or $vboxExtUrl -eq "REPLACE_WITH_ACTUAL_VBOX_EXT_URL") {
        Write-Warning "[!] VirtualBox Extension Pack URL is not available or is a placeholder. Skipping Extension Pack installation."
        return
    }
    $downloadFolder = New-DownloadTempFolder
    # It's better to derive filename from URL or have a fixed known name if URL is stable
    # For now, using a generic name, but this might need adjustment if URL points to different versions
    $vboxExtFileName = "Oracle_VirtualBox_Extension_Pack.vbox-extpack" 
    # Attempt to extract filename from URL if possible
    try {
        $uriObj = [System.Uri]$vboxExtUrl
        $vboxExtFileName = [System.IO.Path]::GetFileName($uriObj.LocalPath)
        if (-not $vboxExtFileName.EndsWith(".vbox-extpack")) {
             $vboxExtFileName = "Oracle_VirtualBox_Extension_Pack.vbox-extpack" # Fallback
        }
    } catch {
        Write-Warning "Could not parse filename from Extension Pack URL. Using default: $vboxExtFileName"
    }

    $vboxExtPath = Join-Path $downloadFolder $vboxExtFileName
    Write-Host "[*] Downloading VirtualBox Extension Pack ($vboxExtFileName)..."
    try {
        Invoke-WebRequest -Uri $vboxExtUrl -OutFile $vboxExtPath -UseBasicParsing 
        Write-Host "[✓] Downloaded Extension Pack."
        $vboxManage = "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe"
        if (-not (Test-Path $vboxManage)) {
            $vboxManage = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
        }
        if (-not (Test-Path $vboxManage)) {
            Write-Host "[!] VBoxManage.exe not found. Please ensure VirtualBox is installed."
            return
        }
        Write-Host "[*] Importing Extension Pack..."
        # The license hash might change with new versions of the extension pack.
        # Consider making this dynamic or prompting user if it fails.
        # For now, using a common one, but this is a point of potential failure.
        $extPackArgs = "extpack install --replace `"$vboxExtPath`" --accept-license=eb31505e56e9b4d0fbca139104da41ac6f6b98f8e78968bdf01b1f3da3c4f9ae"
        Write-DebugMsg "VBoxManage args: $extPackArgs"
        Start-Process -FilePath $vboxManage -ArgumentList $extPackArgs -Wait -NoNewWindow
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
            "" 
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

function Check-VTDStatus {
    Write-Host "========== VT-d (Intel Virtualization Technology for Directed I/O) Status ==========" -ForegroundColor Cyan
    $vtdWmi = Get-WmiObject -Namespace "root\CIMV2" -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VirtualizationFirmwareEnabled
    if ($null -ne $vtdWmi) { 
        Write-Host "[*] VT-d/VirtualizationFirmwareEnabled (WMI): $vtdWmi" -ForegroundColor Green
    } else {
        $sysinfo = systeminfo | Select-String "Virtualization Enabled In Firmware"
        if ($sysinfo) {
            Write-Host "[*] VT-d/Virtualization status (systeminfo): $($sysinfo.ToString().Trim())" -ForegroundColor Green
        } else {
            Write-Host "[!] Could not determine VT-d status automatically. Please check BIOS/UEFI settings manually." -ForegroundColor Yellow
        }
    }
    Write-Host "===================================================================================="
}

function Apply-HypeFirewallRules {
    Write-Host "[*] Adding Hype firewall rules for ports 8001 and 8002..." -ForegroundColor Cyan
    $rule1Name = "Hype 8001"
    $rule2Name = "Hype 8002"
    if (-not (Get-NetFirewallRule -DisplayName $rule1Name -ErrorAction SilentlyContinue)) {
        Write-Host "  - Adding rule for port 8001..."
        New-NetFirewallRule -DisplayName $rule1Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8001 -RemoteAddress "87.121.112.82","LocalSubnet" -Profile Any
    } else {
        Write-Host "  - Firewall rule '$rule1Name' already exists."
    }
    if (-not (Get-NetFirewallRule -DisplayName $rule2Name -ErrorAction SilentlyContinue)) {
        Write-Host "  - Adding rule for port 8002..."
        New-NetFirewallRule -DisplayName $rule2Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8002 -RemoteAddress "87.121.112.82","LocalSubnet" -Profile Any
    } else {
        Write-Host "  - Firewall rule '$rule2Name' already exists."
    }
    Write-Host "[✓] Hype firewall rules checked/applied."
}

function Apply-RegFixes {
    Write-Host "[*] Applying registry fixes..." -ForegroundColor Cyan
    $regPath = "HKEY_USERS\.DEFAULT\Control Panel\Desktop"
    Write-Host "  - Setting AutoEndTasks=1 for default user profile..."
    Set-ItemProperty -Path "Registry::$regPath" -Name AutoEndTasks -Value "1" -Type String -Force
    Write-Host "  - Setting HungAppTimeout=10000 for default user profile..."
    Set-ItemProperty -Path "Registry::$regPath" -Name HungAppTimeout -Value "10000" -Type String -Force
    Write-Host "[✓] Registry fixes applied to default user profile."
    Write-Host "[i] Note: These registry settings apply to new user profiles or those based on the default."
    Write-Host "[i] For the current user, these settings might require a logoff/login or might be applied differently."
}

function Show-FixesMenu {
    Write-Host ""
    Write-Host "========== Fixes & Configuration ==========" -ForegroundColor Cyan
    Write-Host "[1] Set Bulgaria Locale/Time/Keyboard"
    Write-Host "[2] Set Power Settings to Never Sleep/Standby/Spin Down"
    Write-Host "[3] Apply Firewall Rules"
    Write-Host "[4] Apply Registry Fixes (for default user profile)"
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
                Read-Host | Out-Null
            }
            "2" {
                Set-PowerSettingsNever
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host | Out-Null
            }
            "3" {
                Apply-HypeFirewallRules
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host | Out-Null
            }
            "4" {
                Apply-RegFixes
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host | Out-Null
            }
            "5" {
                Open-DeviceManager
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host | Out-Null
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid choice."
                Write-Host "`nPress Enter to return to the Fixes menu..."
                Read-Host | Out-Null
            }
        }
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "========== Remote Tool Setup v$scriptVersion ==========" -ForegroundColor Cyan
    Write-Host "[1] Fixes & Configuration"
    Write-Host "[2] Install AnyDesk"
    Write-Host "[3] Scan Network for Used IP Addresses"
    Write-Host "[4] Send Custom Telegram Message"
    Write-Host "[5] Install VirtualBox (vcredist, VirtualBox, Extension Pack)"
    Write-Host "[x] Exit"
    Write-Host "======================================="
    Check-VTDStatus
}

# Check if any configuration values are still placeholders (optional, but good practice)
$placeholdersFound = $false
if ($anydeskUrl -eq "REPLACE_WITH_ACTUAL_ANYDESK_URL" -or `
    $anydeskPassword -eq "REPLACE_WITH_ACTUAL_ANYDESK_PASSWORD" -or `
    $telegramBotToken -eq "REPLACE_WITH_ACTUAL_TELEGRAM_BOT_TOKEN" -or `
    $telegramChatId -eq "REPLACE_WITH_ACTUAL_TELEGRAM_CHAT_ID" -or `
    $vcredistUrl -eq "REPLACE_WITH_ACTUAL_VCREDIST_URL" -or `
    $vboxUrl -eq "REPLACE_WITH_ACTUAL_VBOX_URL" -or `
    $vboxExtUrl -eq "REPLACE_WITH_ACTUAL_VBOX_EXT_URL") {
    Write-Warning "One or more configuration values are still placeholders. Please edit the script and replace them with actual values."
    $placeholdersFound = $true
    # Optionally, you can exit here if placeholders are critical for script operation
    # Read-Host "Press Enter to continue with placeholders, or Ctrl+C to exit and edit the script."
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
            Read-Host | Out-Null
        }
        "3" {
            Scan-NetworkUsedIPs
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host | Out-Null
        }
        "4" {
            Send-CustomTelegramMessage
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host | Out-Null
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
            Read-Host | Out-Null
        }
    }
}
exit 0
