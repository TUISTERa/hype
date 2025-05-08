# =========================
#      CONFIG (PLAINTEXT)
# =========================

$baseUrl = "http://sh.itpcloud.biz/" # Define the base URL once

$anydeskUrl = $baseUrl + "anydesk.exe"
$vcredistUrl = $baseUrl + "vcredistx64.exe"
$vboxUrl = $baseUrl + "virtualbox.exe"
$vboxExtUrl = $baseUrl + "Oracle_VirtualBox_Extension_Pack-7.1.6.vbox-extpack"
$chromeUrl = $baseUrl + "chrome.exe" # Added Chrome URL

$anydeskPassword = "hype1234"
$telegramBotToken = "5713387645:AAEnE0skfvLy5FmTRs0RwX9gLz9avFj72Wk"
$telegramChatId = "456050407"

$debugMode = $false
$scriptVersion = "1.0.4" # Updated version for Chrome addition

# =========================
#   WELCOME MESSAGE
# =========================
Write-Host "========================================="
Write-Host " Welcome to the Remote Tool Setup Script"
Write-Host "  For support or questions, contact IT. v$scriptVersion "
Write-Host "  WARNING: This version uses plaintext secrets."
Write-Host "=========================================" -ForegroundColor Cyan

# Run VT check once at startup
Check-VTDStatus

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
    if (-not $anydeskPassword) {
        Write-Warning "[!] AnyDesk password is not set. Please update the script."
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

    $bgList = New-WinUserLanguageList bg-BG
    if ($bgList.Count -ge 1) {
        $bgList[0].InputMethodTips.Clear()
        $bgList[0].InputMethodTips.Add("0402:00040402")
    } else {
        Write-Host "[!] Could not create Bulgarian language list."
        return
    }

    $usList = New-WinUserLanguageList en-US
    if ($usList.Count -ge 1) {
        $usList[0].InputMethodTips.Clear()
        $usList[0].InputMethodTips.Add("0409:00000409")
    } else {
        Write-Host "[!] Could not create US English language list."
        return
    }

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
    $adPass = Get-AnyDeskPassword
    if (-not $adPass) {
        Write-Warning "[!] AnyDesk password is not available. Skipping password set."
        return
    }
    
    Write-DebugMsg "Attempting to set AnyDesk password for $anydeskExe"
    try {
        $processOutput = ($adPass | & "$anydeskExe" --set-password 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[✓] Password set command executed for AnyDesk CLI."
            Write-DebugMsg "AnyDesk CLI output: $processOutput"
        } else {
            Write-Warning "[!] AnyDesk CLI command might have failed. Exit code: $LASTEXITCODE"
            Write-Warning "AnyDesk CLI output: $processOutput"
        }
    } catch {
        Write-Host "[!] Failed to set AnyDesk password: $($_.Exception.Message)"
        Write-DebugMsg "Full error: $_"
    }
}

function Get-AnyDeskID {
    $idPath = "$env:ProgramData\AnyDesk\system.conf"
    Write-DebugMsg "Looking for AnyDesk ID in $idPath"
    if (Test-Path $idPath) {
        try {
            $lines = Get-Content $idPath -ErrorAction Stop
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
        } catch {
            Write-Warning "Error reading AnyDesk config '$idPath': $($_.Exception.Message)"
            return $null
        }
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
    if (-not $telegramBotToken -or -not $telegramChatId) {
        Write-Warning "[!] Telegram Bot Token or Chat ID is not set. Skipping message send."
        return
    }
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage"
    $params = @{
        chat_id = $telegramChatId
        text    = $message
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $params -ErrorAction Stop
        Write-DebugMsg "Telegram API response: $($response | ConvertTo-Json -Depth 3)"
        Write-Host "[✓] Sent message to Telegram."
    } catch {
        Write-Host "[!] Failed to send message to Telegram: $($_.Exception.Message)"
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
    Write-Host "`n[*] AnyDesk ID: $Id`n" -ForegroundColor Green
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
            try {
                Start-Process -FilePath $path -ArgumentList "--minimized" -WindowStyle Hidden -ErrorAction Stop
                return
            } catch {
                Write-Warning "Failed to start AnyDesk from '$path': $($_.Exception.Message)"
            }
        }
    }
    Write-Host "[!] AnyDesk.exe not found in standard locations to start."
}

function Install-AnyDesk {
    if (-not $anydeskUrl) {
        Write-Warning "[!] AnyDesk URL is not set. Skipping AnyDesk installation."
        return
    }
    $downloadFolder = New-DownloadTempFolder
    $anydeskInstaller = Join-Path $downloadFolder "anydesk_installer.exe"
    
    if (Is-AnyDeskInstalled) {
        Write-Host "[!] AnyDesk is already installed." -ForegroundColor Yellow
        Start-AnyDesk
        $comment = Read-Host "AnyDesk already installed. Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.), or press Enter to skip"
        if ($comment.Trim() -ne "") {
            PrintAndSend-AnyDeskID -Comment $comment
        } else {
             PrintAndSend-AnyDeskID
        }
        return
    }

    Write-Host "[+] Downloading AnyDesk from $anydeskUrl..."
    try {
        Invoke-WebRequest -Uri $anydeskUrl -OutFile $anydeskInstaller -ErrorAction Stop
    } catch {
        Write-Error "Failed to download AnyDesk: $($_.Exception.Message)"
        return
    }

    Write-Host "[+] Installing AnyDesk with full arguments..."
    $installArgs = '--install "C:\Program Files (x86)\AnyDesk" --start-with-win --create-shortcuts --create-desktop-icon --silent'
    Write-DebugMsg "Installer arguments: $installArgs"
    try {
        Start-Process -FilePath $anydeskInstaller -ArgumentList $installArgs -Wait -ErrorAction Stop
    } catch {
        Write-Error "Failed to install AnyDesk: $($_.Exception.Message)"
        return
    }
    
    Write-Host "[*] Waiting a few seconds for AnyDesk service to initialize..."
    Start-Sleep -Seconds 5

    Start-AnyDesk
    Start-Sleep -Seconds 5

    $id = Wait-ForAnyDeskID
    if ($id -notlike "*not found*") {
        Write-Host "[*] AnyDesk ID: $id" -ForegroundColor Green
        Set-AnyDeskPassword
    } else {
        Write-Warning "[!] Could not retrieve AnyDesk ID after installation."
        Write-Warning "    $id"
    }

    Write-Host "[✓] AnyDesk installation process completed."

    $comment = Read-Host "Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.)"
    PrintAndSend-AnyDeskID -Comment $comment -Id $id
}

function Scan-NetworkUsedIPs {
    Write-Host "`n[*] Detecting available IPv4 networks...`n"
    $adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -notlike '169.254*' -and
        $_.IPAddress -ne '127.0.0.1' -and
        $_.PrefixOrigin -ne 'WellKnown' -and
        $_.InterfaceAlias -notlike "Loopback*"
    }
    if (-not $adapters) {
        Write-Host "[!] No suitable active network adapters found for scanning." -ForegroundColor Yellow
        return
    }
    $choices = @()
    $idx = 1 
    foreach ($adapter in $adapters) {
        $subnet = ($adapter.IPAddress -replace '\.\d+$','.')
        $choices += [PSCustomObject]@{
            Index = $idx
            InterfaceAlias = $adapter.InterfaceAlias
            IPAddress = $adapter.IPAddress
            PrefixLength = $adapter.PrefixLength
            SubnetBase = $subnet
        }
        Write-Host ("[{0}] {1} - {2}/{3} (Subnet: {4}x)" -f $idx, $adapter.InterfaceAlias, $adapter.IPAddress, $adapter.PrefixLength, $subnet)
        $idx++
    }
    if ($choices.Count -eq 0) {
        Write-Host "[!] No scannable networks detected after filtering." -ForegroundColor Yellow
        return
    }
    $sel = Read-Host "Select network to scan (enter number)"
    if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $choices.Count) {
        Write-Host "[!] Invalid selection." -ForegroundColor Red
        return
    }
    $selected = $choices[[int]$sel - 1]
    $base = $selected.SubnetBase
    $ip = $selected.IPAddress
    Write-Host "`n[*] Scanning subnet: $($base)1 - $($base)254 (Your IP: $ip)`n" -ForegroundColor Cyan

    $results = @()
    $maxConcurrentJobs = 32
    $jobs = @()
    1..254 | ForEach-Object {
        $i_scan = $_
        $target = "$base$i_scan"
        if ($target -eq $ip) { return } 

        while (@(Get-Job -State "Running").Count -ge $maxConcurrentJobs) {
            Start-Sleep -Milliseconds 200
        }
        $jobs += Start-Job -ScriptBlock {
            param($targetToPing) 
            if (Test-Connection -ComputerName $targetToPing -Count 1 -TimeoutSeconds 1 -Quiet) {
                $hostname = try { (Resolve-DnsName -Name $targetToPing -Type A -ErrorAction SilentlyContinue).NameHost } catch { "" }
                if (-not $hostname) {
                    try { $hostname = ([System.Net.Dns]::GetHostEntry($targetToPing).HostName) } catch { $hostname = "N/A" }
                }
                
                $macAddress = ""
                try {
                    $neighbor = Get-NetNeighbor -IPAddress $targetToPing -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Unreachable"}
                    if ($neighbor) {
                        $macAddress = $neighbor.LinkLayerAddress -replace "-",":"
                    }
                } catch {}

                if (-not $macAddress) {
                    $arpOutput = arp -a $targetToPing | Select-String -Pattern $targetToPing
                    if ($arpOutput -and ($arpOutput -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')) {
                        $macAddress = $Matches[0]
                    } else {
                        $macAddress = "N/A"
                    }
                }

                [PSCustomObject]@{
                    IP = $targetToPing
                    Hostname = if ($hostname -eq $targetToPing) { "N/A" } else { $hostname }
                    MAC = $macAddress.ToUpper()
                    Status = "Up"
                }
            }
        } -ArgumentList $target
        Write-Progress -Activity "Scanning Network" -Status "Pinging $target" -PercentComplete (($i_scan / 254) * 100)
    }
    Write-Progress -Activity "Scanning Network" -Completed
    
    Write-Host "Waiting for scan jobs to complete..."
    Wait-Job -Job $jobs | Out-Null
    
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job
        if ($result) { $results += $result }
    }
    Remove-Job -Job $jobs

    Write-Host "`n[*] Used IP addresses found:`n"
    if ($results.Count -eq 0) {
        Write-Host "No active hosts found on subnet $base*."
    } else {
        $results | Sort-Object {[version]$_.IP} | Format-Table -AutoSize 
    }
    Write-Host "`n[*] Scan complete.`n"
}

function Set-PowerSettingsNever {
    Write-Host "[*] Setting power settings to 'Never' for sleep, monitor, hard disk, and USB selective suspend..." -ForegroundColor Cyan
    powercfg /change monitor-timeout-ac 0
    powercfg /change standby-timeout-ac 0
    powercfg /change monitor-timeout-dc 0
    powercfg /change standby-timeout-dc 0
    
    $schemeLine = powercfg /getactivescheme
    $scheme = $null
    if ($schemeLine -match '([a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})') { 
        $scheme = $matches[1]
        Write-DebugMsg "Active power scheme GUID: $scheme"
    } else {
        Write-Warning "[!] Could not determine active power scheme GUID."
    }

    if ($scheme) {
        $diskSubGroup = "0012ee47-9041-4b5d-9b77-535fba8b1442"
        $diskSetting = "6738e2c4-e8a5-4a42-b16a-e040e769756e"
        powercfg /setacvalueindex $scheme $diskSubGroup $diskSetting 0
        powercfg /setdcvalueindex $scheme $diskSubGroup $diskSetting 0
        
        $usbSubGroup = "2a737441-1930-4402-8d77-b2bebba308a3"
        $usbSetting = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
        powercfg /setacvalueindex $scheme $usbSubGroup $usbSetting 0
        powercfg /setdcvalueindex $scheme $usbSubGroup $usbSetting 0
        
        powercfg /S $scheme
    }
    
    powercfg /hibernate off
    
    Write-Host "[✓] Power settings updated."
    Write-Host "[i] Verification (current active scheme):"
    if ($scheme) {
        Write-Host "  Monitor Timeout (AC): $(powercfg /query $scheme SUB_VIDEO VIDEOIDLE | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
        Write-Host "  Sleep Timeout (AC): $(powercfg /query $scheme SUB_SLEEP STANDBYIDLE | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
        Write-Host "  Hard Disk Timeout (AC): $(powercfg /query $scheme $diskSubGroup $diskSetting | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
    } else {
        Write-Host "  Could not query specific scheme settings."
    }
}

function Open-DeviceManager {
    Write-Host "[*] Opening Device Manager..."
    Start-Process devmgmt.msc
}

function Send-CustomTelegramMessage {
    Write-Host "[*] Enter your Telegram message. Type a single dot (.) on a new line to finish, or type '#cancel' to abort."
    $lines = @()
    while ($true) {
        $line = Read-Host
        if ($line -eq "." ) { break }
        if ($line.ToLower() -eq "#cancel") {
            Write-Host "[!] Message cancelled by user."
            return
        }
        $lines += $line
    }
    $message = $lines -join "`n"
    if (-not $message.Trim()) {
        Write-Host "[!] No message entered. Aborting."
        return
    }
    Send-TelegramMessage $message 
}

function Is-SoftwareInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string[]]$ExecutablePaths,
        [string]$RegistryPath,
        [string]$RegistryName
    )
    
    foreach ($path in $ExecutablePaths) {
        if (Test-Path $path) {
            Write-DebugMsg "$Name found at $path"
            return $true
        }
    }

    if ($RegistryPath -and $RegistryName) {
        try {
            $regValue = Get-ItemProperty -Path $RegistryPath -Name $RegistryName -ErrorAction SilentlyContinue
            if ($regValue -ne $null) {
                Write-DebugMsg "$Name found in registry: $RegistryPath)"
                return $true
            }
        } catch {
            Write-DebugMsg "Registry check failed for $Name: $($_.Exception.Message)"
        }
    }

    Write-DebugMsg "$Name not found"
    return $false
}

function Is-VirtualBoxInstalled {
    $vboxPaths = @(
        "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
    )
    return Is-SoftwareInstalled -Name "VirtualBox" `
        -ExecutablePaths $vboxPaths `
        -RegistryPath "HKLM:\SOFTWARE\Oracle\VirtualBox" `
        -RegistryName "Version"
}

function Is-VBoxExtPackInstalled {
    if (-not (Is-VirtualBoxInstalled)) { return $false }
    
    try {
        $vboxManage = "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe"
        $extpacks = & $vboxManage list extpacks
        return $extpacks -match "Oracle VM VirtualBox Extension Pack"
    } catch {
        Write-DebugMsg "Failed to check VirtualBox Extension Pack: $($_.Exception.Message)"
        return $false
    }
}

function Is-VcredistInstalled {
    $vcVersions = @(
        @{
            RegistryPath = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
            RegistryName = "Installed"
        },
        @{
            RegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
            RegistryName = "Installed"
        }
    )
    
    foreach ($vc in $vcVersions) {
        if (Is-SoftwareInstalled -Name "VC++ Redistributable" `
            -RegistryPath $vc.RegistryPath `
            -RegistryName $vc.RegistryName) {
            return $true
        }
    }
    return $false
}

function Install-Vcredist {
    if (Is-VcredistInstalled) {
        Write-Host "[!] VC++ Redistributable is already installed." -ForegroundColor Yellow
        return
    }
    
    if (-not $vcredistUrl) {
        Write-Warning "[!] VC Redist URL is not set. Skipping VC Redist installation."
        return
    }
    $downloadFolder = New-DownloadTempFolder
    $vcredistPath = Join-Path $downloadFolder "vc_redist.x64.exe"
    Write-Host "[*] Downloading Visual C++ Redistributable from $vcredistUrl..."
    try {
        Invoke-WebRequest -Uri $vcredistUrl -OutFile $vcredistPath -UseBasicParsing -ErrorAction Stop
        Write-Host "[✓] Downloaded vcredist."
        Write-Host "[*] Installing vcredist..."
        Start-Process -FilePath $vcredistPath -ArgumentList "/install /quiet /norestart" -Wait -ErrorAction Stop
        Write-Host "[✓] vcredist installed."
    } catch {
        Write-Error "[!] Failed to download or install vcredist: $($_.Exception.Message)"
        return
    }
}

function Install-VirtualBoxOnly {
    if (Is-VirtualBoxInstalled) {
        Write-Host "[!] VirtualBox is already installed." -ForegroundColor Yellow
        return
    }
    
    if (-not $vboxUrl) {
        Write-Warning "[!] VirtualBox URL is not set. Skipping VirtualBox installation."
        return
    }
    $downloadFolder = New-DownloadTempFolder
    $vboxPath = Join-Path $downloadFolder "VirtualBox-Installer.exe"
    Write-Host "[*] Downloading VirtualBox installer from $vboxUrl..."
    try {
        Invoke-WebRequest -Uri $vboxUrl -OutFile $vboxPath -UseBasicParsing -ErrorAction Stop
        Write-Host "[✓] Downloaded VirtualBox."
        Write-Host "[*] Installing VirtualBox..."
        Start-Process -FilePath $vboxPath -ArgumentList "--silent --ignore-reboot" -Wait -ErrorAction Stop
        Write-Host "[✓] VirtualBox installed."
    } catch {
        Write-Error "[!] Failed to download or install VirtualBox: $($_.Exception.Message)"
        return
    }
}

function Install-VBoxExtPack {
    if (Is-VBoxExtPackInstalled) {
        Write-Host "[!] VirtualBox Extension Pack is already installed." -ForegroundColor Yellow
        return
    }
    
    if (-not $vboxExtUrl) {
        Write-Warning "[!] VirtualBox Extension Pack URL is not set. Skipping Extension Pack installation."
        return
    }
    $downloadFolder = New-DownloadTempFolder
    $vboxExtFileName = "Oracle_VirtualBox_Extension_Pack.vbox-extpack" 
    try {
        $uriObj = [System.Uri]$vboxExtUrl
        $fileNameFromUrl = [System.IO.Path]::GetFileName($uriObj.LocalPath)
        if ($fileNameFromUrl -and $fileNameFromUrl.EndsWith(".vbox-extpack")) {
             $vboxExtFileName = $fileNameFromUrl
        }
    } catch {
        Write-Warning "Could not parse filename from Extension Pack URL '$vboxExtUrl'. Using default: $vboxExtFileName"
    }

    $vboxExtPath = Join-Path $downloadFolder $vboxExtFileName
    Write-Host "[*] Downloading VirtualBox Extension Pack ($vboxExtFileName) from $vboxExtUrl..."
    try {
        Invoke-WebRequest -Uri $vboxExtUrl -OutFile $vboxExtPath -UseBasicParsing -ErrorAction Stop
        Write-Host "[✓] Downloaded Extension Pack."
        
        $vboxManagePaths = @(
            "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe",
            "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
        )
        $vboxManage = $null
        foreach ($p in $vboxManagePaths) {
            if (Test-Path $p) { $vboxManage = $p; break }
        }

        if (-not (Test-Path $vboxManage)) {
            Write-Error "[!] VBoxManage.exe not found. Please ensure VirtualBox is installed correctly."
            return
        }
        Write-Host "[*] Importing Extension Pack using $vboxManage..."
        $extPackArgs = "extpack install --replace `"$vboxExtPath`" --accept-license=eb31505e56e9b4d0fbca139104da41ac6f6b98f8e78968bdf01b1f3da3c4f9ae"
        Write-DebugMsg "VBoxManage args: $extPackArgs"
        $process = Start-Process -FilePath $vboxManage -ArgumentList $extPackArgs -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        if ($process.ExitCode -eq 0) {
            Write-Host "[✓] Extension Pack imported successfully."
        } else {
            Write-Warning "[!] Extension Pack import may have failed. VBoxManage Exit Code: $($process.ExitCode)."
            Write-Warning "   Ensure the license hash in the script matches the downloaded Extension Pack version if issues occur."
        }
    } catch {
        Write-Error "[!] Failed to download or import Extension Pack: $($_.Exception.Message)"
        return
    }
}

function Install-VirtualBox-Menu {
    while ($true) {
        Write-Host "---- VirtualBox Installation Menu ----" -ForegroundColor Cyan
        Write-Host "[1] Install ALL (vcredist, VirtualBox, Extension Pack) [default]"
        Write-Host "[2] Install Visual C++ Redistributable (vcredist)"
        Write-Host "[3] Install VirtualBox"
        Write-Host "[4] Install VirtualBox Extension Pack"
        Write-Host "[b] Back to main menu"
        Write-Host "--------------------------------------"
        $subChoice = Read-Host "Select an option (Enter for ALL)"
        switch ($subChoice.ToLower()) {
            "1" {
                Install-Vcredist
                Start-Sleep -Seconds 5
                Install-VirtualBoxOnly
                Start-Sleep -Seconds 5
                Install-VBoxExtPack
                Write-Host "[✓] All VirtualBox components installation process finished."
                Read-Host | Out-Null
            }
            "2" {
                Install-Vcredist
                Read-Host | Out-Null
            }
            "3" {
                Install-VirtualBoxOnly
                Read-Host | Out-Null
            }
            "4" {
                Install-VBoxExtPack
                Read-Host | Out-Null
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
                Read-Host | Out-Null
            }
        }
    }
}

function Check-VTDStatus {
    Write-Host "========== VT-x/AMD-V & VT-d/IOMMU Status ==========" -ForegroundColor Cyan
    $cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, Manufacturer, VirtualizationFirmwareEnabled
    Write-Host "[*] CPU: $($cpuInfo.Name)"
    if ($cpuInfo.VirtualizationFirmwareEnabled) {
        Write-Host "[*] CPU Virtualization (VT-x/AMD-V) in Firmware: Enabled" -ForegroundColor Green
    } else {
        Write-Host "[!] CPU Virtualization (VT-x/AMD-V) in Firmware: Disabled or Not Supported" -ForegroundColor Yellow
    }

    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($hyperVFeature.State -eq "Enabled") {
        Write-Host "[*] Hyper-V Platform: Enabled" -ForegroundColor Yellow
    } else {
        Write-Host "[*] Hyper-V Platform: Disabled"
    }
    
    $sysinfoOutput = systeminfo
    $virtFirmwareSysInfo = $sysinfoOutput | Select-String "Virtualization Enabled In Firmware"
    if ($virtFirmwareSysInfo) {
        Write-Host "[*] Systeminfo 'Virtualization Enabled In Firmware': $($virtFirmwareSysInfo.ToString().Split(':')[-1].Trim())"
    }
    
    Write-Host "[i] For VT-d/IOMMU (Directed I/O), ensure it's enabled in BIOS/UEFI if needed for specific VM features."
    Write-Host "===================================================================================="
}

function Apply-HypeFirewallRules {
    Write-Host "[*] Adding/Updating Hype firewall rules for ports 8001 and 8002..." -ForegroundColor Cyan
    $commonRuleParams = @{
        Direction     = "Inbound"
        Action        = "Allow"
        Protocol      = "TCP"
        RemoteAddress = "87.121.112.82","LocalSubnet"
        Profile       = "Any"
        Group         = "Hype Services"
        ErrorAction   = "SilentlyContinue"
    }

    $rule1Name = "Hype 8001 TCP In"
    $rule1Port = 8001
    $rule1 = Get-NetFirewallRule -DisplayName $rule1Name -ErrorAction SilentlyContinue
    if ($rule1) {
        Set-NetFirewallRule -DisplayName $rule1Name @commonRuleParams -LocalPort $rule1Port
    } else {
        New-NetFirewallRule -DisplayName $rule1Name @commonRuleParams -LocalPort $rule1Port
    }

    $rule2Name = "Hype 8002 TCP In"
    $rule2Port = 8002
    $rule2 = Get-NetFirewallRule -DisplayName $rule2Name -ErrorAction SilentlyContinue
    if ($rule2) {
        Set-NetFirewallRule -DisplayName $rule2Name @commonRuleParams -LocalPort $rule2Port
    } else {
        New-NetFirewallRule -DisplayName $rule2Name @commonRuleParams -LocalPort $rule2Port
    }
    Write-Host "[✓] Hype firewall rules checked/applied."
}

function Apply-RegFixes {
    Write-Host "[*] Applying registry fixes for default user profile..." -ForegroundColor Cyan
    $defaultUserProfileRegPath = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop"
    
    try {
        if (-not (Test-Path $defaultUserProfileRegPath)) {
            Write-Warning "Default user profile registry path not found: $defaultUserProfileRegPath"
        }

        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "AutoEndTasks" -Value "1" -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "HungAppTimeout" -Value "10000" -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "WaitToKillAppTimeout" -Value "5000" -Type String -Force -ErrorAction Stop

        Write-Host "[✓] Registry fixes applied to default user profile."
    } catch {
        Write-Error "Failed to apply registry fixes: $($_.Exception.Message)"
    }
}

function Show-FixesMenu {
    Write-Host ""
    Write-Host "========== Fixes & Configuration ==========" -ForegroundColor Cyan
    Write-Host "[1] Set Bulgaria Locale/Time/Keyboard"
    Write-Host "[2] Set Power Settings to Never Sleep/Standby/Spin Down"
    Write-Host "[3] Apply Firewall Rules (Hype Ports 8001, 8002)"
    Write-Host "[4] Apply Registry Fixes (AutoEndTasks, etc. for default user profile)"
    Write-Host "[5] Open Device Manager"
    Write-Host "[b] Back to main menu"
    Write-Host "==========================================="
}

function Fixes-Menu-Loop {
    while ($true) {
        Show-FixesMenu
        $fixChoice = Read-Host "Enter choice"
        switch ($fixChoice.ToLower()) {
            "1" { Set-BulgariaLocaleAndTime }
            "2" { Set-PowerSettingsNever }
            "3" { Apply-HypeFirewallRules }
            "4" { Apply-RegFixes }
            "5" { Open-DeviceManager }
            "b" { return }
            default { Write-Host "Invalid choice." -ForegroundColor Red }
        }
        if ($fixChoice.ToLower() -ne "b") {
            Read-Host | Out-Null
        }
    }
}

function Install-Chrome {
    $chromePaths = @(
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    
    if (Is-SoftwareInstalled -Name "Chrome" -ExecutablePaths $chromePaths) {
        Write-Host "[!] Chrome is already installed." -ForegroundColor Yellow
        return
    }

    if (-not $chromeUrl) {
        Write-Warning "[!] Chrome URL is not set. Skipping Chrome installation."
        return
    }

    $downloadFolder = New-DownloadTempFolder
    $chromeInstaller = Join-Path $downloadFolder "chrome_installer.exe"
    
    Write-Host "[+] Downloading Chrome from $chromeUrl..."
    try {
        Invoke-WebRequest -Uri $chromeUrl -OutFile $chromeInstaller -ErrorAction Stop
    } catch {
        Write-Error "Failed to download Chrome: $($_.Exception.Message)"
        return
    }

    Write-Host "[+] Installing Chrome silently..."
    try {
        $installArgs = "/silent /install"
        Start-Process -FilePath $chromeInstaller -ArgumentList $installArgs -Wait -ErrorAction Stop
        Write-Host "[✓] Chrome installed successfully."
    } catch {
        Write-Error "Failed to install Chrome: $($_.Exception.Message)"
    }
}

function Show-Menu {
    Write-Host "========== Remote Tool Setup v$scriptVersion ==========" -ForegroundColor Cyan
    Write-Host "[1] Fixes & Configuration"
    Write-Host "[2] Install AnyDesk & Send ID"
    Write-Host "[3] Scan Network for Used IP Addresses"
    Write-Host "[4] Send Custom Telegram Message"
    Write-Host "[5] Install VirtualBox Suite"
    Write-Host "[6] Install Google Chrome"
    Write-Host "[x] Exit"
    Write-Host "======================================="
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Enter choice"
    switch ($choice.ToLower()) {
        "1" { Fixes-Menu-Loop }
        "2" { Install-AnyDesk }
        "3" { Scan-NetworkUsedIPs }
        "4" { Send-CustomTelegramMessage }
        "5" { Install-VirtualBox-Menu }
        "6" { Install-Chrome }
        "x" {
            Write-Host "Exiting..." -ForegroundColor Green
            Start-Sleep -Seconds 1
            break
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
            Read-Host | Out-Null
        }
    }
}
exit 0