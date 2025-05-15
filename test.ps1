
#powershell version 5.1 

# =========================
#      CONFIG (PLAINTEXT)
# =========================

$baseUrl = "http://sh.itpcloud.biz/" # Define the base URL once

$anydeskUrl = $baseUrl + "anydesk.exe"
$vcredistUrl = $baseUrl + "vcredistx64.exe"
$vboxUrl = $baseUrl + "virtualbox.exe"
$vboxExtUrl = $baseUrl + "Oracle_VirtualBox_Extension_Pack-7.1.6.vbox-extpack"
$chromeUrl = $baseUrl + "chrome.msi" # Added Chrome URL
$hypeBridgeUrl = $baseUrl + "hypebridge.exe"
$hypeCrUrl     = $baseUrl + "hypecr.msi"
$hypeKdsUrl    = $baseUrl + "hypekds.exe"
$hypeClientUrl = $baseUrl + "hypeclient.exe"

$anydeskPassword = "hype1234"
$telegramBotToken = "5713387645:AAEnE0skfvLy5FmTRs0RwX9gLz9avFj72Wk"
$telegramChatId = "456050407"

$debugMode = $false
$scriptVersion = "1.0.16" # Updated version for Chrome addition

# =========================
#      MAIN SCRIPT LOGIC
# =========================

function Write-DebugMsg($msg) {
    if ($debugMode) { Write-Host "[DEBUG] $msg" -ForegroundColor Yellow }
}

function New-DownloadTempFolder {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $folder = Join-Path $env:TEMP "itpremium_download_$timestamp"
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force
    }
    New-Item -Path $folder -ItemType Directory | Out-Null
    Write-Host "[*] Download folder: $folder" -ForegroundColor Cyan
    return $folder
}

function Get-AnyDeskPassword {
    # Returns the plaintext password directly
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
    
    Write-DebugMsg "Attempting to set AnyDesk password for $anydeskExe"
    try {
        # Use direct PowerShell piping to the external command
        $processOutput = ($adPass | & "$anydeskExe" --set-password 2>&1 | Out-String)
        # AnyDesk CLI might not produce significant output on success or might output to stderr
        # Check $LASTEXITCODE if AnyDesk.exe sets it reliably
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
        if ($id -and $id -notmatch "not found|Could not locate") { # Basic check for valid-looking ID
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
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage" # Uses plaintext token
    $params = @{
        chat_id = $telegramChatId # Uses plaintext chat ID
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
        return $true # Config file implies installation or attempted installation
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
    
    # Setting locale can be done once, perhaps at script start or in a dedicated setup function if needed multiple times
    # Set-BulgariaLocaleAndTime # Moved to Fixes menu, can be called if needed before this

    if (Is-AnyDeskInstalled) {
        Write-Host "[!] AnyDesk is already installed." -ForegroundColor Yellow
        Start-AnyDesk
        $comment = Read-Host "AnyDesk already installed. Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.), or press Enter to skip"
        if ($comment.Trim() -ne "") {
            PrintAndSend-AnyDeskID -Comment $comment
        } else {
             PrintAndSend-AnyDeskID # Send ID without comment if already installed
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
    Start-Sleep -Seconds 5 # Give AnyDesk a moment to start its service and generate config

    # Start AnyDesk to ensure config and ID are generated if not started by installer
    Start-AnyDesk
    Start-Sleep -Seconds 5 # Additional wait after starting

    $id = Wait-ForAnyDeskID
    if ($id -notlike "*not found*") {
        Write-Host "[*] AnyDesk ID: $id" -ForegroundColor Green
        Set-AnyDeskPassword
    } else {
        Write-Warning "[!] Could not retrieve AnyDesk ID after installation. Password setting might fail or be irrelevant."
        Write-Warning "    $id" # Display the "not found" message from Wait-ForAnyDeskID
    }

    Write-Host "[✓] AnyDesk installation process completed."

    $comment = Read-Host "Enter a comment for the Telegram message (e.g., 'Server', 'Workstation', etc.)"
    PrintAndSend-AnyDeskID -Comment $comment -Id $id # Pass ID to avoid re-fetching if already got it
}

function Scan-NetworkUsedIPs {
    Write-Host "`n[*] Detecting available IPv4 networks...`n"
    $adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -notlike '169.254*' -and
        $_.IPAddress -ne '127.0.0.1' -and
        $_.PrefixOrigin -ne 'WellKnown' -and # Exclude loopback, link-local, etc.
        $_.InterfaceAlias -notlike "Loopback*" # Further ensure no loopback
    }
    if (-not $adapters) {
        Write-Host "[!] No suitable active network adapters found for scanning." -ForegroundColor Yellow
        return
    }
    $choices = @()
    $idx = 1 
    foreach ($adapter in $adapters) {
        $subnet = ($adapter.IPAddress -replace '\.\d+$','.') # More robust subnet extraction
        $choices += [PSCustomObject]@{
            Index = $idx
            InterfaceAlias = $adapter.InterfaceAlias
            IPAddress = $adapter.IPAddress
            PrefixLength = $adapter.PrefixLength
            SubnetBase = $subnet # e.g., 192.168.1.
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
    $base = $selected.SubnetBase # e.g., 192.168.1.
    $ip = $selected.IPAddress
    Write-Host "`n[*] Scanning subnet: $($base)1 - $($base)254 (Your IP: $ip)`n" -ForegroundColor Cyan

    $results = @()
    $maxConcurrentJobs = 32
    $jobs = @()
    1..254 | ForEach-Object {
        $i_scan = $_
        $target = "$base$i_scan"
        # Skip scanning own IP if it falls in the range
        if ($target -eq $ip) { return } 

        while (@(Get-Job -State "Running").Count -ge $maxConcurrentJobs) {
            Start-Sleep -Milliseconds 200
        }
        $jobs += Start-Job -ScriptBlock {
            param($targetToPing) 
            # Using Test-Connection as it's a PowerShell cmdlet, more robust than parsing ping.exe
            if (Test-Connection -ComputerName $targetToPing -Count 3  -Quiet) {
                $hostname = try { (Resolve-DnsName -Name $targetToPing -Type A -ErrorAction SilentlyContinue).NameHost } catch { "" }
                if (-not $hostname) {
                    try { $hostname = ([System.Net.Dns]::GetHostEntry($targetToPing).HostName) } catch { $hostname = "N/A" }
                }
                
                # Get-NetNeighbor is more modern for MAC, but arp is fallback
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
    Remove-Job -Job $jobs # Clean up jobs

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
    # AC Power Settings
    powercfg /change monitor-timeout-ac 0
    powercfg /change standby-timeout-ac 0
    # DC Power Settings (for laptops, usually same for servers/desktops but good to set)
    powercfg /change monitor-timeout-dc 0
    powercfg /change standby-timeout-dc 0
    
    $schemeLine = powercfg /getactivescheme
    $scheme = $null
    if ($schemeLine -match '([a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})') { 
        $scheme = $matches[1]
        Write-DebugMsg "Active power scheme GUID: $scheme"
    } else {
        Write-Warning "[!] Could not determine active power scheme GUID. Some settings may not apply."
        # Fallback to trying to set for common schemes if GUID not found, or just proceed
    }

    if ($scheme) {
        # Hard disk timeout (0 = Never)
        $diskSubGroup = "0012ee47-9041-4b5d-9b77-535fba8b1442" # SUB_DISK
        $diskSetting = "6738e2c4-e8a5-4a42-b16a-e040e769756e"  # DISKIDLE
        powercfg /setacvalueindex $scheme $diskSubGroup $diskSetting 0
        powercfg /setdcvalueindex $scheme $diskSubGroup $diskSetting 0
        
        # USB selective suspend (0 = Disabled)
        $usbSubGroup = "2a737441-1930-4402-8d77-b2bebba308a3" # SUB_USB
        $usbSetting = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"  # USBSELECTSUSPEND
        powercfg /setacvalueindex $scheme $usbSubGroup $usbSetting 0
        powercfg /setdcvalueindex $scheme $usbSubGroup $usbSetting 0
        
        powercfg /S $scheme # Apply the current (now modified) scheme
    }
    
    # Hibernate Off
    powercfg /hibernate off
    
    Write-Host "[✓] Power settings updated: No sleep, no monitor off, no HDD spin-down (for active scheme), USB selective suspend disabled (for active scheme), hibernate off."
    Write-Host "[i] Verification (current active scheme):"
    if ($scheme) {
        Write-Host "  Monitor Timeout (AC): $(powercfg /query $scheme SUB_VIDEO VIDEOIDLE | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
        Write-Host "  Sleep Timeout (AC): $(powercfg /query $scheme SUB_SLEEP STANDBYIDLE | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
        Write-Host "  Hard Disk Timeout (AC): $(powercfg /query $scheme $diskSubGroup $diskSetting | Select-String 'Current AC Power Setting Index' | ForEach-Object {$_.Line.Split(':')[-1].Trim()})"
    } else {
        Write-Host "  Could not query specific scheme settings as GUID was not found."
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
    $message = $lines -join "`n" # PowerShell uses `n for newline in strings
    if (-not $message.Trim()) {
        Write-Host "[!] No message entered. Aborting."
        return
    }
    Send-TelegramMessage $message 
}

function Install-Vcredist {
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
        # Common arguments: --silent --ignore-reboot --msiparams REBOOT=ReallySuppress
        # Check VirtualBox documentation for latest silent install flags if issues arise.
        Start-Process -FilePath $vboxPath -ArgumentList "--silent --ignore-reboot" -Wait -ErrorAction Stop
        Write-Host "[✓] VirtualBox installed."
    } catch {
        Write-Error "[!] Failed to download or install VirtualBox: $($_.Exception.Message)"
        return
    }
}

function Install-VBoxExtPack {
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
            "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe" # Less common for 64-bit VBox but check
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
        # The license hash can change. A more robust way is to first run with --accept-license=LATER
        # and then find the hash, or use a known good hash.
        # The provided hash eb31... is for a specific version.
        # Using a generic approach that might require user interaction if license changed significantly
        # or if VBoxManage prompts.
        # For fully silent, the exact hash for the downloaded version is needed.
        # Attempting with a common hash, but this is a known point of failure for automation.
        $extPackArgs = "extpack install --replace `"$vboxExtPath`" --accept-license=eb31505e56e9b4d0fbca139104da41ac6f6b98f8e78968bdf01b1f3da3c4f9ae"
        Write-DebugMsg "VBoxManage args: $extPackArgs"
        # Start-Process with -Wait and -NoNewWindow is good. Capture output for debugging.
        $process = Start-Process -FilePath $vboxManage -ArgumentList $extPackArgs -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        # Check $process.ExitCode
        if ($process.ExitCode -eq 0) {
            Write-Host "[✓] Extension Pack imported successfully."
        } else {
            Write-Warning "[!] Extension Pack import may have failed. VBoxManage Exit Code: $($process.ExitCode)."
            Write-Warning "   Ensure the license hash in the script matches the downloaded Extension Pack version if issues occur."
            Write-Warning "   You might need to run VBoxManage extpack install ""$vboxExtPath"" manually to accept the license."
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
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VirtualBoxOnly
                Write-Host "[*] Waiting 5 seconds before next step..."
                Start-Sleep -Seconds 5
                Install-VBoxExtPack
                Write-Host "[✓] All VirtualBox components installation process finished."
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host | Out-Null
            }
            "2" {
                Install-Vcredist
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host | Out-Null
            }
            "3" {
                Install-VirtualBoxOnly
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host | Out-Null
            }
            "4" {
                Install-VBoxExtPack
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host | Out-Null
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
                Write-Host "`nPress Enter to return to the VirtualBox menu..."
                Read-Host | Out-Null
            }
        }
    }
}

function Check-VTDStatus {
    Write-Host "========== VT-x/AMD-V & VT-d/IOMMU Status ==========" -ForegroundColor Cyan
    # Check for CPU Virtualization (VT-x/AMD-V)
    $cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, Manufacturer, VirtualizationFirmwareEnabled
    Write-Host "[*] CPU: $($cpuInfo.Name)"
    if ($cpuInfo.VirtualizationFirmwareEnabled) {
        Write-Host "[*] CPU Virtualization (VT-x/AMD-V) in Firmware: Enabled" -ForegroundColor Green
    } else {
        Write-Host "[!] CPU Virtualization (VT-x/AMD-V) in Firmware: Disabled or Not Supported" -ForegroundColor Yellow
        Write-Host "    Please check BIOS/UEFI settings to enable it (e.g., Intel VT-x, AMD-V)."
    }

    # Check Hyper-V status (can interfere or indicate virtualization state)
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($hyperVFeature.State -eq "Enabled") {
        Write-Host "[*] Hyper-V Platform: Enabled" -ForegroundColor Yellow
        Write-Host "    Note: Hyper-V being enabled might affect other virtualization software like VirtualBox Type 2 hypervisors."
    } else {
        Write-Host "[*] Hyper-V Platform: Disabled"
    }
    
    # Systeminfo check (often shows "Virtualization Enabled In Firmware")
    $sysinfoOutput = systeminfo
    $virtFirmwareSysInfo = $sysinfoOutput | Select-String "Virtualization Enabled In Firmware"
    if ($virtFirmwareSysInfo) {
        Write-Host "[*] Systeminfo 'Virtualization Enabled In Firmware': $($virtFirmwareSysInfo.ToString().Split(':')[-1].Trim())"
    } else {
        Write-Host "[?] Systeminfo did not report 'Virtualization Enabled In Firmware'."
    }
    
    # VT-d / IOMMU (more for device passthrough, but related)
    # This is harder to check reliably via simple commands for all systems.
    # Win32_Processor.VirtualizationFirmwareEnabled is more about CPU virt.
    # For VT-d/IOMMU, BIOS settings are key. Device Manager under "System devices" might list IOMMU controllers.
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
        Profile       = "Any" # Public, Private, Domain
        Group         = "Hype Services" # Grouping rules
        ErrorAction   = "SilentlyContinue"
    }

    $rule1Name = "Hype 8001 TCP In"
    $rule1Port = 8001
    $rule1 = Get-NetFirewallRule -DisplayName $rule1Name -ErrorAction SilentlyContinue
    if ($rule1) {
        Write-Host "  - Updating existing rule '$rule1Name' for port $rule1Port..."
        Set-NetFirewallRule -DisplayName $rule1Name @commonRuleParams -LocalPort $rule1Port
    } else {
        Write-Host "  - Adding new rule '$rule1Name' for port $rule1Port..."
        New-NetFirewallRule -DisplayName $rule1Name @commonRuleParams -LocalPort $rule1Port
    }

    $rule2Name = "Hype 8002 TCP In"
    $rule2Port = 8002
    $rule2 = Get-NetFirewallRule -DisplayName $rule2Name -ErrorAction SilentlyContinue
    if ($rule2) {
        Write-Host "  - Updating existing rule '$rule2Name' for port $rule2Port..."
        Set-NetFirewallRule -DisplayName $rule2Name @commonRuleParams -LocalPort $rule2Port
    } else {
        Write-Host "  - Adding new rule '$rule2Name' for port $rule2Port..."
        New-NetFirewallRule -DisplayName $rule2Name @commonRuleParams -LocalPort $rule2Port
    }
    Write-Host "[✓] Hype firewall rules checked/applied."
}

function Apply-RegFixes {
    Write-Host "[*] Applying registry fixes for default user profile..." -ForegroundColor Cyan
    # These settings apply to HKEY_USERS\.DEFAULT, affecting new profiles.
    # For current user, HKEY_CURRENT_USER would be used, or changes might need logoff/login.
    
    $defaultUserProfileRegPath = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop"
    
    try {
        if (-not (Test-Path $defaultUserProfileRegPath)) {
            Write-Warning "Default user profile registry path not found: $defaultUserProfileRegPath"
            # Optionally create it, but usually it exists.
            # New-Item -Path $defaultUserProfileRegPath -Force | Out-Null
        }

        Write-Host "  - Setting AutoEndTasks=1 (forces closing apps on shutdown/restart)"
        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "AutoEndTasks" -Value "1" -Type String -Force -ErrorAction Stop
        
        Write-Host "  - Setting HungAppTimeout=10000 (timeout for non-responsive apps in ms)"
        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "HungAppTimeout" -Value "10000" -Type String -Force -ErrorAction Stop
        
        # WaitToKillAppTimeout: Time to wait before killing an app during shutdown.
        Write-Host "  - Setting WaitToKillAppTimeout=5000 (timeout for apps to close on shutdown in ms)"
        Set-ItemProperty -Path $defaultUserProfileRegPath -Name "WaitToKillAppTimeout" -Value "5000" -Type String -Force -ErrorAction Stop

        Write-Host "[✓] Registry fixes applied to default user profile."
        Write-Host "[i] Note: These settings primarily affect new user profiles. For the current user, a logoff/login may be needed, or apply to HKCU."
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
            "1" {
                Set-BulgariaLocaleAndTime
            }
            "2" {
                Set-PowerSettingsNever
            }
            "3" {
                Apply-HypeFirewallRules
            }
            "4" {
                Apply-RegFixes
            }
            "5" {
                Open-DeviceManager
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid choice." -ForegroundColor Red
            }
        }
        if ($fixChoice.ToLower() -ne "b") {
            Write-Host "`nPress Enter to return to the Fixes menu..."
            Read-Host | Out-Null
        }
    }
}

# =========================
#   HYPE TOOLS SUBMENU
# =========================

function Install-HypeTool {
    param(
        [Parameter(Mandatory)]
        [string]$ToolName,
        [Parameter(Mandatory)]
        [string]$ToolUrl
    )
    $installPaths = @(
        "${env:ProgramFiles}\Hype\$ToolName.exe",
        "${env:ProgramFiles(x86)}\Hype\$ToolName.exe"
    )
    foreach ($path in $installPaths) {
        if (Test-Path $path) {
            Write-Host "[!] $ToolName is already installed at $path" -ForegroundColor Yellow
            return
        }
    }
    $downloadFolder = New-DownloadTempFolder
    $installerPath = Join-Path $downloadFolder "$ToolName.exe"
    Write-Host "[+] Downloading $ToolName from $ToolUrl..."
    try {
        Invoke-WebRequest -Uri $ToolUrl -OutFile $installerPath -ErrorAction Stop
    } catch {
        $err = $_
        $errMsg = $err.Exception.Message
        Write-Error ('Failed to download ' + $ToolName + ': ' + $errMsg)
        return
    }
    Write-Host "[+] Installing $ToolName..."
    try {
        Start-Process -FilePath $installerPath -ArgumentList "/silent", "/install" -Wait -ErrorAction Stop
        Write-Host "[✓] $ToolName installed successfully."
    } catch {
        $err = $_
        $errMsg = $err.Exception.Message
        Write-Error ('Failed to install ' + $ToolName + ': ' + $errMsg)
    }
}

function Add-HypeServerToStartup {
    # Get the full path to the current script
    $scriptPath = $MyInvocation.MyCommand.Path

    # Get the user's Startup folder
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $batFile = Join-Path $startupFolder "hypeserver.bat"

    # Prepare the batch file content
    $batContent = "@echo off`r`n" +
                  '"%programfiles%\Oracle\VirtualBox\VBoxManage.exe" startvm HypeServer64 --type headless'


    # Write the batch file
    Set-Content -Path $batFile -Value $batContent -Encoding ASCII

    Write-Host "[✓] Startup batch file created at: $batFile"
    Write-Host "The script will now run automatically at user login."
}

function Show-HypeMenu {
    while ($true) {
        Write-Host ""
        Write-Host "========== Hype Tools Menu ==========" -ForegroundColor Cyan
        Write-Host "[1] Download & Install HypeBridge"
        Write-Host "[2] Download & Install HypeCR"
        Write-Host "[3] Download & Install HypeKDS"
        Write-Host "[4] Download & Install HypeClient"
        Write-Host "[5] Install HypeServer.Bat at startup" # New option
        Write-Host "[b] Back to main menu"
        Write-Host "====================================="
        $hypeChoice = Read-Host "Enter choice"
        switch ($hypeChoice.ToLower()) {
            "1" {
                Install-HypeTool -ToolName "hypebridge" -ToolUrl $hypeBridgeUrl
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
            "2" {
                Install-HypeTool -ToolName "hypecr" -ToolUrl $hypeCrUrl
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
            "3" {
                Install-HypeTool -ToolName "hypekds" -ToolUrl $hypeKdsUrl
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
            "4" {
                Install-HypeTool -ToolName "hypeclient" -ToolUrl $hypeClientUrl
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
            "5" {
                Add-HypeServerToStartup
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
            "b" {
                return
            }
            default {
                Write-Host "Invalid choice." -ForegroundColor Red
                Write-Host "`nPress Enter to return to the Hype menu..."
                Read-Host | Out-Null
            }
        }
    }
}

function Install-Chrome {
    if (-not $chromeUrl) {
        Write-Warning "[!] Chrome URL is not set. Skipping Chrome installation."
        return
    }
    
    $installPaths = @(
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    
    foreach ($path in $installPaths) {
        if (Test-Path $path) {
            Write-Host "[!] Chrome is already installed at $path" -ForegroundColor Yellow
            return
        }
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

# Updated main menu
function Show-Menu {
    Write-Host "========== Remote Tool Setup v$scriptVersion ==========" -ForegroundColor Cyan
    Write-Host "[1] Fixes & Configuration"
    Write-Host "[2] Install AnyDesk & Send ID"
    Write-Host "[3] Scan Network for Used IP Addresses"
    Write-Host "[4] Send Custom Telegram Message"
    Write-Host "[5] Install VirtualBox Suite"
    Write-Host "[6] Install Google Chrome" 
    Write-Host "[7] Hype Tools" # New option
    Write-Host "[x] Exit"
    Write-Host "======================================="
}

# Updated main loop
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
        "7" { Show-HypeMenu } # New case
        "x" {
            Write-Host "Exiting..." -ForegroundColor Green
            Start-Sleep -Seconds 1
            exit 0
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
            Write-Host "`nPress Enter to return to the menu..."
            Read-Host | Out-Null
        }
    }
}
exit 0
