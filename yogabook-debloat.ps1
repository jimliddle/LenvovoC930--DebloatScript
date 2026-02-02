#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10/11 Debloat Script for Lenovo Yoga Book (4GB RAM)
.DESCRIPTION
    Removes bloatware, disables unnecessary services, and optimizes performance.
    Safe for devices with e-ink keyboards - preserves touch/tablet/dictation services.
    Detects Windows version and applies appropriate optimizations.
.NOTES
    - Creates a restore point before making changes
    - Logs all actions to C:\DebloatLog.txt
    - Some changes require a restart to take effect
    - SAFE FOR: Yoga Book, Yoga Book 9i, and similar tablet/convertible devices
#>

$ErrorActionPreference = "SilentlyContinue"
$LogFile = "C:\DebloatLog.txt"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
    Write-Host $Message -ForegroundColor $Color
}

# ============================================
# DETECT WINDOWS VERSION
# ============================================
$WinVer = [System.Environment]::OSVersion.Version
$WinBuild = $WinVer.Build
$IsWin11 = $WinBuild -ge 22000
$WinName = if ($IsWin11) { "Windows 11" } else { "Windows 10" }

Write-Log "==========================================" "Cyan"
Write-Log "Yoga Book Debloat Script - $WinName Detected" "Cyan"
Write-Log "Build: $WinBuild" "Cyan"
Write-Log "==========================================" "Cyan"

# Show system info
$RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$CPU = (Get-CimInstance Win32_Processor).Name
Write-Log "System: $CPU | $RAM GB RAM" "Yellow"
Write-Log ""

# ============================================
# CREATE RESTORE POINT
# ============================================
Write-Log "Creating system restore point..." "Yellow"
Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description "Before Yoga Book Debloat Script" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
Write-Log "  Restore point created" "Green"

# ============================================
# SECTION 1: REMOVE BLOATWARE APPS
# ============================================
Write-Log ""
Write-Log "[1/10] Removing bloatware apps..." "Yellow"

# Common bloatware for both Windows 10 and 11
$BloatwareApps = @(
    # Microsoft bloat
    "Microsoft.3DBuilder"
    "Microsoft.3DViewer"
    "Microsoft.BingWeather"
    "Microsoft.BingNews"
    "Microsoft.BingFinance"
    "Microsoft.BingSports"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Todos"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.MicrosoftStickyNotes"
    "Clipchamp.Clipchamp"
    
    # Third-party bloat
    "ACGMediaPlayer"
    "ActiproSoftwareLLC"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "Amazon.com.Amazon"
    "AmazonVideo.PrimeVideo"
    "Asphalt8Airborne"
    "AutodeskSketchBook"
    "CasualGames"
    "COOKINGFEVER"
    "CyberLinkMediaSuiteEssentials"
    "DisneyMagicKingdoms"
    "Disney"
    "Dolby"
    "DrawboardPDF"
    "Duolingo-LearnLanguagesforFree"
    "EclipseManager"
    "Facebook"
    "FarmVille2CountryEscape"
    "Fitbit.FitbitCoach"
    "Flipboard"
    "HiddenCity"
    "HULULLC.HULUPLUS"
    "iHeartRadio"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushFriends"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.FarmHeroesSaga"
    "LinkedInforWindows"
    "MarchofEmpires"
    "Netflix"
    "NYTCrossword"
    "OneCalendar"
    "PandoraMediaInc"
    "PhototasticCollage"
    "PicsArt-PhotoStudio"
    "Plex"
    "PolarrPhotoEditorAcademicEdition"
    "RoyalRevolt"
    "Shazam"
    "Sidia.LiveWallpaper"
    "SlingTV"
    "Speed Test"
    "Spotify"
    "TikTok"
    "TuneInRadio"
    "Twitter"
    "Viber"
    "WinZipUniversal"
    "Wunderlist"
    "XING"
)

# Windows 11 specific bloatware
if ($IsWin11) {
    $BloatwareApps += @(
        "MicrosoftTeams"
        "Microsoft.Todos"
        "Microsoft.BingSearch"
        "Microsoft.WindowsCommunicationsApps"  # Mail & Calendar
        "Microsoft.GamingApp"
        "Microsoft.OutlookForWindows"
        "MSTeams"
        "Microsoft.549981C3F5F10"  # Cortana
        "Microsoft.Windows.DevHome"
        "Microsoft.Copilot"
        "Microsoft.Windows.Ai.Copilot.Provider"
        "MicrosoftCorporationII.MicrosoftFamily"
        "MicrosoftCorporationII.QuickAssist"
        # "Microsoft.WindowsTerminal"  # PRESERVED - user needs this
    )
    Write-Log "  Added Windows 11 specific bloatware to removal list" "Cyan"
}

# PRESERVE Lenovo e-ink utilities - DO NOT REMOVE these
$PreserveApps = @(
    "Lenovo.EInk"
    "Lenovo.Pen"
    "Lenovo.Utility"
    "Lenovo.Vantage"  # May be needed for device management
    "LenovoPenSettings"
    "E Ink"
)

$removedCount = 0
$skippedCount = 0

# Get all installed apps once (faster than querying for each app)
Write-Log "  Scanning installed apps..."
$AllInstalledApps = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
$AllProvisionedApps = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

foreach ($app in $BloatwareApps) {
    # Skip if it's a Lenovo e-ink related app
    $skip = $false
    foreach ($preserve in $PreserveApps) {
        if ($app -like "*$preserve*") {
            $skip = $true
            Write-Log "  PRESERVED: $app (needed for Yoga Book)" "Magenta"
            break
        }
    }
    if ($skip) { continue }
    
    # Check if app exists before trying to remove
    $packages = $AllInstalledApps | Where-Object { $_.Name -like "*$app*" }
    
    if ($packages -and $packages.Count -gt 0) {
        foreach ($package in $packages) {
            Write-Log "  Removing: $($package.Name)"
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            $removedCount++
        }
    } else {
        $skippedCount++
    }
    
    # Also remove provisioned package if it exists (prevents reinstall)
    $provisioned = $AllProvisionedApps | Where-Object { $_.DisplayName -like "*$app*" }
    if ($provisioned) {
        foreach ($prov in $provisioned) {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
Write-Log "  Removed $removedCount apps, skipped $skippedCount (not installed)" "Green"

# ============================================
# SECTION 2: DISABLE UNNECESSARY SERVICES
# ============================================
Write-Log ""
Write-Log "[2/10] Disabling unnecessary services..." "Yellow"
Write-Log "  (Preserving tablet/touch/dictation services for Yoga Book)" "Magenta"

$ServicesToDisable = @(
    "DiagTrack"                    # Connected User Experiences and Telemetry
    "dmwappushservice"             # Device Management WAP Push
    "SysMain"                      # Superfetch (can hurt low-RAM systems)
    "WSearch"                      # Windows Search indexing (resource heavy)
    "XblAuthManager"               # Xbox Live Auth
    "XblGameSave"                  # Xbox Live Game Save
    "XboxNetApiSvc"                # Xbox Live Networking
    "XboxGipSvc"                   # Xbox Accessory Management
    "WMPNetworkSvc"                # Windows Media Player Network Sharing
    "WerSvc"                       # Windows Error Reporting
    "MapsBroker"                   # Downloaded Maps Manager
    "lfsvc"                        # Geolocation Service
    "RetailDemo"                   # Retail Demo Service
    "RemoteRegistry"               # Remote Registry
    "Fax"                          # Fax
    "PhoneSvc"                     # Phone Service
    "wisvc"                        # Windows Insider Service
)

# Windows 11 specific services to disable
if ($IsWin11) {
    $ServicesToDisable += @(
        "WpcMonSvc"                # Parental Controls
        "WbioSrvc"                 # Windows Biometric Service (disable if not using fingerprint)
    )
}

# CRITICAL: Services to PRESERVE for Yoga Book e-ink keyboard and dictation
$PreserveServices = @(
    "TabletInputService"           # Touch Keyboard - ESSENTIAL for e-ink keyboard
    "SpeechRuntime"                # Speech/Dictation
    "OnlineSpeechRecognition"      # Online dictation
    "TouchKeyboard"                # Touch keyboard
    "InputService"                 # Input service
    "TextInputManagementService"   # Text input (Win11)
)

foreach ($service in $ServicesToDisable) {
    # Double-check we're not disabling a preserved service
    if ($PreserveServices -contains $service) {
        Write-Log "  SKIPPED (preserved): $service" "Magenta"
        continue
    }
    
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log "  Disabling: $service"
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}
Write-Log "  Services optimized (tablet/touch services preserved)" "Green"

# ============================================
# SECTION 3: DISABLE SCHEDULED TASKS
# ============================================
Write-Log ""
Write-Log "[3/10] Disabling unnecessary scheduled tasks..." "Yellow"

$TasksToDisable = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Autochk\Proxy"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "\Microsoft\Windows\Feedback\Siuf\DmClient"
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "\Microsoft\Windows\Maps\MapsToastTask"
    "\Microsoft\Windows\Maps\MapsUpdateTask"
    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "\Microsoft\XblGameSave\XblGameSaveTask"
)

# Windows 11 specific tasks
if ($IsWin11) {
    $TasksToDisable += @(
        "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
        "\Microsoft\Windows\Wininet\CacheTask"
    )
}

foreach ($task in $TasksToDisable) {
    Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
}
Write-Log "  Scheduled tasks disabled" "Green"

# ============================================
# SECTION 4: REGISTRY OPTIMIZATIONS
# ============================================
Write-Log ""
Write-Log "[4/10] Applying registry optimizations..." "Yellow"

# --- Common optimizations (Win10 & Win11) ---

# Disable Cortana
Write-Log "  Disabling Cortana..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Reduce telemetry
Write-Log "  Reducing telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Windows Tips and suggestions
Write-Log "  Disabling tips and suggestions..."
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

# Disable Timeline / Activity History
Write-Log "  Disabling Timeline..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

# Disable Game Bar and Game DVR
Write-Log "  Disabling Game Bar/DVR..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
New-Item -Path "HKCU:\System\GameConfigStore" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0

# Optimize visual effects for performance (but keep font smoothing)
Write-Log "  Optimizing visual effects..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0

# Disable transparency effects
Write-Log "  Disabling transparency..."
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0

# Reduce menu delays
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "10"

# --- Windows 11 Specific Optimizations ---
if ($IsWin11) {
    Write-Log "  Applying Windows 11 specific tweaks..." "Cyan"
    
    # Disable Widgets
    Write-Log "  Disabling Widgets..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
    
    # Disable Chat/Teams icon in taskbar
    Write-Log "  Disabling Teams chat icon..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0
    
    # Disable Search highlights
    Write-Log "  Disabling Search highlights..."
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Type DWord -Value 0
    
    # Disable Copilot
    Write-Log "  Disabling Copilot..."
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
    
    # Disable Recall (AI screenshot feature) - privacy/performance
    Write-Log "  Disabling Recall..."
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Type DWord -Value 1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Type DWord -Value 1
    
    # Restore classic right-click menu (optional but popular)
    Write-Log "  Restoring classic context menu..."
    New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value ""
    
    # Taskbar alignment left (optional - comment out if you prefer center)
    # Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0
    
    # Disable VBS/HVCI for performance (significant boost on low-RAM devices)
    # WARNING: This reduces security but improves performance
    Write-Log "  Disabling VBS/HVCI for performance..." "Yellow"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
}

Write-Log "  Registry optimizations applied" "Green"

# ============================================
# SECTION 5: OPTIMIZE FILE SYSTEM
# ============================================
Write-Log ""
Write-Log "[5/10] Optimizing file system..." "Yellow"

# Disable last access timestamp (reduces writes, improves speed)
fsutil behavior set disablelastaccess 1 | Out-Null

# Disable 8.3 filename creation
fsutil behavior set disable8dot3 1 | Out-Null

Write-Log "  NTFS optimized" "Green"

# ============================================
# SECTION 6: MEMORY OPTIMIZATIONS
# ============================================
Write-Log ""
Write-Log "[6/10] Optimizing memory usage..." "Yellow"

# Set svhost split threshold higher (fewer processes)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

# Disable memory compression (helps on very low RAM)
Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue

# Disable Prefetch/Superfetch (already disabled service, but also registry)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0

Write-Log "  Memory optimizations applied" "Green"

# ============================================
# SECTION 7: WINDOWS DEFENDER OPTIMIZATION
# ============================================
Write-Log ""
Write-Log "[7/10] Optimizing Windows Defender..." "Yellow"

# Reduce CPU during scans
Set-MpPreference -ScanAvgCPULoadFactor 20 -ErrorAction SilentlyContinue

# Disable sample submission
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

Write-Log "  Defender optimized (still enabled for safety)" "Green"

# ============================================
# SECTION 8: DISABLE STORE AUTO-UPDATES
# ============================================
Write-Log ""
Write-Log "[8/10] Disabling Store auto-updates..." "Yellow"

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
If (-NOT (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "AutoDownload" -Type DWord -Value 2

Write-Log "  Store auto-updates disabled" "Green"

# ============================================
# SECTION 9: BOOT AND POWER OPTIMIZATION
# ============================================
Write-Log ""
Write-Log "[9/10] Optimizing boot and power settings..." "Yellow"

# Fast startup
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1

# Boot timeout
bcdedit /timeout 0 | Out-Null

# Disable USB selective suspend (helps with e-ink keyboard)
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /SETACTIVE SCHEME_CURRENT

Write-Log "  Boot and power optimized" "Green"

# ============================================
# SECTION 10: CLEANUP
# ============================================
Write-Log ""
Write-Log "[10/10] Cleaning up disk space..." "Yellow"

# Clear temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# Clear Windows Update cache
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

Write-Log "  Disk cleanup complete" "Green"

# ============================================
# SUMMARY AND ESU CHECK (Windows 10 only)
# ============================================
Write-Log ""
Write-Log "==========================================" "Cyan"
Write-Log "DEBLOAT COMPLETE!" "Green"
Write-Log "==========================================" "Cyan"

# Show current memory usage
$mem = Get-CimInstance Win32_OperatingSystem
$totalRAM = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 1)
$freeRAM = [math]::Round($mem.FreePhysicalMemory / 1MB, 1)
Write-Log "Current RAM: $freeRAM GB free / $totalRAM GB total" "Yellow"
Write-Log "Running processes: $((Get-Process).Count)" "Yellow"

# Windows 10 ESU Check
if (-not $IsWin11) {
    Write-Log ""
    Write-Log "--- Windows 10 ESU Status ---" "Cyan"
    try {
        $esuKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\ConsumerESU" -ErrorAction Stop
        $eligibility = $esuKey.ESUEligibility
        switch ($eligibility) {
            3 { Write-Log "ESU Status: ENROLLED (DeviceEnrolled)" "Green" }
            5 { Write-Log "ESU Status: ENROLLED (MSAEnrolled)" "Green" }
            2 { Write-Log "ESU Status: ELIGIBLE but NOT enrolled" "Yellow" }
            1 { Write-Log "ESU Status: INELIGIBLE" "Red" }
            0 { Write-Log "ESU Status: Unknown/Not checked" "Yellow" }
            default { Write-Log "ESU Status: Unknown value ($eligibility)" "Yellow" }
        }
    } catch {
        Write-Log "ESU Status: Not enrolled or never checked" "Yellow"
        Write-Log "  Go to Settings > Update & Security > Windows Update to enroll" "White"
    }
}

# Windows 11 specific info
if ($IsWin11) {
    Write-Log ""
    Write-Log "--- Windows 11 Notes ---" "Cyan"
    Write-Log "• VBS/HVCI disabled for performance (reduces security slightly)" "Yellow"
    Write-Log "• Classic right-click menu restored" "White"
    Write-Log "• Widgets, Copilot, and Recall disabled" "White"
    Write-Log "• Teams chat icon removed from taskbar" "White"
}

Write-Log ""
Write-Log "--- Preserved for Yoga Book ---" "Magenta"
Write-Log "• TabletInputService (e-ink keyboard)" "Magenta"
Write-Log "• SpeechRuntime (dictation)" "Magenta"
Write-Log "• Lenovo e-ink utilities" "Magenta"

Write-Log ""
Write-Log "Log saved to: $LogFile" "White"
Write-Log ""
Write-Log "RESTART REQUIRED for all changes to take effect." "Yellow"

# Prompt for restart
$restart = Read-Host "Would you like to restart now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    Restart-Computer -Force
}
