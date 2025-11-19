# Import necessary modules
Import-Module -Name Microsoft.PowerShell.LocalAccounts
Import-Module -Name NetSecurity
Import-Module -Name BitsTransfer

$Host.UI.RawUI.ForegroundColor = "DarkGreen"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

Write-Host " _       ___           __                      ________                          "
Write-Host "| |     / (_)___  ____/ /___ _      _______   / ____/ /__  ____ _____  ___  _____"
Write-Host "| | /| / / / __ \/ __  / __ \ | /| / / ___/  / /   / / _ \/ __ `/ __ \/ _ \/ ___/"
Write-Host "| |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  )  / /___/ /  __/ /_/ / / / /  __/ /    "
Write-Host "|__/|__/_/_/ /_/\__,_/\____/|__/|__/____/   \____/_/\___/\__,_/_/ /_/\___/_/  "

$site = "UWStout-CCDC/windows"
Create-Item -Path "C:\CCDC" -ItemType Directory
Create-Item -Path "C:\CCDC\tools-Windows" -ItemType Directory

## Clear persistence and document it ##

# Registry persistence
$startupRegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run"
)

foreach ($path in $startupRegistryPaths) {
    Write-Host "Clearing startup items from $path"
    $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($items) {
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider") {
                $items >> "C:\CCDC\persistence-registry.txt"
                Remove-ItemProperty -Path $path -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
    }
}

# Start menu persistence
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    Write-Host "Clearing startup items from $folder"
    Get-ChildItem -Path $folder | ForEach-Object {
        $_.FullName >> "C:\CCDC\persistence-startup.txt"
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

# Clear scheduled tasks
Write-Host "Clearing scheduled tasks..."
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
    $_.TaskName >> "C:\CCDC\persistence-schtasks.txt"
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
}