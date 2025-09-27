# Enable WSL
$wsl = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

if ($wsl.State -ne "Enabled") {
    Write-Host "Enabling WSL..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
}

# Install Ubuntu to WSL
Write-Host "Installing Ubuntu"
Start-BitsTransfer -Source https://wslstorestorage.blob.core.windows.net/wslblob/Ubuntu2404-240425.AppxBundle -Destination Ubuntu2404-240425.AppxBundle.appx
Rename-Item .\Ubuntu2404-240425.AppxBundle.appx .\Ubuntu2404.zip
Expand-Archive .\Ubuntu2404.zip .\Ubuntu2404
Add-AppxPackage .\Ubuntu2404\Ubuntu_2404.0.5.0_x64.appx