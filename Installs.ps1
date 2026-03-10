$Host.UI.RawUI.ForegroundColor = "DarkGreen"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# add eventlook, https://www.binisoft.org/wfc

Write-Host "Installer Script"

# Download necessary tools
$tools = @(
    @{ Name = "Npcap Installer"; Url = "https://github.com/UWStout-CCDC/CCDC-scripts/raw/refs/heads/master/windows/CCDL-Resources/npcap-1.80.exe"; Path = "$toolsPath\npcap-1.80.exe" },
    @{ Name = "Eventlook Installer"; Url = "https://github.com/kmaki565/EventLook/releases/download/1.6.4.0/EventLook-bin-18e54c9.zip"; Path = "$toolsPath\EventLook-bin-18e54c9.zip" },
    @{ Name = "Firewall Control"; Url = "https://www.binisoft.org/download/wfc6setup.exe"; Path = "$toolsPath\wfc6setup.exe" }
)

foreach ($tool in $tools) {
    Write-Host "Downloading $($tool.Name)..."
    Start-BitsTransfer -Source $tool.Url -Destination $tool.Path
}
# Check if PSWindowsUpdate is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing..."
    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
}

# Winget installs
Write-Host "Installing tools via winget..."
winget install Mozilla.Firefox -e --silent
winget install WiresharkFoundation.Wireshark -e --silent
winget install Microsoft.Sysinternals.Suite -e --silent

Start-Job -ScriptBlock {
    $npcapInstallerPath = "C:\CCDC\npcap-1.80.exe"
    Write-Host "Installing NPCAP..."
    Start-Process -FilePath $npcapInstallerPath -Wait
}

