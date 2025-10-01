$Host.UI.RawUI.ForegroundColor = "DarkGreen"
$Host.UI.RawUI.BackgroundColor = "Black"

Write-Host "Installer Script"

# Firefox
$installFirefox = Read-Host "Do you want to install Firefox? (yes/no)"
if ($installFirefox -eq "yes") {
    Start-Job -ScriptBlock {
        $firefoxInstallerPath = "C:\CCDC\tools-Windows\FirefoxInstaller.exe"
        Write-Host "Installing Firefox..."
        Start-Process -FilePath $firefoxInstallerPath -ArgumentList "/quiet" -Wait
    }
}

# ClamAV
$installClamAV = Read-Host "Do you want to install ClamAV? (yes/no)"
if ($installClamAV -eq "yes") {
    Start-Job -ScriptBlock {
        $clamavInstallerPath = "C:\CCDC\tools-Windows\combined.msi"
        Write-Host "Installing ClamAV..."
        Start-Process -FilePath $clamavInstallerPath -ArgumentList "/quiet /norestart" -Wait
        # Configure ClamAV for regular scans
        Write-Host "Scheduling ClamAV scans..."
        $clamAVPath = "C:\Program Files\ClamAV\"
        # Copy the example configuration files and prepare them for use
        Copy-Item -Path "$clamAVPath\conf_examples\freshclam.conf.sample" -Destination "$clamAVPath\freshclam.conf"
        Copy-Item -Path "$clamAVPath\conf_examples\clamd.conf.sample" -Destination "$clamAVPath\clamd.conf"
        (Get-Content -Path "$clamAVPath\freshclam.conf") -replace '^Example', '' | Set-Content -Path "$clamAVPath\freshclam.conf"
        (Get-Content -Path "$clamAVPath\clamd.conf") -replace '^Example', '' | Set-Content -Path "$clamAVPath\clamd.conf"
        Set-Content -Path "$clamAVPath\clamd.conf" -Value 'LogFile "C:\Program Files\ClamAV\clamd.log"'
        # update the virus definitions
        Start-Process -FilePath "C:\Program Files\ClamAV\freshclam.exe"
        schtasks /create /sc minute /mo 15 /tn "ClamAV Scan" /tr "C:\Program Files\ClamAV\clamscan.exe -r C:\" /st 00:00
    }
}

# NPCAP (Required for Wireshark)
$installNpcap = Read-Host "Do you want to install NPCAP? (yes/no)"
if ($installNpcap -eq "yes") {
    Start-Job -ScriptBlock {
        $npcapInstallerPath = "C:\CCDC\tools-Windows\npcap-1.80.exe"
        Write-Host "Installing NPCAP..."
        Start-Process -FilePath $npcapInstallerPath -Wait
    }
}

# Wireshark
$installWireshark = Read-Host "Do you want to install Wireshark? (yes/no)"
if ($installWireshark -eq "yes") {
    Start-Job -ScriptBlock {
        $wiresharkIntallerPath = "C:\CCDC\tools-Windows\Wireshark-4.4.3-x64.exe"
        Write-Host "Installing Wireshark..."
        Start-Process -FilePath $wiresharkIntallerPath -ArgumentList "/S" -Wait
    }
}

# Sysinternals
$ccdcPath = "C:\CCDC"
$toolsPath = "$ccdcPath\tools-Windows"
$extractPath = "C:\Sysinternals"
$desktopPath = [System.Environment]::GetFolderPath('Desktop')

Write-Host "Ensuring extraction directory exists at $extractPath..."
New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

$sysinternalsTools = @(
    @{ Name = "Autoruns";        Exe = "Autoruns.exe"; Lnk = "Autoruns.lnk" },
    @{ Name = "ProcessExplorer"; Exe = "procexp.exe";  Lnk = "ProcExp.lnk" },
    @{ Name = "ProcessMonitor";  Exe = "Procmon.exe";  Lnk = "ProcMon.lnk" },
    @{ Name = "TCPView";         Exe = "tcpview.exe";  Lnk = "TCPView.lnk" }
)

$WScriptObj = New-Object -ComObject ("WScript.Shell")

foreach ($tool in $sysinternalsTools) {
    $zipFile = Join-Path -Path $toolsPath -ChildPath "$($tool.Name).zip"
    
    if (Test-Path $zipFile) {
        Write-Host "Processing $($tool.Name)..."
        Write-Host "  -> Extracting..."
        Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force #Using force to avoid printing conflicting file errors printing in the terminal
        Write-Host "  -> Creating shortcut on desktop..."
        $exeFile = Join-Path -Path $extractPath -ChildPath $tool.Exe
        $shortcutFile = Join-Path -Path $desktopPath -ChildPath $tool.Lnk
        
        $shortcut = $WScriptObj.CreateShortcut($shortcutFile)
        $shortcut.TargetPath = $exeFile
        $shortcut.Save()
    }
    else {
        Write-Warning "Could not find '$($tool.Name).zip' in $toolsPath. Please run the download script first. Skipping."
    }
}
Write-Host "Sysinternals setup is complete."

# Remove script from startup
$entryName = "MyStartupScript"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName

# Wait for all jobs to complete
Get-Job | Wait-Job

# Set execution policy back to Restricted
Write-Host "Setting execution policy back to Restricted..."
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Restricted -Force

# Set script to run on startup to update windows
$scriptPath = "C:\CCDC\tools-Windows\Win-Update.ps1"
$entryName = "Windows Update Script"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entryName -Value "powershell.exe -File `"$scriptPath`""

# Lockdown the CCDC folder after installs

try {
    $ccdcPath = "C:\CCDC"
    $acl = Get-Acl $ccdcPath
    $acl.SetAccessRuleProtection($true, $false)
    
    # Remove existing access rules
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    
    # Add full control for necessary system accounts
    $adminUser = [System.Security.Principal.NTAccount]"Administrator"
    $systemUser = [System.Security.Principal.NTAccount]"SYSTEM"
    $trustedInstaller = [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller"
    $currentUser = [System.Security.Principal.NTAccount]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminUser, "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemUser, "FullControl", "Allow")
    $trustedInstallerRule = New-Object System.Security.AccessControl.FileSystemAccessRule($trustedInstaller, "FullControl", "Allow")
    $currentUserRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
    
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($trustedInstallerRule)
    $acl.AddAccessRule($currentUserRule)
    
    # Apply the modified ACL to the CCDC folder
    Set-Acl -Path $ccdcPath -AclObject $acl
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "CCDC folder lockdown complete."
    Write-Host "--------------------------------------------------------------------------------"
} catch {
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "An error occurred while locking down the CCDC folder: $_"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
}

Write-Host "Restarting Computer"
Restart-Computer