$AdminPath = "C:\Admin\"
$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"

# Registers Powershell Gallery
If ($null -eq (Get-PSRepository -Name "PSGallery")) {
    If (((Get-Host).Version).Major -gt 5) {
        Register-PSRepository -Default -InstallationPolicy Trusted
    } Else {
        Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
    }
}

# Check for Dell BIOS Provider Module, install if does not exist
If ($null -eq (Get-Module -ListAvailable -Name DellBIOSProvider)) {
    Install-Module -Name DellBIOSProvider -AcceptLicense 
}

Import-Module DellBIOSProvider

# Configure BIOS Power Settings
Set-Item -Path DellSmbios:\PowerManagement\AcPwrRecovery Last
Set-Item -Path DellSmbios:\PowerManagement\DeepSleepCtrl Disabled
Set-Item -Path DellSmbios:\PowerManagement\BlockSleep Enabled

# Set Serial Number as Computer Name
(Get-WmiObject Win32_ComputerSystem).Rename((wmic bios get serialnumber /format:csv | ConvertFrom-Csv).SerialNumber)

# Set Power Settings
$p = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{", "").Replace("}", "")
powercfg /hibernate off

# Set Timezone
Set-TimeZone -Id "Eastern Standard Time"

# Run Decrapinator to clear programs
Invoke-WebRequest https://raw.githubusercontent.com/sthurston99/Decrapinator/main/Decrapinator.ps1 -OutFile ($AdminPath + "Decrapinator.ps1")
&($AdminPath + "Decrapinator.ps1")

# Install Winget
$WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
Invoke-WebRequest -Uri ($WingetUrl + "download/" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($AdminPath + "winget.msixbundle")
Add-AppxPackage ($AdminPath + "winget.msixbundle")

# Install Winget Programs
& winget install Google.Chrome
& winget install Adobe.Acrobat.Reader.64-bit
& winget install Microsoft.Office --override "/configure https://raw.githubusercontent.com/sthurston99/dotfiles/main/.odt.xml"

# Run Dell Command Update
Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/scan -outputLog=$AdminPath`dcuscan.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow
Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/applyUpdates -forceUpdate=enable -outputLog=$AdminPath`dcu.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow

# Self Explanatory
Restart-Computer