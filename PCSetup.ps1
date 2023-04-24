$AdminPath = "C:\Admin\"
$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"

# Check for Admin Rights
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
If(-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Not running in elevated PowerShell"
    Write-Host -NoNewLine 'Press any key to exit...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    exit
}

# Create Adminpath if does not exist
If (!(Test-Path $AdminPath)) {
    New-Item $AdminPath -ItemType Directory -Confirm
}

# Get Manufacturer
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer.Split(" ")[0]

# Registers Powershell Gallery
If ($null -eq (Get-PSRepository -Name "PSGallery")) {
    If (((Get-Host).Version).Major -gt 5) {
        Register-PSRepository -Default -InstallationPolicy Trusted
    } Else {
        Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
    }
}

# Checks if is Dell before running Dell-Specific commands
If ($manufacturer -eq "Dell") {

    # Check for Dell BIOS Provider Module, install if does not exist
    If ($null -eq (Get-Module -ListAvailable -Name DellBIOSProvider)) {
        Install-Module -Name DellBIOSProvider -AcceptLicense 
    }

    Import-Module DellBIOSProvider

    # Configure BIOS Power Settings
    $p = "DellSmbios:\PowerManagement\"
    $a = "AcPwrRcvry"
    $v = "Last"
    If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
        Set-Item -Path ($p + $a) $v
    }
    $a = "DeepSleepControl"
    $v = "Disabled"
    If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
        Set-Item -Path ($p + $a) $v
    }
    $a = "BlockSleep"
    $v = "Enabled"
    If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
        Set-Item -Path ($p + $a) $v
    }
}

# Set Serial Number as Computer Name
(Get-WmiObject Win32_ComputerSystem).Rename((wmic bios get serialnumber /format:csv | ConvertFrom-Csv).SerialNumber) | Out-Null

# Set Power Settings
$p = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
If ($p) { powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{", "").Replace("}", "") }
powercfg /hibernate off

# Set Timezone
Set-TimeZone -Id "Eastern Standard Time"
W32tm /resync /force

# Run Decrapinator to clear programs
# Invoke-WebRequest https://raw.githubusercontent.com/sthurston99/Decrapinator/main/Decrapinator.ps1 -OutFile ($AdminPath + "Decrapinator.ps1")
# &($AdminPath + "Decrapinator.ps1")

# Install Winget
$WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
Invoke-WebRequest -Uri ($WingetUrl + "download/v" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($AdminPath + "winget.msixbundle")
Add-AppxPackage ($AdminPath + "winget.msixbundle")

# Install Winget Programs
& winget install Google.Chrome --accept-source-agreements --accept-package-agreements | Out-Null
& winget install Adobe.Acrobat.Reader.64-bit --accept-source-agreements --accept-package-agreements | Out-Null
& winget install Microsoft.Office --override "/configure https://raw.githubusercontent.com/sthurston99/dotfiles/main/.odt.xml" --accept-source-agreements --accept-package-agreements | Out-Null

# Run Dell Command Update
If ($manufacturer -eq "Dell") {
    & winget install Dell.CommandUpdate.Universal --accept-source-agreements --accept-package-agreements | Out-Null
    Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/scan -outputLog=$AdminPath`dcuscan.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow
    Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/applyUpdates -forceUpdate=enable -outputLog=$AdminPath`dcu.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow
}

# Self Explanatory
Restart-Computer