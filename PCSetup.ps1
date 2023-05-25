$AdminPath = "C:\Admin\"
$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
$XamlUrl = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml"

# Check for Admin Rights
Write-Host "Checking for Administrative Privileges..."
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host "ERROR: Not running in elevated PowerShell" -ForegroundColor White -BackgroundColor Red
	Write-Host -NoNewline 'Press any key to exit...' -ForegroundColor White -BackgroundColor Red
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
	exit
}
Write-Host "Powershell is running with Administrative Privileges."

# Create Adminpath if does not exist
Write-Host "Checking for Admin folder..."
If (!(Test-Path $AdminPath)) {
	Write-Host "Admin folder not found. Creating."
	New-Item $AdminPath -ItemType Directory -Force
} Else {
	Write-Host "Admin folder found."
}

# Registers Powershell Gallery
Write-Host "Checking for PSGallery Registration..."
If ($null -eq (Get-PSRepository -Name "PSGallery")) {
	Write-Host "PSGallery is not registerred. Registering..."
	If (((Get-Host).Version).Major -gt 5) {
		Register-PSRepository -Default -InstallationPolicy Trusted
	} Else {
		Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
	}
}
If ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
	Write-Host "PSGallery is not trusted. Trusting..."
	Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
}

# Get Manufacturer
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer.Split(" ")[0]
Write-Host "Manufacturer is: $manufacturer"

# Checks if is Dell before running Dell-Specific commands
If ($manufacturer -like "*Dell*") {

	# Check for Dell BIOS Provider Module, install if does not exist
	Write-Host "Checking for Dell BIOS Provider..."
	If ($null -eq (Get-Module -ListAvailable -Name DellBIOSProvider)) {
		Install-Module -Name DellBIOSProvider -AcceptLicense 
	}
	Write-Host "Importing Dell BIOS Provider..."
	Import-Module DellBIOSProvider

	# Configure BIOS Power Settings
	$p = "DellSmbios:\PowerManagement\"
	$a = "AcPwrRcvry"
	$v = "Last"
	Write-Host "Setting BIOS Setting $a as $v"
	If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
		Set-Item -Path ($p + $a) $v
	}
	$a = "DeepSleepControl"
	$v = "Disabled"
	Write-Host "Setting BIOS Setting $a as $v"
	If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
		Set-Item -Path ($p + $a) $v
	}
	$a = "BlockSleep"
	$v = "Enabled"
	Write-Host "Setting BIOS Setting $a as $v"
	If ((Get-ChildItem $p).Attribute.Contains($a) -and !(Get-ChildItem ($p + $a)).CurrentValue.Equals($v)) {
		Set-Item -Path ($p + $a) $v
	}
}

# Set Serial Number as Computer Name
Write-Host "Renaming PC to Service Tag/Serial Number"
(Get-WmiObject Win32_ComputerSystem).Rename((wmic bios get serialnumber /format:csv | ConvertFrom-Csv).SerialNumber) | Out-Null
If((Get-WmiObject Win32_ComputerSystem).Name -eq (wmic bios get serialnumber /format:csv | ConvertFrom-Csv).SerialNumber) {
	Write-Host "Successfully set new PC Name."
}

# Set Power Settings
Write-Host "Adjusting Power Settings..."
$p = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
If ($p) {
	Write-Host "High Performance Profile is available. Setting..."
	powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{", "").Replace("}", "") 
}
powercfg /hibernate off

# Set Timezone
Write-Host "Setting and Synchronizing Time..."
Set-TimeZone -Id "Eastern Standard Time"
net start w32time
W32tm /resync /force

# Run Decrapinator to clear programs
# Invoke-WebRequest https://raw.githubusercontent.com/sthurston99/Decrapinator/main/Decrapinator.ps1 -OutFile ($AdminPath + "Decrapinator.ps1")
# &($AdminPath + "Decrapinator.ps1")

# Install Winget
Write-Host "Checking for dependencies..."
If(($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.7" -AllUsers)) -and ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.7" -AllUsers))) {
	Write-Host "Downloading Microsoft UI XAML..."
	Invoke-WebRequest -Uri $XamlUrl -OutFile ($AdminPath + "xaml.zip")
	Expand-Archive -LiteralPath ($AdminPath + "xaml.zip") -DestinationPath ($AdminPath + "xaml")
	Add-AppxPackage ($AdminPath + "xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx") -AllUsers
}
Write-Host "Downloading Package Manager..."
$WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
Invoke-WebRequest -Uri ($WingetUrl + "download/v" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($AdminPath + "winget.msixbundle")
Add-AppxPackage ($AdminPath + "winget.msixbundle")

# Install Winget Programs
Write-Host "Installing Software..."
& winget install Google.Chrome --accept-source-agreements --accept-package-agreements
& winget install Adobe.Acrobat.Reader.64-bit --accept-source-agreements --accept-package-agreements
& winget install Microsoft.Office --override "/configure https://raw.githubusercontent.com/sthurston99/dotfiles/main/.odt.xml" --accept-source-agreements --accept-package-agreements

# Run Dell Command Update
If ($manufacturer -like "*Dell*") {
	Write-Host "Running Dell Command Update..."
	& winget install Dell.CommandUpdate.Universal --accept-source-agreements --accept-package-agreements
	Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/scan -outputLog=$AdminPath`dcuscan.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow
	Start-Process ($Env:Programfiles + "\Dell\CommandUpdate\dcu-cli") -ArgumentList "/applyUpdates -forceUpdate=enable -outputLog=$AdminPath`dcu.log -updateType=bios,firmware,driver,application,others -updateSeverity=security,critical,recommended,optional -silent" -Wait -NoNewWindow
}

# Self Explanatory
# Restart-Computer