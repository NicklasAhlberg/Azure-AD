<#	
	.NOTES
	===========================================================================
	 Created on:   	2021-11-04 06:20
	 Created by:   	Nicklas Ahlberg
	 Organization: 	nicklasahlberg.se
	 Filename:     	Install-AAD-Connect.ps1
	 Version:		1.0.0.3
	===========================================================================
	.DESCRIPTION
		This script will make the installation of Azure AD Connect a breeze.
		Covered by this script:
		- Enable TLS1.2
		- Install RSAT AD Tools
		- Create a new ADDS connector account with a strong password
		- Install Azure AD Connect
		- Delegate permissions to the ADDS connector account
		- Create a KDS Root Key
		- Create a Group Managed Service Account (gMSA)
	.DISCLAIMER
	The script is provided "AS IS" with no warranties
#>


[CmdletBinding()]
Param (
	[Parameter(Mandatory = $false)]
	[string]$KDSRootKeyExists = $null
)


if (! $KDSRootKeyExists)
{
	
	# Make sure TLS1.2 is enabled
	Function Get-ADSyncToolsTls12RegValue
	{
		[CmdletBinding()]
		Param
		(
			# Registry Path
			[Parameter(Mandatory = $true,
					   Position = 0)]
			[string]$RegPath,
			# Registry Name
			[Parameter(Mandatory = $true,
					   Position = 1)]
			[string]$RegName
		)
		$regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
		$output = "" | select Path, Name, Value
		$output.Path = $RegPath
		$output.Name = $RegName
		
		If ($regItem -eq $null)
		{
			$output.Value = "Not Found"
		}
		Else
		{
			$output.Value = $regItem.$RegName
		}
		$output
	}
	
	$regSettings = @()
	$regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'
	
	$regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'
	
	$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'
	
	$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
	$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'
	
	$regSettings = $regSettings | Select-Object -ExpandProperty Value
	$expectedValues = '1', '1', '1', '1', '1', '0', '1', '0'
	
	Write-Host "Making sure TLS1.2 is enabled" -ForegroundColor Yellow
	$compare = Compare-Object $regSettings $expectedValues
	if ($compare)
	{
		If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'))
		{
			New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
		}
		New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		
		If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'))
		{
			New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
		}
		New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		
		If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'))
		{
			New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
		}
		New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
		
		If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'))
		{
			New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
		}
		New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
		New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
		
		Write-Host 'TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take affect.' -ForegroundColor Cyan
		$restartPrompt = Read-Host -Prompt "Do you want to restart the server now? [Y/N] Y is recommended. Remember to restart the server manually if you choose not to do it now."
		if ($restartPrompt -eq 'Y')
		{
			Read-Host -Prompt "Re-run this script to continue with the installation... Save any work and press ENTER to restart this server"
			Read-Host -Prompt "Another one just to be on the safe side ;) Re-run this script to continue with the installation... Save any work and press ENTER to restart this server"
			Restart-Computer
		}
	}
	
	else
	{
		Write-Host "TLS 1.2 is enabled" -ForegroundColor Green
		Write-Host " "
	}
	
	# Make sure Azure AD Connect is not already installed
	Write-Host "Making sure Azure AD Connect is not currently installed" -ForegroundColor Yellow
	if (Get-WmiObject Win32_Product | Where-Object { $_.Name -eq 'Microsoft Azure AD Connect' })
	{
		Write-Host "Azure AD Connect is installed" -ForegroundColor Yellow
		Write-Host "Please uninstall Azure AD Connect and try again" -ForegroundColor Yellow
		Write-Host "Don't forget to export your current settings, if needed" -ForegroundColor Yellow
		Break
	}
	
	else
	{
		Write-Host "Azure AD Connect is not installed...continuing" -ForegroundColor Green
		Write-Host " "
	}
	######################## Install RSAT on the Azure AD Connect Server if needed
	# Get RSAT AD Tools install state
	
	Write-Host "Making sure RSAT AD Tools is enabled" -ForegroundColor Yellow
	if (! (Get-WindowsFeature -Name "RSAT-AD-TOOLS" | Select-Object -ExpandProperty InstallState) -eq 'Installed')
	{
		$RSATMessage = 'RSAT ADDS Tools is needed to continue but was not found. Do you want to enable RSAT ADDS Tools? [Y/N]'
		$RSATresponse = Read-Host -Prompt $RSATMessage
		if ($RSATresponse -eq 'Y')
		{
			try
			{
				Write-Host "Installing RSAT ADDS Tools... Please wait..." -ForegroundColor Green
				Write-Host " "
				Install-WindowsFeature -Name "RSAT-AD-TOOLS"
				Write-Host "RSAT ADDS Tools was successfully enabled. Please restart this server manually and re-run the script" -ForegroundColor Green
			}
			catch
			{
				Write-Host "RSAT ADDS Tools installation failed" -ForegroundColor Red
				Write-Host "$_.Exception.Message" -ForegroundColor Red
				Break
			}
		}
	}
	
	else
	{
		Write-Host "RSAT AD Tools is enabled" -ForegroundColor Green
		Write-Host " "
	}
	
	############
	# Specify ADDS connector account
	Write-Host "Time to create the ADDS connector account. This account is used to read/write AD attributes" -ForegroundColor Yellow
	Write-Host "It is possible to use an existing ADDS connector account if you already have one" -ForegroundColor Yellow
	$ADDSConnectorAccountMessage = 'Do you already have an existing Azure AD Connect connector account? [Y/N]'
	$ADDSResponse = Read-Host -Prompt $ADDSConnectorAccountMessage
	
	# If an ADDS connector account already exists
	if ($ADDSResponse -eq 'Y')
	{
		do
		{
			try
			{
				$ADDSUserExist = $null
				$ADDSAccountSamID = Read-Host -Prompt "Please specify existing ADDS connector account SAMID"
				$ADDSUserExist = Get-ADUser $ADDSAccountSamID -ErrorAction Continue
				Write-Host "You have specified $ADDSUserExist as Azure AD Connect connector account" -ForegroundColor Yellow
			}
			catch
			{
				Write-Host "Specifying an Azure AD Connect connector account failed" -ForegroundColor Red
				Write-Host "$_.Exception.Message" -ForegroundColor Red
				Write-Host "Try again..."
			}
		}
		until ($ADDSUserExist)
	}
	
	# If a new ADDS connector account should be created
	if ($ADDSResponse -eq 'N')
	{
		try
		{
			# Create a strong password
			Add-Type -AssemblyName System.Web
			$specialChars = Get-Random -Minimum 3 -Maximum 12
			$StrongPassword = [System.Web.Security.Membership]::GeneratePassword(15, $specialChars)
			
			$ADDSAccountSamID = Read-Host -Prompt "Please specify new ADDS connector account SAMID ex: ADDS-Connector-Acc"
			New-ADUser `
					   -Name "Active Directory Connector Account" `
					   -GivenName "ADDS Connector" `
					   -Surname "Account" `
					   -SamAccountName "$ADDSAccountSamID" `
					   -AccountPassword (ConvertTo-SecureString -AsPlainText "$StrongPassword" -Force) `
					   -Description "This is the ADDS Connector Account used by Azure AD Connect" `
					   -Department "IT" `
					   -DisplayName "ADDS connector account used by Azure AD Connect to read and write attributes to AD" `
					   -Enabled $True `
					   -Verbose
			
			Write-Host "ADDS connector account: $ADDSAccountSamID successfully created" -ForegroundColor Green
			Write-Host " "
		}
		
		catch
		{
			Write-Host "Unable to create a new Azure AD Connect connector account" -ForegroundColor Red
			Write-Host "$_.Exception.Message" -ForegroundColor Red
			Break
		}
	}
	
	# Install Azure AD Connect
	Write-Host "Time to install Azure AD Connect. Note, this is just the installation and not the actual configuration" -ForegroundColor Yellow
	Read-Host -Prompt "You will now be asked to select AzureADConnect.msi. Please download the latest version and press ENTER to continue..."
	
	try
	{
		Add-Type -AssemblyName System.Windows.Forms
		$browser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
		$null = $browser.ShowDialog()
		cmd /c $browser.FileName /QN
	}
	
	catch
	{
		Write-Host "$_.Exception.Message" -ForegroundColor Red
		Break
	}
	# Delegate permissions to AADC connector account
	Write-Host "It is time to delegate AD permissions to the ADDS Connector Account" -ForegroundColor Yellow
	Read-Host -Prompt "You will now be asked to approve each permission delegation. Press ENTER to continue..."
	
	Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1"
	#$ADDSAccountSamID = Read-Host -Prompt "Please specify new ADDS connector account SAMID ex: AADC_SYNC"
	$rootDomain = (Get-ADForest).rootdomain
	$PermissionsArray = @(
		"Set-ADSyncPasswordHashSyncPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncBasicReadPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncMsDsConsistencyGuidPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncPasswordWritebackPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncUnifiedGroupWritebackPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncExchangeHybridPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
		"Set-ADSyncExchangeMailPublicFolderPermissions -ADConnectorAccountName $ADDSAccountSamID -ADConnectorAccountDomain $rootDomain -ErrorAction SilentlyContinue"
	)
	
	foreach ($command in $PermissionsArray)
	{
		Invoke-Expression $command
	}
	
	######################## Add KDS Root Key
	# Check if a root key already exists
	Write-Host "Checking if this domain already have an existing KDS Root Key" -ForegroundColor Yellow
	$KDSRootKeyExists = Get-KdsRootKey
	if (! $KDSRootKeyExists)
	{
		Write-Host "A KDS Root Key was not found, we need to create one" -ForegroundColor Yellow
		Write-Host "A KDS Root Key is required to create and use a Group Managed Service Account" -ForegroundColor Yellow
		Write-Host "Before we create the KDS Root Key we must determine wether this domain is using multiple or a single domain controller" -ForegroundColor Yellow
		
		$multipleDCs = Read-Host -Prompt 'Does this domain run multiple domain controllers? [Y/N]'
		
		if ($multipleDCs -eq 'Y') # If running multitple domain controllers
		{
			Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(10))
			Write-Host "We must wait 10h to allow for the new KDS Root Key to replicate between your domain controllers" -ForegroundColor Yellow
			Write-Host "Please wait 10h and re-run this script with the -KDSRootKeyExist $true parameter" -ForegroundColor Yellow
			Write-Host "Example: Install-AAD-Connect.ps1 -KDSRootKeyExist $true" -ForegroundColor Yellow
			Read-Host "Press ENTER to close. Remember to wait 10h before you continue ;)"
			Break
		}
		
		if ($multipleDCs -eq 'N') # If running a single domain controller
		{
			Write-Host "Creating a new KDS Root Key" -ForegroundColor Yellow
			Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
			$doNotWait10h = $true
		}
	}
}

Write-Host "Sleeping for 30 seconds before continuing... please wait" -ForegroundColor Yellow
sleep -Seconds '30'
$KDSRootKeyExists = Get-KdsRootKey


######################## Create gMSA
if ($KDSRootKeyExists)
{
	if (!$doNotWait10h) # Do not wait for 10h if a single DC is being used
	{
		Write-Host "An existing KDS Root Key was found" -ForegroundColor Yellow
		Write-Host "If running multiple domain controllers you did wait 10h, right? ;)" -ForegroundColor Yellow
		$10hConfirmation = Read-Host "Confirm that you waited 10h (if running multiple domain controllers) [Y/N]"
	}
	
	else
	{
		$10hConfirmation = 'y' # Do not wait for 10h if a single DC is being used
	}
	
	if ($10hConfirmation -eq 'Y')
	{
		Write-Host "An existing KDS Root Key was found. We are ready to create the Group Managed Service Account" -ForegroundColor Green
		Write-Host "The Group Managed Service Account is used to run the Azure AD Connect service and connect to an external database" -ForegroundColor Yellow
		#Read-Host "Press ENTER to create the Group Managed Service Account"
		
		Try
		{
			$rootDomain = (Get-ADForest).rootdomain
			$AADChostname = hostname
			$gMSAName = Read-Host "Please specify a Group Managed Service Account name. Example: GMSA-AADC"
			$DNShostName = "$gMSAName+DNS.$rootDomain"
			$Description = 'AAD Connect Group Managed Service Account'
			$PrincipalsAllowedToRetrieveManagedPassword = "$AADChostname$"
			
			### Create the Service Account
			New-ADServiceAccount $gMSAName -Enabled $true -DNSHostName $DNShostName -Description $Description -PrincipalsAllowedToRetrieveManagedPassword $PrincipalsAllowedToRetrieveManagedPassword -Passthru
			Write-Host "The Group Managed Service Account was successfully created!" -ForegroundColor Green
			Write-Host " "
			
			### Get gMSA to make sure the creation worked out as intended
			#Get-ADServiceAccount -Identity $gMSAName -Properties *
			
			### Install gMSA (run From the Azure AD Connect Server)
			Write-Host "Attempting to install the GMSA" -ForegroundColor Yellow
			Try
			{
				Install-ADServiceAccount -Identity $gMSAName
				Write-Host "Successfully installed the GMSA" -ForegroundColor Green
				Write-Host " "
			}
			
			catch
			{
				Write-Host "$_.Exception.Message" -ForegroundColor Red
				Break
			}
		}
		catch
		{
			Write-Host "$_.Exception.Message" -ForegroundColor Red
			Break
		}
		
		Write-Host "Success!" -ForegroundColor Green
		Write-Host "Following have been done!" -ForegroundColor Green
		Write-Host "TLS1.2 = Enabled, ADDS Connector account created and permissions have been delegated, Azure AD Connect has been installed, a KDS root key and a group managed service account has been created" -ForegroundColor Green
		Write-Host "We are now ready to configure Azure AD Connect. Remember to use the Group Managed Service Account: $gMSAName" -ForegroundColor Green
		Write-Host " "
		Write-Host " "		
		Read-Host "Press Enter to close"
		Break
	}
	else
	{
		Write-Host "OK, no worries. Please close and re-run the script by running: Install-AAD-Connect.ps1 -KDSRootKeyExist $true" -ForegroundColor Yellow
	}
}
