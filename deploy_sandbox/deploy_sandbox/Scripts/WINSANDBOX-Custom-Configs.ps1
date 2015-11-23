<# This Script does the following:
- Disables IE ESC for Administrators.
- Sets WinRM Unencrypted Traffic to enabled.
- Enables .NET Framework 3.5 for SQL Install.
- Creates 'C:\Chef\trusted_certs' directory for the Chef Client.
- Downloads and Installs Notepad++.
- Imports the PFX Certificate reponsible for decrypting Hashed Credentials.
- Decrypts the File containing the Hashed Credentials.
- Join Host to Domain.
- File(s) are created in 'C:\Windows\Temp' stating whether the actions listed above were successful or not.
#>

<#
param (
	[Parameter(Mandatory=$true, Position=0, HelpMessage="Active Directory Domain Admin Username.")]
	[String]$ADUsername,

	[Parameter(Mandatory=$true, Position=1, HelpMessage="Active Directory Domain Admin Password.")]
	[String]$ADPassword,
	
	[Parameter(Mandatory=$true, Position=2, HelpMessage="The Domain Name, i.e. - contoso.corp, is required.")]
	[String]$ADDomain
)
#>

param (
	[Parameter(Mandatory=$true, Position=0, HelpMessage="The Name of the Text File Containing the Hash of the Encrypted Password is required.")]
	[String]$CredsTextFileName,

	[Parameter(Mandatory=$true, Position=1, HelpMessage="The Name of the Certificate used to Encrypt the Password is required.")]
	[String]$CredsCertFileName
)

# Disabling IE ESC for Administrators on Target Host. UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}".
$Disable_IE_ESC_Admins = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force

if ($Disable_IE_ESC_Admins.IsInstalled -eq 0)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_IE_ESC_For_Admins_Disabled_Sucessfully.txt").Close()
		Write-Verbose -Message "IE ESC For Administrators Disabled Successfully."
	}
	
if ($Disable_IE_ESC_Admins.IsInstalled -ne 0)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_IE_ESC_For_Admins_Disablement_Failed.txt").Close()
		Write-Verbose -Message "Failed to disabled IE ESC For Administrators."
	}

# Setting WinRM to allow Unencrypted traffic.
$AllowUnencrypted = winrm set winrm/config/service '@{AllowUnencrypted="true"}'

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_WinRM_Allow_Unencrypted_Enabled_Sucessfully.txt").Close()
		Write-Verbose -Message "WinRM set to Allow Unencrypted Traffic."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_WinRM_Allow_Unencrypted_Enablement_Failed.txt").Close()
		Write-Verbose -Message "Failed to set WinRM to Allow Unencrypted Traffic."
	}

#Enabling .NET Framework 3.5 for SQL Install.
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All | Out-Null

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_dotNET_Framework_35_Enabled_Sucessfully.txt").Close()
		Write-Verbose -Message ".NET 3.5 Enabled Successfully."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_dotNET_Framework_35_Enablement_Failed.txt").Close()
		Write-Verbose -Message "Failed to Enable .NET 3.5."
	}
	
# Creating 'C:\Chef\trusted_certs' directory for the Chef Client.
[System.IO.Directory]::CreateDirectory("C:\chef\trusted_certs") | Out-Null

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Chef_Client_Directories_Created_Sucessfully.txt").Close()
		Write-Verbose -Message "Created Chef Client Directories Successfully."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Chef_Client_Directories_Creation_Failed.txt").Close()
		Write-Verbose -Message "Failed to Create Chef Client Directories."
	}

# Download Notepad++.
$Notepad_WebClient = New-Object System.Net.WebClient
$Notepad_URI       = "https://notepad-plus-plus.org/repository/6.x/6.8.1/npp.6.8.1.Installer.exe"
$Notepad_File      = "C:\Windows\Temp\npp.6.8.1.Installer.exe"
$Notepad_WebClient.DownloadFile($Notepad_URI,$Notepad_File)

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_NotepadPlusPlus_Downloaded_Successfully.txt").Close()
		Write-Verbose -Message "Downloaded Notepad++ Successfully."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_NotepadPlusPlus_Download_Failed.txt").Close()
		Write-Verbose -Message "Failed to Download Notepad++."
	}

# Install Notepad++.
C:\Windows\Temp\npp.6.8.1.Installer.exe /S

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_NotepadPlusPlus_Installed_Successfully.txt").Close()
		Write-Verbose -Message "Installed Notepad++ Successfully."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_NotepadPlusPlus_Install_Failed.txt").Close()
		Write-Verbose -Message "Failed to Install Notepad++."
	}

# Retrieving Path on Azure Windows VM on 'C:\' where the Text File Containing the Encrypted Hash of the original password is located.
$CredsTextFile = ForEach-Object {Get-ChildItem ($_.DeviceID + "\Packages") -include $CredsTextFileName -recurse}

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Located_Secured_Creds_Text_File_Successfully.txt").Close()
		Write-Verbose -Message "Located Secured Creds Text File."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Failed_To_Locate_Secured_Creds_Text_File.txt").Close()
		Write-Verbose -Message "Failed to locate Secured Creds Text File."
	}

# Retrieving Path on Azure Windows VM on 'C:\' where the Certificate used to Encrypt the password is located.
$CredsCertFile = ForEach-Object {Get-ChildItem ($_.DeviceID + "\Packages") -include $CredsCertFileName -recurse}

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Located_Secured_Creds_Certificate_Successfully.txt").Close()
		Write-Verbose -Message "Located Secured Creds Certificate."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Failed_To_Locate_Secured_Creds_Certificate.txt").Close()
		Write-Verbose -Message "Failed to locate Secured Creds Certificate."
	}

# Importing the PFX Certificate File into the Local Machine Personal Certificate Store.
Import-PfxCertificate -FilePath $CredsCertFile.FullName -CertStoreLocation Cert:\localMachine\My | Out-Null

If ($?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Certificate_Added_To_LocalMachine_Personal_Store_Successfully.txt").Close()
		Write-Verbose -Message "Imported Certificate Successfully to LocalMachine Personal Store."
	}
If (!$?)
	{
		[System.IO.File]::Create("C:\Windows\Temp\_Failed_To_Add_Certificate_To_LocalMachine_Personal_Store.txt").Close()
		Write-Verbose -Message "Failed to Import Certificate into LocalMachine Personal Store."
	}

# Decrypting the Hash File using the Private Key of the PFX Certificate.
$Cert              = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=Azure Secured Credentials"}
$EncryptedPwd      = Get-Content $CredsTextFile.FullName
$EncryptedBytes    = [Convert]::FromBase64String($EncryptedPwd)
$DecryptedBytes    = $Cert.PrivateKey.Decrypt($EncryptedBytes,$true)
$DecryptedPassword = [Text.Encoding]::UTF8.GetString($DecryptedBytes)

Write-Verbose -Message "Decrypted Secured Password Successfully: $($DecryptedPassword)"

<#
# Adding the Host to the Domain
$DomainUsername = $ADDomain + "\" + $ADUsername
$DomainPassword = $DecryptedPassword | ConvertTo-SecureString -asPlainText -Force
$Creds          = New-Object System.Management.Automation.PSCredential($DomainUsername,$DomainPassword)
Add-Computer -DomainName $ADDomain -Credential $Creds -Force -Restart -PassThru
#>