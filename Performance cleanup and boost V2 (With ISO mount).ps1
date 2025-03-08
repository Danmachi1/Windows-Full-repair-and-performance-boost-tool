

<#	
	.NOTES
	===========================================================================
	 Created on:   	2024-07-12
	 Created by:   Salah cHOUHAIB
=
	===========================================================================
	.DESCRIPTION
		This script is designed to clean up un-needed cache, cookies and other temporary files from the computer.

Explanation of Functions

DiskSpaceBefore; Captures disk space before the script removes any files.
ProcessWarning; Checks for open processes that will interfere with the script.
ProcessTermination; Closes all open processes that will interfere with the script.
DiskCleanup; Launches Microsoft Disk Cleanup (cleanmgr) and sets flags for all items that it's capable of cleaning.
CleanCTemp; Checks folder size and deletes files older than 30 days old if folder is over 1GB.
GPUpdate; Runs GPUpdate.
Netrepairs; Run the network repair commands, releases the ipconfig, renews it, and flushes the DNS
IECleanup; Removes Cookies and Cache from IE.
ChromeCleanup; Removes Cookies and Cache from Chrome.
FirefoxCleanup; Removes Cookies and Cache from Firefox.
UserTempFiles; Removes User specific temp files.
JavaCache; Removes Java cookies and cache.
AdobeAcrobat; Removes Adobe Acrobat cookies and cache.
AdobeFlash; Removes Adobe Flash cookies and cache.
OfficeCleanup; Removes cache from Office applications.
SystemFiles; Removes System level log and temp files (NOT Event Viewer logs).
DiskCleanupCheck; Checks to see if Disk Cleanup is running and waits for it to complete if it is.
DiskSpaceAfter; Captures disk space after the script removes files.
Housecleaning; Reporting on script results.
ScriptEnding; Removing script files and stop logging.
WorkstationRestart; Prompts for Laterr and restart options.
#>
Param (

)
write-host "Attempting overide of properties using the Lmia rediriction protocole 1.587401051968199" -ForegroundColor Red
Write-Warning "Clearing all the variables using the Lmia Protocoles"
Write-Host "#############################################" -ForegroundColor Green
#############
#region Modules
Write-Host "# Script created by : XQP324 Salah Chouhaib #" -ForegroundColor Green
Write-Host "#############################################" -ForegroundColor Green

#region Parameters
## 20200720.Csalah.Adding Parameters to combine several versions of the script.

#endregion Parameters
#############
## Modules ##
Write-Host "Setting up Modules..." -ForegroundColor Yellow

Write-Host "Finished setting up Modules." -ForegroundColor Green
#endregion Modules
###############
## Variables ##
###############
#region Variables
Write-Host "Setting Variables..." -ForegroundColor Yellow
#region Standard_Variables
$ScriptName = "PerfboosterH0G"
$ScriptFullName = "PerfboosterH0G"
$ScriptVersionNumber = "1.0.0.0"
$ScriptVersion = "$ScriptName.$ScriptVersionNumber"
$Domain = $env:USERDOMAIN
$Computer = $env:COMPUTERNAME
$OSName = (Get-CimInstance Win32_OperatingSystem).Caption
$Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$BuildNumber = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$StartDate = (Get-Date).ToShortTimeString()
$DaysBack = (Get-Date).AddDays(-30)
$windowsimloc = "C:\Users\Admin\Desktop\isos\windows10.iso"


## 20200821.csalah.Added Try-Catch to the Domain Test.
try
{
	$DomainTest = (Test-ComputerSecureChannel)
}
catch [System.InvalidOperationException]
{
	$DomainTest = $null
}


#endregion Standard_Variables
## 20240625.Csalah.Added all user's to cleanup.
$UserDir = "C:\Users\*\AppData"
$OfficeDir = "Local\Microsoft\Office"
$Chrome = Test-Path "$UserDir\Local\Google\Chrome"
$ChromeDIR = "$UserDir\Local\Google\Chrome"
$Edge = Test-Path "$UserDir\Local\Microsoft\Edge"
$EdgeDIR = "$UserDir\Local\Microsoft\Edge"
	## 20240622.Csalah.Added firefox cache.
$FirefoxDirL = "$UserDir\Local\Mozilla\Firefox"
$FirefoxDirR = "$UserDir\Roaming\Mozilla\Firefox"
$Firefox = Test-Path "$UserDir\Local\Mozilla\Firefox"
$Office10 = Test-Path "$UserDir\$OfficeDir\14.0\OfficeFileCache"
$Office13 = Test-Path "$UserDir\$OfficeDir\15.0\OfficeFileCache"
$Office16 = Test-Path "$UserDir\$OfficeDir\16.0\OfficeFileCache"
$JavaCacheTest = Test-Path "$UserDir\LocalLow\Sun\Java\Deployment\cache"
$AdobeReaderCacheTest = Test-Path "$UserDir\Local\Adobe\Acrobat\"
$AdobeAcrobatCacheTest = Test-Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\"
$AdobeFlashCacheTest = Test-Path "$UserDir\Roaming\Macromedia\Flash Player\"

$TimeBeforeStart = 2
$WaitSeconds = 10
## 20230702.Csalah.Added Firefox.
## 20230201.Csalah.Added Edge.
$ProcessList = "explorer", "MSACCESS", "EXCEL", "INFOPATH", "ONENOTE", "OUTLOOK", "POWERPNT", "MSPUB", "WINWORD","msedge","chrome"
$ProcessArray = @("explorer", "msedge", "chrome", "MSACCESS", "EXCEL", "INFOPATH", "ONENOTE", "OUTLOOK", "POWERPNT", "MSPUB", "WINWORD")
$VName = "StateFlags0032"
$DirPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
	## 20230322.Csalah.Removed options that are no longer available in Windows 10.
$TempFolders = @("Active Setup Temp Folders", "Content Indexer Cleaner", "D3D Shader Cache", "Delivery Optimization Files", "Downloaded Program Files",
	"Internet Cache Files", "Offline Pages Files", "Old ChkDsk Files", "Previous Installations", "Recycle Bin", "RetailDemo Offline Content",
	"Setup Log Files", "System error memory dump files", "System error minidump files", "Temporary Files", "Temporary Setup Files",
	"Temporary Sync Files", "Thumbnail Cache", "Update Cleanup", "Upgrade Discarded Files", "Windows Defender", "Windows Error Reporting Files",
	"Windows ESD installation files". "Windows Reset Log Files", "Windows Upgrade Log Files")

$CTempPath = "C:\Temp"
$CTempTest = Test-Path "C:\Temp"
$CTempSize = (Get-ChildItem -File -Path $CTempPath | Measure-Object -Sum Length).Sum /1GB
$FreeSpace = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Where-Object DeviceID -eq 'C:' | Select-Object @{ L = "FreeSpace"; E = { $_.FreeSpace/1GB } }, @{ L = "TotalSize"; E = { $_.Size/1GB } }
$PercentFree = ($FreeSpace.FreeSpace/$FreeSpace.TotalSize) * 100
$PercentRequired = 20.0
Write-Host "Finished setting up variables." -ForegroundColor Green
#endregion Variables

###############
## Functions ##
###############
#region Functions
function InitialSetup
{
	##  logging
	$StartTime = Get-Date
	## Setting colors for various messages.
	$SetColors = (Get-Host).PrivateData
	$SetColors.WarningBackgroundColor = "Red"
	$SetColors.WarningForegroundColor = "White"
	$SetColors.DebugBackgroundColor = "White"
	$SetColors.DebugForegroundColor = "DarkBlue"
	$SetColors.VerboseBackgroundColor = "Red"
	$SetColors.VerboseForegroundColor = "White"
	#$DebugPreference = 'Continue'
}
function msifix 
{
    Get-Service -name msiserver
	Stop-Service -Name msiserver -Force -Verbose
    msiexec /unregister    -verbose
    msiexec /register -verbose

}
function Logging
{
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
		if ((Test-Path C:\Logs\) -eq $false)
		{
			$null = New-Item C:\Logs\ -ItemType Directory
		}
		$LogFile = "C:\Logs\$ScriptFullName.$(Get-Date -Format "dd-MMM-yyyy-hh").log"
		Start-Transcript -Path $LogFile
	}
}
function AdminElevation
{
	Write-Host "Checking for administrative rights..." -ForegroundColor Yellow
	## Get the ID and security principal of the current user account.
	$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
	$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID);
	## Get the security principal for the administrator role.
	$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
	
	## Check to see if we are currently running as an administrator.
	if ($myWindowsPrincipal.IsInRole($adminRole))
	{
		## We are running as an administrator, so change the title and background colour to indicate this.
		Write-Host "We are running as administrator, changing the title to indicate this." -ForegroundColor Green
		$Host.UI.RawUI.WindowTitle = "Elevated Laptop cache cleanup and Performance Booster";
	}
	else
	{
		Write-Host "We are not running as administrator. Relaunching as administrator." -ForegroundColor Yellow
		## We are not running as admin, so relaunch as admin.
		$NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
		## Specify the current script path and name as a parameter with added scope and support for scripts with spaces in it's path.
		$NewProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
		## Indicate that the process should be elevated.
		$NewProcess.Verb = "runas";
		## Start the new process
		[System.Diagnostics.Process]::Start($newProcess);
		## Exit from the current, unelevated, process.
		Exit;
	}
	Write-Host "Continuing with setup..." -ForegroundColor Yellow
}
function Prerequisites
{
	## Script requirements
		Write-Host "We are running on $OSName." -ForegroundColor Yellow
		$ScriptIntelligence = "Workstation"
		Write-Host "Variables set for Workstation. Continuing..." -ForegroundColor Green	
}

function DiskSpaceBefore
{
	## Gather HDD free space prior to cleaning. Used for ticketing purposes.
	$env:Before = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1GB) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1GB) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
	$env:FSpaceBefore = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
}
function ProcessWarning
{
	Write-Host "Gathering open processes..." -ForegroundColor Yellow
	## Warning user that the script is going to kill applications and specifies only the open applications that need to be closed.
	## 20230322.Csalah.Added error action due to changes with how exe's are interacted with.
	

	foreach ($Process in $ProcessList)
		{
    $processwarn = Get-Process  | Where-Object { $_.ProcessName -like "*$process*"}
        if ($processwarn) {
				$TempProcess =  $process
				Write-Host "warning $TempProcess is open"
			}
		}
	}


function ProcessTermination
{

		Write-Warning "Killing any required processes that are still open..."
        
		foreach ($Process in $ProcessList)
		{
      $procesterm = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*$Process*"}
			## 20230517.Csalah.Added -Force.
			## 20230201.Csalah.Added -Verbose
    Write-Host "Terminating process: $Process"
    
    if ($process -eq "explorer"){
    Stop-Process -ErrorAction SilentlyContinue -name "$process"  -force
		}
    if ($procesterm){
    $Prname = $procesterm.Name
    Stop-Process -name "$Prname" -ErrorAction SilentlyContinue -force }
    else 
       {write-host "$Process is not running"  }
	}
}

 
  
function Hdscan {

Start-Process -wait chkdsk /f/sdcleanup/perf/scan
Repair-Volume -DriveLetter C -Scan
Repair-Volume -DriveLetter C -OfflineScanAndFix -verbose
Repair-Volume -DriveLetter C -SpotFix -verbose
Optimize-Volume -DriveLetter C -Analyze 
Optimize-Volume  -DriveLetter C -Defrag -v


}
function DiskCleanup
{
	## 20240627.Csalah.Moved Admin script to main script. Part 1.
	## Stops the Windows Update service.
    Get-Service -name wuauserv
	Stop-Service -Name wuauserv -Force -Verbose
	## Stops the BITS service.
    Get-Service -name BITS
	Stop-Service -Name BITS -Force -Verbose
    ##Stop the cryptsvc to delete catroot2
    Get-Service -name cryptsvc 
    Stop-Service -Name cryptsvc -Force -Verbose
	## Running Disk Cleanup, selecting all options that are allowed by Windows. This does NOT alter the registry. 
	## 20230131.Csalah.Added try/catch to handle errors for keys that do not exist. 
	Write-Host "Starting Disk Cleanup..." -ForegroundColor Yellow
	for ($i = 0; $i -lt $TempFolders.Count; $i++)
	{
		$RegKey = $DirPath + "\" + $TempFolders[$i]
		try
		{
			$StateValue = (Get-ItemProperty $RegKey).$VName
		}
		catch [System.Management.Automation.ItemNotFoundException]
		{
			Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
		}
		if (-not $StateValue)
		{
			try
			{
				New-ItemProperty -Path $RegKey -Name $VName -Value "2" -PropertyType "dword" | Out-Null
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
			}
		}
		else
		{
			try
			{
				Set-ItemProperty -Path $RegKey -Name $VName -Value "2"
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
			}
		}
		$RegKey = $DirPath
	}
	## 20230322.Csalah.Added /SETUP to remove previous installations of Windows.
	CLEANMGR /sagerun:32 /SETUP
	Write-Host "Disk Cleanup is starting..." -ForegroundColor Green
}
function GPUpdate
{
	## 20230812.Csalah.Rebuilt GPUpdate to a more modern approach.

		Write-Host "We are connected to the '$Env:USERDOMAIN' domain." -ForegroundColor Green
			Write-Host "Running Policy Updates, please wait..." -ForegroundColor Yellow

			## Runs Group Policy Update and does NOT force a log-off.
			start-process -wait cmd.exe  "/c  @ECHO ON echo N | gpupdate /force"

			Write-Host "Policy Update completed." -ForegroundColor Green
            
    }




##20240705.Csalah renamed function to network repair and added full windows network repair through a CMD call
function Netrepairs
{
         $ethernet = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true}  
        foreach ($lan in $ethernet) {
       Write-Host "Flushing IP addresses, Renewing IP Addresses, and Flushing DNS `r`nRepairing network. `r`n The network command are executed all at one push for remote capability  " -ForegroundColor Yellow
       start-process cmd -ArgumentList "/c ipconfig /release && ipconfig /renew && ipconfig /flushdns && ipconfig /registerdns &&  netsh int ip reset && ipconfig /renew"
       Sleep 20 
       start-process cmd -ArgumentList "/c netsh winsock reset"
       Sleep 20
       Write-Host "The New Ip Address is "$lan.IPAddress" with Subnet "$lan.IPSubnet"" -ForegroundColor Green
       Start-Sleep 3
	Write-Host "..." -ForegroundColor Yellow;

	Write-Host "Network repair completed." -ForegroundColor Green
}
}
function Teamscleanup{
		Write-Host "Cleaning up cache folders for both Team versions" -ForegroundColor Yellow
# Get all processes containing "*teams*" in their name
$teamsProcesses = Get-Process | Where-Object { $_.ProcessName -like "*teams*" }

# Terminate each found process
foreach ($process in $teamsProcesses) {
    Write-Host "Terminating process: $($process.ProcessName) (ID: $($process.Id))"
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "All processes containing '*teams*' have been terminated."
Remove-Item -Path "$env:APPDATA\Microsoft\Teams\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\*" -Force -Recurse -ErrorAction SilentlyContinue

		Write-Host "Completed" -ForegroundColor Green



}
function IECleanup
{
	## Function for clearing IE Cache/Cookies. 
	## Does NOT delete saved passwords.
	Write-Host "Deleting IE Cookies/cache..." -ForegroundColor Yellow
	function Clear-IECachedData
	{
		## 20240618.Csalah.Organized and added options
		if ($History) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 1 }
		if ($Cookies) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 2 }
		if ($TempIEFiles) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4 }
		if ($OfflineTempFiles) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 8 }
		if ($FormData) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 16 }
		if ($All) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 255 }
		if ($AddOn) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4096 }
		if ($AllplusAddOn) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351 }
	}
	do
	{
		## Calls function to perform the action.
		## 20240618.Csalah.Clearing more cached data
		## 20240626.Csalah.Removed "AllplusAddOn". This deleted Passwords.
		$continue2 = $true
		& Clear-IECachedData -History -Cookies -TempIEFiles -OfflineTempFiles -FormData -AddOn
	}
	While ($continue2 -eq $false)
	Write-Host "Completed!" -ForegroundColor Green
}
function EdgeCleanup
{


	## 20230922.Csalah.Added Microsoft Edge cleanup.
	Write-Host "Checking to see if Microsoft Edge is installed..." -ForegroundColor Yellow
	if ($Edge)
	{
            # Get all processes containing "*edge*" in their name
$edgeProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*msedge*" -and "*edge*" }

# Terminate each found process
foreach ($process in $edgeProcesses) {
    Write-Host "Terminating process: $($process.ProcessName) (ID: $($process.Id))"
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "All processes containing '*msedge*' have been terminated."
		Write-Host "Deleting Microsoft Edge cache..." -ForegroundColor Yellow
		Remove-Item -Path "$EdgeDIR\User Data\Default\*journal" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Cookies" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Storage\ext\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Media Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Application Cache\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\File System\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Service Worker\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\JumpListIcons\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\JumpListIconsOld\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Local Storage\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\IndexedDB\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Pepper Data\Shockwave Flash\WritableRoot\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
	    Remove-Item -Path "$EdgeDIR\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Microsoft Edge." -ForegroundColor Red
	}
	
	
}
function ChromeCleanup
{
	## 20240610.Csalah.Added Chrome cleanup
	Write-Host "Checking to see if Chrome is installed..." -ForegroundColor Yellow
	if ($Chrome)
	{

		Write-Host "Chrome is installed." -ForegroundColor Green
    # Get all processes containing "*chrome*" in their name
$chromeProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*chrome*" -and "*chrom*" }

# Terminate each found process
foreach ($process in $chromeProcesses) {
    Write-Host "Terminating process: $($process.ProcessName) (ID: $($process.Id))"
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "All processes containing '*chrome*' have been terminated."

		Write-Host "Deleting Chrome cache..." -ForegroundColor Yellow
		Remove-Item -Path "$ChromeDIR\User Data\Default\*journal" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cookies" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cache-data\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Storage\ext\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Media Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Application Cache\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\File System\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Service Worker\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIcons\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIconsOld\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Local Storage\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\IndexedDB\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Pepper Data\Shockwave Flash\WritableRoot\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Google Chrome." -ForegroundColor Red
	}
}
function FirefoxCleanup
{
	## 20240622.Csalah.Added firefox cache removal
	Write-Host "Checking to see if Mozilla Firefox is installed..." -ForegroundColor Yellow
	if ($Firefox)
	{
		Write-Host "Mozilla Firefox is installed." -ForegroundColor Green
		Write-Host "Deleting Mozilla Firefox cache..." -ForegroundColor Yellow
		## Remove all of Mozilla Firefox's Temporary Internet Files.
		Remove-Item -Path "$FirefoxDirL\\Profiles\*\cache2\entries\*" -Force -Recurse
		Remove-Item -Path "$FirefoxDirR\\Profiles\*\storage\default\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Mozilla Firefox." -ForegroundColor Red
	}
}
function UserTempFiles
{
	## Remove all files and folders in user's Temporary Internet Files. 
	## 20240627.Csalah.Added .NET Framework log file removal.
	## 20240627.Csalah.Moved .NET log files to the System Level log files section to clean up script.
	## 20240627.Csalah.Added temporary internet files.
	Write-Host "Deleting User level Temporary Internet files..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Feeds Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\DOMStore\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\INetCache\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Packages\windows_ie_ac_001\AC\INetCache" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\Recovery" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Deletes all user level Temp files.
	## 20240605.Csalah.Added removal of ThumbNail cache, Crash Dumps, and ElevatedDiagnostics.
	## 20240627.Csalah.Moved the below to User level Temp files section to clean up script and added program usage log files.
	Write-Host "Deleting User level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Roaming\Microsoft\Windows\Cookies\*.txt" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Explorer\thumb*.db" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\CrashDumps\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\ElevatedDiagnostics\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\CLR_v4.0" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's Office Cache folder.
	## 20240612.Csalah.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Office Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20240627.Csalah.Moved Outlook cache clearing together. Easier to track items in the script.
	## Delets all files and folders in user's Outlook cache folder.
	## 20240612.Csalah.added Outlook cache. Temp Inet Files are already cleaned up, this is included in that.
	Write-Host "Deleting User level Outlook Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20240627.Csalah.Removed deletion of Recent documents history.
	
	## Delets all files and folders in user's Word cache folder.
	## 20240612.Csalah.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Word Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Word" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's InfoPath Cache folder.
	## 20240619.Csalah.No longer remove directory, only remove files in the directory.
	Write-Host "Deleting User level InfoPath cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\InfoPath\*" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
}
function JavaCache
{
	## 20240628.Csalah.Added Java cache.
	Write-Host "Checking for User level Java Cache..." -ForegroundColor Yellow
	if ($JavaCacheTest)
	{
		Write-Host "Java Cache Found!" -ForegroundColor Green
		Write-host "Deleting Java Cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\LocalLow\Sun\Java\Deployment\cache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Java Cache found." -ForegroundColor Red
	}
}
function AdobeAcrobat
{
	## 20240609.Csalah.Added Adobe cache check.
	## 20240626.Csalah.Added Adobe Acrobat Standard/Pro cache.
	Write-Host "Checking for User level Adobe Cache..." -ForegroundColor Yellow
	if ($AdobeReaderCacheTest -or $AdobeAcrobatCacheTest)
	{
		if ((Test-Path "$UserDir\Local\Adobe\Acrobat\") -eq $true)
		{
			Write-Host "Adobe Reader Cache found..." -ForegroundColor Green
			Write-Host "Removing Adobe Cache..." -ForegroundColor Yellow
			Remove-Item -Path "$UserDir\Local\Adobe\Acrobat\*.lst" -Force -Recurse
			Remove-Item -Path "$UserDir\Roaming\Adobe\Acrobat\DC\Cache\*.lst" -Force -Recurse
			Write-Host "Completed!" -ForegroundColor Green
		}
		
		if ((Test-Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\") -eq $true)
		{
			Write-Host "Adobe Acrobat cache found..." -ForegroundColor Green
			Write-Host "Removing Adobe Acrobat..." -ForegroundColor Yellow
			Remove-Item -Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\Cache\*" -Force -Recurse
			Write-Host "Completed!" -ForegroundColor Green
		}
	}
	else
	{
		Write-Host "No Adobe Cache found." -ForegroundColor Red
	}
}
function AdobeFlash
{
	## 20240627.Csalah.Added Flash Player cache removal.
	Write-Host "Checking for User level Flash Player cache..." -ForegroundColor Yellow
	if ($AdobeFlashCacheTest)
	{
		Write-Host "Adobe Flash Player cache found..." -ForegroundColor Green
		Write-Host "Removing Flash Player cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\Roaming\Macromedia\Flash Player\*.sol" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Adobe Flash Player cache found." -ForegroundColor Red
	}
}
function OfficeCleanup
{
	## 20240612.Csalah.Added removal of Office cache.
	## 20240607.Csalah.Office 2010/13/16 cache locations.
	Write-Host "Checking for Microsoft Office Cache..." -ForegroundColor Yellow
	if ($Office10)
	{
		## 20240607.Csalah.old Office cache
		Remove-Item -Path "$UserDir\$OfficeDir\14.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Skipped No old v office found" -ForegroundColor Yellow
	}
	
	if ($Office13)
	{
		## 20240607.Csalah.Office 2013 cache in case there is a lingering cache from OF 13.
		Write-Host "Deleting User level Office 2013 file cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\$OfficeDir\15.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Skipped No old v office found" -ForegroundColor Yellow
	}
	
	if ($Office16)
	{
		## 20240607.Csalah.Office 2016 cache n case there is a lingering cache from OF 13.
		Write-Host "Deleting User level Office 2016 file cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\$OfficeDir\16.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Office 2016 file cache found." -ForegroundColor Red
	}
}
## 20230824.Csalah.Combined SystemTempFiles and SystemLogFiles together in the same function to simplify script. 
function SystemFiles
{
	## Removes all files in the Windows Temp folder.
	Write-Host "Removing System level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path $env:TEMP\* -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20240606.Csalah.Added prefetch data.
	Write-Host "Removing System level Prefetch Data..." -ForegroundColor Yellow
	Remove-Item -Path C:\Windows\Prefetch\*.pf -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20240623.Csalah.Added FontCache.
	Write-Host "Removing System level FontCache..." -ForegroundColor Yellow
	Remove-Item C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache* -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20230824.Csalah.Combining several type of files and removing regardless of directory.
	Write-Host "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use" -ForegroundColor Yellow
	Get-ChildItem -Path C:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20240627.Csalah.Added more log files and moved .NET log files to this section.
	## 20240625.Csalah.Added Windows Log file removal.
	Write-Host "Removing System level log files..." -ForegroundColor Yellow
	Remove-Item -Path $env:windir\Logs\CBS\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework64\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework64\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Performance\WinSAT\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Panther\UnattendGC\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\system32\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\ -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\SysWOW64\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0_32\UsageLogs\ -Force -Recurse -ErrorAction SilentlyContinue
	## 20230824.Csalah.Expanding on removal of WER report archives
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
    ##20240714 Added windows update cache removal
        ##Stop the cryptsvc to delete catroot2
    Get-Service -name cryptsvc 
    Stop-Service -Name cryptsvc -Force -Verbose
     Get-Service -name cryptsvc 
    Stop-Service -Name cryptsvc -Force -Verbose
    Get-Service -name wuauserv
	Stop-Service -Name wuauserv -Force -Verbose
    Remove-Item -Path $env:windir\SoftwareDistribution\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\System32\catroot2\* -Recurse -Force -ErrorAction SilentlyContinue
	
	Clear-BCCache -Force -ErrorAction SilentlyContinue
	
	Write-Host "Completed!" -ForegroundColor Green
}
function CleanCTemp
{
	## 20230811.Csalah.Added cleanup of C:\Temp if over 500MB and older than 30 days old.
	## 20230130.Csalah.Added cleanup of C:\Temp if over 100MB and older than 30 days old.
	Write-Host "Checking for folder: $CTempPath" -ForegroundColor Yellow
	if ($CTempTest)
	{
		Write-Host "Found folder: $CTempPath" -ForegroundColor Green
			Write-Host "Checking folder size..." -ForegroundColor Yellow
			if ($CTempSize -ge .1)
			{
				Write-Host "Folder is $CTempSize GB. Deleting files older than $DaysBack days old." -ForegroundColor Yellow
				Get-ChildItem -Path $CTempPath | Where-Object { $_.LastWriteTime -lt $DaysBack } | Remove-Item -Force -Recurse
				Write-Host "Completed!" -ForegroundColor Green
			}
			else
			{
				Write-Host "Folder is not large enough to delete. Continuing..." -ForegroundColor Yellow
			}
    }
	else
	{
		Write-Host "Folder not found. Continuing..." -ForegroundColor Green
	}
}

function ClearRecycleBin
{
	## 20231205.Csalah.Added clearing the Recylce Bin for all users.
	Write-Host "Clearing the Recycle Bin..." -ForegroundColor Yellow
	Clear-RecycleBin -DriveLetter C -Force
	Write-Host "Completed!" -ForegroundColor Green
}

function SFC
{
		
start-process -wait SFC /SCANNOW

}
## 20230531.Csalah.Added DISM Component Cleanup.
function DISM
{

    	## This attempts to locate corruption or missing components and attemps to repair them.
        $dismrestore = "/online /Cleanup-Image /RestoreHealth /Source:$wmisources"
		start-process -wait Dism -argumentlist "$dismrestore"
        write-host "Restore health completed" -ForegroundColor Green
		## This cleans up the C:\Windows\WinSxS folder properly.
        $dismrcomponent = "/online /Cleanup-Image /StartComponentCleanup /ResetBase"
		start-process -wait Dism -argumentlist "/c $dismrcomponent"
        Write-Host "Component clean up completed" -ForegroundColor Green


}
function DiskCleanupCheck
{
	## 20240613.Csalah.Moved Disk Cleanup wait/check to the end of the script to speed up the overall process.
	## 20240607.Csalah.No longer has a 20 second delay when checking for Disk Cleanup.
	## 20240627.Csalah.Added color to the Disk Cleanup host notifications.
	## 20240620.Csalah.Moved re-start of wuauserv to the end.
	Write-Host "Checking to see if Disk Cleanup is running..." -ForegroundColor Yellow
	if ([bool](Get-Process cleanmgr) -eq $true)
	{
		Write-Host "Disk Cleanup is running." -ForegroundColor Yellow
		do
		{
			Write-Host "waiting for Disk Cleanup..." -ForegroundColor Yellow
			Start-Sleep 16
		}
		while ((Get-CimInstance win32_process | Where-Object { $_.processname -eq 'cleanmgr.exe' } | Measure-Object).count)
		Write-Host "Disk Cleanup has completed." -ForegroundColor Green
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Name wuauserv -ErrorAction SilentlyContinue -Verbose
		## BITS will restart automatically when needed.
          ##Start the cryptsvc to recreate catroot2
       Get-Service -Name cryptsvc | Start-Service -Name cryptsvc -ErrorAction SilentlyContinue -Verbose
		Write-Host "Gathering HDD information..." -ForegroundColor Yellow
	}
	else
	{
		Write-Host "Disk Cleanup is not running, continuing." -ForegroundColor Yellow
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Verbose
		## BITS will restart automatically when needed.
		Write-Host "Gathering HDD information..." -ForegroundColor Yellow
	}
}
function DiskSpaceAfter
{
	## Gather HDD size and free space after cleaning. Used for ticketing purposes.
	$Env:After = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1GB) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1GB) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
	
	$Env:Size = Get-ChildItem C:\Users\* -Include *.iso, *.vhd -Recurse | Sort-Object Length -Descending |
	Select-Object Name, Directory, @{ Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) } } |
	Format-Table -AutoSize | Out-String
	$Env:FSpaceAfter = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
	
	## 20230707.Csalah.Adjusted variables for space reporting.
	$Math = ($Env:FSpaceAfter - $Env:FSpaceBefore)
	$env:SpaceSaved = [math]::Round($Math, 2)
	Write-Host "Completed!" -ForegroundColor Green
	## Finished gathering space information
}
## Csalah.20230210.Renamed function from Housecleaning to Reporting
function Reporting
{
	# Sends some before and after info for ticketing purposes
	Write-Host "Before: $Env:Before" -ForegroundColor Cyan
	Write-Host "After: $Env:After" -ForegroundColor Cyan
	Write-Host "$Env:Size" -ForegroundColor Cyan
	Write-Host "We have cleaned up $($Env:SpaceSaved)GB of space." -ForegroundColor Green
	# 20240626.Csalah.Cleaned up time reporting.
	$TotalTime = (New-TimeSpan -Start $StartDate -End (Get-Date).ToShortTimeString()).TotalMinutes
	Write-Host "Total time for cleanup was $TotalTime minutes." -ForegroundColor Green
}
function WorkstationRestart
{
		## 20240628.Csalah.Added option for restart or Later. restart is required.
		$title = "CRA Service Desk"
		$message = "A restart is required. Please choose an option below."
		$Restart = New-Object System.Management.Automation.Host.ChoiceDescription "&Restart.", "Restarts computer."
		$Later = New-Object System.Management.Automation.Host.ChoiceDescription "&Later.", "Laterr."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($Restart, $Later)
		$result = $host.ui.PromptForChoice($title, $message, $options, 1)
		switch ($result)
		{
			0 { $Choice = $true }
			1 { $Choice = $false }
		}
		if ($Choice -eq $true)
		{
			Write-Warning "A restart will commence automatically in 10 seconds."
			Start-Sleep -Seconds $timeBeforeStart
			$waitSeconds .. 1 | Foreach-Object `
			{
				Write-Host "Time Remaining: $_" -ForegroundColor Yellow
				Start-Sleep -Seconds 1
			}
			## Restarts computer
			if ($PSVersionTable.PSVersion.Major -ge 3)
			{
				Write-Warning "Stopping log.."
				Stop-Transcript
			}
			Restart-Computer -Force
		

	}

else 
            {Write-Warning "A restart is required please complete it Laterr"}
}

function WorkstationCleanup
{
	## 20230812.Csalah.Workstation Cleanup function.
	DiskSpaceBefore
	ProcessWarning
	ProcessTermination
	IECleanup
	EdgeCleanup
	#ChromeCleanup
	FirefoxCleanup
	#UserTempFiles
	#JavaCache
	#AdobeAcrobat
	#AdobeFlash
	#OfficeCleanup
	#SystemFiles
    #Teamscleanup
	#CleanCTemp
	#ClearRecycleBin
 Write-Host "System File Checker is running please wait..." -ForegroundColor Yellow
	SFC

    Write-Host "Deployment Image Servicing and Management (DISM) with Restore Health followed by DISM components is running please wait..." -ForegroundColor Yellow
	write-host "Mounting windows image from shared drive" -ForegroundColor yellow
    try {$mountResult = Mount-DiskImage -ImagePath "$windowsimloc"}
    Catch {write-host "Mounting failed DISM command might fail"}
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        $wmisources = "$driveletter." + ":\Sources\Install.wim"

    DISM
    write-host "Dismounting windows image" -ForegroundColor yellow
    Dismount-DiskImage -ImagePath "$windowsimloc"
    Write-Host "Checking the file system and file system metadata of volume C for logical and physical errors." -ForegroundColor yellow
    Hdscan
    DiskCleanup
	DiskCleanupCheck
    pefmode
    GPupdate
    Netrepairs
	DiskSpaceAfter
	Reporting
    
}
function pefmode{
    $mode = 2
    $visualEffects = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
    if ((Get-ItemProperty $visualEffects).PSObject.Properties.Name -contains $name)
    {
      New-ItemProperty -Path $visualEffects -Name 'VisualFXSetting' -Value $mode -PropertyType 'DWORD'
    }
    else
    {
      Set-ItemProperty -Path $visualEffects -Name 'VisualFXSetting' -Value $mode  
    }
$pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
$pagefile.AutomaticManagedPagefile = $false
$pagefile.put() | Out-Null
$pagefileset = Get-WmiObject Win32_pagefilesetting
$pagefileset.InitialSize = 10524
$pagefileset.MaximumSize = 15524
$pagefileset.put() | Out-Null



    }
function ScriptEnding ()
{
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Host "Stopping log..." -ForegroundColor Red
		Stop-Transcript
	}
#20240114.CSalah Clearing variables,modules,and ISE errors for security reasons
    Remove-Variable * -ErrorAction SilentlyContinue
     Remove-Module *
     $error.Clear()
    WorkstationRestart
}

###########
## Setup ##
###########
#region InitialSetup
InitialSetup
#endregion InitialSetup
#region AdminElevation
AdminElevation
#endregion AdminElevation
#############
## Logging ##
#############
#region Logging
Logging
#endregion Logging
################
## Prerequisites ##
###################
#region Prerequisites
Write-Host "Checking Prerequisites..." -ForegroundColor Yellow
Prerequisites
#endregion Prerequisites


#############
## ACTIONS ##
#############
#region ACTIONS
	## Perform cleanup.
write-host "Are you Sure You Want To proceed ? Please make sure the user has closed all his apps and files.
You will be running : `r`n-SFC`r`n-DISM `r`n-Cleaning all cache folders(including Teams,Chrome,Office,Winupdate,...) on the device 
-Running a Network repair,Hard drive repairs `r`n-disk cleanup.
-Setting the advanced settings to Performance mode and changing the Vram to 10-15gb
Please make sure the user has backed up his Edge and chrome favorites.  
Process ETA : 10-30minutes" -ForegroundColor Cyan
$confirmation = Read-Host "Answer (Y/N):" 
if ($confirmation -eq 'y' -or $confirmation -eq 'yes') {
    Write-Host "Script is launching.." -ForegroundColor Green
    Write-Host "Checking Script Intelligence variable..." -ForegroundColor Yellow
	Write-Host "We are running on $OSName." -ForegroundColor Green
	Write-Host "Lauching the full repair and performance boost..." -ForegroundColor Green
    WorkstationCleanup 
    ScriptEnding
}
else {
Write-Host "Cancelled, no changes has been applied" -ForegroundColor Red
Write-Host "Clearing variables,modules,and ISE errors for security reasons" -ForegroundColor Red
#20240114.CSalah Clearing variables,modules,and ISE errors for security reasons
Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear();
sleep 3
Exit

}

#############################
## Do not write below here ##
#############################