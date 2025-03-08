.NOTES
	===========================================================================
	 Created on:   	2024-07-12
	 Created by:   Salah cHOUHAIB
	 Filename:     	PCRepairPerfbooster.ps1
	===========================================================================
	.DESCRIPTION
		This script is designed to clean up un-needed cache, cookies and other temporary files from the computer then perform a bunch of repair commands. 
  The v2 version edits and disables some windows styling features from the settings to boost performance
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
