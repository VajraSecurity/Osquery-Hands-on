param(
  [switch] $help = $false,
  [switch] $windows_event_log = $false,
  [switch] $filesystem = $false,
  [switch] $uninstall = $false,
  [switch] $bits32 = $false,
  [switch] $offline = $false
)

# OS Details
$os = Get-WmiObject -Class Win32_OperatingSystem
$majorVersion = [int]($os.Version.Split('.')[0])
$architecture = [int]($os.OSArchitecture.Split('-')[0])
if ($architecture -eq "32")
{
	$bits32 = $true
}
# Globals
$scriptVersion = '1.0.0.0'
if ($bits32) {
	$osquerydDownloadUrl = 'https://github.com/VajraSecurity/vajra-client/raw/main/windows/x86/osqueryd.exe'
	$osqueryFlagsDownloadUrl = 'https://github.com/VajraSecurity/vajra-client/raw/main/windows/x86/osquery.flags'
	$vcredistDownloadUrl = 'https://github.com/VajraSecurity/vajra-client/raw/main/windows/x86/vc_redist.x86.exe'
	$boostDllDownloadUrl = 'https://github.com/VajraSecurity/vajra-client/raw/main/windows/x86/boost_context-vc140-mt-x32-1_66.dll'
}
else {
	$osquerydDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/osqueryd.exe'
	$osqueryFlagsDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/osquery.flags'
	$extnDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/plgx_win_extension.ext.exe'
}
$osqueryConfDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/osquery.conf'
$osqueryEnrollmentSecretDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/enrollment_secret.txt'
$osqueryCertDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/certs/cert.pem'
$osqueryManifestDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/osquery.man'
$extnLoadDownloadUrl = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/extensions.load'

# Globals for packs files
$osqueryPack1Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/hardware-monitoring.conf'
$osqueryPack2Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/incident-response.conf'
$osqueryPack3Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/it-compliance.conf'
$osqueryPack4Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/osquery-monitoring.conf'
$osqueryPack5Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/ossec-rootkit.conf'
$osqueryPack6Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/osx-attacks.conf'
$osqueryPack7Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/unwanted-chrome-extensions.conf'
$osqueryPack8Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/vuln-management.conf'
$osqueryPack9Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/windows-attacks.conf'
$osqueryPack10Url = 'https://github.com/VajraSecurity/Osquery-Hands-on/raw/main/Osquery/packs/windows-hardening.conf'


$ExtnFilename = 'plgx_win_extension.ext.exe'
if ($bits32) {
	if (-not (Test-Path -Path "$pwd\x86")) {
		# Folder does not exist, create it
		New-Item -ItemType "directory" -Path "$pwd\x86" | Out-Null
	}
	$OsquerydFilename = 'x86\osqueryd.exe'
}
if (!$bits32) {
	if (-not (Test-Path -Path "$pwd\x64")) {
		# Folder does not exist, create it
		New-Item -ItemType "directory" -Path "$pwd\x64" | Out-Null
	}
	$OsquerydFilename = 'x64\osqueryd.exe'
}
$OsqueryConfFilename = 'osquery.conf'
$OsqueryFlagsFilename = 'osquery.flags'
$OsqueryExtnLoadFilename = 'extensions.load'
$OsqueryCertFilename = 'cert.pem'
$OsqueryEnrollmentSecretFilename = 'enrollment_secret.txt'
$vcredistFileName = 'vc_redist.x86.exe'
$boostDllFileName = 'boost_context-vc140-mt-x32-1_66.dll'
$OsqueryManifestFilename = 'osquery.man'
$OsqueryPackFile1 = 'hardware-monitoring.conf'
$OsqueryPackFile2 = 'incident-response.conf'
$OsqueryPackFile3 = 'it-compliance.conf'
$OsqueryPackFile4 = 'osquery-monitoring.conf'
$OsqueryPackFile5 = 'ossec-rootkit.conf'
$OsqueryPackFile6 = 'osx-attacks.conf'
$OsqueryPackFile7 = 'unwanted-chrome-extensions.conf'
$OsqueryPackFile8 = 'vuln-management.conf'
$OsqueryPackFile9 = 'windows-attacks.conf'
$OsqueryPackFile10 = 'windows-hardening.conf'


# osquery service variables
$kServiceName = "osqueryd"
$kServiceDescription = "osquery daemon service"
$kServiceBinaryPath = (Join-Path "$Env:ProgramFiles\osquery\osqueryd\" "osqueryd.exe")
$welManifestPath = (Join-Path "$Env:ProgramFiles\osquery\" "osquery.man")
$startupArgs = ("--flagfile=`"$Env:ProgramFiles\osquery\osquery.flags`"")

function DownloadFileFromUrl {		
	param([string]$fileDownloadUrl, [string]$file)
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::TLS12
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

	$webclient = New-Object System.Net.WebClient
	if ($webclient.Length -eq 0) {
		Write-Host -ForegroundColor RED "[-] Webclient not inited. Exiting!!"
		Exit -1
	}

	$filepath = "$pwd\$file"

	try {
		Write-Host -ForegroundColor Yellow  "[+] Downloading file: [$fileDownloadUrl] to [$filepath]"
		$webclient.DownloadFile($fileDownloadUrl, $filepath)       
	}
	catch [Net.WebException] {
		Write-Host -ForegroundColor RED "[-] Aborting Extension Upgrade, Failed to download file from $fileDownloadUrl"
		Exit -1
	}

	Write-Host -ForegroundColor Yellow  "[+] Downloaded file successfully: $file to $pwd"
}

function DownloadFiles {
	DownloadFileFromUrl $osquerydDownloadUrl $OsquerydFilename
	DownloadFileFromUrl $osqueryConfDownloadUrl $OsqueryConfFilename
	DownloadFileFromUrl $osqueryFlagsDownloadUrl $OsqueryFlagsFilename
	DownloadFileFromUrl $osqueryCertDownloadUrl $OsqueryCertFilename
	DownloadFileFromUrl $osqueryEnrollmentSecretDownloadUrl $OsqueryEnrollmentSecretFilename
	if ($bits32) {
		DownloadFileFromUrl $vcredistDownloadUrl $vcredistFileName
		DownloadFileFromUrl $boostDllDownloadUrl $boostDllFileName
	}
	if (!$bits32) {
		DownloadFileFromUrl $extnDownloadUrl $ExtnFilename
		DownloadFileFromUrl $osqueryManifestDownloadUrl $OsqueryManifestFilename
		DownloadFileFromUrl $extnLoadDownloadUrl $OsqueryExtnLoadFilename
	}
	DownloadFileFromUrl $osqueryPack1Url $OsqueryPackFile1
	DownloadFileFromUrl $osqueryPack2Url $OsqueryPackFile2
	DownloadFileFromUrl $osqueryPack3Url $OsqueryPackFile3
	DownloadFileFromUrl $osqueryPack4Url $OsqueryPackFile4
	DownloadFileFromUrl $osqueryPack5Url $OsqueryPackFile5
	DownloadFileFromUrl $osqueryPack6Url $OsqueryPackFile6
	DownloadFileFromUrl $osqueryPack7Url $OsqueryPackFile7
	DownloadFileFromUrl $osqueryPack8Url $OsqueryPackFile8
	DownloadFileFromUrl $osqueryPack9Url $OsqueryPackFile9
	DownloadFileFromUrl $osqueryPack10Url $OsqueryPackFile10	
}

function StartOsqueryService {
	# install osquery service entry with manifest

	New-Service -BinaryPathName "$kServiceBinaryPath $startupArgs" `
				-Name $kServiceName `
				-DisplayName $kServiceName `
				-Description $kServiceDescription `
				-StartupType Automatic
	Write-Host "[+] Installed '$kServiceName' system service." -foregroundcolor Cyan
	
	if (!$bits32) {
		wevtutil im $welManifestPath
		if ($?) {
		Write-Host "[+] The Windows Event Log manifest has been successfully installed." -foregroundcolor Cyan
		} else {
		Write-Host "[-] Failed to install the Windows Event Log manifest." -foregroundcolor RED
		}
	}

    $ServiceObj = Get-Service -Name $kServiceName

    Write-Host -ForegroundColor YELLOW '[+] Starting Osqueryd Service'
    Start-Service -Name $kServiceName

    Start-Sleep(3)
    $ServiceObj.Refresh()
    Write-Host -ForegroundColor YELLOW '[+] Osqueryd Service Status: ' $ServiceObj.Status 
}

function CheckOsqueryService {

    #check osqueryd service
    $ServiceName = 'osqueryd'
    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($ServiceObj.Length -gt 0) {
        Write-Host -ForegroundColor Yellow '[+] Osqueryd Service Status: '  $ServiceObj.status
        Write-Host -ForegroundColor RED '[-] Osqueryd Service exists. Remove existing installation of osquery and try again. Script will abort the installation now!!'
        Exit -1
    } 
	else {
        Write-Host -ForegroundColor Cyan '[+] Osqueryd Service not found on the system: OK'
	}
}


function CheckEiqAgentService {
    #check EIQ agent service
    $ServiceName = 'plgx_agent'
    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($ServiceObj.Length -gt 0) {
        Write-Host -ForegroundColor Yellow '[+] EIQ agent Service Status: '  $ServiceObj.status
        Write-Host -ForegroundColor RED '[-] EIQ agent Service exists. Remove existing installation of EIQ agent and try again. Script will abort the installation now!!'
        Exit -1
    }
	else {
        Write-Host -ForegroundColor Cyan '[+] EIQ agent Service not found on the system: OK'
	}	
}

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}

function CopyFile {
    param([string]$src, [string]$dest)

    # Write-Host -ForegroundColor Yellow "[+] Copying $src to $dest."
    Copy-Item -Path "$src" -Destination "$dest" -Force
}

function CopyFilesToInstalldir {
	New-Item -Path "${Env:ProgramFiles}\osquery" -ItemType Directory
	New-Item -Path "${Env:ProgramFiles}\osquery\osqueryd" -ItemType Directory
	New-Item -Path "${Env:ProgramFiles}\osquery\packs" -ItemType Directory
	New-Item -Path "${Env:ProgramFiles}\osquery\log" -ItemType Directory
	New-Item -Path "${Env:ProgramFiles}\osquery\certs" -ItemType Directory

	CopyFile "$pwd\$OsquerydFilename" "${Env:ProgramFiles}\osquery\osqueryd\osqueryd.exe"
	CopyFile "$pwd\$OsqueryConfFilename" "${Env:ProgramFiles}\osquery\$OsqueryConfFilename"
	CopyFile "$pwd\$OsqueryCertFilename" "${Env:ProgramFiles}\osquery\certs\$OsqueryCertFilename"
	CopyFile "$pwd\$OsqueryEnrollmentSecretFilename" "${Env:ProgramFiles}\osquery\$OsqueryEnrollmentSecretFilename"
	if ($architecture -eq "64") {
		CopyFile "$pwd\x64\$OsqueryFlagsFilename" "${Env:ProgramFiles}\osquery\osquery.flags"
	}
	else{
		CopyFile "$pwd\x86\$OsqueryFlagsFilename" "${Env:ProgramFiles}\osquery\osquery.flags"
	}

	#check what logger option was chosen for install then copy flags file accordingly
	# if($windows_event_log){
	# 	CopyFile "$pwd\$OsqueryEvtloggerFlagsFilename" "${Env:ProgramFiles}\osquery\osquery.flags"
	# } elseif($filesystem) {
	# 	CopyFile "$pwd\$OsqueryFsloggerFlagsFilename" "${Env:ProgramFiles}\osquery\osquery.flags"
	# } else {
	# 	Write-Host -ForegroundColor RED '[-] We should not reach here. Script will abort the installation now!!'
    #     Exit -1
	# }	
	if (!$bits32) {
	CopyFile "$pwd\$ExtnFilename" "${Env:ProgramFiles}\osquery\$ExtnFilename"
	CopyFile "$pwd\$OsqueryManifestFilename" "${Env:ProgramFiles}\osquery\$OsqueryManifestFilename"	
	CopyFile "$pwd\$OsqueryExtnLoadFilename" "${Env:ProgramFiles}\osquery\$OsqueryExtnLoadFilename"	
	}
	CopyFile "$pwd\$OsqueryPackFile1" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile1"
	CopyFile "$pwd\$OsqueryPackFile2" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile2"
	CopyFile "$pwd\$OsqueryPackFile3" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile3"
	CopyFile "$pwd\$OsqueryPackFile4" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile4"
	CopyFile "$pwd\$OsqueryPackFile5" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile5"
	CopyFile "$pwd\$OsqueryPackFile6" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile6"
	CopyFile "$pwd\$OsqueryPackFile7" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile7"
	CopyFile "$pwd\$OsqueryPackFile8" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile8"
	CopyFile "$pwd\$OsqueryPackFile9" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile9"
	CopyFile "$pwd\$OsqueryPackFile10" "${Env:ProgramFiles}\osquery\packs\$OsqueryPackFile10"
}

function InstallVcRedistRuntime {
    if (Test-Path -Path $pwd\x86\$vcredistFileName) {
        $Cmd = "$pwd\x86\$vcredistFileName" 
		$arguments = "/install /passive /norestart"
        Write-Host $Cmd
        $Output = Start-Process -FilePath $Cmd -ArgumentList $arguments -Wait
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[-] Failed to install VC Redistributables, Please Install Manualy. More details: $Output" -ForegroundColor Red
        }
        else {
            Write-Host "[+] Successfully installed VC Redistributables" -ForegroundColor Green
        }
        Start-Sleep(5)
    }
    else {
        Write-Host "[-] Failed to find $vcredistFileName for installation, Please Check Manually that VC Redsitributables are installed"
    }
}

function Do-Help {
	$programName = (Get-Item $PSCommandPath ).Name
	Write-Host "Usage: $programName (-windows_event_log|-filesystem|-help|-uninstall)" -foregroundcolor Yellow
	Write-Host ""
	Write-Host "  Only one of the following options can be used. Using multiple will result in options being ignored."
	Write-Host "    -windows_event_log		Install the osqueryd service and extension with windows_event_log as the logger plugin"
	Write-Host "    -filesystem			Install the osqueryd service and extension with filesystem as the logger plugin"
	Write-Host ""
	Write-Host "    -help			Shows this help screen"
	Write-Host "    -uninstall			Removes the osquery, extension and other installed files"
	Write-Host ""
	Write-Host "  If no option is selected, by default the script will install osquery and extension with filesystem as logger plugin."
	Write-Host ""
  
	Exit 1
}

function CleanupDownloadedFiles {
	if ($bits32) {
		Remove-Item -Path "$pwd\x86" -Recurse -Force -ErrorAction SilentlyContinue
	}
	if (!$bits32) {
		Remove-Item -Path "$pwd\x64" -Recurse -Force -ErrorAction SilentlyContinue
	}
	# Remove-Item "$pwd\$OsquerydFilename"
	Remove-Item "$pwd\$OsqueryConfFilename"
	# Remove-Item "$pwd\$OsqueryEvtloggerFlagsFilename"
	Remove-Item "$pwd\$OsqueryFlagsFilename"

	Remove-Item "$pwd\$OsqueryCertFilename"	
	Remove-Item "$pwd\$OsqueryEnrollmentSecretFilename"	
	if ($bits32) {
		Remove-Item "$pwd\$boostDllFileName"
		Remove-Item "$pwd\$vcredistFileName"
	}
	if (!$bits32){
		Remove-Item "$pwd\$ExtnFilename"
		Remove-Item "$pwd\$OsqueryManifestFilename"	
		Remove-Item "$pwd\$OsqueryExtnLoadFilename"	
	}
	Remove-Item "$pwd\$OsqueryPackFile1"
	Remove-Item "$pwd\$OsqueryPackFile2"
	Remove-Item "$pwd\$OsqueryPackFile3"
	Remove-Item "$pwd\$OsqueryPackFile4"
	Remove-Item "$pwd\$OsqueryPackFile5"
	Remove-Item "$pwd\$OsqueryPackFile6"
	Remove-Item "$pwd\$OsqueryPackFile7"
	Remove-Item "$pwd\$OsqueryPackFile8"
	Remove-Item "$pwd\$OsqueryPackFile9"
	Remove-Item "$pwd\$OsqueryPackFile10"
}

function SetVariables {
	$ipPattern = "^(\d{1,3}\.){3}\d{1,3}$"
	$domainPattern = "^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)\.?)+$"
	$tls_hostname = Read-Host -Prompt "Enter your Server's domain name/IP:"

	# Check the input and prompt again if invalid
	while ([string]::IsNullOrEmpty($tls_hostname) -or ($tls_hostname -notmatch $ipPattern -and $tls_hostname -notmatch $domainPattern)) {
		Write-Host "Invalid input. Please enter a valid IP or domain."
		$tls_hostname = Read-Host -Prompt "Enter an IP or domain:"
	}

	$tls_hostname += ":1234"
	$flagsContent = Get-Content -Path $OsqueryFlagsFilename
	$newFlagsContent = $flagsContent -replace "--tls_hostname=.*", "--tls_hostname=$tls_hostname"
	$newFlagsContent | Set-Content -Path $OsqueryFlagsFilename
}


function CheckOsVersion {
	$os = Get-WmiObject -Class Win32_OperatingSystem
	$majorVersion = [int]($os.Version.Split('.')[0])
	$architecture = [int]($os.OSArchitecture.Split('-')[0])
}


function StopPlgxServices {
    # clean vast service
    $VastSvc = 'vast'
    $VastPath = "${Env:windir}\system32\drivers\vast.sys"    
    $ServiceObj = Get-Service -Name $VastSvc    
    
    if ($ServiceObj.Status -eq 'Running') {
        Stop-Service $VastSvc  -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow '[+] VAST Service Status: ' $ServiceObj.status
        Write-Host -ForegroundColor Yellow '[+] VAST Service Stop Initiated...Wait for service to stop'
        
        $WaitRetryCount = 0
    
        while ($ServiceObj.Status -ne 'Stopped' -and $WaitRetryCount -le 3) {
            Start-Sleep -Seconds 10
            $ServiceObj.Refresh()
            Write-Host -ForegroundColor Yellow '[+] VAST Service Status: ' $ServiceObj.status
            $WaitRetryCount += 1
            Write-Host -ForegroundColor Yellow  '[+] VAST Service Stop Wait Retry Count : ' $WaitRetryCount
        }    
    }
	
    Write-Host -ForegroundColor Yellow '[+] VAST Service is now Stopped or timed-out, cleanup vast.sys'
    Remove-Item -Path $VastPath -Force -ErrorAction SilentlyContinue
        
    # clean vastnw service
    $VastnwSvc = 'vastnw'
    $VastnwPath = "${Env:windir}\system32\drivers\vastnw.sys"
    $ServiceObj = Get-Service -Name $VastnwSvc  

    if ($ServiceObj.Status -eq 'Running') {
        Stop-Service $VastnwSvc  -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow '[+] VASTNW Service Status: ' $ServiceObj.status
        Write-Host -ForegroundColor Yellow '[+] VASTNW Service Stop Initiated...Wait for service to stop'
        
        $WaitRetryCount = 0
        while ($ServiceObj.Status -ne 'Stopped' -and $WaitRetryCount -le 3) {
            Start-Sleep -Seconds 10
            $ServiceObj.Refresh()
            Write-Host -ForegroundColor Yellow '[+] VASTNW Service Status: ' $ServiceObj.status
            $WaitRetryCount += 1
            Write-Host -ForegroundColor Yellow  '[+] VASTNW Service Stop Wait Retry Count '  $WaitRetryCount
        }    
    }
	
    Write-Host -ForegroundColor Yellow '[+] VASTNW service is now Stopped or timed-out, cleanup vastnw.sys'
    Remove-Item -Path $VastnwPath -Force -ErrorAction SilentlyContinue
}

function CleanupInstalledFiles {
	Remove-Item -Path "${Env:ProgramFiles}\osquery" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "${Env:ProgramFiles}\plgx_osquery" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Done cleaning up install folders" -foregroundcolor Yellow
}

function UninstallAgent {
	
	#stop and remove osquery service and manifest
	$osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$kServiceName'"

    if ($osquerydService) {
		Stop-Service $kServiceName
		Write-Host "[+] Found '$kServiceName', stopping the system service..."
		Start-Sleep -s 5
		Write-Host "[+] System service should be stopped."
      
	    # fetch osqueryd and extension process object to terminate forcefully if they survive
		$OsquerydProc = Get-Process osqueryd -ErrorAction SilentlyContinue
		$PlgxExtnProc = Get-Process plgx_win_extension.ext.exe -ErrorAction SilentlyContinue
    
		if ($ServiceObj.Status -ne 'Stopped' -Or $OsquerydProc -Or $PlgxExtnProc) {
			Write-Host -ForegroundColor Yellow '[+] Force kill osqueryd and extension process if still exist'

			if ($OsquerydProc) {
				Stop-Process -Name 'osqueryd' -Force -ErrorAction SilentlyContinue
			}

			if($PlgxExtnProc)
			{
				Stop-Process -Name 'plgx_win_extension.ext' -Force -ErrorAction SilentlyContinue
			}
		}   

		$osquerydService.Delete()
		Write-Host "[+] System service '$kServiceName' uninstalled." -foregroundcolor Cyan
      
		if ($architecture -eq "64") {
		if (-not (Test-Path $welManifestPath)) {
			Write-Host "[-] Failed to find the osquery Event Log manifest file! ($welManifestPath)" -ForegroundColor Red
		} else {
			wevtutil um $welManifestPath
			
			if ($?) {
				Write-Host "[+] The Windows Event Log manifest has been successfully uninstalled." -foregroundcolor Cyan
			} else {
				Write-Host "[-] Failed to uninstall the Windows Event Log manifest." -foregroundcolor Red
			}
		}
	}
    } else {
      Write-Host "'$kServiceName' is not an installed system service." -foregroundcolor Yellow
    }
	
	# stop and remove EIQ agent services
	if ($architecture -eq "64") {
		StopPlgxServices
	}
	
	#clean up all files and directories
	CleanupInstalledFiles
}

function Main {
    Write-Host -ForegroundColor YELLOW  "============ Vajra Helper Script (v$scriptVersion) to install osquery with extension. ============"

    Write-Host "[+] Verifying script is running with Admin privileges" -foregroundcolor Yellow
    if (-not (Test-IsAdmin)) {
        Write-Host "[-] ERROR: Please run this script with Admin privileges!" -foregroundcolor Red
        Exit -1
    }

	if ($help) {
		Do-Help
	} elseif ($uninstall) {
		UninstallAgent		
	} else {
		if ($windows_event_log.ToBool() -Eq 1) {
			Write-Host -ForegroundColor Yellow "[+] Proceeding with windows_event_log as logger plugin."
		} else {
			$filesystem = $true
			Write-Host -ForegroundColor Yellow "[+] Proceeding with filesystem as logger plugin."	
		}
		
		#verify osquery service doesnt exist
		CheckOsqueryService

		#verify EIQ agent service doesnt exist
		if (!$bits32) {
			CheckEiqAgentService
		}

		# Download all files
		if(!$offline){
			if ($majorVersion -ne 7) {
			DownloadFiles
			}
			else {
				Write-Host -ForegroundColor Red "[+] ERROR: Windows 7 does not support TLS V1.2. Please try offline installer."
				Write-Host -ForegroundColor Red "[+] Usage: ./vajrainstall.ps1 -offline"
				Exit -1
			}
		}
		
		# Set server domain or IP
		# SetVariables

		# Copy files to install location
		CopyFilesToInstalldir

		# Install VC Redistributables
		if ($bits32) {
		InstallVcRedistRuntime
		}
		# Start Osquery service
		StartOsqueryService
		
		# Cleanup downloaded files
		# CleanupDownloadedFiles
		
		# Completed
		Write-Host -ForegroundColor Yellow "========================================================================"
	}
}

$startTime = Get-Date
$null = Main
$endTime = Get-Date
Write-Host "[+] Operation took $(($endTime - $startTime).TotalSeconds) seconds."