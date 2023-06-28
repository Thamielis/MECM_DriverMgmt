
<# Gary Blok @gwblok @recastsoftware
Dell Driver Pack Download Script
Leverages the Dell Catalog Cab

Requires that CM Packages are setup in specific way with specific metadata.
I have another script on GitHub for onboarding models which will create the CM Package Placeholders for your Models... all of my other processes hinge off of that script.

Assumptions, you used that script and have Pre-Prod (For Testing) and Prod (For Production Deployments) Packages.

This will grab the required data from the Package and reach out to dell to see if an updated Driver Pack is available, if it is, it downloads and updates the Content and CM Package Info.


2021.09.17 - Updated for Creating WIM files 
 Folder Structure of Package
  - WIM
    - Online
      - Any Setup Based Driver installers
        - Driver Setup Contents
        - CustomInstall.cmd (This you make with the silent command for install)
    - Offline
      - Contains the Extract Dell Cab
  - Version.txt (This is the Version of the Cab File and contains extra information, this script creates that file)

 We then have other processes that Mount the WIM during OSD or IPU to be used, then unmounted again.  These will all be in the WaaS Download on GARYTOWN, scripts will be on github as well


#> 
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Stage")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Pre-Prod", "Prod")]
    $Stage
)

$Script:ScriptPath = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location -Path $Script:ScriptPath

$LogName = "Dell_Driver_PopulateCMPackages"
Import-Module .\logger.ps1 -Force
New-Log -LogName $LogName

$SiteCode = "KOW"

$TargetFolder = "\\atklsccm.kostweingroup.intern\sources$\" #"S:"

$CatalogPath = "$TargetFolder\Drivers\Packages\Windows Client\Catalog"
$DellCabDownloadsPath = "$CatalogPath\DellCabDownloads"
$DellCabExtractPath = "$CatalogPath\DellCabExtract"

$WimTempLocation = "C:\Temp\CM"

$CabPath = "$DellCabDownloadsPath\DriverCatalog.cab"

$DriverURL = "https://downloads.dell.com/catalog/DriverPackCatalog.cab"

$DriverPath = "$TargetFolder\Drivers\Dell"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 


function Get-FolderSize {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Path,
        [ValidateSet("KB", "MB", "GB")]
        $Units = "MB"
    )

    if ( (Test-Path $Path) -and (Get-Item $Path).PSIsContainer ) {
        $Measure = Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
        $Sum = $Measure.Sum / "1$Units"

        [PSCustomObject]@{
            "Path"         = $Path
            "Size($Units)" = $Sum
        }
    }
}

Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)
Set-Location -Path "$($SiteCode):"

if (!($Stage)) { 
    #$Stage = "Prod", "Pre-Prod" | Out-GridView -Title "Select the Stage you want to update" -PassThru
    $Stage = "Prod" | Out-GridView -Title "Select the Stage you want to update" -PassThru 
}

#To Select
$DellModelsSelectTable = Get-CMPackage -Fast -Name "Driver*" | Where-Object { $_.Manufacturer -eq "Dell" -and $_.Mifname -eq $Stage } | Select-Object -Property "Name", "MIFFilename", "PackageID", "Version" | Sort-Object $_.MIFFilename | Out-GridView -Title "Select the Models you want to Update" -PassThru
$DellModelsTable = Get-CMPackage -Fast -Name "Driver*" | Where-Object { $_.PackageID -in $DellModelsSelectTable.PackageID }

Set-Location -Path "C:"

if (!(Test-Path -Path $CabPath) -or $SkipDownload) {
    Out-Info -Message "Downloading Dell Cab" -fcolor Yellow
    
    Invoke-WebRequest -Uri $DriverURL -OutFile $CabPath -UseBasicParsing -Verbose #-Proxy $ProxyServer
    [int32]$n = 1
    
    While (!(Test-Path $CabPath) -and $n -lt '3') {
        Invoke-WebRequest -Uri $DriverURL -OutFile $CabPath -UseBasicParsing -Verbose #-Proxy $ProxyServer
        $n++
    }

    If (Test-Path "$PSScriptRoot\DellSDPCatalogPC.xml") { 
        Remove-Item -Path "$PSScriptRoot\DellSDPCatalogPC.xml" -Force -Verbose 
    }

    Start-Sleep -Seconds 1
    
    if (Test-Path $DellCabExtractPath) { 
        Remove-Item -Path $DellCabExtractPath -Force -Recurse 
    }
    
    New-Item -Path $DellCabExtractPath -ItemType Directory

    Out-Info "Expanding the Cab File..... takes FOREVER...." -fcolor Yellow
    
    Expand $CabPath "$DellCabExtractPath\DriverPackCatalog.xml" | Out-Null
}
else {
    Out-Info "Expanding the Cab File..... takes FOREVER...." -fcolor Yellow
    Expand $CabPath "$DellCabExtractPath\DriverPackCatalog.xml" | Out-Null
}

Out-Info "Loading Dell Catalog XML.... can take awhile" -fcolor Yellow

[xml]$XML = Get-Content "$DellCabExtractPath\DriverPackCatalog.xml" #-Verbose

$DriverPacks = $Xml.DriverPackManifest.DriverPackage | Where-Object -FilterScript { $_.SupportedOperatingSystems.OperatingSystem.osCode -match "Windows10" }
#$DriverPacks.SupportedSystems.Brand.Model.Name | Sort-Object
$DriverPacksModelSupport = $DriverPacks.SupportedSystems.Brand.Model.Name | Sort-Object

#Quick Check of the Supported Models
Out-Info "-------------------------------------------------------" -fcolor Cyan
Out-Info "Dell Model Support in this XML Check" -fcolor Yellow

foreach ($Model in $DellModelsTable) {
    Out-Info "------------------------" -fcolor DarkGray

    if ($DriverPacksModelSupport -contains $Model.MIFFilename) {
        Out-Ok "  Dell XML Supports: $($Model.MIFFilename)"

        $ModelDriverPackInfo = $DriverPacks | Where-Object -FilterScript { $_.SupportedSystems.Brand.Model.Name -eq $($Model.MIFFilename) } | Select-Object -first 1
        
        Out-Ok "  Name in XML: $($ModelDriverPackInfo.SupportedSystems.Brand.Model.Name) "
        Out-Ok "  Cab Available: $($ModelDriverPackInfo.name.Display.'#cdata-section')"
    }
    else {
        Out-Error "  Dell XML does NOT Contain $($Model.MIFFilename) - Might be Name inconsistency"
    }
}

Out-Info "-------------------------------------------------------" -fcolor Cyan

foreach ($Model in $DellModelsTable) { #{}
    Out-Info "----------------------------" -fcolor DarkGray
    Out-Ok "Starting to Process Model: $($Model.MifFileName)"
    
    #Get Info about Driver Package from XML
    $ModelDriverPackInfo = $DriverPacks | Where-Object -FilterScript { $_.SupportedSystems.Brand.Model.systemID -eq $($Model.Language) } | Select-Object -first 1
    
    $TargetVersion = "$($ModelDriverPackInfo.dellVersion)"
    $TargetLink = "https://downloads.dell.com/$($ModelDriverPackInfo.path)"
    
    $TargetFileName = ($ModelDriverPackInfo.name.Display.'#cdata-section').Trim()
    $ReleaseDate = Get-Date $ModelDriverPackInfo.dateTime -Format 'yyyy-MM-dd'
    $TargetInfo = $ModelDriverPackInfo.ImportantInfo.URL
    
    #if (($ModelDriverPackInfo.SupportedSystems.Brand.Model.systemID).count -gt 1){$DellSystemID = ($ModelDriverPackInfo.SupportedSystems.Brand.Model.systemID)[0]}
    #else{$DellSystemID = ($ModelDriverPackInfo.SupportedSystems.Brand.Model.systemID)}
    
    $TargetModelPath = "$($DriverPath)\$($Model.MIFFilename)"
    $TargetDriverCabPath = "$($TargetModelPath)\Driver Cab"
    $TargetExpandedFolder = "Windows10-$($TargetVersion)"
    $TargetExpandedPath = "$($TargetModelPath)\$($TargetExpandedFolder)"
    $TargetFilePathName = "$($TargetDriverCabPath)\$($TargetFileName)"

    $TempModelPath = "$WimTempLocation\$($Model.MIFFilename)"
    $TempExpandedPath = "$TempModelPath\$($TargetExpandedFolder)"

    if ((Test-Path -Path $TempExpandedPath) -eq $false) {
		New-Item -Path $TempExpandedPath -ItemType Directory -Force | Out-Null
	}
    
    $TempDirectory = "C:\Temp\CM\$($Model.MIFFilename)\Windows10-$($TargetVersion)"
	if ((Test-Path -Path $TempDirectory) -eq $false) {
		New-Item -Path $TempDirectory -ItemType Dir | Out-Null
	}
    
    #Determine if XML has newer Package than ConfigMgr Then Download
    if ($Model.Version -Lt $TargetVersion) {
        
        Out-Info " New Update Available: $TargetVersion, Previous: $($Model.Version)" -fcolor Yellow
        
        #Check for Previous Download and see if Current
        if ( Test-Path $TargetFilePathName ) {
            if (!(Test-Path $TempExpandedPath)) {

                if ($TargetFilePathName -match "exe") {
                    $ExpandDrivers = $True
                }
                else {
                    $ExpandDrivers = $False

                    Out-Info " Starting Expand Process for $($Model.MIFFilename) file $TargetFileName"
                    expand $TargetFilePathName -F:* $TempExpandedPath

                    Out-Ok " Completed Expand Process"
                    Out-Ok " Complete with $($Model.MIFFilename) Drivers"
                }
                
            }
            else {
                if ((Get-ChildItem -Path $TempExpandedPath -Force).Count -eq 0) {
                    if ($TargetFilePathName -match "exe") {
                        $ExpandDrivers = $True
                    }
                    else {
                        $ExpandDrivers = $False

                        Out-Info " Starting Expand Process for $($Model.MIFFilename) file $TargetFileName"
                        expand $TargetFilePathName -F:* $TempExpandedPath
    
                        Out-Ok " Completed Expand Process"
                        Out-Ok " Complete with $($Model.MIFFilename) Drivers"
                    }
                }
                else {
                    $ExpandDrivers = $False
                }
                
            }

            #Write-Output "Already Contains Latest Driver Expanded Folder"
        }
        else {
            Out-Info "  Starting Download with BITS: $TargetFilePathName" -fcolor Yellow

            if (!(Test-Path -Path $TargetDriverCabPath)) { 
                New-Item -Path $TargetDriverCabPath -ItemType Directory | Out-Null 
            }

            if (!(Test-Path -Path $TargetExpandedPath)) { 
                New-Item -Path $TargetExpandedPath -ItemType Directory | Out-Null 
            }

            if ($UseProxy -eq $true) { 
                Start-BitsTransfer -Source $TargetLink -Destination $TargetFilePathName -ProxyUsage Override -ProxyList $BitsProxyList -DisplayName $TargetFileName -Asynchronous 
            }
            else { 
                Start-BitsTransfer -Source $TargetLink -Destination $TargetFilePathName -DisplayName $TargetFileName -Asynchronous
                #TODO: Download auf lokales Gerät und dann auf NAS verschieben.
            }
            
            do {
                $DownloadAttempts++
                $GetTransfer = Get-BitsTransfer -Name $TargetFileName -ErrorAction SilentlyContinue | Select-Object -Last 1
                Resume-BitsTransfer -BitsJob $GetTransfer.JobID
            }
            while
                ((Test-Path "$TargetFilePathName") -ne $true -and $DownloadAttempts -lt 15)
            
            if (!(Test-Path "$TargetFilePathName")) {
                Out-Warning " Failed to download with BITS, trying with Invoke WebRequest"

                Invoke-WebRequest -Uri $TargetLink -OutFile $TargetFilePathName -UseBasicParsing -Verbose -HttpVersion 2.0 #-Proxy $ProxyServer
            }

            if (Test-Path -Path $TargetFilePathName) {
                if ($TargetFilePathName -match "exe") {
                    $ExpandDrivers = $True
                }
                else {
                    Out-Info " Starting Expand Process for $($Model.MIFFilename) file $TargetFileName"

                    $Expand = expand $TargetFilePathName -F:* $TempExpandedPath

                    Out-Ok " Completed Expand Process"
                    Out-Ok " Complete with $($Model.MIFFilename) Drivers"
                }
                
            }

        }

        if ($ExpandDrivers) {
            if ($TargetFilePathName -match "exe") {
                Out-Info " Extracting Drivers for $($Model.MIFFilename) - $($Model.Language)" -fcolor Yellow

                Set-Location $TargetDriverCabPath
                
                $ProcArgs = "/s /e=`"$TempExpandedPath`""
                $DriverProcess = Start-Process -FilePath $TargetFilePathName -ArgumentList $ProcArgs -NoNewWindow -Wait -PassThru

                While ((Get-Process).ID -eq $DriverProcess.ID) {
                    Out-Info " Waiting for extract process (Process ID: $($DriverProcess.ID)) to complete. Next check in 30 seconds" -fcolor Yellow
                    Start-Sleep -seconds 30
                }
            }
        }

        if ((Get-ChildItem -Path $TempExpandedPath -Force).Count -gt 0) {
            Out-Info " Generating WIM DriverPackage" -fcolor Yellow

            $DismArgs = "/Capture-Image /ImageFile:`"$TempModelPath\Drivers.wim`" /CaptureDir:`"$TempExpandedPath`" /Name:`"$($Model.MIFFilename) - $($Model.Language)`" /Compress:max"
            $DismProcess = Start-Process "dism.exe" -ArgumentList $DismArgs -NoNewWindow -Wait -PassThru #-RedirectStandardOutput "$TempModelPath\dism-$($Model.MIFFilename).log"

            if ($DismProcess.ExitCode -eq 1) {
                Out-Error " Error: Issues occrured during WIM compression progress. Review the DismAction log."

            } else {
                $DriverPackageDest = "$($Model.PkgSourcePath)\Drivers.wim"

                if ([boolean](Get-ChildItem -Path $TempModelPath -Filter "Drivers.wim")) {
                    Out-Ok " DriverPackage: Self-extracting WIM driver package created"
                    Out-Info " DriverPackage: Copying Drivers.wim to $($DriverPackageDest)" -fcolor Yellow
                    
                    Get-ChildItem -Path $TempModelPath -Filter "Drivers.wim" | Copy-Item -Destination "$DriverPackageDest" -Force
                    
                } else {
                    Out-Error " Error: Failed to locate Drivers.wim. Please review the DISM log file located in $DriverExtractDest"
                }
            }

            if ($DriverPackageDest) {
                $ReadmeContents = "Model: $($Model.Name) | Pack Version: $TargetVersion | CM PackageID: $($Model.PackageID)"
                $ReadmeContents | Out-File -FilePath "$($Model.PkgSourcePath)\$($TargetVersion).txt"
                
                Set-Location -Path "$($SiteCode):"
                Update-CMDistributionPoint -PackageId $Model.PackageID
                
                Set-Location -Path "C:"
                $FolderSize = (Get-FolderSize $TempExpandedPath)
                $FolderSize = [math]::Round($FolderSize.'Size(MB)') 
                
                Out-Ok " Finished Expand & WIM Process for $TempModelPath, size: $FolderSize"

                Remove-Item -Path $TempModelPath -Force -Recurse
                
                Out-Info " Confirming Package $($Model.Name) with updated Info" -fcolor Yellow

                Set-Location -Path "$($SiteCode):"
                Set-CMPackage -Id $Model.PackageID -Version $TargetVersion
                Set-CMPackage -Id $Model.PackageID -MifVersion $ReleaseDate
                Set-CMPackage -Id $Model.PackageID -Description $TargetInfo
                #Set-CMPackage -Id $Model.PackageID -Language $DellSystemID 
                Set-Location -Path "C:"
            }

        }
        
    }
    else { 
        Out-Ok " No Update Available: Current CM Version:$($Model.Version) | Dell Online version $TargetVersion"
    }
}

Set-Location -Path $Script:ScriptPath
