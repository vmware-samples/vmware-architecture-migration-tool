<#
    .NOTES
    ===========================================================================
     Created by:    Austin Browder
     Date:          August 24, 2022
     Organization:  VMware Professional Services
    ===========================================================================
    .SYNOPSIS
        The VMware Architecture Migration Tool is designed to provide an easy and automated process to
        migrate machines between clusters of different architecture types within the same or co-located vCenters.
    .DESCRIPTION
        Script that performs cold migration on VMs between two compute environments during a specified change window.
    .EXAMPLE
        $options = @{
            action = "migrate"
            inputFilePath = "c:\temp\servers.csv"
            changeWindowStart = "6/9/2022 9:16:58"
            changeWindowDuration = 180
            parallelTaskCount = 5
            syslogHost = "192.168.1.14:514"
            toEmail = "teamemail@corp.com"
            fromEmail = "migrations@corp.com"
            debugLogging = $true
        }
        .\VMwareArchitectureMigrationTool.ps1 @options
#>

#############################################################################################################################
#
#region inputs
#
#############################################################################################################################

[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('migrate','rollback','cleanup')]
    [String]$action,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String]$inputFilePath,

    [Parameter(Mandatory)] <# List of vCenter Hostnames or IPs#>
    [ValidateNotNullOrEmpty()]
    [String[]]$vCenters,

    [Parameter()] <# Optional: If not set, the user will be prompted for a credential and that credential will be stored (encrypted) on the filesystem.
                    Note: This is an ordered list that will correspond to the vCenters intput. You can pass 1 credential for all vCenters, or 1 credential per vCenter.#>
    [ValidateNotNullOrEmpty()]
    [PSCredential[]]$vcCredentials,

    [Parameter()] <# "6/9/2022 9:16:58" #>
    [ValidateNotNullOrEmpty()]
    [String]$changeWindowStart,

    [Parameter()] <# minutes: default (0) is unlimited #>
    [Int]$changeWindowDuration = 0,

    [Parameter()] <# number of concurrent tasks to execute #>
    [Int]$parallelTaskCount = 10,

    [Parameter()] <# number of retries that should be attempted if the VM has active vCenter Tasks preventing the migration #>
    [Int]$jobRetries = 5,

    [Parameter()] <# Amount of time in seconds to wait when shutting down a guest os before we time out #>
    [Int]$osShutdownTimeout = 600,

    [Parameter()] <# Amount of time in seconds to wait for VMtools to start when powering on a VM post migration #>
    [Int]$osPowerOnTimeout = 900,

    [Parameter()] <# Amount of time in seconds between job status refreshes #>
    [Int]$statusRefreshInterval = 15,

    [Parameter()] <# ip/fqdn:port - port optional #>
    [ValidateNotNullOrEmpty()]
    [String]$syslogHost,

    [Parameter(Mandatory,ParameterSetName='Email')] <# Optional: ip/fqdn:port - port optional #>
    [ValidateNotNullOrEmpty()]
    [String]$smtpServer,

    [Parameter(Mandatory,ParameterSetName='Email')] <# Required if smtpServer is specified #>
    [ValidateNotNullOrEmpty()]
    [String[]]$toEmail,

    [Parameter(Mandatory,ParameterSetName='Email')] <# Required if smtpServer is specified #>
    [ValidateNotNullOrEmpty()]
    [String]$fromEmail,

    [Parameter(ParameterSetName='Email')] <# Optional #>
    [ValidateNotNullOrEmpty()]
    [PSCredential]$secureMailCred,

    [Parameter(ParameterSetName='Email')] <# Optional #>
    [Switch]$useMailCred,

    [Parameter()] <# do not validate that VMTools is running before starting and do not wait when finished #>
    [Switch]$ignoreVmTools,

    [Parameter()] <#CAUTION: this switch skips validation of the tag states on VMs before executing an action #>
    [Switch]$ignoreTags,

    [Parameter()] <# force poweroff if initial clean shutdown times out #>
    [Switch]$forcePowerOff,

    [Parameter()] <# poweron the VM if rollback occurs #>
    [Switch]$powerOnIfRollback,

    [Parameter(ParameterSetName='Email')] <# Optional #>
    [Switch]$smtpUseSsl,

    [Parameter()]
    [Switch]$debugLogging,

    [Parameter()] <# whatif will establish a connection to the provided vCenter and go through the logic for each machine without actually moving it #>
    [Switch]$WhatIf
)
#endregion
#############################################################################################################################

#############################################################################################################################
#
#region Script Variables
#
#############################################################################################################################

#Validate vCenters input
if ($vCenters.count -ne $($vCenters.toLower() | Select-Object -Unique).count) {
    throw "Duplicate vCenters found in 'vCenters' inputs."
}

#Validate vC Credentials and create cred Hash Table
if (($null -eq $vcCredentials) -or ($vcCredentials.count -eq 1) -or ($vcCredentials.count -eq $vCenters.count)) {
    $vcCredentialTable = @{}
    if ($null -ne $vcCredentials) {
        $index = 0
        foreach ($vCenter in $vCenters) {
            if ($vcCredentials.count -eq 1) {
                $vcCredentialTable.Add($vCenter,$vcCredentials[0])
            } else {
                $vcCredentialTable.Add($vCenter,$vcCredentials[$index])
            }
            $index++
        }
    }
} else {
    throw "Failed vCenter Credential validation. You must either pass 1 credential for all vCenters; Or 1 credential per vCenter; Or no credentials (local lookup will occur) - $(Get-Date)"
}

#logging variables
if (![string]::IsNullOrWhiteSpace($syslogHost)) {
    $Script:vamtSyslogServer = $syslogHost.Split(":")[0].trim()
    if ([string]::IsNullOrEmpty($syslogHost.Split(":")[1])) {
        $Script:vamtSyslogPort = 514
    } else {
        [Int]$Script:vamtSyslogPort = $syslogHost.Split(":")[1].trim()
    }
}
#$Script:debugLogging = !!$PSBoundParameters.Debug.IsPresent
$Script:vamtDebugLogging = !!$debugLogging
$Script:vamtCredentialDirectory = "$env:userprofile\documents"
if ([string]::IsNullOrEmpty($PSScriptRoot)) {
    $Script:vamtWorkingDirectory = Get-Location | Select-Object -ExpandProperty Path
} else {
    $Script:vamtWorkingDirectory = $PSScriptRoot
}
$Script:vamtScriptPath = $MyInvocation.MyCommand.path
$Script:vamtScriptLaunchTime = Get-Date
$Script:vamtLoggingDirectory = "$vamtWorkingDirectory\vamt_runlogs\$($vamtScriptLaunchTime | Get-Date -f "yyyyMMdd-HHmmss")"
$Script:vamtAction = [cultureinfo]::GetCultureInfo("en-US").TextInfo.ToTitleCase($action)

#email variables
if (![string]::IsNullOrWhiteSpace($smtpServer)) {
    $Script:vamtSmtpServer = $smtpServer.Split(":")[0].trim()
    if ([string]::IsNullOrEmpty($smtpServer.Split(":")[1])) {
        $Script:vamtSmtpPort = 25
    } else {
        [Int]$Script:vamtSmtpPort = $smtpServer.Split(":")[1].trim()
    }
}
if (!!$secureMailCred -or !!$useMailCred) {
    $authenticatedEmail = $true
} else {
    $authenticatedEmail = $false
}

#tagging defaults
$Script:vamtTagDetails = @{
    tagCatName = "VAMT"
    readyTagName = "readyToMigrate"
    inProgressTagName = "inProgress"
    completeTagName = "complete"
    completeWithErrorsTagName = "completeWithErrors"
    failedTagName = "failed"
    readyToRollbackTagName = "readyToRollback"
    rollbackTagName = "rolledBack"
    ignored = "Unknown(Skipped)"
}

#rollback & auditing VM attributes
$Script:vamtVcAttrDetails = @{
    sourceVcAttribute = "vamtSourcevCenterName"
    sourceHostAttribute = "vamtSourceESXiHostId"
    sourceRpAttribute = "vamtSourceResourcePoolId"
    sourceFolderAttribute = "vamtSourceFolderId"
    sourceDsAttribute = "vamtSourceDatastoreId"
    sourcePgAttribute = "vamtSourcePortgroupId"
    migrationTsAttribute = "vamtLastMigrationTime"
    snapshotNameAttribute = "vamtSnapshotName"
}
#job variables
$Script:vamtOsShutdownTimeout = $osShutdownTimeout
$Script:vamtOsPowerOnTimeout = $osPowerOnTimeout
$Script:vamtForceShutdown = (!!$forcePowerOff -or !!$ignoreVmTools)
$Script:vamtPowerOnIfRollback = !!$powerOnIfRollback
$Script:vamtIgnoreVmTools = !!$ignoreVmTools
$Script:vamtIgnoreTags = !!$ignoreTags

#job controller variables
$jobNotRun = "Not attempted"
$jobInProgress = "Running"
$jobInProgressExternal = "$($vamtTagDetails.inProgressTagName)-External"
$jobComplete = "Completed"
$jobCompleteExternal = "$jobComplete-External"
$jobCompleteWithErrors = "CompletedWithErrors"
$jobCompleteWithErrorsExternal = "$($vamtTagDetails.completeWithErrorsTagName)-External"
$jobFailed = "Failed"
$jobFailedExternal = "$jobFailed-External"
$jobRolledBack = "rolledBack"
$jobRolledBackExternal = "$jobRolledBack-External"
$jobControllerRefreshInterval = $statusRefreshInterval
$jobStates = @{
    completeExternal = $jobCompleteExternal
    completeWithErrorsExternal = $jobCompleteWithErrorsExternal
    failedExternal = $jobFailedExternal
    inProgressExternal = $jobInProgressExternal
    rolledBackExternal = $jobRolledBackExternal
    jobNotRun = $jobNotRun
}
$Script:doNotRunStates = @(
    $jobComplete,
    $jobCompleteExternal,
    $jobCompleteWithErrors,
    $jobCompleteWithErrorsExternal,
    $jobFailed,
    $jobFailedExternal,
    $jobInProgressExternal,
    $jobRolledBack,
    $jobRolledBackExternal,
    $jobNotRun,
    "notag"
)
if ($action -eq "migrate") {
    $jobReady = $vamtTagDetails.readyTagName
    $doNotRunStates += $vamtTagDetails.readyToRollbackTagName
} elseif ($action -eq "rollback") {
    $jobReady = $vamtTagDetails.readyToRollbackTagName
    $doNotRunStates += $vamtTagDetails.readyTagName
}
$retryErrors = @(
    "Object reference not set to an instance of an object.",
    "has already been deleted or has not been completely created",
    "Invalid configuration for device",
    "Could not complete network copy for file",
    "There was no endpoint listening at",
    "Could not find any of the objects specified by name"
) -join '|'

#cleanup variables
$readyToCleanup = "readyToClean"
$cleanupCompleteStates = @($jobComplete, $jobCompleteWithErrors, $jobFailed)

#inputs csv header defs
$inputHeaders = @{
    name = "vmname"
    vcenter = "target_vc"
    compute = "target_hostpoolcluster"
    network = "target_portgroup"
    storage = "target_datastore"
    folder = "target_folder"
}

$scriptVars = (Get-Variable -Scope Script -Include "vamt*")

#endregion
#############################################################################################################################

#############################################################################################################################
#
#region Setup
#
#############################################################################################################################

#Pre-Create log dir
if(!(Test-Path $vamtLoggingDirectory)){
    Write-Host "Creating logging directory for current execution ($vamtLoggingDirectory). - $(Get-Date)" -foregroundColor Cyan
    New-Item -Path $vamtLoggingDirectory -ItemType Directory -Force | Out-Null
}
#Stop any hanging transcripts
try { Stop-Transcript } catch {}
Start-Transcript -Path "$vamtLoggingDirectory/transcript-$($vamtScriptLaunchTime | Get-Date -Format FileDateTime).log"

#Import VAMT functions module
if(!(Test-Path "$vamtWorkingDirectory/VAMT.psm1")){
    throw "VAMT functions module ($vamtWorkingDirectory/VAMT.psm1) was not found. Quiting now. - $(Get-Date)"
}
#Clear the module before import to refresh any changes
Remove-Module "*VAMT*"
Import-Module -Name "$vamtWorkingDirectory/VAMT.psm1"
$PSDefaultParameterValues = @{
    'Write-Log:logDir' = $vamtLoggingDirectory
    'Write-Log:logFileNamePrefix' = $vamtAction
    'Write-Log:debugLogging' = $vamtDebugLogging
}
if (![string]::IsNullOrEmpty($vamtSyslogServer)) {
    $PSDefaultParameterValues.Add('Write-Log:syslogServer', $vamtSyslogServer)
}
if (![string]::IsNullOrEmpty($vamtSyslogPort)) {
    $PSDefaultParameterValues.Add('Write-Log:syslogPort', $vamtSyslogPort)
}
Write-Log -logDefaults $PSDefaultParameterValues -severityLevel Info -logMessage "VAMT Module has been imported and logging defaults have been loaded into module."

#validate inputs
Write-Log -severityLevel Info -logMessage "Beginning inputs file validation."
try {
    if ( [IO.Path]::GetExtension($inputFilePath).ToLower() -eq ".json" ) {
        $inputs = Get-Content -Raw -Path $inputFilePath | ConvertFrom-Json -ErrorAction Stop
    } elseif ( [IO.Path]::GetExtension($inputFilePath).ToLower() -eq ".csv" ) {
        $inputs = Import-Csv -Path $inputFilePath
    } else {
        #No file extension found.
        try {
            #try json first since it will throw an exception on invalid parse
            $inputs = Get-Content -Raw -Path $inputFilePath | ConvertFrom-Json -ErrorAction Stop
        } catch {
            #failed to parse as a json file to try to import as csv. Issues will be flushed out in validation below.
            $inputs = Import-Csv -Path $inputFilePath
        }
    }
} catch {
    Write-Log -severityLevel Error -logMessage "Failed to import inputs file located at '$inputFilePath'. Error:`n`t$($_.Exception.message)"
    throw $_
}

$errorLines = @()
$inputs | ForEach-Object {
    if (
        [String]::IsNullOrWhiteSpace($_."$($inputHeaders.name)") -or
        [String]::IsNullOrWhiteSpace($_."$($inputHeaders.vcenter)") -or
        [String]::IsNullOrWhiteSpace($_."$($inputHeaders.compute)") -or
        [String]::IsNullOrWhiteSpace($_."$($inputHeaders.network)") -or
        [String]::IsNullOrWhiteSpace($_."$($inputHeaders.storage)")
        #No need to check folder as it's not required.
    ) {
        $errorLines += [String]($inputs.IndexOf($_)+1)
    }
}

if ($errorLines.Length -gt 0) {
    $message = "Missing data detected on object/line(s) ($($errorLines -join ', ')) in inputs file."
    Write-Log -severityLevel Error -logMessage $message
    throw $message
}

$vmnames = $inputs.vmname | Select-Object -Unique
$duplicates = Compare-object -referenceobject $inputs.vmname -differenceobject $vmnames
if ($duplicates.InputObject.Length -gt 0) {
    $message = "The following VM names were found more than once ($(($duplicates.InputObject | Sort-Object | Get-Unique) -join ', ')) in the inputs CSV file."
    Write-Log -severityLevel Error -logMessage $message
    throw $message
}

Write-Log -severityLevel Info -logMessage "Inputs file successfully validated for completeness."

#Setup and validate email credential
if ($authenticatedEmail) {
    Write-Log -severityLevel Info -logMessage "Authenticated email specified, retrieving and/or storing credentials."
    if (!$secureMailCred) {
        $emailCredential = Get-StoredCredential -credName $fromEmail -credentialDirectory $vamtCredentialDirectory
    } else {
        $emailCredential = Save-Credential -credName $fromEmail -cred $secureMailCred -credentialDirectory $vamtCredentialDirectory
    }
}

#First clear any active or stale VI Connections from this session.
try { Disconnect-VIServer * -Confirm:$false } catch {}
$viConnections = $vCenters | ForEach-Object {
    Initialize-VIServer -vCenters $_ -Credential $vcCredentialTable[$_] -credentialDirectory $vamtCredentialDirectory
}
#Validate that all Tags and Categories required for the migration exist in all specified vCenters.
if (!$vamtIgnoreTags) {
    Confirm-Tags -tagDetails $vamtTagDetails -viConnections $viConnections
} else {
    Write-Log -severityLevel Warn -logMessage "Skipping tag state validation."
}

#ensure all VM attributes exist
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourceVcAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourceHostAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourceRpAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourceFolderAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourceDsAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.sourcePgAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.migrationTsAttribute -viConnections $viConnections
Confirm-CustomAttribute -attributeName $vamtVcAttrDetails.snapshotNameAttribute -viConnections $viConnections

$validationParams = @{
    inputs = $inputs
    inputHeaders = $inputHeaders
    tagDetails = $vamtTagDetails
    viConnections = $viConnections
    ignoreTags = $vamtIgnoreTags
}
if ($action -eq "migrate") {
    $migrationTargets = Confirm-MigrationTargets @validationParams -jobStates $jobStates -doNotRunStates $doNotRunStates -ignoreVmTools:$vamtIgnoreVmTools
} elseif ($action -eq "rollback") {
    $migrationTargets = Confirm-RollbackTargets @validationParams -jobStates $jobStates -doNotRunStates $doNotRunStates -vCenterAttrs $vamtVcAttrDetails -ignoreVmTools:$vamtIgnoreVmTools
} elseif ($action -eq "cleanup") {
    $cleanupTargets = Confirm-CleanupTargets @validationParams -snapshotAttrName $vamtVcAttrDetails.snapshotNameAttribute -readyState $readyToCleanup
}

#check change window
if (![string]::IsNullOrEmpty($changeWindowStart)) {
    if ($action -ne "cleanup") {
        $changeWindow = $true
        $startTime = Get-Date -Date $changeWindowStart
        Write-Log -severityLevel Info -logMessage "Change window start time: $startTime"
        if ($changeWindowDuration -gt 0) {
            $endTime = $startTime.AddMinutes($changeWindowDuration)
            Write-Log -severityLevel Info -logMessage "Change window end time: $endTime"
        } else {
            Write-Log -severityLevel Info -logMessage "Change window does not have an end time."
        }
    } else {
        Write-Log -severityLevel Warn -logMessage "Change window specified but is not appropriate for action 'cleanup'. Ignoring change window."
        $changeWindow = $false
    }
} else {
    $changeWindow = $false
    Write-Log -severityLevel Info -logMessage "No change window specified. Proceeding with script now."
}

if (!!$startTime) {
    if ($vamtScriptLaunchTime -lt $startTime) {
        #we are before the change window, schedule the run.
        if (!$WhatIf) {
            Write-Log -severityLevel Info -logMessage "Current time ($vamtScriptLaunchTime) is before the beginning of the specified change window start time ($startTime). Scheduling workflow to run at start of change window."
            New-ScheduledExecution -startTime $startTime -parameters $PSBoundParameters -scriptPath $vamtScriptPath -workingDirectory $vamtWorkingDirectory
            return
        } else {
            Write-Log -severityLevel Info -logMessage "Current time ($vamtScriptLaunchTime) is before the beginning of the specified change window start time ($startTime). Whatif enabled. Continuing with Script."
        }

    } elseif (Confirm-InChangeWindow -executeTime $vamtScriptLaunchTime -startWindow $startTime -endWindow $endTime) {
        # we are in the change window now
        Write-Log -severityLevel Info -logMessage "Current time ($vamtScriptLaunchTime) is within the specified change window. Proceeding with script now."
    } else {
        #we are after the change window.
        Write-Log -severityLevel Warn -logMessage "Current time ($vamtScriptLaunchTime) is after the end of the specified change window end time ($endTime). Nothing to do. Exiting."
        return
    }
}

#endregion
#############################################################################################################################

#############################################################################################################################
#
#region Main
#
#############################################################################################################################

if ($action -in @("migrate","rollback")) {
    #Migration & Rollback tasks
    Write-Log -severityLevel Info -logMessage "Pre-$action target states:`n$($migrationTargets | Format-Table | Out-String)"

    while(([array]($migrationTargets | Where-Object {$_.job_state -notin $doNotRunStates})).count -gt 0) {
        #check and update job progress
        $migrationTargets | Where-Object {$_.job_state -eq $jobInProgress} | ForEach-Object {
            $job = $_.job.ChildJobs
            #Job states: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate
            if ($job.State -ne $jobInProgress) {
                if ($job.State -eq $jobComplete) {
                    if ($job.Error -eq $null) {
                        Write-Log -severityLevel Info "VM move job for '$($_.tgt_vm.Name)' is complete."
                        $_.job_state = $jobComplete
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.tgt_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                    } else {
                        Write-Log -severityLevel Warn "VM move job for '$($_.tgt_vm.Name)' completed with unhandled errors. Considering it '$jobCompleteWithErrors'. Errors:`n$(($job.Error | ForEach-Object { if (!!$_) {$_.ToString()}}) -join "`n")"
                        $_.job_state = $jobCompleteWithErrors
                        $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtTagDetails.completeWithErrorsTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:(!!$WhatIf) -viConn $viConnections -ignoreTags:$vamtIgnoreTags
                    }
                } elseif ($job.State -eq $jobFailed) {
                    Write-Log -severityLevel Error "VM move job for '$($_.tgt_vm.Name)' failed with errors:`n$($job.Error.Exception.Message -join "`n")"
                    Write-Log -severityLevel Error -logMessage "Failed Job Details:`n$($job | ConvertTo-Json -Depth 4)" -skipConsole -logFileNamePrefix $_.tgt_vm.Name -syslogServer ''
                    if (!$job.Error -or ($job.Error.ToString() -match $retryErrors)) {
                        if ($_.attempts -lt $jobRetries) {
                            Write-Log -severityLevel Warn -logMessage "Error is eligible to be re-tried. Setting retry status to try again later for '$($_.tgt_vm.Name)'."
                            $_.job_state = "failed_pendingRetry"
                        } else {
                            Write-Log -severityLevel Error -logMessage "All retry attempts for '$($_.tgt_vm.Name)' have been exhaused. Setting job state to '$jobFailed'."
                            $_.job_state = $jobFailed
                            $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtTagDetails.failedTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:(!!$WhatIf) -viConn $viConnections -ignoreTags:$vamtIgnoreTags
                        }
                    } else {
                        $_.job_state = $jobFailed
                        $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtTagDetails.failedTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:(!!$WhatIf) -viConn $viConnections -ignoreTags:$vamtIgnoreTags
                    }
                } elseif ($job.State -eq "NotStarted") {
                    Write-Log -severityLevel Info "VM move job for '$($_.tgt_vm.Name)' is still preparing to run."
                } else {
                    Write-Log -severityLevel Error  "VM move job for '$($_.tgt_vm.Name)' ended with unsupported state $($job.State). Considering this job failed."
                    Write-Log -severityLevel Error -logMessage "Unkown Job State Details:`n$($job | ConvertTo-Json -Depth 4)" -skipConsole -logFileNamePrefix $_.tgt_vm.Name -syslogServer ''
                    $_.job_state = $jobFailed
                    $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtTagDetails.failedTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:(!!$WhatIf) -viConn $viConnections -ignoreTags:$vamtIgnoreTags
                }
            }
        }
        if (([array]($migrationTargets | Where-Object {$_.job_state -notin $doNotRunStates})).count -le 0) {
            break
        }
        #check if changewindow is complete
        if ($changeWindow) {
            $stillWithinChangeWindow = Confirm-InChangeWindow -executeTime (Get-Date) -startWindow $startTime -endWindow $endTime
            if (!$stillWithinChangeWindow) {
                if ($parallelTaskCount -gt 0) {
                    Write-Log -severityLevel Warn -logMessage "We are nolonger inside our change window. Turning the job throttle down to 0. All currently in progress tasks will be allowed to finish."
                    $parallelTaskCount = 0
                    $migrationTargets | Where-Object {$_.job_state -eq $jobReady} | ForEach-Object {
                        $_.job = "Job not executed due to being past the end of the change window."
                        $_.job_state = $jobNotRun
                    }
                }
                if (([array]($migrationTargets | Where-Object {$_.job_state -eq $jobInProgress})).count -le 0) {
                    break
                }
            }
        }

        #calculate how many slots for new jobs we have
        [int]$movesInProgress = ([array]($migrationTargets | Where-Object {$_.job_state -eq $jobInProgress})).count
        [int]$pendingMoves = ([array]($migrationTargets | Where-Object {$_.job_state -like "*pendingRetry" -or $_.job_state -eq $jobReady})).count
        $currentThrottle = [math]::Max(0, ($parallelTaskCount - $movesInProgress))
        Write-Log -severityLevel Info -logMessage "There are currently $movesInProgress moves in progress and $pendingMoves moves waiting to start."

        [array]$batch = $migrationTargets | Sort-Object -Property attempts | Where-Object {$_.job_state -eq $jobReady} | Select-Object -First $currentThrottle
        if ($batch.count -lt $currentThrottle) {
            $batch += $migrationTargets | Sort-Object -Property attempts | Where-Object {$_.job_state -like "*pendingRetry"} | Select-Object -First ($currentThrottle-$batch.count)
        }
        #launch new jobs
        if ($batch.count -gt 0) {
            Write-Log -severityLevel Info -logMessage "New batch of moves: $($batch.tgt_vm.Name -join ", ")"
            $batch | ForEach-Object {
                $vm = $_.tgt_vm
                $srcViConn = $_.src_vcenter
                $tgtViConn = $_.tgt_vcenter

                [array]$activeTasks = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn
                if ($null -ne $activeTasks) {
                    if ($_.attempts -lt $jobRetries) {
                        Write-Log -severityLevel Warn -logMessage "VM ($($vm.Name)) has $($activeTasks.count) active task(s) already. Setting retry status to try again later."
                        $_.job_state = "busy_pendingRetry"
                        $_.attempts++
                    } else {
                        $_.job_state = $jobFailed
                        $_.job = "Failed waiting for active tasks on VM to complete. Exhausted all $jobRetries retries."
                        Write-Log -severityLevel Error -logMessage "VM ($($vm.Name)) failed with error: $($_.job)"
                        $_.tag_state = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.failedTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:(!!$WhatIf) -viConn $viConnections -ignoreTags:$vamtIgnoreTags
                    }
                    return
                }

                $jobParams = @{
                    srcViConn = $srcViConn
                    tgtViConn = $tgtViConn
                    vm = $vm
                    network = $_.tgt_network
                    WhatIf = !!$WhatIf
                    isRetry = ($_.attempts -gt 0)
                    scriptVars = $scriptVars
                }
                if ($null -ne $_.tgt_folder) {
                    $jobParams.vmfolder = $_.tgt_folder
                }

                if ($action -eq "migrate") {
                    $_.job = Start-MigrateVMJob @jobParams -compute $_.tgt_compute -storage $_.tgt_storage
                } elseif ($action -eq "rollback") {
                    $_.job = Start-RollbackVMJob @jobParams -vmhost $_.tgt_host -respool $_.tgt_respool -datastore $_.tgt_datastore -snapshot $_.tgt_snapshot
                }
                $_.job_state = $jobInProgress
                $_.attempts++
            }
        }

        if (([array]($migrationTargets | Where-Object {$_.job_state -eq $jobInProgress})).count -gt 0) {
            Start-Sleep -Seconds $jobControllerRefreshInterval
        }
    }

    #Cleanup $null target folders for report.
    $migrationTargets | ForEach-Object {if ($null -eq $_.tgt_folder) {$_.tgt_folder = "N/A"}}
    Write-Log -severityLevel Info -logMessage "$action target states:`n$($migrationTargets | Format-Table | Out-String)"
    $finalObj = Save-Report -actionResult $migrationTargets -loggingDirectory $vamtLoggingDirectory
} elseif ($action -eq "cleanup") {
    Write-Log -severityLevel Info -logMessage "Pre-$action target states:`n$($cleanupTargets | Format-Table | Out-String)"
    #Cleanup task
    while(([array]($cleanupTargets | Where-Object {$_.job_state -notin $cleanupCompleteStates})).count -gt 0) {
        #check and update job progress
        $cleanupTargets | Where-Object {$_.job_state -eq $jobInProgress} | ForEach-Object {
            $job = $_.job.ChildJobs
            #Job states: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate
            if ($job.State -ne $jobInProgress) {
                if ($job.State -eq $jobComplete) {
                    if ($job.Error -eq $null) {
                        Write-Log -severityLevel Info "VM cleanup job for '$($_.clean_vm.Name)' is complete."
                        $_.job_state = $jobComplete
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                    } else {
                        Write-Log -severityLevel Warn "VM cleanup job for '$($_.clean_vm.Name)' completed with unhandled errors. Considering it complete with errors."
                        $_.job_state = $jobCompleteWithErrors
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                    }
                } elseif ($job.State -eq $jobFailed) {
                    Write-Log -severityLevel Error "VM cleanup job for '$($_.clean_vm.Name)' failed with errors:`n$($job.Error.Exception.Message -join "`n")"
                    Write-Log -severityLevel Error -logMessage "Failed Job Details:`n$($job | ConvertTo-Json -Depth 4)" -skipConsole -logFileNamePrefix $_.tgt_vm.Name -syslogServer ''
                    if (!$job.Error -or ($job.Error.ToString() -match $retryErrors)) {
                        if ($_.attempts -lt $jobRetries) {
                            Write-Log -severityLevel Warn -logMessage "Error is eligible to be re-tried. Setting retry status to try again later for '$($_.clean_vm.Name)'."
                            $_.job_state = "failed_pendingRetry"
                        } else {
                            Write-Log -severityLevel Error -logMessage "All retry attempts for '$($_.clean_vm.Name)' have been exhaused. Setting job state to '$jobFailed'."
                            $_.job_state = $jobFailed
                            $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                        }
                    } else {
                        $_.job_state = $jobFailed
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                    }
                } elseif ($job.State -eq "NotStarted") {
                    Write-Log -severityLevel Info "VM cleanup job for '$($_.clean_vm.Name)' is still preparing to run."
                } else {
                    Write-Log -severityLevel Error  "VM cleanup job for '$($_.clean_vm.Name)' ended with unsupported state $($job.State). Considering this job failed."
                    Write-Log -severityLevel Error -logMessage "Unkown Job State Details:`n$($job | ConvertTo-Json -Depth 4)" -skipConsole -logFileNamePrefix $_.clean_vm.Name -syslogServer ''
                    $_.job_state = $jobFailed
                    $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                }
            }
        }
        if (([array]($cleanupTargets | Where-Object {$_.job_state -notin $cleanupCompleteStates})).count -le 0) {
            break
        }

        #calculate how many slots for new jobs we have
        [int]$cleansInProgress = ([array]($cleanupTargets | Where-Object {$_.job_state -eq $jobInProgress})).count
        [int]$pendingCleans = ([array]($cleanupTargets | Where-Object {$_.job_state -like "*pendingRetry" -or $_.job_state -eq $jobReady})).count
        $currentThrottle = [math]::Max(0, ($parallelTaskCount - $cleansInProgress))
        Write-Log -severityLevel Info -logMessage "There are currently $cleansInProgress cleanups in progress and $pendingCleans cleanups waiting to start."

        [array]$batch = $cleanupTargets | Where-Object {$_.job_state -eq $readyToCleanup} | Select-Object -First $currentThrottle
        #launch new jobs
        if ($batch.count -gt 0) {
            Write-Log -severityLevel Info -logMessage "New batch of cleanups: $($batch.clean_vm.Name -join ", ")"
            $batch | ForEach-Object {
                $vm = $_.clean_vm
                $viConn = $_.clean_vc

                [array]$activeTasks = Confirm-ActiveTasks -vm $vm -viConnection $viConn
                if ($null -ne $activeTasks) {
                    if ($_.attempts -lt $jobRetries) {
                        Write-Log -severityLevel Warn -logMessage "VM ($($vm.Name)) has $($activeTasks.count) active task(s) already. Setting retry status to try again later."
                        $_.job_state = "busy_pendingRetry"
                        $_.attempts++
                    } else {
                        $_.job_state = $jobFailed
                        $_.job = "Failed waiting for active tasks on VM to complete. Exhausted all $jobRetries retries."
                        Write-Log -severityLevel Error -logMessage "VM ($($vm.Name)) failed with error: $($_.job)"
                        $_.tag_state = Get-VMStateBasedOnTag -vm $vm -viConn $viConn -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtIgnoreTags
                    }
                    return
                }
                $_.job = Start-CleanupVMJob -viConn $viConn -vm $vm -snapshot $_.clean_snapshot -scriptVars $scriptVars -WhatIf:(!!$WhatIf)
                $_.job_state = $jobInProgress
                $_.attempts++
            }
        }

        if (([array]($cleanupTargets | Where-Object {$_.job_state -eq $jobInProgress})).count -gt 0) {
            Start-Sleep -Seconds $jobControllerRefreshInterval
        }
    }

    Write-Log -severityLevel Info -logMessage "Post-$action VM states:`n$($cleanupTargets | Format-Table | Out-String)"
    $finalObj = Save-Report -actionResult $cleanupTargets -loggingDirectory $vamtLoggingDirectory
} else {
    #unhandled action fail
    $errorMessage = "Unknown action '$action' received. Allowable options are 'migrate', 'rollback', 'cleanup'. Exiting."
    Write-Log -severityLevel Error -logMessage $errorMessage -skipConsole
    throw $errorMessage
}

$currentTime = Get-Date
$finalMessage = "Script run summary:`n`tScript start: '$vamtScriptLaunchTime'"
$finalMessage += "`n`tScript runtime: $([math]::Round(($currentTime - $vamtScriptLaunchTime).TotalMinutes)) minutes"
$finalMessage += "`n`tScript completion: '$currentTime'"
$finalMessage += "`n`tTotal VM targets in migration run: $($finalObj.Count)"
$vmMultiAttemptCount = ($finalObj | Where-Object { $_.attempts -gt 1}).Count
$finalMessage += "`n`tTotal VM jobs with retry attempts: $vmMultiAttemptCount"
$notAttemptedCount = 0
$finalObj.job_state | Select-Object -Unique | ForEach-Object {
    $state = $_
    $jobs = $finalObj | Where-Object {$_.job_state -eq $state}
    if ($state -notin $jobStates.Values) {
        $finalMessage += "`n`tVM migration jobs with final status '$state': $($jobs.count)"
    } else {
        $notAttemptedCount += $jobs.count
    }
}
if ($notAttemptedCount -gt 0) {
    $finalMessage += "`n`tVM migration jobs Not Attempted: $notAttemptedCount"
}


Write-Log -severityLevel Info -logMessage $finalMessage
Write-Log -severityLevel Info -logMessage "Final report:`n$($finalObj | Format-Table | Out-String)"

if (![string]::IsNullOrWhiteSpace($smtpServer)) {
    try {
        $reportParameters = @{
            launchTime = $vamtScriptLaunchTime
            action = $vamtAction
            smtpServer = $vamtSmtpServer
            smtpPort = $vamtSmtpPort
            finalObject = $finalObj
            message = $finalMessage
            toEmail = $toEmail
            fromEmail = $fromEmail
            useSsl = $smtpUseSsl
        }
        if ($authenticatedEmail) {
            $reportParameters.secureMailCred = $emailCredential
        }
        Write-Log -severityLevel Info -logMessage "Preparing to send final status email."
        Send-Report @reportParameters
    } catch {
        Write-Log -severityLevel Error -logMessage "Failed to send final email message with following exception:`n$($_.toString())"
    }
}

try { Disconnect-VIServer * -Confirm:$false } catch {}
Stop-Transcript
#endregion
#############################################################################################################################