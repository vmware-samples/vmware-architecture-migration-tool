<#
    .NOTES
    ===========================================================================
     Created by:    Austin Browder
     Date:          June 1, 2022
     Organization:  VMware Professional Services
    ===========================================================================
    .SYNOPSIS
        The VMware Architecture Migration Tool is designed to provide an easy and automated process to 
        migrate machines between clusters of different architecture types within the same or linked vCenters.
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

    [Parameter()] <# Optional: If not set, the user will be prompted for a credential and that credential will be stored (encrypted) on the filesystem. #>
    [ValidateNotNullOrEmpty()]
    [PSCredential]$vcCredential,

    [Parameter()] <# "6/9/2022 9:16:58" #>
    [ValidateNotNullOrEmpty()]
    [String]$changeWindowStart,

    [Parameter()] <# minutes: default (0) is unlimited #>
    [Int]$changeWindowDuration = 0,

    [Parameter()] <# number of concurrent tasks to execute #>
    [Int]$parallelTaskCount = 10,

    [Parameter()] <# number of retries that should be attempted if the VM has active vCenter Tasks preventing the migration #>
    [Int]$jobRetries = 5,

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
    
    [Parameter()] <# force poweroff if initial clean shutdown times out #>
    [Switch]$ignoreVmTools,
    
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
$Script:credentialDirectory = "$env:userprofile\documents"
if ([string]::IsNullOrEmpty($PSScriptRoot)) {
    $Script:workingDirectory = Get-Location | Select -ExpandProperty Path
} else {
    $Script:workingDirectory = $PSScriptRoot
}
$Script:scriptPath = $MyInvocation.MyCommand.path
$Script:vamtScriptLaunchTime = Get-Date
$Script:vamtLoggingDirectory = "$workingDirectory\vamt_runlogs\$($vamtScriptLaunchTime | Get-Date -f "yyyyMMdd-HHmmss")"
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
$Script:vamtTagCatName = "VAMT"
$Script:vamtReadyTagName = "readyToMigrate"
$Script:vamtInProgressTagName = "inProgress"
$Script:vamtCompleteTagName = "complete"
$Script:vamtCompleteWithErrorsTagName = "completeWithErrors"
$Script:vamtFailedTagName = "failed"
$Script:vamtReadyToRollbackTagName = "readyToRollback"
$Script:vamtRollbackTagName = "rolledBack"

#rollback & auditing VM attributes
$Script:vamtSourceVcAttribute = "vamtSourcevCenterName"
$Script:vamtSourceHostAttribute = "vamtSourceESXiHostId"
$Script:vamtSourceRpAttribute = "vamtSourceResourcePoolId"
$Script:vamtSourceFolderAttribute = "vamtSourceFolderId"
$Script:vamtSourceDsAttribute = "vamtSourceDatastoreId"
$Script:vamtSourcePgAttribute = "vamtSourcePortgroupId"
$Script:vamtMigrationTsAttribute = "vamtLastMigrationTime"
$Script:vamtSnapshotNameAttribute = "vamtSnapshotName"

#job variables
$Script:vamtOsShutdownTimeout = 600 #seconds
$Script:vamtOsPowerOnTimeout = 900 #seconds
$Script:vamtForceShutdown = (!!$forcePowerOff -or !!$ignoreVmTools)
$Script:vamtPowerOnIfRollback = !!$powerOnIfRollback
$Script:vamtIgnoreVmTools = !!$ignoreVmTools

#job controller variables
$jobNotRun = "Not attempted"
$jobInProgress = "Running"
$jobInProgressExternal = "$vamtInProgressTagName-External"
$jobComplete = "Completed"
$jobCompleteExternal = "$jobComplete-External"
$jobCompleteWithErrors = "CompletedWithErrors"
$jobCompleteWithErrorsExternal = "$vamtCompleteWithErrorsTagName-External"
$jobFailed = "Failed"
$jobFailedExternal = "$jobFailed-External"
$jobRolledBack = "rolledBack"
$jobRolledBackExternal = "$jobRolledBack-External"
$jobControllerRefreshInterval = 15 #seconds
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
    $jobReady = $vamtReadyTagName
    $doNotRunStates += $vamtReadyToRollbackTagName
} elseif ($action -eq "rollback") {
    $jobReady = $vamtReadyToRollbackTagName
    $doNotRunStates += $vamtReadyTagName
}
$retryErrors = @(
    "Object reference not set to an instance of an object.",
    "has already been deleted or has not been completely created",
    "Invalid configuration for device"
) -join '|'

#cleanup variables
$readyToCleanup = "readyToClean"
$cleanupCompleteStates = @($jobComplete, $jobCompleteWithErrors, $jobFailed)

#inputs csv header defs
$Script:vmName_attr = "vmname"
$Script:tgtCompute_attr = "target_hostpoolcluster"
$Script:tgtNetwork_attr = "target_portgroup"
$Script:tgtStorage_attr = "target_datastore"

#endregion
#############################################################################################################################

#############################################################################################################################
#
#region Function Definitions
#
#############################################################################################################################

function TestAndConnect-VIServer {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$vCenters,
        [Parameter()]
        [PSCredential]$cred
    )
    $connections = @()
    foreach ($vCenter in $vCenters) {
        try {
            if ($null -eq $cred) {
                Write-Log -severityLevel Debug -logMessage "No credential for vCenter $vCenter was passed in via input parameter. Starting stored credential retrieval."
                $cred = Get-StoredCredential -credName $vCenter
            } else {
                Write-Log -severityLevel Debug -logMessage "Credential for vCenter $vCenter with Username $($cred.UserName) was passed in via input parameter. Overwriting stored credential."
                $cred = Save-Credential -credName $vCenter -cred $cred
            }
            Write-Log -severityLevel Info -logMessage "Logging in to vCenter $vCenter with User: $($cred.UserName)"
            $connection = Connect-VIServer $vCenter -Credential $cred -ErrorAction Stop
            $connections += $connection
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to connect to $vCenter with the following Error:`n`t$($_.Exception.innerexception.message)"
            Write-Log -severityLevel Warn -logMessage "In the case of expired/incorrect credentials, you can clear the credential file used to connect to vCenter located here: $credentialDirectory"
            Write-Log -severityLevel Warn -logMessage "Cleaning up and exiting the execution."
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    }
    return $connections
}

function Get-StoredCredential {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$credName
    )

    $credFile = "$credentialDirectory\$credName-$($env:USERNAME).cred"
    if (Test-Path -Path $credFile) {
        $cred = Import-Clixml -Path $credFile
        Write-Log -severityLevel Debug -logMessage "Found credential for '$credName'. User: $($cred.UserName)"
    } else {
        Write-Log -severityLevel Debug -logMessage "No stored credential found for '$credName'."
        $cred = Save-Credential -credName $credName
    }

    return $cred
}

function Save-Credential {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$credName,

        [Parameter()]
        [PSCredential]$cred
    )

    $credFile = "$credentialDirectory\$credName-$($env:USERNAME).cred"
    Write-Log -severityLevel Debug -logMessage "Preparing to set credential for '$credName'."
    if ($null -eq $cred) {
        $cred = Get-Credential -Message "Please enter the credentials to use for connections to '$credName'. Recommended Username format: user@domain"
    }
    $cred | Export-Clixml -Path $credFile
    Write-Log -severityLevel Info -logMessage "Saved new credential for '$credName'. User: '$($cred.UserName)'"

    return $cred
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$logMessage,

        [Parameter()]
        [ValidateSet('Info','Warn','Debug','Error')]
        [string]$severityLevel = 'Info',

        [Parameter()]
        [String]$logDir = $vamtLoggingDirectory,

        [Parameter()]
        [String]$logFileNamePrefix = $vamtAction,

        [Parameter()]
        [Switch]$skipSyslog,

        [Parameter()]
        [Switch]$skipConsole
    )

    if(!(Test-Path $logDir)){
        Write-Host "Logging directory for current execution ($logDir) was not found. Creating directory now. - $(Get-Date)" -foregroundColor Cyan
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }

    $logDate = Get-Date
    $logStamp = "[$severityLevel] $logDate"
    $stampedlogMessage = "$logStamp - $logMessage"
    
    switch ($severityLevel) {
        "Info" { 
            $foregroundColor = [System.ConsoleColor] 10 <#Green#>
            $logToConsole = !$skipConsole
            $syslogSeverity = 6
            break 
        } "Warn" { 
            $foregroundColor = [System.ConsoleColor] 14 <#Yellow#>
            $logToConsole = !$skipConsole
            $syslogSeverity = 4
            break 
        } "Debug" { 
            $foregroundColor = [System.ConsoleColor] 11 <#Cyan#>
            $logToConsole = $vamtDebugLogging -and !$skipConsole
            $syslogSeverity = 7
            break 
        } "Error" { 
            $foregroundColor = [System.ConsoleColor] 12 <#Red#>
            $logToConsole = !$skipConsole
            $syslogSeverity = 3
            break 
        }
    }
    
    if ($logToConsole) {
        Write-Host $stampedlogMessage -foregroundColor $foregroundColor
    }
    Add-Content -Path "$logDir/$($logFileNamePrefix)_Script_Log.log" -value $stampedlogMessage
    
    if ($severityLevel -eq "Error") {
        Add-content -Path "$logDir/$($logFileNamePrefix)_Error_Log.log" -value $stampedlogMessage
    }

    if (!$skipSyslog -and ![string]::IsNullOrEmpty($vamtSyslogServer)) {
        
        $params = @{}
        $params.syslogServer = $vamtSyslogServer
        $params.syslogPort = $vamtSyslogPort
        $params.severityLevel = $syslogSeverity
        $params.syslogMessage = $logMessage
        $params.logDate = $logDate
        $params.logFileNamePrefix = $logFileNamePrefix

        Send-Syslog @params
    }
}    

function Send-Syslog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$syslogServer,
        [Parameter()]
        [Int]$syslogPort = 514,
        [Parameter()]
        [ValidateSet(3,4,6,7)]
        [Int]$severityLevel = 6,
        [Parameter()]
        [Int]$facility = 16,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$logDate,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$syslogMessage,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$logFileNamePrefix
    )

    $logParameters = @{
        skipSyslog = $true
    }
    if (![String]::IsNullOrWhiteSpace($logFileNamePrefix)) {
        $logParameters.logFileNamePrefix = $logFileNamePrefix
    }
    
    try {
        $UDP_Client = New-Object System.Net.Sockets.UdpClient
        $UDP_Client.Connect($syslogServer, $syslogPort)
        $priority = ($facility * 8) + $severityLevel
        $timestamp = $logDate | Get-Date -Format "yyyy:MM:dd:-HH:mm:ss zzz"
        $formattedSyslogMessage = "<{0}>{1} {2} {3}" -f [String]$priority, $timestamp, $env:COMPUTERNAME, $syslogMessage
        $asciiEncoding = [System.Text.Encoding]::ASCII
        $byteSyslogMessage = $asciiEncoding.GetBytes($formattedSyslogMessage)
        $result = $UDP_Client.Send($byteSyslogMessage, $byteSyslogMessage.Length)
        if ($result -eq $byteSyslogMessage.Length) {
            Write-Log @logParameters -severityLevel Debug -logMessage "Successfully sent Syslog message. Payload size: $($byteSyslogMessage.Length) bytes." -skipConsole
        } else {
            Write-Log @logParameters -severityLevel Error -logMessage "Failed to send Syslog message. Payload size: $($byteSyslogMessage.Length) bytes. Sent payload $result bytes."
        }
    } catch {
        Write-Log @logParameters -severityLevel Error -logMessage "Failed to send Syslog message with following exception:`n$_"
    }
}

function Check-InChangeWindow {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$executeTime,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$startWindow,
        [Parameter()]
        $endWindow
    )

    if ($startWindow -le $executeTime) {
        if (!!$endWindow) {
            if ($executeTime -lt $endWindow) {
                return $true
            }
        } else {
            #no end window specified so we are safe to proceed
            return $true
        }
    }

    return $false
}

function New-ScheduledExecution {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$startTime,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]$parameters
    )
    
    Write-Log -severityLevel Info -logMessage "Validating we are running in an Administrator console."
    #Scheduled tasks can only be created by an admin console so we must first check.
    $currentId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentId)
    $administratorRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if ($currentPrincipal.IsInRole($administratorRole)) {
        $currentUserPassword = Read-Host -AsSecureString  -Prompt "Please enter the password for '$($currentId.Name)' to be used for creating the scheduled task"
        $currentUserCred = New-Object System.Management.Automation.PSCredential -ArgumentList $currentId.Name, $currentUserPassword
        $parameterString = ($parameters.GetEnumerator() | % {
            $key = $_.Key
            $value = $_.Value
            switch ($value.GetType().Name) {
                "SwitchParameter" { 
                    "-$($key)"
                    break 
                } "Boolean" { 
                    "-$($key) `$$($value)"
                    break 
                } "String" { 
                    "-$($key) '$($value)'"
                    break 
                } "String[]" { 
                    "-$($key) @('$($value -join ', ')')"
                    break 
                } "PSCredential" { 
                    if ($key -eq "secureMailCred") {
                        "-useMailCred"
                    }
                    break 
                }  Default { 
                    "-$($key) $($value)"
                    break 
                }
            }
        }) -join ' '
        
        $pwshArg = "-Command `"& '$scriptPath' $parameterString`""
        #Write-Host $pwshArg
        $taskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $pwshArg -WorkingDirectory $workingDirectory
        $startTrigger = New-ScheduledTaskTrigger -At $startTime -Once -RandomDelay (New-TimeSpan -Seconds 10)
        $taskParameters = @{
            Action = $taskAction
            TaskName = "VAMT_Scheduled_Run_$($startTime | Get-Date -f "yyyyMMdd-HHmmss")"
            Trigger = $startTrigger
            RunLevel = "Highest"
            User = $currentId.Name
            Password = $currentUserCred.GetNetworkCredential().Password
        }
        $taskResult = Register-ScheduledTask @taskParameters
    } else {
        Write-Log -severityLevel Error -logMessage "Creating a Schedule Task using PowerShell requires an Administrator console. Please re-launch the console as Administrator and execute the script again."
    }
}

function Validate-Tags {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections
    )
    $missingCategories = @()
    $categories = $viConnections | %{
        $viConn = $_
        try {
            $category = Get-TagCategory -Name $vamtTagCatName -Server $viConn -ErrorAction Stop
            if ($category.Cardinality -ne 'Single') {
                throw "Tag cardinality was detected as '$($category.Cardinality)'. Must be set to 'Single'."
            }
            $category | Add-Member -MemberType NoteProperty -Name 'vCenter' -Value $viConn
            $category
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to validate tag category '$vamtTagCatName' in vCenter '$($viConn.Name)'. Error:`n`t$($_.Exception.message)"
            $missingCategories += "'$vamtTagCatName' in vCenter '$($viConn.Name)'"
        }
    }
    if ($missingCategories.Length -gt 0) {
        $message = "Missing or invalid category detected: $($missingCategories -join ', ')"
        Write-Log -severityLevel Error -logMessage $message
        throw $message 
    }
    
    $missingTags = @()
    $categories | %{
        $category = $_
        try {
            $tag = Get-Tag -Name $vamtReadyTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtReadyTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtReadyTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtInProgressTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtInProgressTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtInProgressTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtCompleteTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtCompleteTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtCompleteTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtCompleteWithErrorsTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtCompleteWithErrorsTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtCompleteWithErrorsTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtFailedTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtFailedTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtFailedTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtRollbackTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtRollbackTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtRollbackTagName' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $vamtReadyToRollbackTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$vamtReadyToRollbackTagName' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$vamtReadyToRollbackTagName' in vCenter '$($category.vCenter.Name)'"
        }
    }

    if ($missingTags.Length -gt 0) {
        $message = "Missing tags detected: $($missingTags -join ', ')"
        Write-Log -severityLevel Error -logMessage $message
        throw $message 
    }

    Write-Log -severityLevel Info -logMessage "All tags and categories have been validated."
}

function Validate-CustomAttribute {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$attributeName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections
    )
    $viConnections | %{
        $viConn = $_
        $attr = Get-CustomAttribute -Server $viConn -Name $attributeName -ErrorAction Ignore
        if (!$attr) {
            Write-Log -severityLevel Info -logMessage "Failed to find vm attribute '$attributeName' in vCenter '$($viConn.Name)'. Creating it now."
            $null = New-CustomAttribute -Server $viConn -Name $attributeName -TargetType VirtualMachine
        } else {
            Write-Log -severityLevel Info -logMessage "Found vm attribute '$attributeName' in vCenter '$($viConn.Name)'. No action required."
        }
    }
}

function Get-VMStateBasedOnTag {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConn
    )
    
    $tagAssignment = Get-TagAssignment -Entity $vm -Category $vamtTagCatName -Server $viConn
    if (!$tagAssignment) {
        Write-Log -severityLevel Warn -logMessage "No state tag applied to VM $($vm.name)."
        return "notag"
    } 

    if ($tagAssignment.Tag.Length -gt 1) {
        $message = "Detected $($tagAssignment.Tag.Length) state tags applied to VM $($vm.name). Should not be possible with Single cardinality."
        Write-Log -severityLevel Warn -logMessage $message
        throw $message
    }

    return $tagAssignment.Tag.Name
}

function Set-VMStateTag {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$tagName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConn,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    $logParameters = @{
        skipConsole = $false
    }
    if (![String]::IsNullOrWhiteSpace($envLogPrefix)) {
        $logParameters.logFileNamePrefix = $envLogPrefix
    }
    try {
        Write-Log @logParameters -severityLevel Info -logMessage "Preparing to set '$tagName' tag on '$($vm.Name)'"
        Get-TagAssignment -Entity $vm -Category $vamtTagCatName -Server $viConn | Remove-TagAssignment -Confirm:$false -WhatIf:(!!$WhatIf)
        $tag = Get-Tag -Name $tagName -Category $vamtTagCatName -Server $viConn 
        $null = New-TagAssignment -Entity $vm -Tag $tag -Server $viConn -WhatIf:(!!$WhatIf)
        Write-Log @logParameters -severityLevel Info -logMessage "Successfully to set '$tagName' tag on '$($vm.Name)'"
    } catch { 
        Write-Log @logParameters -severityLevel Error -logMessage "Failed to set '$tagName' tag on '$($vm.Name)'"
        throw $_ 
    }

    return $tag.Name
}

function Check-ActiveTasks {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl]$viConnection,

        [Parameter()]
        [Switch]$waitTasks,

        [Parameter()]
        [Switch]$WhatIf
    )
    $logParameters = @{
        skipConsole = $false
    }
    if (![String]::IsNullOrWhiteSpace($envLogPrefix)) {
        $logParameters.logFileNamePrefix = $envLogPrefix
    }

    $activeTasks = Get-Task -Server $viConnection | ?{ $_.State -eq 'Running' -and $_.ObjectId -eq $vm.ExtensionData.MoRef.ToString() }

    if(!!$activeTasks -and !!$waitTasks) {
        Write-Log @logParameters -severityLevel Info -logMessage "$($activeTasks.Count) active tasks found on '$($vm.Name)'. Waiting for tasks to complete."
        if (!$WhatIf) {
            $null = Wait-Task -Task $activeTasks
        }
        return
    }

    return $activeTasks
}

function Check-VMTools {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm
    )
    $toolsStatus = $vm.ExtensionData.Guest.ToolsStatus
    if ($toolsStatus -in @("toolsOk", "toolsOld")) {
        Write-Log -severityLevel Debug -logMessage "VM Tools on '$($vm.Name)' has been validated with status '$toolsStatus'."
        return $true
    }
    Write-Log -severityLevel Warn -logMessage "VM Tools on '$($vm.Name)' failed validation with status '$toolsStatus'."
    return $false
}

function Start-PreMigrationExtensibility {
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    return $true
}

function Start-PostMigrationExtensibility {
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    return $true
}

function Validate-NotNullOrEmpty {
    param (
        [Parameter(Mandatory)]
        [String]$inString,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$failMessage = "Input is null or empty."
    )
    if ([String]::IsNullOrEmpty($inString)) {
        Write-Log -severityLevel Error -logMessage $failMessage
        throw $failMessage
    }

    return $inString
}

function Validate-VMs {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$vmNames
    )
    $missingVMs = @()
    $vms = $vmNames | %{
        $vmname = $_
        try{
            $vm = Get-VM -Name $vmname -Server $viConnection -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Warn -logMessage "No VM was found with name '$vmname'."
            $missingVMs += $vmname
        }
        if ($vm.count -ne 1) {
            Write-Log -severityLevel Warn -logMessage "$($vm.count) VM(s) found with name '$vmname'."
            $missingVMs += $vmname
        }
        $vm
    }

    return [PSCustomObject]@{
        vms = $vms
        missingVMs = $missingVMs
    }
}

function Validate-Computes {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter()]
        [ValidateSet('HostSystem','ResourcePool','ClusterComputeResource','All')]
        [String]$computeType,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$computeNames
    )
    $missingComputes = @()
    $hostViews = Get-View -ViewType HostSystem -Server $viConnection
    $clusterViews = Get-View -ViewType ClusterComputeResource -Server $viConnection
    $rpViews = Get-View -ViewType ResourcePool -Server $viConnection
    $computeViews = @()
    if (!$computeType -or $computeType -eq "All") {
        $computeViews = ($hostViews + $clusterViews + $rpViews)
    } elseif ($computeType -eq "HostSystem") {
        $computeViews = $hostViews
    } elseif ($computeType -eq "ResourcePool") {
        $computeViews = $rpViews
    } elseif ($computeType -eq "ClusterComputeResource") {
        $computeViews = $clusterViews
    } else {
        throw "Invalid computeType '$computeType' passed into Validate-Computes function"
    }

    $computes = $computeNames | Sort | Get-Unique | %{
        $computeName = $_
        $computeView = $computeViews| ?{$_.Name -eq $computeName}
        if (!!$computeView) {
            if ($computeView.Length -gt 1) {
                Write-Log -severityLevel Warn -logMessage "$($computeView.Length) computes were found with name ($computeName) and type(s) ($(($computeView.MoRef.Type | Sort | Get-Unique) -join ', '))."
                $missingComputes += $computeName
            } else {
                Get-VIObjectByVIView -VIView $computeView
            }
        } else {
            Write-Log -severityLevel Warn -logMessage "No computes were found with name ($computeName)."
            $missingComputes += $computeName
        }
    }

    return [PSCustomObject]@{
        computes = $computes
        missingComputes = $missingComputes
    }
}

function Validate-MigrationTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs
    )
    #Check that all VMs and target locations listed in input file are valid
    $vmValidationResult = Validate-VMs -vmNames $inputs."$vmName_attr" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    $cmptValidationResult = Validate-Computes -computeNames $inputs."$tgtCompute_attr" -computeType All -viConnection $viConnections
    $missingComputes = $cmptValidationResult.missingComputes
    $computes = $cmptValidationResult.computes

    if (($missingVMs.Length + $missingComputes.Length) -gt 0) {
        $missingMessage = "The following inputs are missing from the provided vCenters.`n`tMissing VMs: $($missingVMs -join ', '); Missing Computes: $($missingComputes -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    #Now we will re-build the table from our inputs file except using the actual objects we have retrieved so far. 
    #Additionaly, we will validate the network & storage selections with the context of the selected compute for each row.
    $missingPortGroups = @()
    $missingStorage = @()
    $dscViews = Get-View -ViewType StoragePod -Server $viConnections
    $migrationTargets = $inputs | %{
        $vmName = $_."$vmName_attr" 
        $computeName = $_."$tgtCompute_attr"
        $networkName = $_."$tgtNetwork_attr"
        $storageName = $_."$tgtStorage_attr"

        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $viConn = $viConnections | ?{$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select -First 1)}
        $computeObj = $computes | ?{$_.Name -eq $computeName} 
        $computeView = $computeObj | Get-View
        if ($computeView.GetType().Name -eq 'ResourcePool') {
            $computeView.updateviewdata('Owner.*')
            $computeView = $computeView.LinkedView.Owner
        }
        $computeView.updateviewdata('Network.*','Datastore.*')
        $networkViews = $computeView.LinkedView.Network

        $networkView = $networkViews | ?{$_.Name -eq $networkName}
        if (!!$networkView) {
            if ($networkView.Length -gt 1) {
                Write-Log -severityLevel Warn -logMessage "$($networkView.Length) networks were found with name ($networkName) and type(s) ($(($networkView.MoRef.Type | Sort | Get-Unique) -join ', ')) within Compute ($computeName)."
                $missingPortGroups += $networkName
            } else {
                $networkObj = Get-VIObjectByVIView -VIView $networkView
            }
        } else {
            Write-Log -severityLevel Warn -logMessage "No networks were found with name ($networkName) within Compute ($computeName)."
            $missingPortGroups += $networkName
        }

        $datastoreViews = $computeView.LinkedView.Datastore
        $dscViews = $datastoreViews | %{
            if ($_.Parent.Type -eq "StoragePod") {
                $_.updateviewdata('Parent.*')
                $_.LinkedView.Parent
            }
        } | Sort -Property Name -Unique
        $storageView = ($datastoreViews + $dscViews) | ?{$_.Name -eq $storageName}
        if (!!$storageView) {
            if ($storageView.Length -gt 1) {
                Write-Log -severityLevel Warn -logMessage "$($storageView.Length) Datastores or DSCs were found with name ($storageName) and type(s) ($(($storageView.MoRef.Type | Sort | Get-Unique) -join ', ')) within Compute ($computeName)."
                $missingStorage += $storageName
            } else {
                $storageObj = Get-VIObjectByVIView -VIView $storageView
            }
        } else {
            Write-Log -severityLevel Warn -logMessage "No Datastores or DSCs were found with name ($storageName) within Compute ($computeName)."
            $missingStorage += $storageName
        }

        $validationErrors = @()
        $vmState = Get-VMStateBasedOnTag -vm $vmObj -viConn $viConn
        $jobState = $vmState
        $job = $null
        $eligibleToRun = $false
        $notAttempted = "Not attempted due to job state '{0}'"
        if ($jobState -eq $vamtInProgressTagName) {
            $jobState = $jobInProgressExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtCompleteTagName) {
            $jobState = $jobCompleteExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtCompleteWithErrorsTagName) {
            $jobState = $jobCompleteWithErrorsExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtFailedTagName) {
            $jobState = $jobFailedExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtRollbackTagName) {
            $jobState = $jobRolledBackExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq "notag") {
            $jobState = $jobNotRun
            $validationErrors += ($notAttempted -f $jobState)
        } else {
            $eligibleToRun = $true
        }

        #Check VMtools IF machine is powered on and we are not ignoring tools - this will support pre-powered off machines
        if ($eligibleToRun -and $vmObj.PowerState -eq "PoweredOn" -and !$vamtIgnoreVmTools) {
            if (!(Check-VMTools -vm $vmObj)) {
                $jobState = $jobNotRun
                $validationErrors += "Not attempted due to VMware tools not running."
            }
        }
        if ($validationErrors.Length -gt 0) {
            $job = $validationErrors -join ", `n"
            if ($jobState -notin $doNotRunStates) {
                $jobState = $jobNotRun
            }
        }

        [PSCustomObject]@{
            tgt_vm = $vmObj
            tgt_compute = $computeObj
            tgt_network = $networkObj
            tgt_storage = $storageObj
            tag_state = $vmState
            job_state = $jobState
            job = $job
            attempts = 0
        }
    }

    if (($missingPortGroups.Length + $missingStorage.Length) -gt 0) {
        $missingMessage = "The following inputs are missing from the provided vCenters OR are not accessible from the specified compute targets.`n`Invalid Portgroups: $($missingPortGroups -join ', '); Invalid Datastores/DSCs: $($missingStorage -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    return $migrationTargets
}

function Validate-RollbackTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs
    )
    #Check that all VMs listed in input file are valid
    $vmValidationResult = Validate-VMs -vmNames $inputs."$vmName_attr" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    if (($missingVMs.Length) -gt 0) {
        $missingMessage = "The following VMs are missing from the provided vCenter: $($missingVMs -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    #Check that all rollback attributes are populated on the input VM objects.
    $missingRollbackAttrs = @()
    $rollbackTargets = $inputs | %{
        $vmName = $_."$vmName_attr"
        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackVcName = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourceVcAttribute) -failMessage ($emptyAttrError -f $vamtSourceVcAttribute)
            $rollbackHostId = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourceHostAttribute) -failMessage ($emptyAttrError -f $vamtSourceHostAttribute)
            $rollbackResPoolId = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourceRpAttribute) -failMessage ($emptyAttrError -f $vamtSourceRpAttribute)
            $rollbackVmFolderId = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourceFolderAttribute) -failMessage ($emptyAttrError -f $vamtSourceFolderAttribute)
            $rollbackDatastoreId = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourceDsAttribute) -failMessage ($emptyAttrError -f $vamtSourceDsAttribute)
            $rollbackPortGroupId = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSourcePgAttribute) -failMessage ($emptyAttrError -f $vamtSourcePgAttribute)
            $rollbackSnapshotName = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSnapshotNameAttribute) -failMessage ($emptyAttrError -f $vamtSnapshotNameAttribute)
        } catch {
            $missingRollbackAttrs += $vmName
        }

        [PSCustomObject]@{
            tgt_vm = $vmObj
            tgt_vc = $rollbackVcName
            tgt_host = $rollbackHostId
            tgt_respool = $rollbackResPoolId
            tgt_folder = $rollbackVmFolderId
            tgt_network = $rollbackPortGroupId
            tgt_datastore = $rollbackDatastoreId
            tgt_snapshot = $rollbackSnapshotName
        }
    }

    if (($missingRollbackAttrs.Length) -gt 0) {
        $missingMessage = "The following VMs are missing one or more of the required Custom Attributes for performing a rollback.`n`tVMs: $($missingRollbackAttrs -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    #Now we will re-build the table using the actual objects we have IDs for. 
    $missingvCenters = @()
    $missingPortGroups = @()
    $missingDatastores = @()
    $missingHosts = @()
    $missingResPools = @()
    $missingFolders = @()
    $missingSnapshots = @()
    $rollbackTargets = $rollbackTargets | %{
        $vm = $_.tgt_vm
        $tgtVc = $_.tgt_vc
        $viConn = $viConnections | ?{$_.Name -eq $tgtVc}

        $validationErrors = @()
        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn
        $jobState = $vmState
        $job = $null
        $eligibleToRun = $false
        $notAttempted = "Not attempted due to job state '{0}'"
        if ($jobState -eq $vamtInProgressTagName) {
            $jobState = $jobInProgressExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtCompleteTagName) {
            $jobState = $jobCompleteExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtCompleteWithErrorsTagName) {
            $jobState = $jobCompleteWithErrorsExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtFailedTagName) {
            $jobState = $jobFailedExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $vamtRollbackTagName) {
            $jobState = $jobRolledBackExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq "notag") {
            $jobState = $jobNotRun
            $validationErrors += ($notAttempted -f $jobState)
        } else {
            $eligibleToRun = $true
        }

        if (!$viConn) {
            Write-Log -severityLevel Error -logMessage "No current connection for rollback vCenter '$($_.tgt_vc)' was found (vCenter for VM: '$($vm.Name)'). You must specify all required vCenters when executing the script."
            $missingvCenters += $_.tgt_vc
            continue
        }

        $notFoundError = "No object found matching MoRef or Name '{0}' in vCenter '$($viConn.Name)'"
        try {
            $rollbackHostId = $_.tgt_host
            $hostObj = Get-VIObjectByVIView -MORef $rollbackHostId -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackHostId)
                $validationErrors += ($notFoundError -f $rollbackHostId)
            }
        }
        try {
            $rollbackResPoolId = $_.tgt_respool
            $rpObj = Get-VIObjectByVIView -MORef $rollbackResPoolId -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackResPoolId)
                $validationErrors += ($notFoundError -f $rollbackResPoolId)
            }
        }
        try {
            $rollbackVmFolderId = $_.tgt_folder
            $folderObj = Get-VIObjectByVIView -MORef $rollbackVmFolderId -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackVmFolderId)
                $validationErrors += ($notFoundError -f $rollbackVmFolderId)
            }
        }
        try {
            $rollbackPortGroupId = $_.tgt_network
            $pgObj = Get-VIObjectByVIView -MORef $rollbackPortGroupId -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackPortGroupId)
                $validationErrors += ($notFoundError -f $rollbackPortGroupId)
            }
        }
        try {
            $rollbackDatastoreId = $_.tgt_datastore
            $dsObj = Get-VIObjectByVIView -MORef $rollbackDatastoreId -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackDatastoreId)
                $validationErrors += ($notFoundError -f $rollbackDatastoreId)
            }
        }
        try {
            $rollbackSnapshotName = $_.tgt_snapshot
            $snapObj = Get-Snapshot -VM $vm -Name $rollbackSnapshotName -Server $viConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackSnapshotName)
                $validationErrors += ($notFoundError -f $rollbackSnapshotName)
            }
        }
        
        #Check VMtools IF machine is powered on and we are not ignoring tools - this will support pre-powered off machines
        if ($eligibleToRun -and $vm.PowerState -eq "PoweredOn" -and !$vamtIgnoreVmTools) {
            if (!(Check-VMTools -vm $vm)) {
                $validationErrors += "Not attempted due to VMware tools not running."
            }
        }
        if ($validationErrors.Length -gt 0) {
            $job = $validationErrors -join ", `n"
            if ($jobState -notin $doNotRunStates) {
                $jobState = $jobNotRun
            }
        }

        [PSCustomObject]@{
            tgt_vm = $vm
            tgt_vc = $viConn
            tgt_host = $hostObj
            tgt_respool = $rpObj
            tgt_folder = $folderObj
            tgt_network = $pgObj
            tgt_datastore = $dsObj
            tgt_snapshot = $snapObj
            tag_state = $vmState
            job_state = $jobState
            job = $job
            attempts = 0
        }
    }

    $missingMessage = "The following rollback target vCenters are missing from the provided inputs:`n"
    $missingCount = 0
    if ($missingvCenters.Length -gt 0) {
        $missingMessage += $($missingvCenters -join ', ')
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    return $rollbackTargets
}

function Validate-CleanupTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs
    )
    #Check that all VMs listed in input file are valid
    $vmValidationResult = Validate-VMs -vmNames $inputs."$vmName_attr" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    if (($missingVMs.Length) -gt 0) {
        $missingMessage = "The following inputs are missing from the provided vCenters.`n`tMissing VMs: $($missingVMs -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    #Check that rollback attributes are populated on the input VM objects.
    $cleanupTargets = $inputs | %{
        $vmName = $_."$vmName_attr"
        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $viConn = $viConnections | ?{$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select -First 1)}
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackSnapshotName = Validate-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vamtSnapshotNameAttribute) -failMessage ($emptyAttrError -f $vamtSnapshotNameAttribute)
            $status = $readyToCleanup
        } catch {
            $missingMessage = "The snapshot attribute on vm '$vmName' was not populated. Will not attempt to cleanup any snaps."
            Write-Log -severityLevel Warn -logMessage $missingMessage
        }

        [PSCustomObject]@{
            clean_vm = $vmObj
            clean_vc = $viConn
            clean_snapshot = $rollbackSnapshotName
        }
    }

    #Now we will re-build the table using the actual objects we have IDs for. 
    $missingvCenters = @()
    $cleanupTargets = $cleanupTargets | %{
        $vm = $_.clean_vm
        $viConn = $_.clean_vc
        if (!$viConn) {
            Write-Log -severityLevel Error -logMessage "No current connection for cleanup vCenter '$($_.clean_vc)' was found (vCenter for VM: '$($vm.Name)'). You must specify all required vCenters when executing the script."
            $missingvCenters += $_.clean_vc
            continue
        }

        $notFoundError = "No snapshot found matching Name '{0}' on vm '$($vm.Name)' in vCenter '$($viConn.Name)'"
        try {
            $rollbackSnapshotName = $_.clean_snapshot
            if (!!$rollbackSnapshotName) {
                $snapObj = Get-Snapshot -VM $vm -Name $rollbackSnapshotName -Server $viConn -ErrorAction Stop
            }
        } catch {
            Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackSnapshotName)
        }

        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn

        [PSCustomObject]@{
            clean_vm = $vm
            clean_vc = $viConn
            clean_snapshot = $snapObj
            tag_state = $vmState
            job_state = $readyToCleanup
            job = $null
            attempts = 0
        }
    }

    if ($missingvCenters.Length -gt 0) {
        $missingMessage = "The following vCenter connections are missing. The vcenters specified on each VMs custom attributes must be passed in as inputs to the script execution.`n"
        $missingMessage += "Missing vCenters: $($missingvCenters -join ', ')`n"
        Write-Log -severityLevel Error -logMessage $missingMessage -skipConsole
        throw $missingMessage
    }

    return $cleanupTargets
}

function Start-MigrateVMJob {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $viConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $compute,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $network,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $storage,

        [Parameter()]
        [PSCredential]$cred,

        [Parameter()]
        [Switch]$isRetry,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    if ($null -eq $cred) {
        $cred = Get-StoredCredential -credName $viConn.Name
    } 

    $jobFunctions = "function Start-PreMigrationExtensibility { ${function:Start-PreMigrationExtensibility} }`n"
    $jobFunctions += "function Start-PostMigrationExtensibility { ${function:Start-PostMigrationExtensibility} }`n"
    $jobFunctions += "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Check-ActiveTasks { ${function:Check-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }`n"
    $jobFunctions += "function Get-VMStateBasedOnTag { ${function:Get-VMStateBasedOnTag} }`n"
    $jobFunctions += "function Set-VMStateTag { ${function:Set-VMStateTag} }"

    $scriptVars = Get-Variable -Scope Script -Include "vamt*"
    $test = !!$WhatIf
    $retry = !!$isRetry
    $migrationJob = Start-Job -ScriptBlock {
        try {
            $using:scriptVars | %{ New-Variable -Name $_.Name -Value $_.Value}
            #Had to move awawy from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $using:viConn -Session $using:viConn.SessionSecret
            $viConn = Connect-ViServer -Server $using:viConn.Name -Credential $using:cred
            $vm = Get-VIObjectByVIView -MORef $using:vm.Id -Server $viConn
            $compute = Get-VIObjectByVIView -MORef $using:compute.Id -Server $viConn        
            $network = Get-VIObjectByVIView -MORef $using:network.Id -Server $viConn
            $storage = Get-VIObjectByVIView -MORef $using:storage.Id -Server $viConn
            $WhatIf = $using:test
            $isRetry = $using:retry
            $vmName = $vm.Name
            $Script:envLogPrefix = $vmName

            if ($isRetry) {
                $retryMessage = "retry of "
            }
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage ("Starting {0}migration process on '$($vm.Name)'." -f $retryMessage)
            
            #validate no-one is stepping on our job
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn
            $allowedStates = @($vamtReadyTagName)
            if ($isRetry) {
                $allowedStates += $vamtInProgressTagName
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtInProgressTagName -WhatIf:$WhatIf -viConn $viConn
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }
            
            #get current compute, network, storage
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Gathering current compute, network, storage, folder details for '$($vm.Name)'."
            $currentVC = $viConn.Name
            $currentHostId = $vm.VMHostId
            $currentRpId = $vm.ResourcePoolId
            $currentFolderId = $vm.FolderId
            #Current support is for only 1 source and target Datastore - rollback will result in all disks rolled back to original OS disk Datastore
            $currentDsId = (Get-HardDisk -VM $vm | sort -Property Name | Select -First 1).ExtensionData.Backing.Datastore.ToString()
            #Current support is for only 1 source and target PortGroup - rollback will result first network being rolled back to original Portgroup. All others disconnected.
            $currentPgId = ($vm | Get-View | Select -ExpandProperty Network | Select -First 1).ToString()

            #Setup Move targets and validate move is needed.
            $moveParameters = @{
                VM = $vm
                Confirm = $false
                Server = $viConn
                WhatIf = !!$WhatIf
                ErrorAction = "Stop"
            }
            $currentStorage = Get-View -id $currentDsId -Server $viConn
            if ($storage.Id -notin @($currentDsId, $currentStorage.Parent.ToString())) {
                $moveParameters.Datastore = $storage
            }
            if ($currentPgId -ne $network.Id) {
                if ($network.NetworkType -eq "Opaque") {
                    $moveParameters.Network = $network
                } else {
                    $moveParameters.PortGroup = $network
                }
            }
            $currentResPool = Get-VIObjectByVIView -MORef $currentRpId
            if ($compute.Id -notin @($currentHostId, $currentRpId, $currentResPool.ExtensionData.Owner.ToString())) {
                if ($compute.ExtensionData.MoRef.Type -eq "ClusterComputeResource") {
                    $tgtCompute = Get-VMHost -Location $compute | ?{$_.ConnectionState -eq "Connected"} | Get-Random
                } elseif ($compute.ExtensionData.MoRef.Type -eq "ResourcePool") {
                    $tgtCluster = Get-Cluster -Id $compute.ExtensionData.Owner.ToString() -Server $viConn
                    $tgtCompute = Get-VMHost -Location $tgtCluster | ?{$_.ConnectionState -eq "Connected"} | Get-Random
                } else {
                    $tgtCompute = $compute
                }
                $moveParameters.Destination = $tgtCompute
            }
            #catch incase nothing is apparently moving, maybe move has already occured or a mistake was made.
            if (!$moveParameters.Destination -and !$moveParameters.Datastore) {
                $message = "Current VM location details match the migration target. Nothing to do."
                Write-Log -severityLevel Error -logFileNamePrefix $envLogPrefix -logMessage $message -skipConsole
                Write-Error $message
                return [PSCustomObject]@{
                    result = "Migration parameters for VM '$($vm.Name)' are too similar to current Cluster/Storage. No action performed."
                }
            }

            #write attributes for current compute, network, storage, snapshot name
            $sourceVcAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourceVcAttribute
            $sourceHostAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourceHostAttribute
            $sourceRpAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourceRpAttribute
            $sourceFolderAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourceFolderAttribute
            $sourceDsAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourceDsAttribute
            $sourcePgAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSourcePgAttribute
            $timestampAttribute = Get-CustomAttribute -Server $viConn -Name $vamtMigrationTsAttribute
            $snapshotNameAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSnapshotNameAttribute

            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Writing current compute, network, storage, folder details to '$($vm.Name)' custom attributes."
            if (!$WhatIf) {
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks
                $null = $vm | Set-Annotation -CustomAttribute $sourceVcAttribute -Value $currentVC
                $null = $vm | Set-Annotation -CustomAttribute $sourceHostAttribute -Value $currentHostId
                $null = $vm | Set-Annotation -CustomAttribute $sourceRpAttribute -Value $currentRpId
                $null = $vm | Set-Annotation -CustomAttribute $sourceFolderAttribute -Value $currentFolderId
                $null = $vm | Set-Annotation -CustomAttribute $sourceDsAttribute -Value $currentDsId
                $null = $vm | Set-Annotation -CustomAttribute $sourcePgAttribute -Value $currentPgId
                $null = $vm | Set-Annotation -CustomAttribute $timestampAttribute -Value $vamtScriptLaunchTime.ToString()
            }

            #preMigration extensibility stub
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Starting Pre Migration Extensibility actions."
            $extResult = Start-PreMigrationExtensibility -viConnection $viConn -vm $vm -WhatIf:$WhatIf
            if (!$extResult) {
                throw "Pre Migration Extensibility actions failed."
            }

            #shutdown VM
            $vm = Get-VM -Id $vm.Id -Server $viConn #refresh VM object
            if (!$WhatIf) {
                if ($vm.PowerState -eq "PoweredOn") {
                    $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Beginning GuestOS Shutdown on '$($vm.Name)'"
                    $null = Stop-VMGuest -VM $vm -Confirm:$false
                    $sleepTimer = 5 #seconds
                    while ($vm.PowerState -eq "PoweredOn") {
                        Start-Sleep -Seconds $sleepTimer
                        $waitDuration += $sleepTimer
                        if ($waitDuration -ge $vamtOsShutdownTimeout) {
                            if (!$vamtForceShutdown) {
                                throw "Shutdown of VM '$($vm.Name)' has timed out and force shutdown is disabled. Considering this job failed."
                            }
                            Write-Log -severityLevel Warn -logFileNamePrefix $envLogPrefix -logMessage "Shutdown of VM '$($vm.Name)' has timed out. Forcing poweroff now."
                            $vm = Stop-VM -VM $vm -Server $viConn -Confirm:$false
                        }
                        $vm = Get-VM -Id $vm.Id -Server $viConn #refresh VM object
                    }
                } else {
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "'$($vm.Name)' is already PoweredOff. Continuing."
                } 
            } else {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "WhatIf enabled. Not modifying '$($vm.Name)'. Current PowerState: '$($vm.PowerState)'. Continuing."
            }

            #snapshot VM
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Creating/Retrieving pre-migration snapshot on '$($vm.Name)'."
            $snapshotName = "VAMT_Migration_$($vamtScriptLaunchTime.ToShortDateString() -replace '/','_')_$($vamtScriptLaunchTime.ToLongTimeString() -replace ' ','_')"
            $snapshotDescription = "Snapshot taken by VAMT migration script.`nRun by: $($env:USERNAME)"
            $snapshot = Get-Snapshot -VM $vm -Name $snapshotName -Server $viConn -ErrorAction SilentlyContinue
            if (!$snapshot) {
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $snapshot = New-Snapshot -VM $vm -Name $snapshotName -Description $snapshotDescription -Server $viConn -Confirm:$false -WhatIf:$WhatIf -ErrorAction Stop
            }
            $null = $vm | Set-Annotation -CustomAttribute $snapshotNameAttribute -Value $snapshot.Name -WhatIf:$WhatIf
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Successfully created/retrieved pre-migration snapshot on '$($vm.Name)' with name: $snapshotName"
            
            #Move VM
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Starting VM Migration for '$($vm.Name)'."
            Write-Log -severityLevel Debug -logFileNamePrefix $envLogPrefix -logMessage "VM migration spec:`n$($moveParameters | Out-String)"
            $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
            $vm = Move-VM @moveParameters
            if ($compute.ExtensionData.MoRef.Type -eq "ResourcePool" -and $vm.ResourcePoolId -ne $compute.Id) {
                $moveParameters = @{
                    VM = $vm
                    Destination = $compute
                    Confirm = $false
                    Server = $viConn
                    WhatIf = !!$WhatIf
                    ErrorAction = "Stop"
                }
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Moving VM '$($vm.Name)' into resource pool '$($compute.Name)'."
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $vm = Move-VM @moveParameters
            }


            #start the VM and wait for VM tools
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Migration completed successfully. Powering on '$($vm.Name)'."
            $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
            $vm = Start-VM -VM $vm -Server $viConn -Confirm:$false -WhatIf:$WhatIf
            if (!$WhatIf -and !$vamtIgnoreVmTools) {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Waiting for VMware Tools...(Timeout: $vamtOsPowerOnTimeout seconds)"
                #Adding sleep to avoid VMtools not installed issue
                Start-Sleep -Seconds 25
                $vm = Wait-Tools -VM $vm -TimeoutSeconds $vamtOsPowerOnTimeout -ErrorAction Stop
            }

            #post migraion extensibility stub
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Starting Post Migration Extensibility actions."
            $extResult = Start-PostMigrationExtensibility -viConnection $viConn -vm $vm -WhatIf:$WhatIf
            if (!$extResult) {
                throw "Post Migration Extensibility actions failed."
            }

            #change tag to complete
            $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VMStateTag -vm $vm -tagName $vamtCompleteTagName -WhatIf:$WhatIf -viConn $viConn

            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Migration of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer $viConn -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully moved VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in migration job:`n$_"
            Write-Log -severityLevel Error -logFileNamePrefix $envLogPrefix -logMessage $message -skipConsole
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    } -InitializationScript ([scriptblock]::Create($jobFunctions)) -ArgumentList($viConn,$vm,$compute,$network,$storage,$cred,$retry,$test,$scriptVars)

    return $migrationJob 
}

function Start-RollbackVMJob {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $viConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vmhost,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $respool,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $portgroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vmfolder,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $datastore,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $snapshot,

        [Parameter()]
        [PSCredential]$cred,

        [Parameter()]
        [Switch]$isRetry,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    if ($null -eq $cred) {
        $cred = Get-StoredCredential -credName $viConn.Name
    } 

    $jobFunctions = "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Start-PostMigrationExtensibility { ${function:Start-PostMigrationExtensibility} }`n"
    $jobFunctions += "function Check-ActiveTasks { ${function:Check-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }`n"
    $jobFunctions += "function Get-VMStateBasedOnTag { ${function:Get-VMStateBasedOnTag} }`n"
    $jobFunctions += "function Set-VMStateTag { ${function:Set-VMStateTag} }"

    $scriptVars = Get-Variable -Scope Script -Include "vamt*"
    $test = !!$WhatIf
    $retry = !!$isRetry
    $rollbackJob = Start-Job -ScriptBlock {
        try {
            $using:scriptVars | %{ New-Variable -Name $_.Name -Value $_.Value}
            #Had to move awawy from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $using:viConn -Session $using:viConn.SessionSecret
            $viConn = Connect-ViServer -Server $using:viConn.Name -Credential $using:cred
            $vm = Get-VIObjectByVIView -MORef $using:vm.Id -Server $viConn
            $vmName = $vm.Name
            $vmhost = Get-VIObjectByVIView -MORef $using:vmhost.Id -Server $viConn
            $respool = Get-VIObjectByVIView -MORef $using:respool.Id -Server $viConn
            $portgroup = Get-VIObjectByVIView -MORef $using:portgroup.Id -Server $viConn
            $vmfolder = Get-VIObjectByVIView -MORef $using:vmfolder.Id -Server $viConn
            $datastore = Get-VIObjectByVIView -MORef $using:datastore.Id -Server $viConn
            $snapshot = Get-VIObjectByVIView -MORef $using:snapshot.Id -Server $viConn
            $WhatIf = $using:test
            $isRetry = $using:retry
            $Script:envLogPrefix = $vmName

            if ($isRetry) {
                $retryMessage = "retry of "
            }
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage ("Starting {0}rollback process on '$vmName'." -f $retryMessage)

            #validate no-one is stepping on our job
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn
            $allowedStates = @($vamtReadyToRollbackTagName)
            if ($isRetry) {
                $allowedStates += $vamtInProgressTagName
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtInProgressTagName -WhatIf:$WhatIf -viConn $viConn
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }

            #get current compute, network, storage
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Gathering current compute, network, storage, folder details for '$vmName'."
            $currentVC = $viConn.Name
            $currentHostId = $vm.VMHostId
            $currentRpId = $vm.ResourcePoolId
            $currentFolderId = $vm.FolderId
            #Current support is for only 1 source and target Datastore - rollback will result in all disks rolled back to original OS disk Datastore
            $currentDsId = $vm.DatastoreIdList[0]
            #Current support is for only 1 source and target PortGroup - rollback will result first network being rolled back to original Portgroup. All others disconnected.
            $currentPgId = ($vm | Get-View | Select -ExpandProperty Network | Select -First 1).ToString()

            #Setup Move targets and validate move is needed.
            $moveParameters = @{
                VM = $vm
                Confirm = $false
                Server = $viConn
                WhatIf = $WhatIf
                ErrorAction = "Stop"
            }
            if ($currentDsId -ne $datastore.Id) {
                $moveParameters.Datastore = $datastore
            }
            if ($currentPgId -ne $portgroup.Id) {
                #Move-VM uses different network parameters for NSX-T networks vs std & vds PortGroups
                if ($network.NetworkType -eq "Opaque") {
                    $moveParameters.Network = $portgroup
                } else {
                    $moveParameters.PortGroup = $portgroup
                }
            }
            if ($currentFolderId -ne $vmfolder.Id) {
                $moveParameters.InventoryLocation = $vmfolder
            }
            $currentHost = Get-VIObjectByVIView -MORef $currentHostId -Server $viConn
            if ($currentHostId -ne $vmhost.Id -and $currentHost.Parent.Id -ne $vmhost.Parent.Id) {
                $moveParameters.Destination = $vmhost
            }
            #catch incase nothing is apparently moving, just add the compute and vCenter will handle it gracefully.
            if (!$moveParameters.Destination -and !$moveParameters.Datastore -and !$moveParameters.InventoryLocation) {
                $message = "Current VM location details match the rollback targets. Will not attempt Move-VM."
                Write-Log -severityLevel Error -logFileNamePrefix $envLogPrefix -logMessage $message
                if (!$isRetry) {
                    Write-Error $message
                    return [PSCustomObject]@{
                        result = "Rollback parameters for VM '$($vm.Name)' are too similar to current Cluster/Storage."
                    }
                }
                $moveVM = $false
            } else {
                $moveVM = $true
            }

            #PowerOff VM
            $vm = Get-VM -Id $vm.Id -Server $viConn #refresh VM object
            if (!$WhatIf) {
                if ($vm.PowerState -eq "PoweredOn") {
                    $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Beginning PowerOff on '$($vm.Name)'"
                    $vm = Stop-VM -VM $vm -Server $viConn -Confirm:$false
                } else {
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "'$($vm.Name)' is already PoweredOff. Continuing."
                } 
            } else {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "WhatIf enabled. Not modifying '$($vm.Name)'. Current PowerState: '$($vm.PowerState)'. Continuing."
            }
            
            #Move VM
            if ($moveVM) {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Starting VM Rollback Migration for '$($vm.Name)'."
                Write-Log -severityLevel Debug -logFileNamePrefix $envLogPrefix -logMessage "VM migration spec:`n$($moveParameters | Out-String)"
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $vm = Move-VM @moveParameters
        
                #check to restore resource pool that VM originally lived in
                if ($vm.ResourcePoolId -ne $respool.Id) {
                    $moveParameters = @{
                        VM = $vm
                        Destination = $respool
                        Confirm = $false
                        Server = $viConn
                        WhatIf = $WhatIf
                        ErrorAction = "Stop"
                    }
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Restoring VM '$($vm.Name)' to resource pool '$($respool.Name)'."
                    $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                    $vm = Move-VM @moveParameters
                }
            }
            #revert snapshot on VM
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Reverting to pre-migration snapshot on '$($vm.Name)' with name '$($snapshot.Name)'."
            $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VM -VM $vm -Snapshot $snapshot -Confirm:$false -WhatIf:$WhatIf -ErrorAction Stop
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Successfully reverted to pre-migration snapshot on '$($vm.Name)'."
                    
            #start the VM and wait for VM tools
            if ($vamtPowerOnIfRollback) {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Powering on '$($vm.Name)'."
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                $vm = Start-VM -VM $vm -Server $viConn -Confirm:$false -WhatIf:$WhatIf
                if (!$WhatIf -and !$vamtIgnoreVmTools) {
                    Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Waiting for VMware Tools..."
                    #Adding sleep to avoid VMtools not installed issue
                    Start-Sleep -Seconds 25
                    $vm = Wait-Tools -VM $vm -TimeoutSeconds $vamtOsPowerOnTimeout -ErrorAction Stop
                }
            }

            #change tag to complete
            $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VMStateTag -vm $vm -tagName $vamtRollbackTagName -WhatIf:$WhatIf -viConn $viConn

            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Rollback of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer $viConn -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully rolled back VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in rollback job:`n$_"
            Write-Log -severityLevel Error -logFileNamePrefix $envLogPrefix -logMessage $message -skipConsole
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    } -InitializationScript ([scriptblock]::Create($jobFunctions)) -ArgumentList($viConn,$vm,$vmhost,$respool,$portgroup,$vmfolder,$datastore,$cred,$snapshot,$retry,$test,$scriptVars)

    return $rollbackJob 
}

function Start-CleanupVMJob {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $viConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vm,

        [Parameter()]
        $snapshot,

        [Parameter()]
        [PSCredential]$cred,

        [Parameter()]
        [Switch]$WhatIf
    )
    
    if ($null -eq $cred) {
        $cred = Get-StoredCredential -credName $viConn.Name
    } 

    $jobFunctions = "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Check-ActiveTasks { ${function:Check-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }"

    $scriptVars = Get-Variable -Scope Script -Include "vamt*"
    $test = !!$WhatIf
    $cleanupJob = Start-Job -ScriptBlock {
        try {
            $using:scriptVars | %{ New-Variable -Name $_.Name -Value $_.Value}
            #Had to move awawy from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $using:viConn -Session $using:viConn.SessionSecret
            $viConn = Connect-ViServer -Server $using:viConn.Name -Credential $using:cred
            $vm = Get-VIObjectByVIView -MORef $using:vm.Id -Server $viConn
            $WhatIf = $using:test
            $vmName = $vm.Name
            $Script:envLogPrefix = $vmName
            if (!!$using:snapshot) {
                $snapshot = Get-VIObjectByVIView -MORef $using:snapshot.Id -Server $viConn
            }

            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Starting cleanup process on '$($vm.Name)'."

            #delete the snapshot if it exists
            if (!!$snapshot) {
                $null = Check-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Removing snapshot '$($snapshot.Name)' from '$($vm.Name)'."
                Remove-Snapshot -Snapshot $snapshot -Confirm:$false -WhatIf:$WhatIf
                $snapshotNameAttribute = Get-CustomAttribute -Server $viConn -Name $vamtSnapshotNameAttribute
                $null = Set-Annotation -Entity $vm -CustomAttribute $snapshotNameAttribute -Value '' -WhatIf:$WhatIf
            }

            #Remove VAMT Tag
            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Looking for VAMT tags on '$($vm.Name)'."
            $tagAssignments = Get-TagAssignment -Category $vamtTagCatName -Entity $vm -Server $viConn
            if ($tagAssignments.count -gt 0) {
                Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Removing VAMT tag from '$($vm.Name)'."
                Remove-TagAssignment -TagAssignment $tagAssignments -Confirm:$false -WhatIf:$WhatIf
            }

            Write-Log -severityLevel Info -logFileNamePrefix $envLogPrefix -logMessage "Cleanup of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer $viConn -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully cleaned up VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in cleanup job:`n$_"
            Write-Log -severityLevel Error -logFileNamePrefix $envLogPrefix -logMessage $message -skipConsole
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    } -InitializationScript ([scriptblock]::Create($jobFunctions)) -ArgumentList($viConn,$vm,$cred,$snapshot,$test,$scriptVars)

    return $cleanupJob 
}

function Save-Report {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$actionResult,

        [Parameter()]
        [Switch]$WhatIf
    )
    $unknownResult = "Job completed with unknown result. See scripting logs for details."
    $finalObject = $actionResult | %{
        $result = $_
        $object = @{}
        $result | Get-Member -MemberType NoteProperty | Select -ExpandProperty Name | Sort | %{
            $resProperty = $result."$_"
            if ($_ -eq "job") {
                $key = "job_result"
                if ($null -ne $resProperty) {
                    if ($resProperty.GetType().Name -eq "PSRemotingJob"){
                        $job = $resProperty.ChildJobs
                        if (![string]::IsNullOrEmpty($job.Output.result)) {
                            $value = $job.Output.result
                        } elseif (!!$job.Error) {
                            $value = ($job.Error | %{if (!!$_){ $_.ToString()}}) -join "`n"
                        } else {
                            $value = $unknownResult
                        }
                    } else {
                        $value = $resProperty.ToString()
                    }
                } else {
                    $value = $unknownResult
                }
            } else {
                $key = $_
                if ($null -eq $resProperty -or [string]::IsNullOrEmpty($resProperty)) {
                    $value = $unknownResult
                } else {
                    $value = $resProperty.ToString()
                }
            }
            $object."$key" = $value
        }
        [PSCustomObject]$object
    }

    try {
        $finalObject | Export-CSV -Path "$vamtLoggingDirectory\final_report.csv" -NoTypeInformation -Force -Confirm:$false -WhatIf:(!!$WhatIf)
    } catch {
        Write-Log -severityLevel Error -logMessage "Failed to export final report to CSV file located at '$vamtLoggingDirectory\final_report.csv'. Error:`n`t$($_.Exception.message)"
    }

    return $finalObject
}

function Send-Report {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$finalObject,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$message,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$toEmail,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$fromEmail,

        [Parameter()]
        [PSCredential]$secureMailCred,
        
        [Parameter()]
        [Switch]$useSsl
    )
    $title = "VAMT '$vamtAction' report"
    $subject = "$title - $($vamtScriptLaunchTime.ToString())"
    $bodyMessage = "<h2>$title</h2>"
    if (![String]::IsNullOrWhiteSpace($message)) {
        $message = $message -replace "`n","<br>"
        $message = $message -replace "`t","&emsp;"
        $bodyMessage += "<p>$message</p>"
    }
    $bodyMessage += "<p>The following table shows the final status of the VAMT '$vamtAction' execution:</p>"
    $style = "<style> table, th, td { border: 1px solid black; } </style>"
    $emailBody = $finalObject | ConvertTo-Html -As Table -Head $style -Title $subject -PreContent $bodyMessage | Out-String

    $emailParameters = @{
        SmtpServer = $vamtSmtpServer
        Port = $vamtSmtpPort
        From = $fromEmail
        To = $toEmail
        Subject = $subject
        Body = $emailBody
        BodyAsHtml = $true
        UseSsl = !!$useSsl
        WarningAction = "SilentlyContinue"
    }

    if (!!$secureMailCred) {
        $emailParameters.Credential = $secureMailCred
    }

    Send-MailMessage @emailParameters

}

#endregion
#############################################################################################################################

#############################################################################################################################
#
#region Setup
#
#############################################################################################################################

#Stop any hanging transcripts
try { Stop-Transcript } catch {}
Start-Transcript -Path "$vamtLoggingDirectory/transcript-$($vamtScriptLaunchTime | Get-Date -Format FileDateTime).log"

#validate inputs
Write-Log -severityLevel Info -logMessage "Beginning inputs file validation."
try {
    $inputs = Import-Csv -Path $inputFilePath
} catch {
    Write-Log -severityLevel Error -logMessage "Failed to import inputs CSV file located at '$inputFilePath'. Error:`n`t$($_.Exception.message)"
    throw $_
}

$errorLines = @()
$inputs | %{
    if (
        [String]::IsNullOrWhiteSpace($_."$vmName_attr") -or
        [String]::IsNullOrWhiteSpace($_."$tgtCompute_attr") -or
        [String]::IsNullOrWhiteSpace($_."$tgtNetwork_attr") -or
        [String]::IsNullOrWhiteSpace($_."$tgtStorage_attr")
    ) {
        $errorLines += [String]($inputs.IndexOf($_)+2)
    }
}

if ($errorLines.Length -gt 0) {
    $message = "Missing data detected on lines ($($errorLines -join ', ')) in inputs CSV file."
    Write-Log -severityLevel Error -logMessage $message
    throw $message
}

$vmnames = $inputs.vmname | select -Unique
$duplicates = Compare-object -referenceobject $inputs.vmname -differenceobject $vmnames 
if ($duplicates.InputObject.Length -gt 0) {
    $message = "The following VM names were found more than once ($(($duplicates.InputObject | Sort | Get-Unique) -join ', ')) in the inputs CSV file."
    Write-Log -severityLevel Error -logMessage $message
    throw $message
}

Write-Log -severityLevel Info -logMessage "Inputs CSV file successfully validated for completeness."

#Setup and validate email credential
if ($authenticatedEmail) {
    Write-Log -severityLevel Info -logMessage "Authenticated email specified, retrieving and/or storing credentials."
    if (!$secureMailCred) {
        $emailCredential = Get-StoredCredential -credName $fromEmail 
    } else {
        $emailCredential = Save-Credential -credName $fromEmail -cred $secureMailCred
    }
}

#First clear any active or stale VI Connections from this session.
try { Disconnect-VIServer * -Confirm:$false } catch {}
$viConnections = TestAndConnect-VIServer -vCenters $vCenters -cred $vcCredential

#Validate that all Tags and Categories required for the migration exist in all specified vCenters.
Validate-Tags -viConnections $viConnections

#ensure all VM attributes exist
Validate-CustomAttribute -attributeName $vamtSourceVcAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSourceHostAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSourceRpAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSourceFolderAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSourceDsAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSourcePgAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtMigrationTsAttribute -viConnections $viConnections
Validate-CustomAttribute -attributeName $vamtSnapshotNameAttribute -viConnections $viConnections

if ($action -eq "migrate") {
    $migrationTargets = Validate-MigrationTargets -inputs $inputs -viConnections $viConnections
} elseif ($action -eq "rollback") {
    $migrationTargets = Validate-RollbackTargets -inputs $inputs -viConnections $viConnections
} elseif ($action -eq "cleanup") {
    $cleanupTargets = Validate-CleanupTargets -inputs $inputs -viConnections $viConnections
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
            New-ScheduledExecution -startTime $startTime -parameters $PSBoundParameters
            return
        } else {
            Write-Log -severityLevel Info -logMessage "Current time ($vamtScriptLaunchTime) is before the beginning of the specified change window start time ($startTime). Whatif enabled. Continuing with Script."
        }
        
    } elseif (Check-InChangeWindow -executeTime $vamtScriptLaunchTime -startWindow $startTime -endWindow $endTime) {
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
    Write-Log -severityLevel Info -logMessage "Pre-$action target states:`n$($migrationTargets | ft | Out-String)"

    while(([array]($migrationTargets | ?{$_.job_state -notin $doNotRunStates})).count -gt 0) {
        #check and update job progress
        $migrationTargets | ?{$_.job_state -eq $jobInProgress} | %{
            $job = $_.job.ChildJobs
            #Job states: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate
            if ($job.State -ne $jobInProgress) {
                if ($job.State -eq $jobComplete) {
                    if ($job.Error -eq $null) {
                        Write-Log -severityLevel Info "VM move job for '$($_.tgt_vm.Name)' is complete."
                        $_.job_state = $jobComplete
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.tgt_vm -viConn $viConnections
                    } else {
                        Write-Log -severityLevel Warn "VM move job for '$($_.tgt_vm.Name)' completed with unhandled errors. Considering it '$jobCompleteWithErrors'. Errors:`n$(($job.Error | %{ if (!!$_) {$_.ToString()}}) -join "`n")"
                        $_.job_state = $jobCompleteWithErrors
                        $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtCompleteWithErrorsTagName -WhatIf:(!!$WhatIf) -viConn $viConnections
                    }
                } elseif ($job.State -eq $jobFailed) {
                    Write-Log -severityLevel Error "VM move job for '$($_.tgt_vm.Name)' failed with errors:`n$($job.Error.Exception.Message -join "`n")"
                    if (!!$job.Error -and $job.Error.ToString() -match $retryErrors) {
                        if ($_.attempts -lt $jobRetries) {
                            Write-Log -severityLevel Warn -logMessage "Error is eligible to be re-tried. Setting retry status to try again later for '$($_.tgt_vm.Name)'."
                            $_.job_state = "failed_pendingRetry"
                        } else {
                            Write-Log -severityLevel Error -logMessage "All retry attempts for '$($_.tgt_vm.Name)' have been exhaused. Setting job state to '$jobFailed'."
                            $_.job_state = $jobFailed
                            $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtFailedTagName -WhatIf:(!!$WhatIf) -viConn $viConnections
                        }
                    } else {
                        $_.job_state = $jobFailed
                        $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtFailedTagName -WhatIf:(!!$WhatIf) -viConn $viConnections
                    }
                } elseif ($job.State -eq "NotStarted") {
                    Write-Log -severityLevel Info "VM move job for '$($_.tgt_vm.Name)' is still preparing to run."
                } else {
                    Write-Log -severityLevel Error  "VM move job for '$($_.tgt_vm.Name)' ended with unsupported state $($job.State). Considering this job failed."
                    $_.job_state = $jobFailed
                    $_.tag_state = Set-VMStateTag -vm $_.tgt_vm -tagName $vamtFailedTagName -WhatIf:(!!$WhatIf) -viConn $viConnections
                }
            }
        }
        if (([array]($migrationTargets | ?{$_.job_state -notin $doNotRunStates})).count -le 0) {
            break
        }
        #check if changewindow is complete
        if ($changeWindow) {
            $stillWithinChangeWindow = Check-InChangeWindow -executeTime (Get-Date) -startWindow $startTime -endWindow $endTime
            if (!$stillWithinChangeWindow) {
                if ($parallelTaskCount -gt 0) {
                    Write-Log -severityLevel Warn -logMessage "We are nolonger inside our change window. Turning the job throttle down to 0. All currently in progress tasks will be allowed to finish."
                    $parallelTaskCount = 0
                    $migrationTargets | ?{$_.job_state -eq $jobReady} | %{ 
                        $_.job = "Job not executed due to being past the end of the change window."
                        $_.job_state = $jobNotRun
                    }
                }
                if (([array]($migrationTargets | ?{$_.job_state -eq $jobInProgress})).count -le 0) {
                    break
                }
            }
        }
        
        #calculate how many slots for new jobs we have
        [int]$movesInProgress = ([array]($migrationTargets | ?{$_.job_state -eq $jobInProgress})).count
        [int]$pendingMoves = ([array]($migrationTargets | ?{$_.job_state -like "*pendingRetry" -or $_.job_state -eq $jobReady})).count
        $currentThrottle = [math]::Max(0, ($parallelTaskCount - $movesInProgress))
        Write-Log -severityLevel Info -logMessage "There are currently $movesInProgress moves in progress and $pendingMoves moves waiting to start."

        [array]$batch = $migrationTargets | Sort-Object -Property attempts | ?{$_.job_state -eq $jobReady} | Select -First $currentThrottle 
        if ($batch.count -lt $currentThrottle) {
            $batch += $migrationTargets | Sort-Object -Property attempts | ?{$_.job_state -like "*pendingRetry"} | Select -First ($currentThrottle-$batch.count)
        }
        #launch new jobs
        if ($batch.count -gt 0) {
            Write-Log -severityLevel Info -logMessage "New batch of moves: $($batch.tgt_vm.Name -join ", ")"
            $batch | %{
                $vm = $_.tgt_vm
                $viConn = $viConnections | ?{$_.Id -eq ($vm.Uid -Split 'VirtualMachine' | Select -First 1)}

                [array]$activeTasks = Check-ActiveTasks -vm $vm -viConnection $viConn
                if ($null -ne $activeTasks) {
                    if ($_.attempts -lt $jobRetries) {
                        Write-Log -severityLevel Warn -logMessage "VM ($($vm.Name)) has $($activeTasks.count) active task(s) already. Setting retry status to try again later."
                        $_.job_state = "busy_pendingRetry"
                        $_.attempts++
                    } else {
                        $_.job_state = $jobFailed
                        $_.job = "Failed waiting for active tasks on VM to complete. Exhausted all $jobRetries retries."
                        Write-Log -severityLevel Error -logMessage "VM ($($vm.Name)) failed with error: $($_.job)"
                        $_.tag_state = Set-VMStateTag -vm $vm -tagName $vamtFailedTagName -WhatIf:(!!$WhatIf) -viConn $viConn
                    }
                    return
                }
                $jobParams = @{
                    viConn = $viConn
                    vm = $vm
                    WhatIf = !!$WhatIf
                    isRetry = ($_.attempts -gt 0)
                    cred = $vcCredential
                }
                if ($action -eq "migrate") {
                    $_.job = Start-MigrateVMJob @jobParams -compute $_.tgt_compute -network $_.tgt_network -storage $_.tgt_storage
                } elseif ($action -eq "rollback") {
                    $_.job = Start-RollbackVMJob @jobParams -vmhost $_.tgt_host -respool $_.tgt_respool -portgroup $_.tgt_network -vmfolder $_.tgt_folder -datastore $_.tgt_datastore -snapshot $_.tgt_snapshot
                }
                $_.job_state = $jobInProgress
                $_.attempts++
            }
        }

        if (([array]($migrationTargets | ?{$_.job_state -eq $jobInProgress})).count -gt 0) {
            Start-Sleep -Seconds $jobControllerRefreshInterval
        }
    }

    Write-Log -severityLevel Info -logMessage "$action target states:`n$($migrationTargets | ft | Out-String)"
    $finalObj = Save-Report -actionResult $migrationTargets
} elseif ($action -eq "cleanup") {
    Write-Log -severityLevel Info -logMessage "Pre-$action target states:`n$($cleanupTargets | ft | Out-String)"
    #Cleanup task
    while(([array]($cleanupTargets | ?{$_.job_state -notin $cleanupCompleteStates})).count -gt 0) {
        #check and update job progress
        $cleanupTargets | ?{$_.job_state -eq $jobInProgress} | %{
            $job = $_.job.ChildJobs
            #Job states: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate
            if ($job.State -ne $jobInProgress) {
                if ($job.State -eq $jobComplete) {
                    if ($job.Error -eq $null) {
                        Write-Log -severityLevel Info "VM cleanup job for '$($_.clean_vm.Name)' is complete."
                        $_.job_state = $jobComplete
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections
                    } else {
                        Write-Log -severityLevel Warn "VM cleanup job for '$($_.clean_vm.Name)' completed with unhandled errors. Considering it complete with errors."
                        $_.job_state = $jobCompleteWithErrors
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections
                    }
                } elseif ($job.State -eq $jobFailed) {
                    Write-Log -severityLevel Error "VM cleanup job for '$($_.clean_vm.Name)' failed with errors:`n$($job.Error.Exception.Message -join "`n")"
                    if ($job.Error.ToString() -match $retryErrors) {
                        if ($_.attempts -lt $jobRetries) {
                            Write-Log -severityLevel Warn -logMessage "Error is eligible to be re-tried. Setting retry status to try again later for '$($_.clean_vm.Name)'."
                            $_.job_state = "failed_pendingRetry"
                        } else {
                            Write-Log -severityLevel Error -logMessage "All retry attempts for '$($_.clean_vm.Name)' have been exhaused. Setting job state to '$jobFailed'."
                            $_.job_state = $jobFailed
                            $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections
                        }
                    } else {
                        $_.job_state = $jobFailed
                        $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections
                    }
                } elseif ($job.State -eq "NotStarted") {
                    Write-Log -severityLevel Info "VM cleanup job for '$($_.clean_vm.Name)' is still preparing to run."
                } else {
                    Write-Log -severityLevel Error  "VM cleanup job for '$($_.clean_vm.Name)' ended with unsupported state $($job.State). Considering this job failed."
                    $_.job_state = $jobFailed
                    $_.tag_state = Get-VMStateBasedOnTag -vm $_.clean_vm -viConn $viConnections
                }
            }            
        }
        if (([array]($cleanupTargets | ?{$_.job_state -notin $cleanupCompleteStates})).count -le 0) {
            break
        }
        
        #calculate how many slots for new jobs we have
        [int]$cleansInProgress = ([array]($cleanupTargets | ?{$_.job_state -eq $jobInProgress})).count
        [int]$pendingCleans = ([array]($cleanupTargets | ?{$_.job_state -like "*pendingRetry" -or $_.job_state -eq $jobReady})).count
        $currentThrottle = [math]::Max(0, ($parallelTaskCount - $cleansInProgress))
        Write-Log -severityLevel Info -logMessage "There are currently $cleansInProgress cleanups in progress and $pendingCleans cleanups waiting to start."

        [array]$batch = $cleanupTargets | ?{$_.job_state -eq $readyToCleanup} | Select -First $currentThrottle
        #launch new jobs
        if ($batch.count -gt 0) {
            Write-Log -severityLevel Info -logMessage "New batch of cleanups: $($batch.clean_vm.Name -join ", ")"
            $batch | %{
                $vm = $_.clean_vm
                $viConn = $_.clean_vc

                [array]$activeTasks = Check-ActiveTasks -vm $vm -viConnection $viConn
                if ($null -ne $activeTasks) {
                    if ($_.attempts -lt $jobRetries) {
                        Write-Log -severityLevel Warn -logMessage "VM ($($vm.Name)) has $($activeTasks.count) active task(s) already. Setting retry status to try again later."
                        $_.job_state = "busy_pendingRetry"
                        $_.attempts++
                    } else {
                        $_.job_state = $jobFailed
                        $_.job = "Failed waiting for active tasks on VM to complete. Exhausted all $jobRetries retries."
                        Write-Log -severityLevel Error -logMessage "VM ($($vm.Name)) failed with error: $($_.job)"
                        $_.tag_state = Get-VMStateBasedOnTag -vm $vm -viConn $viConn
                    }
                    return
                }
                $_.job = Start-CleanupVMJob -viConn $viConn -vm $vm -snapshot $_.clean_snapshot -cred $vcCredential -WhatIf:(!!$WhatIf)
                $_.job_state = $jobInProgress
                $_.attempts++
            }
        }

        if (([array]($cleanupTargets | ?{$_.job_state -eq $jobInProgress})).count -gt 0) {
            Start-Sleep -Seconds $jobControllerRefreshInterval
        }
    }

    Write-Log -severityLevel Info -logMessage "Post-$action VM states:`n$($cleanupTargets | ft | Out-String)"
    $finalObj = Save-Report -actionResult $cleanupTargets
} else {
    #unhandled action fail
    $errorMessage = "Unknown action '$action' received. Allowable options are 'migrate', 'rollback', 'cleanup'. Exiting."
    Write-Log -severityLevel Error -logMessage $errorMessage -skipConsole
    throw $errorMessage
}

$currentTime = Get-Date
$finalMessage = "Script run summary:`n`tScript start: '$vamtScriptLaunchTime'"
$finalMessage += "`n`tScript runtime: $(($currentTime - $vamtScriptLaunchTime).Minutes) minutes"
$finalMessage += "`n`tScript completion: '$currentTime'"

Write-Log -severityLevel Info -logMessage $finalMessage
Write-Log -severityLevel Info -logMessage "Final report:`n$($finalObj | ft | Out-String)"

if (![string]::IsNullOrWhiteSpace($smtpServer)) {
    try {
        $reportParameters = @{
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