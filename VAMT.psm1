<#
    .NOTES
    ===========================================================================
     Created by:    Austin Browder
     Date:          August 24, 2022
     Organization:  VMware Professional Services
    ===========================================================================
    .EXAMPLE
        Import-Module -Name .\VAMT.psm1
#>

#############################################################################################################################
#
#region Function Definitions
#
#############################################################################################################################

function Initialize-VIServer {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$vCenters,
        [Parameter()]
        [PSCredential]$Credential,
        [Parameter()]
        [String]$credentialDirectory
    )
    $connections = @()
    foreach ($vCenter in $vCenters) {
        try {
            if ($null -eq $Credential) {
                Write-Log -severityLevel Debug -logMessage "No credential for vCenter $vCenter was passed in via input parameter. Starting stored credential retrieval."
                $cred = Get-StoredCredential -credName $vCenter -credentialDirectory $credentialDirectory
            } else {
                Write-Log -severityLevel Debug -logMessage "Credential for vCenter $vCenter with Username $($cred.UserName) was passed in via input parameter. Overwriting stored credential."
                $cred = Save-Credential -credName $vCenter -cred $Credential -credentialDirectory $credentialDirectory
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
        [String]$credName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$credentialDirectory
    )

    $credFile = "$credentialDirectory\$credName-$($env:USERNAME).cred"
    if (Test-Path -Path $credFile) {
        $cred = Import-Clixml -Path $credFile
        Write-Log -severityLevel Debug -logMessage "Found credential for '$credName'. User: $($cred.UserName)"
    } else {
        Write-Log -severityLevel Debug -logMessage "No stored credential found for '$credName'."
        $cred = Save-Credential -credName $credName -credentialDirectory $credentialDirectory
    }

    return $cred
}

function Save-Credential {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$credName,

        [Parameter()]
        [PSCredential]$cred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$credentialDirectory
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
        [ValidateNotNullOrEmpty()]
        [String]$logDir,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$logFileNamePrefix,

        [Parameter()]
        [String]$syslogServer,

        [Parameter()]
        [Int]$syslogPort,

        [Parameter()] <#@{
            'Write-Log:logDir' = 'C:\logs'
            'Write-Log:logFileNamePrefix' = 'Migrate'
        }#>
        [Object]$logDefaults,

        [Parameter()]
        [Switch]$skipConsole,

        [Parameter()]
        [Switch]$debugLogging
    )

    if($null -ne $logDefaults) {
        $Script:PSDefaultParameterValues = $logDefaults
    }

    if(![string]::IsNullOrEmpty($logDir) -and !(Test-Path $logDir)){
        Write-Host "Logging directory for current execution ($logDir) was not found. Creating directory now. - $(Get-Date)" -foregroundColor Cyan
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
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
            $logToConsole = $debugLogging -and !$skipConsole
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

    if (![string]::IsNullOrEmpty($logDir) -and ![string]::IsNullOrEmpty($logFileNamePrefix)) {
        Add-Content -Path "$logDir/$($logFileNamePrefix)_Script_Log.log" -value $stampedlogMessage
        if ($severityLevel -eq "Error") {
            Add-content -Path "$logDir/$($logFileNamePrefix)_Error_Log.log" -value $stampedlogMessage
        }
    }

    if (![string]::IsNullOrEmpty($syslogServer)) {
        $params = @{}
        $params.syslogServer = $syslogServer
        $params.syslogPort = $syslogPort
        $params.severityLevel = $syslogSeverity
        $params.syslogMessage = $logMessage
        $params.logDate = $logDate
        $params.logFileNamePrefix = $logFileNamePrefix
        $params.logDir = $logDir
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
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$logFileNamePrefix,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$logDir
    )

    $logParameters = @{
        syslogServer = ""
        logFileNamePrefix = $logFileNamePrefix
        logDir = $logDir
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

function Confirm-InChangeWindow {
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
        [Hashtable]$parameters,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$scriptPath,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$workingDirectory
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

function Confirm-Tags {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$tagDetails,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections
    )

    $missingCategories = @()
    $categories = $viConnections | %{
        $viConn = $_
        try {
            $category = Get-TagCategory -Name $tagDetails.tagCatName -Server $viConn -ErrorAction Stop
            if ($category.Cardinality -ne 'Single') {
                throw "Tag cardinality was detected as '$($category.Cardinality)'. Must be set to 'Single'."
            }
            $category | Add-Member -MemberType NoteProperty -Name 'vCenter' -Value $viConn
            $category
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to validate tag category '$($tagDetails.tagCatName)' in vCenter '$($viConn.Name)'. Error:`n`t$($_.Exception.message)"
            $missingCategories += "'$($tagDetails.tagCatName)' in vCenter '$($viConn.Name)'"
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
            $tag = Get-Tag -Name $tagDetails.readyTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.readyTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.readyTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.inProgressTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.inProgressTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.inProgressTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.completeTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.completeTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.completeTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.completeWithErrorsTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.completeWithErrorsTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.completeWithErrorsTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.failedTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.failedTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.failedTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.rollbackTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.rollbackTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.rollbackTagName)' in vCenter '$($category.vCenter.Name)'"
        }
        try {
            $tag = Get-Tag -Name $tagDetails.readyToRollbackTagName -Category $category -Server $category.vCenter -ErrorAction Stop
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to find tag '$($tagDetails.readyToRollbackTagName)' in category '$($category.Name)' in vCenter '$($category.vCenter.Name)'. Error:`n`t$($_.Exception.message)"
            $missingTags += "'$($tagDetails.readyToRollbackTagName)' in vCenter '$($category.vCenter.Name)'"
        }
    }

    if ($missingTags.Length -gt 0) {
        $message = "Missing tags detected: $($missingTags -join ', ')"
        Write-Log -severityLevel Error -logMessage $message
        throw $message 
    }

    Write-Log -severityLevel Info -logMessage "All tags and categories have been validated."
}

function Confirm-CustomAttribute {
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
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$stateTagsCatName
    )

    $vm = get-vm $vm -Server $viConn
    $tagAssignment = Get-TagAssignment -Entity $vm -Category $stateTagsCatName -Server $viConn
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
        [String]$stateTagsCatName,

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
        Write-Log @logParameters -severityLevel Info -logMessage "Refreshing VM '$($vm.Name)' object"
        $vm = get-vm $vm -Server $viConn
        #Update viConn incase more than 1 was passed.
        $viConn = $viConn | ?{$_.Id -eq ($vm.Uid -Split 'VirtualMachine' | Select -First 1)}

        Write-Log @logParameters -severityLevel Info -logMessage "Preparing to set '$stateTagsCatName : $tagName' tag on '$($vm.Name)'"
        $currentTagAssignment = Get-TagAssignment -Entity $vm -Category $stateTagsCatName -Server $viConn
        if (!!$currentTagAssignment) {
            Remove-TagAssignment -TagAssignment $currentTagAssignment -Confirm:$false -WhatIf:(!!$WhatIf)
        }
        $tag = Get-Tag -Name $tagName -Category $stateTagsCatName -Server $viConn 
        $null = New-TagAssignment -Entity $vm -Tag $tag -Server $viConn -WhatIf:(!!$WhatIf)
        Write-Log @logParameters -severityLevel Info -logMessage "Successfully to set '$stateTagsCatName : $tagName' tag on '$($vm.Name)'"
    } catch { 
        Write-Log @logParameters -severityLevel Error -logMessage "Failed to set '$stateTagsCatName : $tagName' tag on '$($vm.Name)'"
        throw $_ 
    }

    return $tag.Name
}

function Confirm-ActiveTasks {
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

function Test-VMTools {
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

function Confirm-NotNullOrEmpty {
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

function Confirm-VMs {
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

function Confirm-Computes {
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
        throw "Invalid computeType '$computeType' passed into Confirm-Computes function"
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

function Confirm-MigrationTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$inputHeaders,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$tagDetails,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$jobStates,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$doNotRunStates,
        
        [Parameter()]
        [Switch]$ignoreVmTools
    )
    #Check that all VMs and target locations listed in input file are valid
    $missingvCenters = $inputs."$($inputHeaders.vcenter)".ToLower() | select -Unique | ?{$_ -notin $viConnections.Name.ToLower()}
    if ($missingvCenters.Length -gt 0) {
        $missingMessage = "The following vCenters specified in the input CSV are missing from the 'vCenters' input:$($missingvCenters -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    $vmValidationResult = Confirm-VMs -vmNames $inputs."$($inputHeaders.name)" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    $cmptValidationResult = Confirm-Computes -computeNames $inputs."$($inputHeaders.compute)" -computeType All -viConnection $viConnections
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
    #$dscViews = Get-View -ViewType StoragePod -Server $viConnections
    $migrationTargets = $inputs | %{
        $vmName = $_."$($inputHeaders.name)"
        $vCenterName = $_."$($inputHeaders.vcenter)"
        $computeName = $_."$($inputHeaders.compute)"
        $networkName = $_."$($inputHeaders.network)"
        $storageName = $_."$($inputHeaders.storage)"

        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $srcViConn = $viConnections | ?{$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select -First 1)}
        $tgtViConn = $viConnections | ?{$_.Name -eq $vCenterName}
        $computeObj = $computes | ?{$_.Name -eq $computeName -and $_.Uid -like "*$($tgtViConn.Id)*"} 
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
        $vmState = Get-VMStateBasedOnTag -vm $vmObj -viConn $srcViConn -stateTagsCatName $tagDetails.tagCatName
        $jobState = $vmState
        $job = $null
        $eligibleToRun = $false
        $notAttempted = "Not attempted due to job state '{0}'"
        if ($jobState -eq $tagDetails.inProgressTagName) {
            $jobState = $jobStates.inProgressExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.completeTagName) {
            $jobState = $jobStates.completeExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.completeWithErrorsTagName) {
            $jobState = $jobStates.completeWithErrorsExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.failedTagName) {
            $jobState = $jobStates.failedExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.rollbackTagName) {
            $jobState = $jobStates.rolledBackExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq "notag") {
            $jobState = $jobStates.jobNotRun
            $validationErrors += ($notAttempted -f $jobState)
        } else {
            $eligibleToRun = $true
        }

        #Check VMtools IF machine is powered on and we are not ignoring tools - this will support pre-powered off machines
        if ($eligibleToRun -and $vmObj.PowerState -eq "PoweredOn" -and !$ignoreVmTools) {
            if (!(Test-VMTools -vm $vmObj)) {
                $jobState = $jobStates.jobNotRun
                $validationErrors += "Not attempted due to VMware tools not running."
            }
        }
        if ($validationErrors.Length -gt 0) {
            $job = $validationErrors -join ", `n"
            if ($jobState -notin $doNotRunStates) {
                $jobState = $jobStates.jobNotRun
            }
        }

        [PSCustomObject]@{
            src_vcenter = $srcViConn
            tgt_vm = $vmObj
            tgt_compute = $computeObj
            tgt_network = $networkObj
            tgt_storage = $storageObj
            tgt_vcenter = $tgtViConn
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

function Confirm-RollbackTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$inputHeaders,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$tagDetails,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$vCenterAttrs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$jobStates,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]]$doNotRunStates,
        
        [Parameter()]
        [Switch]$ignoreVmTools
    )
    #Check that all VMs listed in input file are valid


    $vmValidationResult = Confirm-VMs -vmNames $inputs."$($inputHeaders.name)" -viConnection $viConnections
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
        $vmName = $_."$($inputHeaders.name)"
        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackVcName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceVcAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceVcAttribute)
            $rollbackHostId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceHostAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceHostAttribute)
            $rollbackResPoolId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceRpAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceRpAttribute)
            $rollbackVmFolderId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceFolderAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceFolderAttribute)
            $rollbackDatastoreId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceDsAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceDsAttribute)
            $rollbackPortGroupId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourcePgAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourcePgAttribute)
            $rollbackSnapshotName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.snapshotNameAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.snapshotNameAttribute)
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
        $target = $_
        $vm = $target.tgt_vm
        $srcViConn = $viConnections | ?{$_.Id -eq ($vm.Uid -Split 'VirtualMachine' | Select -First 1)}
        $tgtViConn = $viConnections | ?{$_.Name -eq $target.tgt_vc}

        $validationErrors = @()
        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $tagDetails.tagCatName
        $jobState = $vmState
        $job = $null
        $eligibleToRun = $false
        $notAttempted = "Not attempted due to job state '{0}'"
        if ($jobState -eq $tagDetails.inProgressTagName) {
            $jobState = $jobStates.inProgressExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.completeTagName) {
            $jobState = $jobStates.completeExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.completeWithErrorsTagName) {
            $jobState = $jobStates.completeWithErrorsExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.failedTagName) {
            $jobState = $jobStates.failedExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.rollbackTagName) {
            $jobState = $jobStates.rolledBackExternal
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq "notag") {
            $jobState = $jobStates.jobNotRun
            $validationErrors += ($notAttempted -f $jobState)
        } else {
            $eligibleToRun = $true
        }

        if (!$tgtViConn) {
            Write-Log -severityLevel Error -logMessage "No current connection for rollback vCenter '$($_.tgt_vc)' was found (vCenter for VM: '$($vm.Name)'). You must specify all required vCenters when executing the script."
            $missingvCenters += $_.tgt_vc
            continue
        }

        $notFoundError = "No object found matching MoRef or Name '{0}' in vCenter '$($tgtViConn.Name)'"
        try {
            $rollbackHostId = $_.tgt_host
            $hostObj = Get-VIObjectByVIView -MORef $rollbackHostId -Server $tgtViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackHostId)
                $validationErrors += ($notFoundError -f $rollbackHostId)
            }
        }
        try {
            $rollbackResPoolId = $_.tgt_respool
            $rpObj = Get-VIObjectByVIView -MORef $rollbackResPoolId -Server $tgtViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackResPoolId)
                $validationErrors += ($notFoundError -f $rollbackResPoolId)
            }
        }
        try {
            $rollbackVmFolderId = $_.tgt_folder
            $folderObj = Get-VIObjectByVIView -MORef $rollbackVmFolderId -Server $tgtViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackVmFolderId)
                $validationErrors += ($notFoundError -f $rollbackVmFolderId)
            }
        }
        try {
            $rollbackPortGroupId = $_.tgt_network
            $pgObj = Get-VIObjectByVIView -MORef $rollbackPortGroupId -Server $tgtViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackPortGroupId)
                $validationErrors += ($notFoundError -f $rollbackPortGroupId)
            }
        }
        try {
            $rollbackDatastoreId = $_.tgt_datastore
            $dsObj = Get-VIObjectByVIView -MORef $rollbackDatastoreId -Server $tgtViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackDatastoreId)
                $validationErrors += ($notFoundError -f $rollbackDatastoreId)
            }
        }
        try {
            $rollbackSnapshotName = $_.tgt_snapshot
            $snapObj = Get-Snapshot -VM $vm -Name $rollbackSnapshotName -Server $srcViConn -ErrorAction Stop
        } catch {
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackSnapshotName)
                $validationErrors += ($notFoundError -f $rollbackSnapshotName)
            }
        }
        
        #Check VMtools IF machine is powered on and we are not ignoring tools - this will support pre-powered off machines
        if ($eligibleToRun -and $vm.PowerState -eq "PoweredOn" -and !$ignoreVmTools) {
            if (!(Test-VMTools -vm $vm)) {
                $validationErrors += "Not attempted due to VMware tools not running."
            }
        }
        if ($validationErrors.Length -gt 0) {
            $job = $validationErrors -join ", `n"
            if ($jobState -notin $doNotRunStates) {
                $jobState = $jobStates.jobNotRun
            }
        }

        [PSCustomObject]@{
            src_vcenter = $srcViConn
            tgt_vm = $vm
            tgt_vcenter = $tgtViConn
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

function Confirm-CleanupTargets {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnections,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$inputs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$inputHeaders,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$snapshotAttrName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object]$tagDetails,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$readyState
    )
    #Check that all VMs listed in input file are valid
    $vmValidationResult = Confirm-VMs -vmNames $inputs."$($inputHeaders.name)" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    if (($missingVMs.Length) -gt 0) {
        $missingMessage = "The following inputs are missing from the provided vCenters.`n`tMissing VMs: $($missingVMs -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    #Check that rollback attributes are populated on the input VM objects.
    $cleanupTargets = $inputs | %{
        $vmName = $_."$($inputHeaders.name)"
        $vmObj = $vms | ?{$_.Name -eq $vmName}
        $viConn = $viConnections | ?{$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select -First 1)}
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackSnapshotName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($snapshotAttrName) -failMessage ($emptyAttrError -f $snapshotAttrName)
            $status = $readyState
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

        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn -stateTagsCatName $tagDetails.tagCatName

        [PSCustomObject]@{
            clean_vm = $vm
            clean_vc = $viConn
            clean_snapshot = $snapObj
            tag_state = $vmState
            job_state = $readyState
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
        $srcViConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $tgtViConn,

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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$srcCred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$tgtCred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $scriptVars,

        [Parameter()]
        [Switch]$isRetry,

        [Parameter()]
        [Switch]$WhatIf
    )

    $jobFunctions = "function Start-PreMigrationExtensibility { ${function:Start-PreMigrationExtensibility} }`n"
    $jobFunctions += "function Start-PostMigrationExtensibility { ${function:Start-PostMigrationExtensibility} }`n"
    $jobFunctions += "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Confirm-ActiveTasks { ${function:Confirm-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }`n"
    $jobFunctions += "function Get-VMStateBasedOnTag { ${function:Get-VMStateBasedOnTag} }`n"
    $jobFunctions += "function Set-VMStateTag { ${function:Set-VMStateTag} }"

    $test = !!$WhatIf
    $retry = !!$isRetry
    $migrationJob = Start-Job -ScriptBlock {
        try {
            $using:scriptVars | %{ New-Variable -Name $_.Name -Value $_.Value}
            #Had to move awawy from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $using:viConn -Session $using:viConn.SessionSecret
            $srcViConn = Connect-ViServer -Server $using:srcViConn.Name -Credential $using:srcCred
            $tgtViConn = Connect-ViServer -Server $using:tgtViConn.Name -Credential $using:tgtCred
            $vm = Get-VIObjectByVIView -MORef $using:vm.Id -Server $srcViConn
            $compute = Get-VIObjectByVIView -MORef $using:compute.Id -Server $tgtViConn
            $network = Get-VIObjectByVIView -MORef $using:network.Id -Server $tgtViConn
            $storage = Get-VIObjectByVIView -MORef $using:storage.Id -Server $tgtViConn
            $WhatIf = $using:test
            $isRetry = $using:retry
            $vmName = $vm.Name
            $Script:envLogPrefix = $vmName
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
            }
            if (![string]::IsNullOrEmpty($vamtSyslogServer)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogServer', $vamtSyslogServer)
            }
            if (![string]::IsNullOrEmpty($vamtSyslogPort)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogPort', $vamtSyslogPort)
            }

            if ($isRetry) {
                $retryMessage = "retry of "
            }
            Write-Log -severityLevel Info -logMessage ("Starting {0}migration process on '$($vm.Name)'." -f $retryMessage)
            
            #validate no-one is stepping on our job
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $vamtTagDetails.tagCatName
            $allowedStates = @($vamtTagDetails.readyTagName)
            if ($isRetry) {
                $allowedStates += $vamtTagDetails.inProgressTagName
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.inProgressTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $srcViConn
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }
            
            #get current compute, network, storage
            Write-Log -severityLevel Info -logMessage "Gathering current compute, network, storage, folder details for '$($vm.Name)'."
            $currentVC = $srcViConn.Name
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
                Server = $tgtViConn
                WhatIf = !!$WhatIf
                ErrorAction = "Stop"
            }
            $currentStorage = Get-View -id $currentDsId -Server $srcViConn
            if ($storage.Id -notin @($currentDsId, $currentStorage.Parent.ToString())) {
                $moveParameters.Datastore = $storage
            }
            if ($currentPgId -ne $network.Id) {
                if ($null -ne $network.NetworkType) {
                    $moveParameters.Network = $network
                } else {
                    $moveParameters.PortGroup = $network
                }
            }
            $currentResPool = Get-VIObjectByVIView -MORef $currentRpId -Server $srcViConn
            if ($compute.Id -notin @($currentHostId, $currentRpId, $currentResPool.ExtensionData.Owner.ToString())) {
                if ($compute.ExtensionData.MoRef.Type -eq "ClusterComputeResource") {
                    $tgtCompute = Get-VMHost -Location $compute | ?{$_.ConnectionState -eq "Connected"} | Get-Random
                } elseif ($compute.ExtensionData.MoRef.Type -eq "ResourcePool") {
                    $tgtCluster = Get-Cluster -Id $compute.ExtensionData.Owner.ToString() -Server $tgtViConn
                    $tgtCompute = Get-VMHost -Location $tgtCluster | ?{$_.ConnectionState -eq "Connected"} | Get-Random
                } else {
                    $tgtCompute = $compute
                }
                $moveParameters.Destination = $tgtCompute
            }
            #catch incase nothing is apparently moving, maybe move has already occured or a mistake was made.
            if (!$moveParameters.Destination -and !$moveParameters.Datastore) {
                $message = "Current VM location details match the migration target. Nothing to do."
                Write-Log -severityLevel Error -logMessage $message -skipConsole
                Write-Error $message
                return [PSCustomObject]@{
                    result = "Migration parameters for VM '$($vm.Name)' are too similar to current Cluster/Storage. No action performed."
                }
            }

            #write attributes for current compute, network, storage, snapshot name
            $sourceVcAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourceVcAttribute
            $sourceHostAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourceHostAttribute
            $sourceRpAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourceRpAttribute
            $sourceFolderAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourceFolderAttribute
            $sourceDsAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourceDsAttribute
            $sourcePgAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.sourcePgAttribute
            $timestampAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.migrationTsAttribute
            $snapshotNameAttribute = Get-CustomAttribute -Server $srcViConn -Name $vamtVcAttrDetails.snapshotNameAttribute

            Write-Log -severityLevel Info -logMessage "Writing current compute, network, storage, folder details to '$($vm.Name)' custom attributes."
            if (!$WhatIf) {
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks
                $null = $vm | Set-Annotation -CustomAttribute $sourceVcAttribute -Value $currentVC
                $null = $vm | Set-Annotation -CustomAttribute $sourceHostAttribute -Value $currentHostId
                $null = $vm | Set-Annotation -CustomAttribute $sourceRpAttribute -Value $currentRpId
                $null = $vm | Set-Annotation -CustomAttribute $sourceFolderAttribute -Value $currentFolderId
                $null = $vm | Set-Annotation -CustomAttribute $sourceDsAttribute -Value $currentDsId
                $null = $vm | Set-Annotation -CustomAttribute $sourcePgAttribute -Value $currentPgId
                $null = $vm | Set-Annotation -CustomAttribute $timestampAttribute -Value $vamtScriptLaunchTime.ToString()
            }

            #preMigration extensibility stub
            Write-Log -severityLevel Info -logMessage "Starting Pre Migration Extensibility actions."
            $extResult = Start-PreMigrationExtensibility -viConnection $srcViConn -vm $vm -WhatIf:$WhatIf
            if (!$extResult) {
                throw "Pre Migration Extensibility actions failed."
            }

            #shutdown VM
            $vm = Get-VM -Id $vm.Id -Server $srcViConn #refresh VM object
            if (!$WhatIf) {
                if ($vm.PowerState -eq "PoweredOn") {
                    $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks
                    Write-Log -severityLevel Info -logMessage "Beginning GuestOS Shutdown on '$($vm.Name)'"
                    $null = Stop-VMGuest -VM $vm -Confirm:$false
                    $sleepTimer = 5 #seconds
                    while ($vm.PowerState -eq "PoweredOn") {
                        Start-Sleep -Seconds $sleepTimer
                        $waitDuration += $sleepTimer
                        if ($waitDuration -ge $vamtOsShutdownTimeout) {
                            if (!$vamtForceShutdown) {
                                throw "Shutdown of VM '$($vm.Name)' has timed out and force shutdown is disabled. Considering this job failed."
                            }
                            Write-Log -severityLevel Warn -logMessage "Shutdown of VM '$($vm.Name)' has timed out. Forcing poweroff now."
                            $vm = Stop-VM -VM $vm -Server $viConn -Confirm:$false
                        }
                        $vm = Get-VM -Id $vm.Id -Server $srcViConn #refresh VM object
                    }
                } else {
                    Write-Log -severityLevel Info -logMessage "'$($vm.Name)' is already PoweredOff. Continuing."
                } 
            } else {
                Write-Log -severityLevel Info -logMessage "WhatIf enabled. Not modifying '$($vm.Name)'. Current PowerState: '$($vm.PowerState)'. Continuing."
            }

            #snapshot VM
            Write-Log -severityLevel Info -logMessage "Creating/Retrieving pre-migration snapshot on '$($vm.Name)'."
            $snapshotName = "VAMT_Migration_$($vamtScriptLaunchTime.ToShortDateString() -replace '/','_')_$($vamtScriptLaunchTime.ToLongTimeString() -replace ' ','_')"
            $snapshotDescription = "Snapshot taken by VAMT migration script.`nRun by: $($env:USERNAME)"
            $snapshot = Get-Snapshot -VM $vm -Name $snapshotName -Server $srcViConn -ErrorAction SilentlyContinue
            if (!$snapshot) {
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $snapshot = New-Snapshot -VM $vm -Name $snapshotName -Description $snapshotDescription -Server $srcViConn -Confirm:$false -WhatIf:$WhatIf -ErrorAction Stop
            }
            $null = $vm | Set-Annotation -CustomAttribute $snapshotNameAttribute -Value $snapshot.Name -WhatIf:$WhatIf
            Write-Log -severityLevel Info -logMessage "Successfully created/retrieved pre-migration snapshot on '$($vm.Name)' with name: $snapshotName"
            
            #Move VM
            Write-Log -severityLevel Info -logMessage "Starting VM Migration for '$($vm.Name)'."
            Write-Log -severityLevel Debug -logMessage "VM migration spec:`n$($moveParameters | Out-String)"
            $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
            $vm = Move-VM @moveParameters
            if ($compute.ExtensionData.MoRef.Type -eq "ResourcePool" -and $vm.ResourcePoolId -ne $compute.Id) {
                $moveParameters = @{
                    VM = $vm
                    Destination = $compute
                    Confirm = $false
                    Server = $tgtViConn
                    WhatIf = !!$WhatIf
                    ErrorAction = "Stop"
                }
                Write-Log -severityLevel Info -logMessage "Moving VM '$($vm.Name)' into resource pool '$($compute.Name)'."
                $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
                $vm = Move-VM @moveParameters
            }


            #start the VM and wait for VM tools
            Write-Log -severityLevel Info -logMessage "Migration completed successfully. Powering on '$($vm.Name)'."
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $vm = Start-VM -VM $vm -Server $tgtViConn -Confirm:$false -WhatIf:$WhatIf
            if (!$WhatIf -and !$vamtIgnoreVmTools) {
                Write-Log -severityLevel Info -logMessage "Waiting for VMware Tools...(Timeout: $vamtOsPowerOnTimeout seconds)"
                #Adding sleep to avoid VMtools not installed issue
                Start-Sleep -Seconds 25
                $vm = Wait-Tools -VM $vm -TimeoutSeconds $vamtOsPowerOnTimeout -ErrorAction Stop
            }

            #write attributes to migrated machine if it's in a new vCenter as attributes are not moved
            if ($srcViConn.Name -notcontains $tgtViConn.Name) {
                Write-Log -severityLevel Info -logMessage "Writing past compute, network, storage, folder details to '$($vm.Name)' custom attributes."
                if (!$WhatIf) {
                    $sourceVcAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourceVcAttribute
                    $sourceHostAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourceHostAttribute
                    $sourceRpAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourceRpAttribute
                    $sourceFolderAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourceFolderAttribute
                    $sourceDsAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourceDsAttribute
                    $sourcePgAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.sourcePgAttribute
                    $timestampAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.migrationTsAttribute
                    $snapshotNameAttribute = Get-CustomAttribute -Server $tgtViConn -Name $vamtVcAttrDetails.snapshotNameAttribute
                    $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks
                    $null = $vm | Set-Annotation -CustomAttribute $sourceVcAttribute -Value $currentVC
                    $null = $vm | Set-Annotation -CustomAttribute $sourceHostAttribute -Value $currentHostId
                    $null = $vm | Set-Annotation -CustomAttribute $sourceRpAttribute -Value $currentRpId
                    $null = $vm | Set-Annotation -CustomAttribute $sourceFolderAttribute -Value $currentFolderId
                    $null = $vm | Set-Annotation -CustomAttribute $sourceDsAttribute -Value $currentDsId
                    $null = $vm | Set-Annotation -CustomAttribute $sourcePgAttribute -Value $currentPgId
                    $null = $vm | Set-Annotation -CustomAttribute $timestampAttribute -Value $vamtScriptLaunchTime.ToString()
                    $null = $vm | Set-Annotation -CustomAttribute $snapshotNameAttribute -Value $snapshot.Name
                }
            }

            #post migraion extensibility stub
            Write-Log -severityLevel Info -logMessage "Starting Post Migration Extensibility actions."
            $extResult = Start-PostMigrationExtensibility -viConnection $tgtViConn -vm $vm -WhatIf:$WhatIf
            if (!$extResult) {
                throw "Post Migration Extensibility actions failed."
            }

            #change tag to complete
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.completeTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $tgtViConn

            Write-Log -severityLevel Info -logMessage "Migration of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer * -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully moved VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in migration job:`n$_"
            Write-Log -severityLevel Error -logMessage $message -skipConsole
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    } -InitializationScript ([scriptblock]::Create($jobFunctions)) -ArgumentList($srcViConn,$tgtViConn,$vm,$compute,$network,$storage,$cred,$retry,$test,$scriptVars)

    return $migrationJob 
}

function Start-RollbackVMJob {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $srcViConn,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $tgtViConn,

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
        $network,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $vmfolder,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $datastore,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $snapshot,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$srcCred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$tgtCred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $scriptVars,

        [Parameter()]
        [Switch]$isRetry,

        [Parameter()]
        [Switch]$WhatIf
    )

    $jobFunctions = "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Start-PostMigrationExtensibility { ${function:Start-PostMigrationExtensibility} }`n"
    $jobFunctions += "function Confirm-ActiveTasks { ${function:Confirm-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }`n"
    $jobFunctions += "function Get-VMStateBasedOnTag { ${function:Get-VMStateBasedOnTag} }`n"
    $jobFunctions += "function Set-VMStateTag { ${function:Set-VMStateTag} }"

    $test = !!$WhatIf
    $retry = !!$isRetry
    $rollbackJob = Start-Job -ScriptBlock {
        try {
            $using:scriptVars | %{ New-Variable -Name $_.Name -Value $_.Value}
            #Had to move awawy from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $using:viConn -Session $using:viConn.SessionSecret
            $srcViConn = Connect-ViServer -Server $using:srcViConn.Name -Credential $using:srcCred
            $tgtViConn = Connect-ViServer -Server $using:tgtViConn.Name -Credential $using:tgtCred
            $vm = Get-VIObjectByVIView -MORef $using:vm.Id -Server $srcViConn
            $vmName = $vm.Name
            $vmhost = Get-VIObjectByVIView -MORef $using:vmhost.Id -Server $tgtViConn
            $respool = Get-VIObjectByVIView -MORef $using:respool.Id -Server $tgtViConn
            $network = Get-VIObjectByVIView -MORef $using:network.Id -Server $tgtViConn
            $vmfolder = Get-VIObjectByVIView -MORef $using:vmfolder.Id -Server $tgtViConn
            $datastore = Get-VIObjectByVIView -MORef $using:datastore.Id -Server $tgtViConn
            $snapshotName = $using:snapshot.Name
            $WhatIf = $using:test
            $isRetry = $using:retry
            $Script:envLogPrefix = $vmName
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
            }
            if (![string]::IsNullOrEmpty($vamtSyslogServer)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogServer', $vamtSyslogServer)
            }
            if (![string]::IsNullOrEmpty($vamtSyslogPort)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogPort', $vamtSyslogPort)
            }

            if ($isRetry) {
                $retryMessage = "retry of "
            }
            Write-Log -severityLevel Info -logMessage ("Starting {0}rollback process on '$vmName'." -f $retryMessage)

            #validate no-one is stepping on our job
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $vamtTagDetails.tagCatName
            $allowedStates = @($vamtTagDetails.readyToRollbackTagName)
            if ($isRetry) {
                $allowedStates += $vamtTagDetails.inProgressTagName
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.inProgressTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $srcViConn
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }

            #get current compute, network, storage
            Write-Log -severityLevel Info -logMessage "Gathering current compute, network, storage, folder details for '$vmName'."
            $currentVC = $srcViConn.Name
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
                Server = $tgtViConn
                WhatIf = $WhatIf
                ErrorAction = "Stop"
            }
            if ($currentDsId -ne $datastore.Id -or $srcViConn.Name -notcontains $tgtViConn.Name) {
                $moveParameters.Datastore = $datastore
            }
            if ($currentPgId -ne $network.Id -or $srcViConn.Name -notcontains $tgtViConn.Name) {
                #Move-VM uses different network parameters for NSX-T networks vs std & vds PortGroups
                if ($null -ne $network.NetworkType) {
                    $moveParameters.Network = $network
                } else {
                    $moveParameters.PortGroup = $network
                }
            }
            if ($currentFolderId -ne $vmfolder.Id -or $srcViConn.Name -notcontains $tgtViConn.Name) {
                $moveParameters.InventoryLocation = $vmfolder
            }
            $currentHost = Get-VIObjectByVIView -MORef $currentHostId -Server $srcViConn
            if (($currentHostId -ne $vmhost.Id -and $currentHost.Parent.Id -ne $vmhost.Parent.Id) -or $srcViConn.Name -notcontains $tgtViConn.Name) {
                $moveParameters.Destination = $vmhost
            }
            #catch incase nothing is apparently moving, just add the compute and vCenter will handle it gracefully.
            if (!$moveParameters.Destination -and !$moveParameters.Datastore -and !$moveParameters.InventoryLocation) {
                $message = "Current VM location details match the rollback targets. Will not attempt Move-VM."
                Write-Log -severityLevel Error -logMessage $message
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
            $vm = Get-VM -Id $vm.Id -Server $srcViConn #refresh VM object
            if (!$WhatIf) {
                if ($vm.PowerState -eq "PoweredOn") {
                    $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks
                    Write-Log -severityLevel Info -logMessage "Beginning PowerOff on '$($vm.Name)'"
                    $vm = Stop-VM -VM $vm -Server $srcViConn -Confirm:$false
                } else {
                    Write-Log -severityLevel Info -logMessage "'$($vm.Name)' is already PoweredOff. Continuing."
                } 
            } else {
                Write-Log -severityLevel Info -logMessage "WhatIf enabled. Not modifying '$($vm.Name)'. Current PowerState: '$($vm.PowerState)'. Continuing."
            }
            
            #Move VM
            if ($moveVM) {
                Write-Log -severityLevel Info -logMessage "Starting VM Rollback Migration for '$($vm.Name)'."
                Write-Log -severityLevel Debug -logMessage "VM migration spec:`n$($moveParameters | Out-String)"
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $vm = Move-VM @moveParameters
        
                #check to restore resource pool that VM originally lived in
                if ($vm.ResourcePoolId -ne $respool.Id) {
                    $moveParameters = @{
                        VM = $vm
                        Destination = $respool
                        Confirm = $false
                        Server = $tgtViConn
                        WhatIf = $WhatIf
                        ErrorAction = "Stop"
                    }
                    Write-Log -severityLevel Info -logMessage "Restoring VM '$($vm.Name)' to resource pool '$($respool.Name)'."
                    $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
                    $vm = Move-VM @moveParameters
                }
            }
            #revert snapshot on VM
            Write-Log -severityLevel Info -logMessage "Reverting to pre-migration snapshot on '$($vm.Name)' with name '$($snapshot.Name)'."
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $snapshot = Get-Snapshot -Name $snapshotName -Server $tgtViConn -VM $vm
            $null = Set-VM -VM $vm -Snapshot $snapshot -Confirm:$false -WhatIf:$WhatIf -ErrorAction Stop
            Write-Log -severityLevel Info -logMessage "Successfully reverted to pre-migration snapshot on '$($vm.Name)'."
                    
            #start the VM and wait for VM tools
            if ($vamtPowerOnIfRollback) {
                Write-Log -severityLevel Info -logMessage "Powering on '$($vm.Name)'."
                $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
                $vm = Start-VM -VM $vm -Server $tgtViConn -Confirm:$false -WhatIf:$WhatIf
                if (!$WhatIf -and !$vamtIgnoreVmTools) {
                    Write-Log -severityLevel Info -logMessage "Waiting for VMware Tools..."
                    #Adding sleep to avoid VMtools not installed issue
                    Start-Sleep -Seconds 25
                    $vm = Wait-Tools -VM $vm -TimeoutSeconds $vamtOsPowerOnTimeout -ErrorAction Stop
                }
            }

            #change tag to complete
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.rollbackTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $tgtViConn

            Write-Log -severityLevel Info -logMessage "Rollback of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer * -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully rolled back VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in rollback job:`n$_"
            Write-Log -severityLevel Error -logMessage $message -skipConsole
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    } -InitializationScript ([scriptblock]::Create($jobFunctions)) -ArgumentList($srcViConn,$tgtViConn,$vm,$vmhost,$respool,$network,$vmfolder,$datastore,$cred,$snapshot,$retry,$test,$scriptVars)

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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$cred,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $scriptVars,

        [Parameter()]
        [Switch]$WhatIf
    )

    $jobFunctions = "function Write-Log { ${function:Write-Log} }`n"
    $jobFunctions += "function Confirm-ActiveTasks { ${function:Confirm-ActiveTasks} }`n"
    $jobFunctions += "function Send-Syslog { ${function:Send-Syslog} }"

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
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
            }
            if (![string]::IsNullOrEmpty($vamtSyslogServer)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogServer', $vamtSyslogServer)
            }
            if (![string]::IsNullOrEmpty($vamtSyslogPort)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogPort', $vamtSyslogPort)
            }
            
            if (!!$using:snapshot) {
                $snapshot = Get-VIObjectByVIView -MORef $using:snapshot.Id -Server $viConn
            }

            Write-Log -severityLevel Info -logMessage "Starting cleanup process on '$($vm.Name)'."

            #delete the snapshot if it exists
            if (!!$snapshot) {
                $null = Confirm-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                Write-Log -severityLevel Info -logMessage "Removing snapshot '$($snapshot.Name)' from '$($vm.Name)'."
                Remove-Snapshot -Snapshot $snapshot -Confirm:$false -WhatIf:$WhatIf
                $snapshotNameAttribute = Get-CustomAttribute -Server $viConn -Name $vamtVcAttrDetails.snapshotNameAttribute
                $null = Set-Annotation -Entity $vm -CustomAttribute $snapshotNameAttribute -Value '' -WhatIf:$WhatIf
            }

            #Remove VAMT Tag
            Write-Log -severityLevel Info -logMessage "Looking for VAMT tags on '$($vm.Name)'."
            $tagAssignments = Get-TagAssignment -Category $vamtTagDetails.tagCatName -Entity $vm -Server $viConn
            if ($tagAssignments.count -gt 0) {
                Write-Log -severityLevel Info -logMessage "Removing VAMT tag from '$($vm.Name)'."
                Remove-TagAssignment -TagAssignment $tagAssignments -Confirm:$false -WhatIf:$WhatIf
            }

            Write-Log -severityLevel Info -logMessage "Cleanup of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer $viConn -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully cleaned up VM '$($vm.Name)'."
            }
        } catch {
            $message = "Caught excecption in cleanup job:`n$_"
            Write-Log -severityLevel Error -logMessage $message -skipConsole
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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$loggingDirectory,

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
        $finalObject | Export-CSV -Path "$loggingDirectory\final_report.csv" -NoTypeInformation -Force -Confirm:$false -WhatIf:(!!$WhatIf)
    } catch {
        Write-Log -severityLevel Error -logMessage "Failed to export final report to CSV file located at '$loggingDirectory\final_report.csv'. Error:`n`t$($_.Exception.message)"
    }

    return $finalObject
}

function Send-Report {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$finalObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$launchTime,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$action,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$message,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$smtpServer,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Int]$smtpPort,

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

    $title = "VAMT '$action' report"
    $subject = "$title - $($launchTime.ToString())"
    $bodyMessage = "<h2>$title</h2>"
    if (![String]::IsNullOrWhiteSpace($message)) {
        $message = $message -replace "`n","<br>"
        $message = $message -replace "`t","&emsp;"
        $bodyMessage += "<p>$message</p>"
    }
    $bodyMessage += "<p>The following table shows the final status of the VAMT '$action' execution:</p>"
    $style = "<style> table, th, td { border: 1px solid black; } </style>"
    $emailBody = $finalObject | ConvertTo-Html -As Table -Head $style -Title $subject -PreContent $bodyMessage | Out-String

    $emailParameters = @{
        SmtpServer = $smtpServer
        Port = $smtpPort
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