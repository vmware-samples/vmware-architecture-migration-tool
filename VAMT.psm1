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
        [Parameter()] #Optional if credentialDirectory is provided.
        [PSCredential]$Credential,
        [Parameter()] #Optional if Credential is provided.
        [String]$credentialDirectory
    )

    if ($null -eq $Credential -and $null -eq $credentialDirectory) {
        throw "Both Inputs 'Credential' and 'credentialDirectory' are empty. 1 OR Both are required for this function to work."
    }

    $connections = @()
    foreach ($vCenter in $vCenters) {
        try {
            if ($null -eq $Credential) {
                Write-Log -severityLevel Debug -logMessage "No credential for vCenter '$vCenter' was passed in via input parameter. Starting stored credential retrieval."
                $cred = Get-StoredCredential -credName $vCenter -credentialDirectory $credentialDirectory
            } elseif (![string]::IsNullOrEmpty($credentialDirectory)) {
                Write-Log -severityLevel Debug -logMessage "Credential for vCenter '$vCenter' with Username '$($Credential.UserName)' was passed in via input parameter. Overwriting stored credential."
                $cred = Save-Credential -credName $vCenter -cred $Credential -credentialDirectory $credentialDirectory
            } else {
                $cred = $Credential
            }
            Write-Log -severityLevel Info -logMessage "Logging in to vCenter '$vCenter' with User: $($cred.UserName)"
            $connection = Connect-VIServer $vCenter -Credential $cred -ErrorAction Stop
            #extend the vIConnection to contain the credential used to connect it. This can be used later rather than retrieving the credential again if the session needs to be recreated (i.e. in a job)
            $connection | Add-Member NoteProperty -Name Credential -Value $cred -Force
            $connections += $connection
        } catch {
            Write-Log -severityLevel Error -logMessage "Failed to connect to '$vCenter' with the following Error:`n`t$($_.Exception.innerexception.message)"
            Write-Log -severityLevel Warn -logMessage "In the case of expired/incorrect stored credentials, you can clear the credential file used to connect to vCenter located here: $credentialDirectory"
            Write-Log -severityLevel Warn -logMessage "Cleaning up and exiting the execution."
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $_
        }
    }
    return $connections
}

function Invoke-Move {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine[]]$vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl]$Server,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VIContainer]$Destination,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.FolderContainer]$InventoryLocation,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.VirtualDevice.NetworkAdapter[]]$NetworkAdapter,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.AdvancedOption[]]$AdvancedOption,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        $Network,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.DatastoreManagement.StorageResource[]]$Datastore,

        [Parameter()]
        [Object]$logDefaults
    )
    if (!!$logDefaults) {
        Write-Log -logDefaults $logDefaults -severityLevel Debug -logMessage "Starting 'Invoke-Move'."
    }else {
        Write-Log -severityLevel Debug -logMessage "Starting 'Invoke-Move'."
    }

    $moveParameters = @{
        VM = $vm
        Confirm = $false
        Server = $Server
        VMotionPriority = "High"
        WhatIf = !!$WhatIf
        ErrorAction = $PSCmdlet.GetVariableValue("ErrorAction")

    }
    if ($null -ne $Destination) {
        if ($Destination.ExtensionData.MoRef.Type -eq "ClusterComputeResource") {
            $moveParameters.Destination = Get-VMHost -Location $compute | Where-Object {$_.ConnectionState -eq "Connected"} | Get-Random
        } elseif ($Destination.ExtensionData.MoRef.Type -eq "ResourcePool") {
            $tgtCluster = Get-Cluster -Id $compute.ExtensionData.Owner.ToString() -Server $Server
            $moveParameters.Destination = Get-VMHost -Location $tgtCluster | Where-Object {$_.ConnectionState -eq "Connected"} | Get-Random
        } else {
            $moveParameters.Destination = $Destination
        }
    }
    if ($null -ne $InventoryLocation) {
        $moveParameters.InventoryLocation = $InventoryLocation
    }
    if ($null -ne $NetworkAdapter) {
        $moveParameters.NetworkAdapter = $NetworkAdapter
    }
    if ($null -ne $AdvancedOption) {
        $moveParameters.AdvancedOption = $AdvancedOption
    }

    #Check if we can use the Move-VM commandlet and use it if possible. Otherwise we'll have to use the relocation spec.
    $netCheck = $Network | Where-Object {$null -ne $_.NetworkType}
    if ($Datastore.Count -le 1 -and $netCheck.Count -in @(0,$Network.Count)) {
        Write-Log -severityLevel Debug -logMessage "Using 'Move-VM' commandlet to perform migration."
        if ($null -ne $Datastore) {
            $moveParameters.Datastore = $Datastore[0]
        }
        if ($null -ne $Network) {
            if ($null -ne $Network.NetworkType) {
                $moveParameters.Network = $Network
            } else {
                $moveParameters.PortGroup = $Network
            }
        }

        $movedVM = Move-VM @moveParameters
        #Workaround for simulate mode not returning the full VM object
        if ($null -eq $movedVM.Name) {
            $vm = Get-VM -Name $vm.Name -Server $Server
        } else {
            $vm = $movedVM
        }
        return $vm
    }

    #We must use relocate spec due to multiple target datastores OR multiple target Network types
    if ($null -ne $Datastore) {
        $moveParameters.Datastore = $Datastore
    }
    if ($null -ne $Network) {
        $moveParameters.Network = $Network
    }
    Write-Log -severityLevel Debug -logMessage "Using 'RelocateVM' to perform migration."
    $spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
    foreach ($key in $moveParameters.Keys) {
        $value = $moveParameters[$key]
        Write-Log -severityLevel Debug -logMessage "Processing key '$key' for the relocation spec with the value(s) '$value'"
        if ($key -eq "Datastore") {
            $vmDisks = $vm | Get-HardDisk | Sort-Object -Property Name #Sort 'Hard Disk 1', '...2', '...3', etc
            $storagePodDSTable = @{}
            #Keep VMX details at same location as Hard Disk 1
            $spec.Datastore = New-Object VMware.Vim.ManagedObjectReference
            if ($value[0].ExtensionData.MoRef.Type -eq "StoragePod") {
                #This is a DatastoreCluster so we must choose a DS. Picking the one with the most space.
                $ds = $value[0] | Get-Datastore | Sort-Object -Property FreeSpaceGB -Descending | Select-Object -First 1
                $spec.Datastore = $ds.ExtensionData.MoRef
                $storagePodDSTable.Add($value[0].Name,$ds)
            } else {
                $spec.Datastore = $value[0].ExtensionData.MoRef
            }

            #check how many target Datastores were passed. If 1, put everything on it.
            if ($value.Count -eq 1) {
                $dsIndex = 0
                $singleDS = $true
            } else {
                $singleDS = $false
            }

            $spec.Disk = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator[]($vmDisks.Count)
            for ($i = 0; $i -lt $vmDisks.Count; $i++) {
                if (!$singleDS) {
                    $dsIndex = $i
                }
                $spec.Disk[$i] = New-Object VMware.Vim.VirtualMachineRelocateSpecDiskLocator
                $spec.Disk[$i].DiskId = $vmDisks[$i].ExtensionData.Key
                $spec.Disk[$i].Datastore = New-Object VMware.Vim.ManagedObjectReference
                if ($value[$dsIndex].ExtensionData.MoRef.Type -eq "StoragePod") {
                    if ($null -ne $storagePodDSTable[$value[$dsIndex].Name]) {
                        $spec.Disk[$i].Datastore = $storagePodDSTable[$value[$dsIndex].Name].ExtensionData.MoRef
                    } else {
                        #This is a DatastoreCluster so we must choose a DS. Picking the one with the most space.
                        $ds = $value[$dsIndex] | Get-Datastore | Sort-Object -Property FreeSpaceGB -Descending | Select-Object -First 1
                        $spec.Disk[$i].Datastore = $ds.ExtensionData.MoRef
                        $storagePodDSTable.Add($value[$dsIndex].Name,$ds)
                    }
                } else {
                    $spec.Disk[$i].Datastore = $value[$dsIndex].ExtensionData.MoRef
                }
            }
        }

        if ($key -eq "Network") {
            $vmNetAdapters = $moveParameters["NetworkAdapter"]
            if ($null -eq $vmNetAdapters) {
                $vmNetAdapters = Get-NetworkAdapter -VM $vm | Sort-Object -Property Name
            }

            #check how many target Networks were passed. If 1, put everything on it.
            if ($value.Count -eq 1) {
                $netIndex = 0
                $singleNet = $true
            } else {
                $singleNet = $false
            }

            $spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] ($vmNetAdapters.Count)
            for ($i = 0; $i -lt $vmNetAdapters.Count; $i++) {
                if (!$singleNet) {
                    $netIndex = $i
                }
                $spec.DeviceChange[$i] = New-Object VMware.Vim.VirtualDeviceConfigSpec
                #$spec.DeviceChange[$i].Device = $vmNetAdapters[$i].ExtensionData
                $spec.DeviceChange[$i].Device = New-Object $vmNetAdapters[$i].ExtensionData.GetType().FullName
                $spec.DeviceChange[$i].Device.Key = $vmNetAdapters[$i].ExtensionData.Key
                if ($value[$netIndex].ExtensionData.MoRef.Type -eq "OpaqueNetwork") {
                    $spec.DeviceChange[$i].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardOpaqueNetworkBackingInfo
                    $spec.DeviceChange[$i].Device.Backing.OpaqueNetworkId = $value[$netIndex].OpaqueNetworkId
                    $spec.DeviceChange[$i].Device.Backing.OpaqueNetworkType = $value[$netIndex].OpaqueNetworkType
                } elseif ($value[$netIndex].ExtensionData.MoRef.Type -eq "Network") {
                    $spec.DeviceChange[$i].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardNetworkBackingInfo
                    $spec.DeviceChange[$i].Device.Backing.DeviceName = $value[$netIndex].Name
                } elseif ($value[$netIndex].ExtensionData.MoRef.Type -eq "DistributedVirtualPortgroup") {
                    $spec.DeviceChange[$i].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardDistributedVirtualPortBackingInfo
                    $spec.DeviceChange[$i].Device.Backing.Port = New-Object VMware.Vim.DistributedVirtualSwitchPortConnection
                    $spec.DeviceChange[$i].Device.Backing.Port.SwitchUuid = $value[$netIndex].VirtualSwitch.Key
                    $spec.DeviceChange[$i].Device.Backing.Port.PortgroupKey = $value[$netIndex].Key
                } else {
                    throw "Encountered unknown network type '$($value[$netIndex].ExtensionData.MoRef.Type)' while building relocation spec. Associated network: $($value[$netIndex].Name)."
                }
                $spec.DeviceChange[$i].Operation = 'edit'
            }
        }

        if ($key -eq "InventoryLocation") {
            $spec.Folder = New-Object VMware.Vim.ManagedObjectReference
            $spec.Folder = $value.ExtensionData.MoRef
        }

        if ($key -eq "Destination") {
            $spec.Host = New-Object VMware.Vim.ManagedObjectReference
            $spec.Host = $value.ExtensionData.MoRef
            $spec.Pool = New-Object VMware.Vim.ManagedObjectReference
            if ($Destination.ExtensionData.MoRef.Type -eq "ResourcePool") {
                $spec.Pool = $Destination.ExtensionData.MoRef
            } else {
                #Since $value is a Host here, we look for it's default res pool first.
                $pool = $value | Get-ResourcePool -Name "Resources" -Server $Server -ErrorAction SilentlyContinue
                if ($null -eq $pool) {
                    #if default res pool wasnt found, then it's likely in a cluster, search the parent.
                    $pool = $value.Parent | Get-ResourcePool -Name "Resources" -Server $Server
                }
                $spec.Pool = $pool.ExtensionData.MoRef
            }
        }
    }

    if ($vm.ExtensionData.Client.ServiceUrl -ne $Server.ServiceUri.AbsoluteUri) {
        #The relocation spec requires credentials for cross vc.
        # Make sure the viconn was created with VAMT Initialize-VIServer
        if ($null -ne $Server.Credential) {
            $spec.Service = New-Object VMware.Vim.ServiceLocator
            $spec.Service.Credential = New-Object VMware.Vim.ServiceLocatorNamePassword
            $spec.Service.Credential.Username = $Server.Credential.UserName
            $spec.Service.Credential.Password = $Server.Credential.GetNetworkCredential().Password
        } else {
            throw "Credential property inside the specified VI Connection was null. This function should only be used with VI Connections created by VAMT\Initialize-VIServer."
        }
        #$cert = Get-VIMachineCertificate -Server $Server -VCenterOnly | ?{ $_.Subject -eq $Server.ServiceUri.Host }
        #$spec.Service.SslThumbprint = ($cert.Certificate.Thumbprint -split '(..)' -ne '') -join ":"
        $spec.Service.SslThumbprint = Get-SSLThumbprint -URL $Server.ServiceUri.AbsoluteUri
        $spec.Service.InstanceUuid = $Server.InstanceUuid
        $spec.Service.Url = $Server.ServiceUri.AbsoluteUri
    }
    $printSpec = $spec | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    if (!!$spec.Service.Credential.Password) {
        $printSpec.Service.Credential.Password = "***********"
    }
    Write-Log -severityLevel Debug -logMessage "Built the following relocation spec: $($printSpec | ConvertTo-Json -Depth 10)"
    Write-Log -severityLevel Info -logMessage "Starting Move Now."
    $vm.ExtensionData.RelocateVM($spec,'highPriority')
    return (Get-VM -Name $vm.Name -Server $Server)
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
            #This causes far too many unnecessary logs in the logfile. Absence of logs can be seen as success. Left code incase needed later.
            #Write-Log @logParameters -severityLevel Debug -logMessage "Successfully sent Syslog message. Payload size: $($byteSyslogMessage.Length) bytes." -skipConsole
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
        $parameterString = ($parameters.GetEnumerator() | ForEach-Object {
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

function Get-VMFolderPath {
    param (
        [Parameter(Mandatory)]
        $folder,

        [Parameter()]
        [switch]$showHidden
    )

    $path = @()
    while ($folder) {
        $parent = $folder.Parent
        if ($null -ne $parent -and $null -eq $parent.Parent -and !$showHidden) {
            $folder = $parent
        } else {
            $path += $folder.Name
            $folder = $parent
        }
    }
    [Array]::Reverse($path)
    return ($path -join "/")
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
    $categories = $viConnections | ForEach-Object {
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
    $categories | ForEach-Object {
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
    $viConnections | ForEach-Object {
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
        [String]$stateTagsCatName,

        [Parameter()]
        [Switch]$ignoreTags
    )

    if (!!$ignoreTags) {
        return "Unknown(Skipped)"
    }

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
    [CmdletBinding(SupportsShouldProcess)]
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
        [Switch]$ignoreTags
    )

    if (!!$ignoreTags) {
        return "Unknown(Skipped)"
    }

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
        $viConn = $viConn | Where-Object {$_.Id -eq ($vm.Uid -Split 'VirtualMachine' | Select-Object -First 1)}

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
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl]$viConnection,

        [Parameter()]
        [Switch]$waitTasks
    )
    $logParameters = @{
        skipConsole = $false
    }
    if (![String]::IsNullOrWhiteSpace($envLogPrefix)) {
        $logParameters.logFileNamePrefix = $envLogPrefix
    }

    $activeTasks = Get-Task -Server $viConnection | Where-Object { $_.State -eq 'Running' -and $_.ObjectId -eq $vm.ExtensionData.MoRef.ToString() }

    if(!!$activeTasks -and !!$waitTasks) {
        Write-Log @logParameters -severityLevel Info -logMessage "$($activeTasks.Count) active tasks found on '$($vm.Name)'. Waiting for tasks to complete."
        if (!$WhatIf) {
            $null = Wait-Task -Task $activeTasks
        }
        return
    }

    return $activeTasks
}

function Get-VIObjectByObject {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $refObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl]$Server,

        [Parameter()]
        [Switch]$simulateMode
    )

    if (!!$simulateMode) {
        #the code in this if block is written to enable the simulator mode feature to function when we are running the script against gvmomi's vcsim.
        $type = $refObject.Id.Split('-')[0]
        if ($type -eq "VirtualMachine") {
            $obj = Get-VM -Name $refObject.Name -Server $Server
        } elseif ($type -eq "ClusterComputeResource") {
            $obj = Get-Cluster -Name $refObject.Name -Server $Server
        } elseif ($type -eq "HostSystem") {
            $obj = Get-VMHost -Name $refObject.Name -Server $Server
        } elseif ($type -eq "ResourcePool") {
            $obj = Get-ResourcePool -Name $refObject.Name -Server $Server
        } elseif ($type -in @("DistributedVirtualPortgroup","Network")) {
            $obj = Get-VirtualPortGroup -Name $refObject.Name -Server $Server
        } elseif ($type -eq "Folder") {
            $obj = Get-Folder -Type VM -Name $refObject.Name -Server $Server | Select-Object -First 1
        } elseif ($type -eq "Datastore") {
            $obj = Get-Datastore -Name $refObject.Name -Server $Server
        } else {
            throw "Unsupported object type '$($type)' found on object named '$($refObject.Name)' while using simulate mode."
        }
    } else {
        if ($refObject.count -gt 1) {
            $obj = @()
            foreach ($element in $refObject) {
                $obj += Get-VIObjectByVIView -MORef $element.Id -Server $Server
            }
        } else {
            $obj = Get-VIObjectByVIView -MORef $refObject.Id -Server $Server
        }
    }
    return $obj
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

function Get-SSLThumbprint {
    param(
        [Parameter(Mandatory)]
        [String]$url
    )

    #Original Author: William Lam (https://gist.github.com/lamw/988e4599c0f88d9fc25c9f2af8b72c92)

    if ($null -eq ([System.Management.Automation.PSTypeName]'IDontCarePolicy').Type) {
add-type '
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
        public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
'
    }
    [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

    # Need to connect using simple GET operation for this to work
    try {Invoke-RestMethod -Uri $url -Method Get | Out-Null} catch {}

    try {
        $endpoint_request = [System.Net.Webrequest]::Create("$url")
        $ssl_thumbprint = $endpoint_request.ServicePoint.Certificate.GetCertHashString()
    } catch {
        if ($null -eq $ssl_thumbprint) {
            throw "Unable to retrieve Cert/Thumbprint from url '$url'. See error:`n`t$_"
        }
    }

    return $ssl_thumbprint -replace '(..(?!$))','$1:'
}

function Start-PreMigrationExtensibility {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm
    )

    return $true
}

function Start-PostMigrationExtensibility {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Impl.V1.VIServerImpl[]]$viConnection,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$vm
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
    $vms = $vmNames | ForEach-Object {
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
    [array]$hostViews = Get-View -ViewType HostSystem -Server $viConnection
    [array]$clusterViews = Get-View -ViewType ClusterComputeResource -Server $viConnection
    [array]$rpViews = Get-View -ViewType ResourcePool -Server $viConnection
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

    $computes = $computeNames | Sort-Object | Get-Unique | ForEach-Object {
        $computeName = $_
        $computeView = $computeViews| Where-Object {$_.Name -eq $computeName}
        if (!!$computeView) {
            if ($computeView.Length -gt 1) {
                Write-Log -severityLevel Warn -logMessage "$($computeView.Length) computes were found with name ($computeName) and type(s) ($(($computeView.MoRef.Type | Sort-Object | Get-Unique) -join ', '))."
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
        [Switch]$ignoreVmTools,

        [Parameter()]
        [Switch]$ignoreTags
    )
    #Check that all VMs and target locations listed in input file are valid
    $targetVcNames = $inputs."$($inputHeaders.vcenter)".ToLower() | Select-Object -Unique
    $missingvCenters = $targetVcNames | Where-Object {$_ -notin $viConnections.Name.ToLower()}
    if ($missingvCenters.Length -gt 0) {
        $missingMessage = "The following vCenters specified in the input CSV are missing from the 'vCenters' input:$($missingvCenters -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    $vmValidationResult = Confirm-VMs -vmNames $inputs."$($inputHeaders.name)" -viConnection $viConnections
    $missingVMs = $vmValidationResult.missingVMs
    $vms = $vmValidationResult.vms

    #This partially addresses a known limitation of this verification. The limitation is that this code will only validate that exactly
    #1 instance of the specified Cluster/Pool/Host for the target location exists. If the same Pool/Cluster names exist in more than 1 target vC,
    #This validation will fail. This could be addressed with enhanced logic but this could be very environment specific.
    $targetVCs = $targetVcNames | ForEach-Object { $vcName = $_; $viConnections | Where-Object {$_.Name.ToLower() -eq $vcName}}
    $cmptValidationResult = Confirm-Computes -computeNames $inputs."$($inputHeaders.compute)" -computeType All -viConnection $targetVCs
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
    #Validate that provided count of PGs and Datastores, is either 1 or equal to the count of NICs and Disks on each VM
    $invalidTgtPGs = @()
    $invalidTgtDSs = @()
    #Validate that for each specified folder, exactly 1 exists with the given name and path (if applicable)
    $invalidFolders = @()
    #make sure the current NIC isnt null, will break rollback.
    $invalidNICs = @()

    $migrationTargets = $inputs | ForEach-Object {
        $vmName = $_."$($inputHeaders.name)"
        $vCenterName = $_."$($inputHeaders.vcenter)"
        $computeName = $_."$($inputHeaders.compute)"
        $networkNames = $_."$($inputHeaders.network)"
        $storageNames = $_."$($inputHeaders.storage)"
        $folderName = $_."$($inputHeaders.folder)"

        $vmObj = $vms | Where-Object {$_.Name -eq $vmName}
        $srcViConn = $viConnections | Where-Object {$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select-Object -First 1)}
        $tgtViConn = $viConnections | Where-Object {$_.Name -eq $vCenterName}
        $computeObj = $computes | Where-Object {$_.Name -eq $computeName -and $_.Uid -like "*$($tgtViConn.Id)*"}
        $computeView = $computeObj | Get-View
        if ($computeView.GetType().Name -eq 'ResourcePool') {
            $computeView.updateviewdata('Owner.*')
            $computeView = $computeView.LinkedView.Owner
        }
        $computeView.updateviewdata('Network.*','Datastore.*')
        $networkViews = $computeView.LinkedView.Network

        $networkObjs = @()
        foreach ($networkName in $networkNames) {
            $networkView = $networkViews | Where-Object {$_.Name -eq $networkName}
            if (!!$networkView) {
                if ($networkView.Length -gt 1) {
                    Write-Log -severityLevel Warn -logMessage "$($networkView.Length) networks were found with name ($networkName) and type(s) ($(($networkView.MoRef.Type | Sort-Object | Get-Unique) -join ', ')) within Compute ($computeName)."
                    $missingPortGroups += $networkName
                } else {
                    $networkObjs += Get-VIObjectByVIView -VIView $networkView
                }
            } else {
                Write-Log -severityLevel Warn -logMessage "No networks were found with name ($networkName) within Compute ($computeName)."
                $missingPortGroups += $networkName
            }
        }
        $vmNICs = $vmObj | Get-NetworkAdapter
        $invalidAdapters = $vmNICs | Where-Object {$null -eq $_.NetworkName}
        if ($null  -ne $invalidAdapters) {
            $invalidNICs += $vmObj.Name
        }
        if ($networkNames -is [array]) {
            if ($vmNICs.count -ne $networkObjs.count) {
                $invalidTgtPGs += $vmObj.Name
            }
            # Preserving the type of network input going forward. If the input was an array of net names, then we are doing
            # a multi vnic migration.
            $network = $networkObjs
        } else {
            #If Not array, then we move all NICs to the single Network specified.
            $network = $networkObjs[0]
        }

        $datastoreViews = $computeView.LinkedView.Datastore
        $dscViews = $datastoreViews | ForEach-Object {
            if ($_.Parent.Type -eq "StoragePod") {
                $_.updateviewdata('Parent.*')
                $_.LinkedView.Parent
            }
        } | Sort-Object -Property Name -Unique

        $storageObjs = @()
        foreach ($storageName in $storageNames) {
            $storageView = ($datastoreViews + $dscViews) | Where-Object {$_.Name -eq $storageName}
            if (!!$storageView) {
                if ($storageView.Length -gt 1) {
                    Write-Log -severityLevel Warn -logMessage "$($storageView.Length) Datastores or DSCs were found with name ($storageName) and type(s) ($(($storageView.MoRef.Type | Sort-Object | Get-Unique) -join ', ')) within Compute ($computeName)."
                    $missingStorage += $storageName
                } else {
                    $storageObjs += Get-VIObjectByVIView -VIView $storageView
                }
            } else {
                Write-Log -severityLevel Warn -logMessage "No Datastores or DSCs were found with name ($storageName) within Compute ($computeName)."
                $missingStorage += $storageName
            }
        }

        if ($storageNames -is [array]) {
            $vmDisks = $vmObj | Get-HardDisk
            if ($vmDisks.count -ne $storageObjs.count) {
                $invalidTgtDSs += $vmObj.Name
            }
            # Same situation as network above.
            $storage = $storageObjs
        } else {
            $storage = $storageObjs[0]
        }

        $folder = $null #null out the previous loop iteration.
        if (![string]::IsNullOrEmpty($folderName)) {
            if ($folderName.Split("/").count -eq 1) {
                #Get the specified folder and filter out default hidden vm folder to avoid conflict.
                $folder = Get-Folder -Name $folderName -Server $tgtViConn -ErrorAction SilentlyContinue | Where-Object { $_.Parent.ExtensionData.MoRef.Type -ne "Datacenter" }
            } else {
                $shortName = $folderName.Split("/")[-1]
                $folder = Get-Folder -Name $shortName -Server $tgtViConn -ErrorAction SilentlyContinue | Where-Object {
                    $path = Get-VMFolderPath -folder $_ -showHidden:$false
                    return ($path -eq $folderName)
                }
            }

            if ($null -eq $folder) {
                $invalidFolders += "Could not find any folder with name or path '$folderName'"
            } elseif ($folder.count -gt 1) {
                $invalidFolders += "Found $($folder.count) folders with name '$folderName'."
            }
        }

        $validationErrors = @()
        $vmState = Get-VMStateBasedOnTag -vm $vmObj -viConn $srcViConn -stateTagsCatName $tagDetails.tagCatName -ignoreTags:(!!$ignoreTags)
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
        } elseif ($jobState -eq $tagDetails.ignored) {
            $jobState = $tagDetails.readyTagName
            $eligibleToRun = $true
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
            tgt_network = $network
            tgt_storage = $storage
            tgt_folder = $folder
            tgt_vcenter = $tgtViConn
            tag_state = $vmState
            job_state = $jobState
            job = $job
            attempts = 0
        }
    }

    if (($missingPortGroups.Length + $missingStorage.Length) -gt 0) {
        $missingMessage = "The following inputs are missing from the provided vCenters OR are not accessible from the specified compute targets.`n`tInvalid Portgroups: $($missingPortGroups -join ', ')`n`tInvalid Datastores/DSCs: $($missingStorage -join ', ')"
        Write-Log -severityLevel Error -logMessage $missingMessage
        throw $missingMessage
    }

    if (($invalidTgtPGs.Length + $invalidTgtDSs.Length) -gt 0) {
        $invalidMessage = "The following machines in the inputs file have target network or storage destinations that do not match the number of Net Adapters or Disks attached to the VM in vCenter.`n`tInvalid Net Targets: $($invalidTgtPGs -join ', ')`n`tInvalid Storage Targets: $($invalidTgtDSs -join ', ')"
        Write-Log -severityLevel Error -logMessage $invalidMessage
        throw $invalidMessage
    }

    if ($invalidNICs.Length -gt 0) {
        $invalidMessage = "The following machines in the inputs file have network adapters with misconfigured portgroups. This will break rollback functionality.`n`tInvalid Net Adapters: $($invalidNICs -join ', ')"
        Write-Log -severityLevel Error -logMessage $invalidMessage
        throw $invalidMessage
    }

    if ($invalidFolders.Length -gt 0) {
        $uniqueErrors = $invalidFolders | Select-Object -Unique
        $invalidMessage = "The following errors were encountered when validating the target vm folders for this migration. Be sure to specify a full folder path (Format: 'Datacenter/topfolder/middlefolder/bottomfolder') if your desired foldername is duplicated anywhere in your folder tree in your target vCenter.`nFolder validation Errors:`n`t$($uniqueErrors -join ",`n`t")"
        Write-Log -severityLevel Error -logMessage $invalidMessage
        throw $invalidMessage
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
        [Switch]$ignoreVmTools,

        [Parameter()]
        [Switch]$ignoreTags
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
    $rollbackTargets = $inputs | ForEach-Object {
        $vmName = $_."$($inputHeaders.name)"
        $vmObj = $vms | Where-Object {$_.Name -eq $vmName}
        $attrValidated = $true
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackVcName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceVcAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceVcAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackHostId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceHostAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceHostAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackResPoolId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceRpAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceRpAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackVmFolderId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceFolderAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceFolderAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackDatastoreId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourceDsAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourceDsAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackPortGroupId = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.sourcePgAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.sourcePgAttribute)
        } catch {
            $attrValidated = $false
        } try {
            $rollbackSnapshotName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($vCenterAttrs.snapshotNameAttribute) -failMessage ($emptyAttrError -f $vCenterAttrs.snapshotNameAttribute)
        } catch {
            $attrValidated = $false
        }
        if (!$attrValidated) {
            $missingRollbackAttrs += $vmName
        }

        try {
            $rollbackPortGroupIds = $rollbackPortGroupId | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $rollbackPortGroupIds = $rollbackPortGroupId
        }
        try {
            $rollbackDatastoreIds = $rollbackDatastoreId | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $rollbackDatastoreIds = $rollbackDatastoreId
        }

        [PSCustomObject]@{
            tgt_vm = $vmObj
            tgt_vc = $rollbackVcName
            tgt_host = $rollbackHostId
            tgt_respool = $rollbackResPoolId
            tgt_folder = $rollbackVmFolderId
            tgt_network = $rollbackPortGroupIds
            tgt_datastore = $rollbackDatastoreIds
            tgt_snapshot = $rollbackSnapshotName
            tgt_attrs_valid = $attrValidated
        }
    }

    if (($missingRollbackAttrs.Length) -gt 0) {
        $missingMessage = "The following VMs are missing one or more of the required Custom Attributes for performing a rollback.`n`tVMs: $($missingRollbackAttrs -join ', ')"
        Write-Log -severityLevel Warn -logMessage $missingMessage
    }

    #Now we will re-build the table using the actual objects we have IDs for.
    $missingvCenters = @()
    $rollbackTargets = $rollbackTargets | ForEach-Object {
        $target = $_
        $vm = $target.tgt_vm
        $srcViConn = $viConnections | Where-Object {$_.Id -eq ($vm.Uid -Split 'VirtualMachine' | Select-Object -First 1)}
        $tgtViConn = $viConnections | Where-Object {$_.Name -eq $target.tgt_vc}
        $validationErrors = @()
        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $tagDetails.tagCatName -ignoreTags:(!!$ignoreTags)
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
        } elseif ($jobState -eq "notag" -or !$target.tgt_attrs_valid) {
            $jobState = $jobStates.jobNotRun
            $validationErrors += ($notAttempted -f $jobState)
        } elseif ($jobState -eq $tagDetails.ignored) {
            $jobState = $tagDetails.readyToRollbackTagName
            $eligibleToRun = $true
        } else {
            $eligibleToRun = $true
        }

        if (!$tgtViConn -and $eligibleToRun) {
            Write-Log -severityLevel Error -logMessage "No current connection for rollback vCenter '$($_.tgt_vc)' was found (vCenter for VM: '$($vm.Name)'). You must specify all required vCenters when executing the script."
            $missingvCenters += $_.tgt_vc
            continue
        }

        $notFoundError = "No object found matching MoRef or Name '{0}' in vCenter '$($tgtViConn.Name)'"
        try {
            $rollbackHostId = $_.tgt_host
            $hostObj = Get-VIObjectByVIView -MORef $rollbackHostId -Server $tgtViConn -ErrorAction Stop
        } catch {
            $hostObj = "Not Found"
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackHostId)
                $validationErrors += ($notFoundError -f $rollbackHostId)
            }
        }
        try {
            $rollbackResPoolId = $_.tgt_respool
            $rpObj = Get-VIObjectByVIView -MORef $rollbackResPoolId -Server $tgtViConn -ErrorAction Stop
        } catch {
            $rpObj = "Not Found"
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackResPoolId)
                $validationErrors += ($notFoundError -f $rollbackResPoolId)
            }
        }
        try {
            $rollbackVmFolderId = $_.tgt_folder
            $folderObj = Get-VIObjectByVIView -MORef $rollbackVmFolderId -Server $tgtViConn -ErrorAction Stop
        } catch {
            $folderObj = "Not Found"
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackVmFolderId)
                $validationErrors += ($notFoundError -f $rollbackVmFolderId)
            }
        }
        try {
            $rollbackPortGroupIds = $_.tgt_network
            $pgObjs = $rollbackPortGroupIds | ForEach-Object {
                $rollbackPortGroupId = $_
                Get-VIObjectByVIView -MORef $rollbackPortGroupId -Server $tgtViConn -ErrorAction Stop
            }
        } catch {
            $pgObjs = "Not Found"
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackPortGroupId)
                $validationErrors += ($notFoundError -f $rollbackPortGroupId)
            }
        }
        try {
            $rollbackDatastoreIds = $_.tgt_datastore
            $dsObjs = $rollbackDatastoreIds | ForEach-Object {
                $rollbackDatastoreId = $_
                Get-VIObjectByVIView -MORef $rollbackDatastoreId -Server $tgtViConn -ErrorAction Stop
            }
        } catch {
            $dsObjs = "Not Found"
            if ($eligibleToRun) {
                Write-Log -severityLevel Error -logMessage ($notFoundError -f $rollbackDatastoreId)
                $validationErrors += ($notFoundError -f $rollbackDatastoreId)
            }
        }
        try {
            $rollbackSnapshotName = $_.tgt_snapshot
            $snapObj = Get-Snapshot -VM $vm -Name $rollbackSnapshotName -Server $srcViConn -ErrorAction Stop
        } catch {
            $snapObj = "Not Found"
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

        if ($null -eq $tgtViConn) {
            $tgtViConn = "Not Found"
        }

        [PSCustomObject]@{
            src_vcenter = $srcViConn
            tgt_vm = $vm
            tgt_vcenter = $tgtViConn
            tgt_host = $hostObj
            tgt_respool = $rpObj
            tgt_folder = $folderObj
            tgt_network = $pgObjs
            tgt_datastore = $dsObjs
            tgt_snapshot = $snapObj
            tag_state = $vmState
            job_state = $jobState
            job = $job
            attempts = 0
        }
    }

    $missingMessage = "The following rollback target vCenters are missing from the provided inputs:`n"
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
        [String]$readyState,

        [Parameter()]
        [Switch]$ignoreTags
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
    $cleanupTargets = $inputs | ForEach-Object {
        $vmName = $_."$($inputHeaders.name)"
        $vmObj = $vms | Where-Object {$_.Name -eq $vmName}
        $viConn = $viConnections | Where-Object {$_.Id -eq ($vmObj.Uid -Split 'VirtualMachine' | Select-Object -First 1)}
        $emptyAttrError = "VM attribute '{0}' is not set on VM '$vmName'."
        try {
            $rollbackSnapshotName = Confirm-NotNullOrEmpty -inString $vmObj.CustomFields.Item($snapshotAttrName) -failMessage ($emptyAttrError -f $snapshotAttrName)
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
    $cleanupTargets = $cleanupTargets | ForEach-Object {
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

        $vmState = Get-VMStateBasedOnTag -vm $vm -viConn $viConn -stateTagsCatName $tagDetails.tagCatName -ignoreTags:(!!$ignoreTags)

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
    [CmdletBinding(SupportsShouldProcess)]
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

        [Parameter()]
        $vmfolder,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $storage,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $scriptVars,

        [Parameter()]
        [Switch]$isRetry
    )

    if ($null -eq $srcViConn.Credential -or $null -eq $tgtViConn.Credential) {
        throw "This function only supports VI Connections created with VAMT\Initialize-VIServer"
    }

    $test = !!$WhatIf
    $retry = !!$isRetry
    $migrationJob = Start-Job -ScriptBlock {
        param ($srcViConn,$tgtViConn,$vm,$compute,$network,$vmfolder,$storage,$retry,$test,$scriptVars)

        try {
            #Wait-Debugger
            $scriptVars | ForEach-Object { New-Variable -Name $_.Name -Value $_.Value}
            #Import VAMT functions module
            if(!(Test-Path "$vamtWorkingDirectory/VAMT.psm1")){
                throw "VAMT functions module ($vamtWorkingDirectory/VAMT.psm1) was not found. Quiting now. - $(Get-Date)"
            }
            Import-Module -Name "$vamtWorkingDirectory/VAMT.psm1"
            #Had to move away from using the session secret due to PowerCLI/vC Lookup Service issue when running inside of a PS Job
            #$viConn = Connect-ViServer -Server $viConn -Session $viConn.SessionSecret
            $srcViConn = Initialize-VIServer -vCenters $srcViConn.Name -Credential $srcViConn.Credential
            $tgtViConn = Initialize-VIServer -vCenters $tgtViConn.Name -Credential $tgtViConn.Credential
            #Write-Host "VM Name: $($vm.Name)"
            #Write-Warning "VM Name: $($vm.Name)"
            #Write-Error "VM Name: $($vm.Name)"
            Write-Output "VM Name: $($vm.Name)"
            Write-Output "VM ID: $($vm.Id)"
            Write-Output "VM Ext: $($vm.ExtensionData.MoRef.Type)"
            $vm = Get-VIObjectByObject -refObject $vm -Server $srcViConn -simulateMode:$vamtSimulateMode
            Write-Output "Compute Name: $($compute.Name)"
            $compute = Get-VIObjectByObject -refObject $compute -Server $tgtViConn -simulateMode:$vamtSimulateMode
            #continue to preserve the network type (array vs not) as we're relying on this to determine if we're doing multi nic/datastore migration
            $network = Get-VIObjectByObject -refObject $network -Server $tgtViConn -simulateMode:$vamtSimulateMode
            $storage = Get-VIObjectByObject -refObject $storage -Server $tgtViConn -simulateMode:$vamtSimulateMode
            if ($null -ne $vmfolder) { #since vmfolder is optional, we must account for it being null.
                $vmfolder = Get-VIObjectByObject -refObject $vmfolder -Server $tgtViConn -simulateMode:$vamtSimulateMode
            }
            $WhatIf = $test
            $isRetry = $retry
            $vmName = $vm.Name
            $Script:envLogPrefix = $vmName
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
                'Write-Log:debugLogging' = $vamtDebugLogging
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
            Write-Log -logDefaults $PSDefaultParameterValues -severityLevel Info -logMessage ("Starting {0}migration process on '$($vm.Name)'." -f $retryMessage)

            #validate no-one is stepping on our job
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtSimulateMode
            $allowedStates = @($vamtTagDetails.readyTagName)
            if ($isRetry) {
                $allowedStates += $vamtTagDetails.inProgressTagName
            }
            if ($vamtSimulateMode) {
                $errorAction = "Ignore"
                $allowedStates += $vamtTagDetails.ignored
            } else {
                $errorAction = "Stop"
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.inProgressTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $srcViConn -ignoreTags:$vamtSimulateMode
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }

            #get current compute, network, storage
            Write-Log -severityLevel Info -logMessage "Gathering current compute, network, storage, folder details for '$($vm.Name)'."
            $currentVC = $srcViConn.Name
            $currentHostId = $vm.VMHostId
            $currentRpId = $vm.ResourcePoolId
            $currentFolderId = $vm.FolderId
            $currentDsIds = (Get-HardDisk -VM $vm | Sort-Object -Property Name).ExtensionData.Backing.Datastore | ForEach-Object { $_.ToString() }
            $netAdapters = Get-NetworkAdapter -VM $vm | Sort-Object -Property Name
            $currentPgIds = $netAdapters | ForEach-Object {
                $netName = $_.NetworkName
                ($vm.ExtensionData | Select-Object -ExpandProperty Network | Where-Object { (Get-View -Id $_.ToString()).Name -eq $netName }).ToString()
            }
            #Setup Move targets and validate move is needed.
            $moveParameters = @{
                VM = $vm
                Server = $tgtViConn
                WhatIf = !!$WhatIf
                ErrorAction = $errorAction
                logDefaults = $PSDefaultParameterValues
            }
            #if cross vCenter vMotion, add storage details OR
            #if current disk config doesnt match passed disk config
            $currentStorage = Get-View -id $currentDsIds -Server $srcViConn
            #get a list of morefs for current storage where the Pod ID is used if applicable.
            $currentPodIDs = $currentStorage | ForEach-Object {
                if ($_.Parent.Type -eq "StoragePod") {
                    $_.Parent.ToString()
                } else {
                    $_.MoRef.ToString()
                }
            }
            $moveStorage = $false
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid) { #cross vc
                $moveStorage = $true
            } elseif ($storage.Count -eq 1) { #one or more disk(s) move to single storage backing
                if ($storage.ExtensionData.MoRef.Type -eq "StoragePod") {
                    if (($currentPodIDs | Select-Object -Unique) -ne $storage.ExtensionData.MoRef.ToString()) {
                        $moveStorage = $true
                    }
                } elseif ($storage.ExtensionData.MoRef.Type -eq "Datastore") {
                    if (($currentDsIds | Select-Object -Unique) -ne $storage.ExtensionData.MoRef.ToString()) {
                        $moveStorage = $true
                    }
                }
            } else { #one or more disk(s) move to multi storage backing
                for ($i = 0; $i -lt $currentStorage.Count; $i++) {
                    if ($storage[$i].ExtensionData.MoRef.Type -eq "StoragePod") {
                        if ($currentPodIDs[$i] -ne $storage[$i].ExtensionData.MoRef.ToString()) {
                            $moveStorage = $true
                            break
                        }
                    } elseif ($storage[$i].ExtensionData.MoRef.Type -eq "Datastore") {
                        if ($currentDsIds[$i] -ne $storage[$i].ExtensionData.MoRef.ToString()) {
                            $moveStorage = $true
                            break
                        }
                    }
                }
            }
            if ($moveStorage) {
                $moveParameters.Datastore = $storage
            }

            #if cross vCenter vMotion, add network details OR
            #if current nic config doesnt match passed nic config
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or
            (($currentPgIds -join '') -ne ($network.Id -join '') -and
            ($currentPgIds  | Select-Object -Unique) -ne $network.Id)) {
                $moveParameters.NetworkAdapter = $netAdapters
                $moveParameters.Network = $network
            }

            $currentResPool = Get-VIObjectByVIView -MORef $currentRpId -Server $srcViConn
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or $compute.Id -notin @($currentHostId, $currentRpId, $currentResPool.ExtensionData.Owner.ToString())) {
                $moveParameters.Destination = $compute
            }

            if ($null -ne $vmfolder -and ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or $currentFolderId -ne $vmfolder.Id)) {
                $moveParameters.InventoryLocation = $vmfolder
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
                $null = $vm | Set-Annotation -CustomAttribute $sourceDsAttribute -Value ($currentDsIds | ConvertTo-Json)
                $null = $vm | Set-Annotation -CustomAttribute $sourcePgAttribute -Value ($currentPgIds | ConvertTo-Json)
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
                    $null = Stop-VMGuest -VM $vm -Confirm:$false -ErrorAction $errorAction
                    $sleepTimer = 5 #seconds
                    while ($vm.PowerState -eq "PoweredOn") {
                        Start-Sleep -Seconds $sleepTimer
                        $waitDuration += $sleepTimer
                        if ($waitDuration -ge $vamtOsShutdownTimeout) {
                            if (!$vamtForceShutdown) {
                                throw "Shutdown of VM '$($vm.Name)' has timed out and force shutdown is disabled. Considering this job failed."
                            }
                            Write-Log -severityLevel Warn -logMessage "Shutdown of VM '$($vm.Name)' has timed out. Forcing poweroff now."
                            $vm = Stop-VM -VM $vm -Server $srcViConn -Confirm:$false
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
                $snapshot = New-Snapshot -VM $vm -Name $snapshotName -Description $snapshotDescription -Server $srcViConn -Confirm:$false -WhatIf:$WhatIf -ErrorAction $errorAction
                if ($null -eq $snapshot) {
                    $snapshot = Get-Snapshot -VM $vm -Name $snapshotName -Server $srcViConn -ErrorAction SilentlyContinue
                }
            }
            $null = $vm | Set-Annotation -CustomAttribute $snapshotNameAttribute -Value $snapshot.Name -WhatIf:$WhatIf
            Write-Log -severityLevel Info -logMessage "Successfully created/retrieved pre-migration snapshot on '$($vm.Name)' with name: $snapshotName"

            #Move VM
            Write-Log -severityLevel Info -logMessage "Starting VM Migration for '$($vm.Name)'."
            Write-Log -severityLevel Debug -logMessage "VM migration parameters:`n$($moveParameters | Out-String)"
            $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
            $vm = Invoke-Move @moveParameters
            if ($compute.ExtensionData.MoRef.Type -eq "ResourcePool" -and $vm.ResourcePoolId -ne $compute.Id) {
                $moveParameters = @{
                    VM = $vm
                    Destination = $compute
                    Confirm = $false
                    Server = $tgtViConn
                    WhatIf = !!$WhatIf
                    ErrorAction = $errorAction
                }
                Write-Log -severityLevel Info -logMessage "Moving VM '$($vm.Name)' into resource pool '$($compute.Name)'."
                $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
                $movedVM = Move-VM @moveParameters
                #Workaround for simulate mode not returning the full VM object
                if ($null -eq $movedVM.Name) {
                    $vm = Get-VM -Name $vm.Name -Server $Server
                } else {
                    $vm = $movedVM
                }
            }


            #start the VM and wait for VM tools
            Write-Log -severityLevel Info -logMessage "Migration completed successfully. Powering on '$($vm.Name)'."
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $vm = Start-VM -VM $vm -Server $tgtViConn -Confirm:$false -WhatIf:$WhatIf
            #Workaround for simulate mode not returning the full VM object
            if ($null -eq $vm.Name) {
                $vm = Get-VM -Id $vm.Id -Server $tgtViConn
            }
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
                    $null = $vm | Set-Annotation -CustomAttribute $sourceDsAttribute -Value ($currentDsIds | ConvertTo-Json)
                    $null = $vm | Set-Annotation -CustomAttribute $sourcePgAttribute -Value ($currentPgIds | ConvertTo-Json)
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
            $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.completeTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $tgtViConn -ignoreTags:$vamtSimulateMode

            Write-Log -severityLevel Info -logMessage "Migration of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer * -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully moved VM '$($vm.Name)'."
            }
        } catch {
            $exception = $_
            $exceptionMessage = $exception.Exception.Message
            $lineNumber = $exception.InvocationInfo.ScriptLineNumber
            $lineContent = $exception.InvocationInfo.Line
            $message = "Caught excecption in migration job on line '$lineNumber':`n$exceptionMessage`nLine content: $lineContent"
            try {
                Write-Log -severityLevel Error -logMessage $message -skipConsole
            } catch {
                Write-Host "Failed before or during import of VAMT Module."
            }
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $exception
        }
    } -ArgumentList($srcViConn,$tgtViConn,$vm,$compute,$network,$vmfolder,$storage,$retry,$test,$scriptVars)
    #Debug-Job -Job $migrationJob
    return $migrationJob
}

function Start-RollbackVMJob {
    [CmdletBinding(SupportsShouldProcess)]
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
        $scriptVars,

        [Parameter()]
        [Switch]$isRetry
    )

    if ($null -eq $srcViConn.Credential -or $null -eq $tgtViConn.Credential) {
        throw "This function only supports VI Connections created with VAMT\Initialize-VIServer"
    }

    $test = !!$WhatIf
    $retry = !!$isRetry
    $rollbackJob = Start-Job -ScriptBlock {
        param ($srcViConn,$tgtViConn,$vm,$vmhost,$respool,$network,$vmfolder,$datastore,$snapshot,$retry,$test,$scriptVars)
        try {
            $scriptVars | ForEach-Object { New-Variable -Name $_.Name -Value $_.Value}
            #Import VAMT functions module
            if(!(Test-Path "$vamtWorkingDirectory/VAMT.psm1")){
                throw "VAMT functions module ($vamtWorkingDirectory/VAMT.psm1) was not found. Quiting now. - $(Get-Date)"
            }
            Import-Module -Name "$vamtWorkingDirectory/VAMT.psm1"

            $srcViConn = Initialize-VIServer -vCenters $srcViConn.Name -Credential $srcViConn.Credential
            $tgtViConn = Initialize-VIServer -vCenters $tgtViConn.Name -Credential $tgtViConn.Credential

            $vm = Get-VIObjectByVIView -MORef $vm.Id -Server $srcViConn
            $vmName = $vm.Name
            $vmhost = Get-VIObjectByVIView -MORef $vmhost.Id -Server $tgtViConn
            $respool = Get-VIObjectByVIView -MORef $respool.Id -Server $tgtViConn
            $network = Get-VIObjectByObject -refObject $network -Server $tgtViConn
            $vmfolder = Get-VIObjectByVIView -MORef $vmfolder.Id -Server $tgtViConn
            $datastore = Get-VIObjectByObject -refObject $datastore -Server $tgtViConn
            $snapshotName = $snapshot.Name
            $WhatIf = $test
            $isRetry = $retry
            $Script:envLogPrefix = $vmName
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
                'Write-Log:debugLogging' = $vamtDebugLogging
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
            $currentState = Get-VMStateBasedOnTag -vm $vm -viConn $srcViConn -stateTagsCatName $vamtTagDetails.tagCatName -ignoreTags:$vamtSimulateMode
            $allowedStates = @($vamtTagDetails.readyToRollbackTagName)
            if ($isRetry) {
                $allowedStates += $vamtTagDetails.inProgressTagName
            }
            if ($vamtSimulateMode) {
                $allowedStates += $vamtTagDetails.ignored
            }
            if ($currentState -in $allowedStates) {
                #change tag to in progress
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.inProgressTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $srcViConn -ignoreTags:$vamtSimulateMode
            } else {
                throw "Detected invalid tag state '$currentState' on '$vmName'. This is likely the result of a concurent job running on the VM elsewhere."
            }

            #get current compute, network, storage
            Write-Log -severityLevel Info -logMessage "Gathering current compute, network, storage, folder details for '$vmName'."
            $currentHostId = $vm.VMHostId
            $currentFolderId = $vm.FolderId
            $currentDsIds = (Get-HardDisk -VM $vm | Sort-Object -Property Name).ExtensionData.Backing.Datastore | ForEach-Object { $_.ToString() }
            $netAdapters = Get-NetworkAdapter -VM $vm | Sort-Object -Property Name
            $currentPgIds = $netAdapters | ForEach-Object {
                $netName = $_.NetworkName
                ($vm.ExtensionData | Select-Object -ExpandProperty Network | Where-Object { (Get-View -Id $_.ToString()).Name -eq $netName }).ToString()
            }

            #Setup Move targets and validate move is needed.
            $moveParameters = @{
                VM = $vm
                Server = $tgtViConn
                WhatIf = $WhatIf
                ErrorAction = "Stop"
                logDefaults = $PSDefaultParameterValues
            }

            #if cross vCenter vMotion, add storage details OR
            #if current disk config doesnt match passed disk config
            $currentStorage = Get-View -id $currentDsIds -Server $srcViConn
            $moveStorage = $false
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid) { #cross vc
                $moveStorage = $true
            } else { #one or more disk(s) move to multi storage backing
                for ($i = 0; $i -lt $currentStorage.Count; $i++) {
                    if ($currentDsIds[$i] -ne $datastore[$i].ExtensionData.MoRef.ToString()) {
                        $moveStorage = $true
                        break
                    }
                }
            }
            if ($moveStorage) {
                $moveParameters.Datastore = $datastore
            }

            #if cross vCenter vMotion, add network details OR
            #if current nic config doesnt match passed nic config
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or
            (($currentPgIds -join '') -ne ($network.Id -join '') -and
            ($currentPgIds  | Select-Object -Unique) -ne $network.Id)) {
                $moveParameters.NetworkAdapter = $netAdapters
                $moveParameters.Network = $network
            }

            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or $currentFolderId -ne $vmfolder.Id) {
                $moveParameters.InventoryLocation = $vmfolder
            }

            $currentHost = Get-VIObjectByVIView -MORef $currentHostId -Server $srcViConn
            if ($tgtViConn.InstanceUuid -ne $srcViConn.InstanceUuid -or ($currentHostId -ne $vmhost.Id -and $currentHost.Parent.Id -ne $vmhost.Parent.Id)) {
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
                Write-Log -severityLevel Debug -logMessage "VM migration parameters:`n$($moveParameters | Out-String)"
                $null = Confirm-ActiveTasks -vm $vm -viConnection $srcViConn -waitTasks -WhatIf:$WhatIf
                $vm = Invoke-Move @moveParameters

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
                #Sleep to make sure the VM is ready before starting
                Start-Sleep -Seconds 10
                Write-Log -severityLevel Info -logMessage "Powering on '$($vm.Name)'."
                $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
                try {
                    $vm = Start-VM -VM $vm -Server $tgtViConn -Confirm:$false -WhatIf:$WhatIf
                } catch {
                    #Sometimes vCenter is not ready for the VM to start so we'll wait a little longer
                    Start-Sleep -Seconds 15
                    $vm = Start-VM -VM $vm -Server $tgtViConn -Confirm:$false -WhatIf:$WhatIf
                }
                if (!$WhatIf -and !$vamtIgnoreVmTools) {
                    Write-Log -severityLevel Info -logMessage "Waiting for VMware Tools..."
                    #Adding sleep to avoid VMtools not installed issue
                    Start-Sleep -Seconds 25
                    $vm = Wait-Tools -VM $vm -TimeoutSeconds $vamtOsPowerOnTimeout -ErrorAction Stop
                }
            }

            #change tag to complete
            $null = Confirm-ActiveTasks -vm $vm -viConnection $tgtViConn -waitTasks -WhatIf:$WhatIf
            $null = Set-VMStateTag -vm $vm -tagName $vamtTagDetails.rollbackTagName -stateTagsCatName $vamtTagDetails.tagCatName -WhatIf:$WhatIf -viConn $tgtViConn -ignoreTags:$vamtSimulateMode

            Write-Log -severityLevel Info -logMessage "Rollback of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer * -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully rolled back VM '$($vm.Name)'."
            }
        } catch {
            $exception = $_
            $exceptionMessage = $exception.Exception.Message
            $lineNumber = $exception.InvocationInfo.ScriptLineNumber
            $lineContent = $exception.InvocationInfo.Line
            $message = "Caught excecption in rollback job on line '$lineNumber':`n$exceptionMessage`nLine content: $lineContent"
            try {
                Write-Log -severityLevel Error -logMessage $message -skipConsole
            } catch {
                Write-Host "Failed before or during import of VAMT Module."
            }
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $exception
        }
    } -ArgumentList($srcViConn,$tgtViConn,$vm,$vmhost,$respool,$network,$vmfolder,$datastore,$snapshot,$retry,$test,$scriptVars)

    return $rollbackJob
}

function Start-CleanupVMJob {
    [CmdletBinding(SupportsShouldProcess)]
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
        $scriptVars
    )

    $test = !!$WhatIf
    $cleanupJob = Start-Job -ScriptBlock {
        param ($viConn,$vm,$snapshot,$test,$scriptVars)
        try {
            $scriptVars | ForEach-Object { New-Variable -Name $_.Name -Value $_.Value}
            #Import VAMT functions module
            if(!(Test-Path "$vamtWorkingDirectory/VAMT.psm1")){
                throw "VAMT functions module ($vamtWorkingDirectory/VAMT.psm1) was not found. Quiting now. - $(Get-Date)"
            }
            Import-Module -Name "$vamtWorkingDirectory/VAMT.psm1"
            $viConn = Initialize-VIServer -vCenters $viConn.Name -Credential $viConn.Credential

            $vm = Get-VIObjectByVIView -MORef $vm.Id -Server $viConn
            $WhatIf = $test
            $vmName = $vm.Name
            $Script:envLogPrefix = $vmName
            $PSDefaultParameterValues = @{
                'Write-Log:logDir' = $vamtLoggingDirectory
                'Write-Log:logFileNamePrefix' = $envLogPrefix
                'Write-Log:debugLogging' = $vamtDebugLogging
            }
            if (![string]::IsNullOrEmpty($vamtSyslogServer)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogServer', $vamtSyslogServer)
            }
            if (![string]::IsNullOrEmpty($vamtSyslogPort)) {
                $PSDefaultParameterValues.Add('Write-Log:syslogPort', $vamtSyslogPort)
            }

            Write-Log -logDefaults $PSDefaultParameterValues -severityLevel Info -logMessage "Starting cleanup process on '$($vm.Name)'."

            if (!!$snapshot) {
                $snapshot = Get-VIObjectByVIView -MORef $snapshot.Id -Server $viConn
            }

            #delete the snapshot if it exists
            if (!!$snapshot) {
                $null = Confirm-ActiveTasks -vm $vm -viConnection $viConn -waitTasks -WhatIf:$WhatIf
                Write-Log -severityLevel Info -logMessage "Removing snapshot '$($snapshot.Name)' from '$($vm.Name)'."
                Remove-Snapshot -Snapshot $snapshot -Confirm:$false -WhatIf:$WhatIf
                $snapshotNameAttribute = Get-CustomAttribute -Server $viConn -Name $vamtVcAttrDetails.snapshotNameAttribute
                $null = Set-Annotation -Entity $vm -CustomAttribute $snapshotNameAttribute -Value '' -WhatIf:$WhatIf
            }

            #Remove VAMT Tag
            if (!$vamtSimulateMode) {
                Write-Log -severityLevel Info -logMessage "Looking for VAMT tags on '$($vm.Name)'."
                $tagAssignments = Get-TagAssignment -Category $vamtTagDetails.tagCatName -Entity $vm -Server $viConn
                if ($tagAssignments.count -gt 0) {
                    Write-Log -severityLevel Info -logMessage "Removing VAMT tag from '$($vm.Name)'."
                    Remove-TagAssignment -TagAssignment $tagAssignments -Confirm:$false -WhatIf:$WhatIf
                }
            }

            Write-Log -severityLevel Info -logMessage "Cleanup of '$($vm.Name)' completed successfully."
            try { Disconnect-VIServer $viConn -Confirm:$false } catch {}

            return [PSCustomObject]@{
                result = "Successfully cleaned up VM '$($vm.Name)'."
            }
        } catch {
            $exception = $_
            $exceptionMessage = $exception.Exception.Message
            $lineNumber = $exception.InvocationInfo.ScriptLineNumber
            $lineContent = $exception.InvocationInfo.Line
            $message = "Caught excecption in cleanup job on line '$lineNumber':`n$exceptionMessage`nLine content: $lineContent"
            try {
                Write-Log -severityLevel Error -logMessage $message -skipConsole
            } catch {
                Write-Host "Failed before or during import of VAMT Module."
            }
            Write-Error $message
            try { Disconnect-VIServer * -Confirm:$false } catch {}
            throw $exception
        }
    } -ArgumentList($viConn,$vm,$snapshot,$test,$scriptVars)

    return $cleanupJob
}

function Save-Report {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$actionResult,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$loggingDirectory
    )
    $unknownResult = "Job completed with unknown result. See scripting logs for details."
    $finalObject = $actionResult | ForEach-Object {
        $result = $_
        $object = @{}
        $result | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {
            $resProperty = $result."$_"
            if ($_ -eq "job") {
                $key = "job_result"
                if ($null -ne $resProperty) {
                    if ($resProperty.GetType().Name -eq "PSRemotingJob"){
                        $job = $resProperty.ChildJobs
                        if (![string]::IsNullOrEmpty($job.Output.result)) {
                            $value = $job.Output.result
                        } elseif (!!$job.Error) {
                            $value = ($job.Error | ForEach-Object {if (!!$_){ $_.ToString()}}) -join "`n"
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
                    $value = ($resProperty | ForEach-Object {$_.ToString()}) -join '; '
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