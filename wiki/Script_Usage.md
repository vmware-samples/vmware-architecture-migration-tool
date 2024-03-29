# VAMT Usage
## Table of Contents

- [Inputs](#inputs)
  * [action](#action)
  * [inputFilePath](#inputfilepath)
  * [vCenters](#vcenters)
  * [vcCredentials](#vcCredentials)
  * [changeWindowStart](#changewindowstart)
  * [changeWindowDuration](#changewindowduration)
  * [parallelTaskCount](#paralleltaskcount)
  * [jobRetries](#jobretries)
  * [statusRefreshInterval](#statusrefreshinterval)
  * [osShutdownTimeout](#osshutdowntimeout)
  * [osPowerOnTimeout](#ospowerontimeout)
  * [syslogHost](#sysloghost)
  * [smtpServer](#smtpserver)
  * [toEmail](#toemail)
  * [fromEmail](#fromemail)
  * [secureMailCred](#securemailcred)
  * [useMailCred](#usemailcred)
  * [smtpUseSsl](#smtpusessl)
  * [ignoreVmTools](#ignorevmtools)
  * [ignoreTags](#ignoretags)
  * [forcePowerOff](#forcepoweroff)
  * [powerOnIfRollback](#poweronifrollback)
  * [debugLogging](#debuglogging)
  * [WhatIf](#whatif)
- [Execution Examples](#execution-examples)
  * [Run using named parameters on the command line](#run-using-named-parameters-on-the-command-line)
  * [Run using splatting](#run-using-splatting)
  * [Run with change window](#run-with-change-window)
  * [Run with authenticated email](#run-with-authenticated-email)
  * [Run with Syslog forwarding](#run-with-syslog-forwarding)

# Inputs
    
## action
The action to be performed by the script.
```
Input type        | String
Required          | true
Allowed values    | migrate, rollback, cleanup
```

## inputFilePath
Full path to the input file. This can be a csv file or a json file. See examples: [toMigrate.csv](../example/toMigrate.csv) & [toMigrate.json](../example/toMigrate.json).
```
Input type        | String
Required          | true
Example value     | "c:\temp\migrations.csv"
```

## vCenters
List of vCenter Hostnames or IPs where target VMs live.
```
Input type        | String[]
Required          | true
Example values    | "vcenter01.corp.local" OR @("vcenter01.corp.local","vcenter02.corp.local")
```

## vcCredentials
This parameter should either be a single PSCredential object to be used to connect to all specified [vCenters](#vcenters), OR an ordered array of PSCredential objects where the length matches the specified vCenters list and each element in this vcCredentials array will be used to authenticate to the corresponding element in the [vCenters](#vcenters) array.

When this parameter is used, it will overwrite any credential currently stored for the specified vCenters.

If not set, a lookup will occur to find the credential(s) for each [vCenters](#vcenters) element stored locally. If not found, the user will be prompted for a credential and that credential will be stored (encrypted) on the filesystem for future retrieval. 
```
Input type        | PSCredential[]
Required          | false
Example values    | @((Get-Credential -Message "Enter vc01 creds"),(Get-Credential -Message "Enter vc02 creds"))
```

## changeWindowStart
If set, the script will validate the specified time and act in the following ways:
* If input time is in the future -> create a scheduled task for the specified time to rerun the script
* If input time is in the past or present -> check [changeWindowDuration](#changewindowduration)
    * If current time is > [changeWindowStart](#changewindowstart) AND < ([changeWindowStart](#changewindowstart) + [changeWindowDuration](#changewindowduration)) -> we are within the change window so execute the script
    * If current time is past change window duration -> error message and exit the script
```
Input type        | String
Required          | false
Example values    | "6/9/2022 9:16:58"
```

## changeWindowDuration
Duration in Minutes that the changewindow should last. If not set, the default (0) of unlimited duration will be used.
```
Input type        | Int32
Required          | false
Default value     | 0
Example value     | 90
```

## parallelTaskCount
Number of concurrent [action](#action) jobs that should run.
```
Input type        | Int32
Required          | false
Default value     | 10
```

## jobRetries
Number of retries that should be attempted if the VM has active vCenter Tasks preventing the [action](#action) OR a retriable error occurs during the action.
```
Input type        | Int32
Required          | false
Default value     | 5
```

## statusRefreshInterval
Amount of time between polls of the main job queue loop. This can be tuned for more or less frequent updates. At scale, a lower value could speed up total execution time since there will be less waiting between checks, however this will come at the expense of increased demand on the script host and increased noise in the logs.
```
Input type        | Int32
Required          | false
Default value     | 15
```
## osShutdownTimeout
Amount of time in seconds to wait when shutting down a guest os before we time out. A timeout will result in a failed migration/rollback job.
```
Input type        | Int32
Required          | false
Default value     | 600
```
## osPowerOnTimeout
Amount of time in seconds to wait for VMtools to start when powering on a VM post migration. A timeout will result in a failed migration/rollback job.
```
Input type        | Int32
Required          | false
Default value     | 900
```

## syslogHost
Syslog host that all logs from the script execution will be forwarded to. The format is `ip/fqdn:port` where `port` is optional.
```
Input type        | String
Required          | false
Example value     | log.corp.local OR 192.168.10.50:514
Default Port      | 514
```

## smtpServer
SMTP server where the final report of the script execution will be sent. The format is `ip/fqdn:port` where `port` is optional.
> **Note**: If you are attempting to use SSL/TLS with your SMTP server, be sure to reference [smtpUseSsl](#smtpUseSsl).
```
Input type        | String
Required          | false
Example value     | smtp.corp.local OR smtp.corp.local:458
Default Port      | 25
```

## toEmail
Email address(es) where the final report of the script execution will be sent.
```
Input type        | String[]
Required          | Only if SMTP server is specified.
Example value     | jack@corp.local OR @("jack@corp.local","rachell@corp.local")
```

## fromEmail
Email address that the final report of the script execution will be sent from.
```
Input type        | String
Required          | Only if SMTP server is specified.
Example value     | jack@corp.local
```

## secureMailCred
Credential to be used for authenticated to the SMTP server. If specified, this credential will set/replace an encrypted credential file for the specified smtp server.
```
Input type        | PSCredential
Required          | false
Example value     | (Get-Credential -Message "Enter SMTP creds")
```

## useMailCred
Switch that if specified will retrieve an encrypted credential from the filesystem for the specified smtp server. 
```
Input type        | Switch
Required          | false
```

## smtpUseSsl
Switch that will enable secure smtp. 
```
Input type        | Switch
Required          | false
```

## ignoreVmTools
Switch that will cause the script to ignore the pre and post migration VM tools state when a migration [action](#action) is specified. If not selected, the script will only start the migration IF VMware tools is running and will only successfully complete IF VMware tools is running after the migration completes.
```
Input type        | Switch
Required          | false
```

## ignoreTags
Switch that will cause the script to ignore the [tag validation](./Script_Prerequisites.md#vcenter-tags) that occurs on each VM before each migration [action](#action) job. 
```
Input type        | Switch
Required          | false
```

## forcePowerOff
Switch that will cause the VM to be forced to power off if the shutdown guest os operation has not completed within the timeout threshold.
```
Input type        | Switch
Required          | false
```

## powerOnIfRollback
Switch that will cause the VM to be powered on after rollback has been completed.
```
Input type        | Switch
Required          | false
```

## debugLogging
Switch that will enable more detailed logging to the console AND execution log file.
```
Input type        | Switch
Required          | false
```

## WhatIf
Switch that will enable a test mode of the script where no actions will be applied on the target VMs but everything will be validated.
```
Input type        | Switch
Required          | false
```

# Execution Examples

## Run using named parameters on the command line
```
./VMwareArchitectureMigrationTool.ps1 -action "migrate" -inputFilePath "c:\temp\toMigrate.csv" -vCenters "vcenter01.corp.local"
```

## Run using splatting
```
$options = @{
    action = "migrate"
    vcenters = "vcenter01.corp.local"
    inputFilePath = "c:\temp\toMigrate.csv"
}
.\VMwareArchitectureMigrationTool.ps1 @options
```

## Run with change window
```
$options = @{
    action = "migrate"
    vcenters = "vcenter01.corp.local"
    inputFilePath = "c:\temp\toMigrate.csv"
    changeWindowStart = "7/11/2022 13:16:58"
    changeWindowDuration = 180
    parallelTaskCount = 10
}
.\VMwareArchitectureMigrationTool.ps1 @options
```

## Run with authenticated email
```
# SMTP credentials setup
[string]$userName = 'account@corp.local'
[string]$userPassword = 'password'
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential($userName, $secStringPassword)

$options = @{
    action = "migrate"
    vcenters = "vcenter01.corp.local"
    inputFilePath = "c:\temp\toMigrate.csv"
    toEmail = "team@corp.com"
    fromEmail = "account@corp.local"
    smtpServer = "smtpserver.corp.local:port"
    secureMailCred = $credObject
    smtpUseSsl = $true
    debugLogging = $true
}
.\VMwareArchitectureMigrationTool.ps1 @options
```

## Run with Syslog forwarding
```
$options = @{
    action = "migrate"
    vcenters = "vcenter01.corp.local"
    inputFilePath = "c:\temp\toMigrate.csv"
    parallelTaskCount = 5
    syslogHost = "syslog.corp.local:port"
    debugLogging = $true
}
.\VMwareArchitectureMigrationTool.ps1 @options
```

# Troubleshooting

## Debugging PS Job
Within the VAMT module there are multiple functions which spin up a PS job to perform the task at hand. 
```
Start-MigrateVMJob
Start-RollbackVMJob
Start-CleanupVMJob
```
If a user/developer finds themself in a scenario where an issue is occuring within one of these jobs and the reason cannot be determined from the job details or job logging, debugging the job may be necessary. To perform this task, here are the basic steps to get you started.
```
#Put the following Commandlet at the top of the appropriate job script block withing VAMT module
Wait-Debugger
```
E.X.:
```
$migrationJob = Start-Job -ScriptBlock {
param ($srcViConn,$tgtViConn,$vm,$compute,$network,$vmfolder,$storage,$retry,$test,$scriptVars)
Wait-Debugger
try {
    ...<rest of job script block>...
```
Next, execute the VMwareArchitectureMigrationTool.ps1 script as you have been doing effectively reproducing the error you are seeing. 
> **Note**: It may be advantageous for you to only execuite the script with a single VM target to reduce setup/cleanup complexity.

You should see the error shown below when running the script as `AtBreakpoint` is not a valid job state, this is expected. Now, from the current shell where the script was executed, run the following commands:
```
#This command will produce a list of current PSJobs. Note the Id of one that contains the State AtBreakpoint
Get-Job
#Get the active PS runspace for the appropriate job
$runspc = (Get-Job -Id <Id Noted Above>).ChildJobs.Runspace
#Enter an interactive debug session within the Job
$runspc | Debug-Runspace
```