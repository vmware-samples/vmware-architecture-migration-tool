# VAMT Requirements
## Table of Contents
- [Prerequisites](#prerequisites)
    + [PowerShell](#powershell)
    + [Operating Systems](#operating-systems)
    + [Platform](#platform)
    + [Access](#access)
    + [Connectivity](#connectivity)
- [Setup](#setup)
    + [vCenter Tags](#vcenter-tags)
    + [PowerCLI](#powercli)
    + [Source Code](#source-code)

# Prerequisites

In order to execute the VAMT there are several prerequisite requirements. These requirements are outlined in the sections below.

### PowerShell

This project has been built leveraging the following components:
* [**Windows PowerShell 5.1**](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_windows_powershell_5.1?view=powershell-5.1)
* [**PowerCLI 12.6+**](https://www.powershellgallery.com/packages/VMware.PowerCLI/12.6.0.19610541)

### Operating Systems

* Microsoft Windows Server 2019
* Microsoft Windows 10
> **Note**
>
> The aforementioned operating systems have been confirmed but any os with Windows PowerShell 5.1 should suffice.

### Platform

* VMware vSphere 7.0+
> **Note**
>
> The aforementioned version(s) have been confirmed but earlier versions may also be compatible.

### Access

* It is required to have *Administrator* access on the Windows OS where the script will be executed.
* It is recommended to have *Administrator* access in the vCenter(s) where the target VMs live.

### Connectivity

* Ability to connect to your vCenter Server from your Windows OS via PowerCLI. 
    * See: [Connect to a vCenter Server System](https://developer.vmware.com/docs/15315/powercli-user-s-guide/GUID-1FE80126-ADE6-45AC-A568-AA6CD849DA81.html)
* Ability to connect to your SMTP server from your Windows OS via PowerShell*
    * See: [Send-MailMessage](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-5.1)
* Ability to send syslog traffic to your syslog collector from your Windows OS*
> **Note**
>
> *Only required if using these features.


# Setup

In order to execute the VAMT there are configuration steps required in vCenter as outlined below.

## vCenter Tags

* A Tag Category named **`VAMT`** must exist on each vCenter where target VMs live.
    - Single Cardinality required for the Category.
    - Scope on the Category should be `VirtualMachine`.
* The following tags must exist in the  **`VAMT`** category on each vCenter: 
    - complete
    - completeWithErrors
    - readyToMigrate
    - readyToRollback
    - inProgress
    - failed
    - rolledBack

## PowerCLI
* PowerCLI should be installed and configured according to the documentation here: [ PowerCLI Installation Guide ](https://developer.vmware.com/powercli/installation-guide)

## Source Code

* Pull the [VMwareArchitectureMigrationTool.ps1](../VMwareArchitectureMigrationTool.ps1) script down to a location where you have read/write access on your Windows OS.