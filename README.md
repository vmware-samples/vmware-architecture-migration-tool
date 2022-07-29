# VMware Architecture Migration Tool

## Getting Started

Visit our [QuickStart guide](./wiki/QuickStartGuide.md) and explore
our [Table of Contents](#table-of-contents) below to review the projects documentation. 

## Table of Contents

- [Getting Started](#getting-started)
- [Purpose](#purpose)
- [Known Limitations](#known-limitations)
- [Design](#design)
- [Prerequisites](#prerequisites)
- [Execution](#execution)
- [Contributing](#contributing)
- [License](#license)

## Purpose 

The **V**Mware **A**rchitecture **M**igration **T**ool (VAMT) is designed to provide an easy and automated process to cold migrate machines between clusters of different architecture types within the same vCenter. In an effort to provide a useful and intuitive tool, the following features have been implemented.

 - **Change Window Support** - Ability to schedule migration within a time frame and stop new migrations if the defined time frame is exceeded.
 - **Process Throttling** - Control of how many parallel migrations tasks that vSphere will be asked to execute.
 - **Syslog Support** - Ability to send logs to a syslog server.
 - **Email Notifications Support** - A report of the logs and individual VM migration status can be sent to an email address.
 - **Best Effort Migrated VM Success Validation** - The tool will wait for VMware Tools to load successfully after the VM has been migrated.
 - **Extensibility Stubs** - The tool provides a stub of functions to add customization before and after VM is migrated.
 - **Maintain the VM's UUID** - In an effort to ensure external tools still recognize the VM after migration the UUID is maintained.
 - **Rollback** - Ability to rollback a migration after initial migration execution.
 
## Known Limitations

Below is a list of known limitations. This by no means can be a complete list as there may be limitations that have not been considered.  Many of these limitations are a result of focusing on the 80% of use cases to the exclusion of the 20%, aka 80/20 rule.

- Designed to be executed from Windows only.
- When migrating a machine with more than one network card, only the first network card will be connected. The user will need to connect the other NICs post migration.
- Migrating a machine on multiple datastores will result in the VM being moved to one datastore.
- Rollback of a machine from multiple datastores will result in it being moved back to one datastore on the original location.
    - Rollback process will only send VM back to its original ESXi host, resource pool, first datastore, first network - not supporting cluster for rollback allows the widest array of supported scenarios. If rollback target needs to be modified, it can be updated in the VM properties/attributes.    
- Migrations will start up until the end of the change window and run until complete, possibly past the defined window.
- Cold migrations initiated by this script are constrained by the limitations and requirements of vSphere.

## Design

Visit [Design.md](./wiki/Design.md) to review the details of VAMT's design including:
- [Overview](./wiki/Design.md#overview)
- [Design Philosophy](./wiki/Design.md#philosophy)
- [Conceptual Model](./wiki/Design.md#conceptual-model)
- [Logic Flow Diagrams](./wiki/Design.md#logic-flow-diagrams)

## Prerequisites

Visit [Script_Prerequisites.md](./wiki/Script_Prerequisites.md) to review the prerequisites for running the VAMT.

## Execution

Visit [Script_Usage.md](./wiki/Script_Usage.md) to review the details for running [VMwareArchitectureMigrationTool.ps1](VMwareArchitectureMigrationTool.ps1).

## Contributing

The vmware-architecture-migration-tool project team welcomes contributions from the community. Before you start working with this project please read and sign our Contributor License Agreement (https://cla.vmware.com/cla/1/preview). If you wish to contribute code and you have not signed our Contributor License Agreement (CLA), our bot will prompt you to do so when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq). For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

VMware Architecture Migration Tool is available under the GPL v3.0 license. Please see [LICENSE](LICENSE).