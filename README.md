# Sysmon-PowerShell
This project demonstrates basic Sysmon usage, the various events associated with sysmon and how to invoke them.<br>

| Event ID | Description      |
|:-------:|------------------|
| 1     | Process Creation |
| 2     | A process changed a file creation time |
| 3     | Network connection|
| 4     | Sysmon service state changed |
| 5     | Process terminated |
| 6     | Driver loaded |
| 7     | Image loaded |
| 8     | CreateRemoteThread |
| 9     | RawAccessRead |
|10     | ProcessAccess |
|11     | FileCreate |
|12     | RegistryEvent (Object create and delete) |
|13     | RegistryEvent (Value Set) |
|14     | RegistryEvent (Key and Value Rename) |
|15     | FileCreateStreamHash |
|16     | Sysmon configuration change |
|17     | PipeEvent (Pipe Created) |
|18     | PipeEvent (Pipe Connected) |
|19     | WmiEvent (WmiEventFilter activity detected) |
|20     | WmiEvent (WmiEventConsumer activity detected) |
|21     | WmiEvent (WmiEventConsumerToFilter activity detected) |

PowerShell is used to walk through the various event invocations. <br>

### Relevent Links
- [Sysmon v6.10](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sysinternals Sysmon unleashed](https://blogs.technet.microsoft.com/motiba/2016/10/18/sysinternals-sysmon-unleashed/)
- [Sysinternals Sysmon 6.10 Tracking of Permanent WMI Events](https://www.darkoperator.com/blog/2017/10/15/sysinternals-sysmon-610-tracking-of-permanent-wmi-events)
- [Tracking Hackers on Your Network with Sysinternals Sysmon](https://www.rsaconference.com/writable/presentations/file_upload/hta-w05-tracking_hackers_on_your_network_with_sysinternals_sysmon.pdf)

