### Description

Please summarize the change, which issue is fixed, and any dependencies required, including any relevant motivation and context.

### Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [X] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)

### Testing

Please describe the tests that you ran to verify your changes and confirm that no regressions were introduced and describe the results you observed. Provide instructions so we can reproduce and list any relevant details for your test configuration.

- SharpSCCM_merged.exe invoke adminService "EventLog('Security', 1h) | where EventID == 4624"
- SharpSCCM_merged.exe invoke adminService "EventLog('Security', 1h) | where EventID == 4624" -i SMS00001
- SharpSCCM_merged.exe invoke adminService "Device" -i SMS00001
- SharpSCCM_merged.exe local site-info

**Test Configuration**:
* SCCM Site Version (result of`.\SharpSCCM.exe get class-instances SMS_Site -p Version`):

============================================================================================

C:\Users\LabAdmin\Desktop\Debug_share>SharpSCCM.exe get class-instances SMS_Site -p Version

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |

[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: CM1.corp.contoso.com
[+] Site code: CHQ
[+] Connecting to \\CM1.corp.contoso.com\root\SMS\site_CHQ
[+] Executing WQL query: SELECT SiteCode,Version FROM SMS_Site
-----------------------------------
SMS_Site
-----------------------------------
Version: 5.00.9078.1000
-----------------------------------
[+] Completed execution in 00:00:00.2486533

===============================================================================================


* SCCM Client Version (result of `.\SharpSCCM_merged.exe local class-instances SMS_Client`):

===============================================================================================

C:\Users\LabAdmin\Desktop>SharpSCCM_merged.exe local class-instances SMS_Client

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |

[+] Connecting to \\127.0.0.1\root\CCM
[+] Executing WQL query: SELECT * FROM SMS_Client
-----------------------------------
SMS_Client
-----------------------------------
AllowLocalAdminOverride: True
ClientType: 1
ClientVersion: 5.00.9078.1006
EnableAutoAssignment: False
-----------------------------------
[+] Completed execution in 00:00:00.0930895

===============================================================================================

### Bonus Points:

- [X] I have commented my code, particularly in hard-to-understand areas
- [Not yet] I have incremented the build/revision number in https://github.com/Mayyhem/SharpSCCM/blob/main/Properties/AssemblyInfo.cs
- [Not yet] I have made corresponding changes to the documentation
- [Not yet] I have added unit tests that prove my fix is effective or that my feature works
