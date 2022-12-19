### Description

Please summarize the change, which issue is fixed, and any dependencies required, including any relevant motivation and context.

### Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)

### Testing

Please describe the tests that you ran to verify your changes and confirm that no regressions were introduced and describe the results you observed. Provide instructions so we can reproduce and list any relevant details for your test configuration.

- Test A
- Test B

**Test Configuration**:
* SCCM Site Version (result of`.\SharpSCCM.exe get class-instances SMS_Site -p Version`):
* SCCM Client Version (result of `.\SharpSCCM_merged.exe local class-instances SMS_Client`):

### Bonus Points:

- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have incremented the build/revision number in https://github.com/Mayyhem/SharpSCCM/blob/main/Properties/AssemblyInfo.cs
- [ ] I have made corresponding changes to the documentation
- [ ] I have added unit tests that prove my fix is effective or that my feature works
