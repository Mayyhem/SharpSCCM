# Pull Requests

## Requirements

Please fill out the template below. Any pull request that does not include enough information to be reviewed in a timely manner may be closed at the maintainers' discretion.

For more details, please see <https://github.com/Mayyhem/SharpSCCM/blob/main/CONTRIBUTING.md#pull-requests>.

### Description

Please include a summary of the change and which issue is fixed. Please also include relevant motivation and context. List any dependencies that are required for this change. Keep in mind that the maintainer reviewing this PR may not be familiar with or have worked with the code here recently, so please walk us through the concepts.

Fixes # (issue)

If there is not yet an issue for your bug/feature, please open a new issue and then link to that issue in your pull request.

### Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update

### Testing

Please describe the tests that you ran to verify your changes and confirm that no regressions were introduced (including buttons you clicked, text you typed, commands you ran, etc.) and describe the results you observed. Provide instructions so we can reproduce. Please also list any relevant details for your test configuration.

- [ ] Test A
- [ ] Test B

**Test Configuration**:
* SCCM site version:
* SCCM client version:

### Release Notes

Please describe the changes in a single line that explains this improvement in terms that a user can understand. This text may be used in SharpSCCM's release notes.

If this change is not user-facing or notable enough to be included in release notes you may use the strings "Not applicable" or "N/A" here.

Examples:

- Fixed ``Import Oplog`` button URL
- Support for ``ProjectScope`` export to text file

### Checklist:
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published in downstream modules
