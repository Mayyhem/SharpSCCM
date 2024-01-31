# SharpSCCM Release Notes

### Version 2.0.7 (January 31, 2024)
##### Changes
- Fixed issue 36

### Version 2.0.6 (January 31, 2024)
##### Changes
- Fixed issue 35

### Version 2.0.5 (January 31, 2024)
##### Changes
- Fixed issue 40

### Version 2.0.4 (January 29, 2024)
##### Changes
- Fixed issue 39

### Version 2.0.3 (November 7, 2023)
##### Changes
- Fixed SCCM site system role name
- Fixed default wait-time for exec

### Version 2.0.2 (October 26, 2023)
##### Changes
- Replaced ILMerge with dnMerge for Release builds, merged size down to ~1MB
- Updated variable, option, and class names and descriptions to reflect the correct SCCM site system roles
- Added --wait-time option to allow the user to wait for exec propagation longer before cleanup in large environments

### Version 2.0.1 (May 24, 2023)
##### New Commands
- invoke admin-service (CMPivot queries)
- get site-info (retrieve site server names via LDAP)
##### Additions
- Added inline decryption of secrets
- Added secret retrieval using PXE cert and GUID
- Added --no-banner option

### Version 2.0.0 (February 17, 2023)
##### New Commands
- exec (deploy to user primary devices and collections, PowerShell examples)
- get collection-members
- get collection-rules
- get secrets (replaces get naa, dumps additional credentials from server)
- get users
- local query
- local secrets (replaces local naa, dumps additional credentials from client)
- local triage (gather information from client logs)
- new collection-member (replaces add commands)
- new device (obtain reusable certificate for subsequent requests without creating multiple device records)
- remove collection-member
- remove collection-rule
##### Additions
- Documentation now available at https://github.com/Mayyhem/SharpSCCM/wiki
- Added "--debug" option to trace code execution through Client Messaging SDK and dump stack traces/exceptions
- Added command line arguments/options and input validation
- Added exception handling
- Added execution timer
- Added required roles to command descriptions
- Reorganized and cleaned up code
- Started adding unit testing
- Fixed localhost name resolution issue

### Version 1.0.0 (April 13, 2022)
- Initial release of SharpSCCM
