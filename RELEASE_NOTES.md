# SharpSCCM Release Notes

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
