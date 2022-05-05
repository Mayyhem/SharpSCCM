# Tool Overview
SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr, formerly SCCM) for lateral movement without requiring access to the SCCM administration console GUI. SharpSCCM was initially created to execute user hunting and lateral movement functions ported from PowerSCCM (by @harmj0y, @jaredcatkinson, @enigma0x3, and @mattifestation) and now contains additional functionality to abuse newly discovered attack primitives for coercing NTLM authentication in SCCM sites where automatic site-wide client push installation is enabled. Specifically, operators with non-privileged access to any Windows SCCM client can coerce NTLM authentication from all client push installation accounts used by SCCM management point servers. As these accounts require local administrator privileges for SCCM to install software on legitimate clients, coercing NTLM authentication from client push installation accounts often allows lateral movement to additional machines in SCCM sites where SMB signing is not required or where the password is weak and can be cracked. With access to an SCCM administrator account, operators of SharpSCCM can also execute code as SYSTEM on any SCCM client or coerce NTLM authentication from the currently logged-in user.

Currently, SharpSCCM supports the NTLMv2 coercion attack techniques noted in this post (https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a), as well as the lateral movement techniques noted in this post (https://enigma0x3.net/2016/02/29/offensive-operations-with-powersccm/), which have been modified to coerce NTLMv2 authentication rather than running PowerShell on the target. SharpSCCM can also be used to dump information about the SCCM environment from a client, including the cleartext credentials for Network Access Accounts.
 
This tool works from any Windows machine running the SCCM client software and leverages Windows Management Instrumentation (WMI) and the ConfigMgr Client Messaging SDK to communicate with SCCM management points.

Research is ongoing to add SharpSCCM features to:
- pull cleartext Network Access Account credentials from SCCM using a low-privileged account on any client machine
- execute SharpSCCM actions in environments that require PKI certificates
- escalate privileges from local administrator on site servers to SCCM Full Administrator

Recommended security settings for configuring SCCM can be found here: https://docs.microsoft.com/en-us/mem/configmgr/core/clients/deploy/plan/security-and-privacy-for-clients

### Build
1. Clone the git repository.
```
git clone https://github.com/Mayyhem/SharpSCCM.git
```
2. Open SharpSCCM.sln in Visual Studio.
3. Select Target (e.g., Release > x64)
4. Build

A version of the SharpSCCM assembly that contains all of its dependencies will be placed in the $(TargetDir) directory (e.g., .\SharpSCCM\bin\x64\Release\SharpSCCM_merged.exe).

### Command Line Usage
All commands and subcommands have a help page that is automatically generated using the System.CommandLine library. Help pages can be accessed by entering any SharpSCCM command followed by -h, --help, /h, /?, or -?. Required positional arguments are shown within angle brackets and options are shown within square brackets. SharpSCCM supports command line tab completion with dotnet-suggest. For more information, see https://github.com/dotnet/command-line-api/blob/main/docs/Features-overview.md.

### Author
Chris Thompson is the primary author of this project. Duane Michael (@subat0mik) and Evan McBroom (@mcbroom_evan) are active contributors as well. Please feel free to reach out on Twitter (@_Mayyhem) with questions, ideas for improvements, etc., and on GitHub with issues and pull requests.

### Warning
This tool was written as a proof of concept in a lab environment and has not been thoroughly tested. There are lots of unfinished bits, terrible error handling, and functions I may never complete. Please be careful and use at your own risk.