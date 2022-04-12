# SharpSCCM
A C# utility for interacting with SCCM, inspired by the PowerSCCM project by @harmj0y, @jaredcatkinson, @enigma0x3, and @mattifestation. This tool can be used to demonstrate the impact of configuring SCCM without the recommended security settings, which can be found here: https://docs.microsoft.com/en-us/mem/configmgr/core/clients/deploy/plan/security-and-privacy-for-clients

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
Chris Thompson (@_Mayyhem) is the primary author of this project. Duane Michael (@subat0mik) and Evan McBroom (@mcbroom_evan) are active contributors to this project as well.

### Warning
This tool was written as a proof of concept in a lab environment and has not been thoroughly tested. There are lots of unfinished bits, terrible error handling, and functions I may never complete. Please be careful and use at your own risk.