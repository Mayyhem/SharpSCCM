# SharpSCCM
A C# utility for interacting with SCCM, inspired by the PowerSCCM project by @harmj0y, @jaredcatkinson, @enigma0x3, and @mattifestation. This tool can be used to demonstrate the impact of not configuring SCCM with the recommended security settings, which can be found here: https://docs.microsoft.com/en-us/mem/configmgr/core/clients/deploy/plan/security-and-privacy-for-clients

### Build
1. Clone the git repository.
```
git clone https://github.com/Mayyhem/SharpSCCM.git
```
2. Open SharpSCCM.sln in Visual Studio.
3. Target .NET Framework 4.7.2 (minimum version required for CertificateRequest)
4. Install System.CommandLine and System.CommandLine.NamingConventionBinder from Nuget (https://www.nuget.org/packages/System.CommandLine and https://www.nuget.org/packages/System.CommandLine.NamingConventionBinder).
5. Add a reference for the System.Management assembly.
6. Build
7. Merge dependent assemblies into SharpSCCM.exe.
```
cd C:\path\to\SharpSCCM\bin\x64\Release
C:\path\toSharpSCCM\packages\ILMerge.3.0.41\tools\net452\ILMerge.exe .\SharpSCCM.exe .\System.CommandLine.dll .\System.CommandLine.NamingConventionBinder .\System.ValueTuple .\System.Memory.dll .\Microsoft.ConfigurationManagement.Messaging.dll .\Microsoft.ConfigurationManagement.Security.Cryptography.dll /out:SharpSCCM_merged.exe
```

### Command Line Usage
All commands and subcommands have a help page that is automatically generated using the System.CommandLine library. Help pages can be accessed by entering any SharpSCCM command followed by -h, --help, /h, /?, or -?. Required positional arguments are shown within angle brackets and options are shown within square brackets. SharpSCCM supports command line tab completion with dotnet-suggest. For more information, see https://github.com/dotnet/command-line-api/blob/main/docs/Features-overview.md.

```
SharpSCCM
  Interact with Microsoft Endpoint Configuration Manager

Usage:
  SharpSCCM [options] <server> <sitecode> [command]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  --version       Show version information
  -?, -h, --help  Show help and usage information

Commands:
  add     A group of commands that add objects to other objects (e.g., add device to collection)
  get     A group of commands that query certain objects and display their contents
  invoke  A group of commands that execute actions on the server
  local   A group of commands to interact with the local workstation/server
  new     A group of commands that create new objects on the server
  remove  A group of commands that deletes objects from the server

--- Subcommands ---

add
  A group of commands that add objects to other objects (e.g., add device to collection)

Usage:
  SharpSCCM [options] <server> <sitecode> add [command]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -?, -h, --help  Show help and usage information

Commands:
  device-to-collection <device-name> <collection-name>  Add a device to a collection for application deployment
  user-to-collection <user-name> <collection-name>      Add a user to a collection for application deployment		

---

get
  A group of commands that query certain objects and display their contents

Usage:
  SharpSCCM [options] <server> <sitecode> get [command]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -c, --count                    Returns the number of rows that match the specified criteria
  -d, --dry-run                  Display the resulting WQL query but do not connect to the specified server and execute 
                                 it
  -o, --order-by <order-by>      An ORDER BY clause to set the order of data returned by the query (e.g., "ResourceID
                                 DESC"). Defaults to ascending (ASC) order.
  -p, --properties <properties>  A space-separated list of properties to query (e.g., "IsActive UniqueUserName". Always 
                                 includes key properties.
  -w, --where <where>            A WHERE condition to narrow the scope of data returned by the query (e.g.,
                                 "Name='cave.johnson'" or "Name LIKE '%cave%'")
  -v, --verbose                  Display all class properties and their values (default: false)
  -?, -h, --help                 Show help and usage information

Commands:
  application                  Get information on applications
  classes <wmiPath>            Get information on remote WMI classes
  class-instances <wmiClass>   Get information on WMI class instances
  class-properties <wmiClass>  Get all properties of a specified WMI class
  collection                   Get information on collections
  collection-member <name>     Get the members of a specified collection
  deployment                   Get information on deployments
  device                       Get information on devices
  naa                          Get network access accounts and passwords from the server policy
  primary-user                 Get information on primary users set for devices

---

invoke
  A group of commands that execute actions on the server

Usage:
  SharpSCCM [options] <server> <sitecode> invoke [command]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -?, -h, --help  Show help and usage information

Commands:
  client-push          Coerce the server to authenticate to an arbitrary destination via NTLM (if enabled) by
                       registering a new device and sending a heartbeat data discovery record (DDR) with the
                       ClientInstalled flag set to false.
  query <query>        Execute a given WQL query
  update <collection>  Force all members of a specified collection to check for updates and execute any new
                       applications that are available

---

local
  A group of commands to interact with the local workstation/server

Usage:
  SharpSCCM <server> <sitecode> local [command] [options]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -?, -h, --help  Show help and usage information


Commands:
  class-instances <wmiClass>   Get information on local WMI class instances
  class-properties <wmiClass>  Get all properties of a specified WMI class
  clientinfo                   Get the primary Management Point and Site Code for the local host
  naa                          Get any network access accounts for the site
  siteinfo                     Get the primary Management Point and Site Code for the local host
  classes <wmiPath>            Get information on local WMI classes

---

new
  A group of commands that create new objects on the server

Usage:
  SharpSCCM <server> <sitecode> new [command] [options]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -?, -h, --help  Show help and usage information


Commands:
  application <name> <path>                       Create an application
  collection <collection-type> <collection-name>  Create a collection of devices or users
  deployment <application> <collection>           Create an assignment to deploy an application to a collection

---

remove
  A group of commands that deletes objects from the server

Usage:
  SharpSCCM <server> <sitecode> remove [command] [options]

Arguments:
  <server>    The FQDN or NetBIOS name of the Configuration Manager server to connect to
  <sitecode>  The site code of the Configuration Manager server (e.g., PS1)

Options:
  -?, -h, --help  Show help and usage information


Commands:
  application <name>                     Delete a specified application
  collection <name>                      Delete a specified collection
  deployment <application> <collection>  Delete a deployment of a specified application to a specified collection
```

### Author
Chris Thompson (@_Mayyhem) is the primary author of this project. 