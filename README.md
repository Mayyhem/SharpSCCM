[![Sponsored by SpecterOps](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json)](https://github.com/specterops#SharpSCCM)
[![Black Hat USA Arsenal](https://img.shields.io/badge/Black%20Hat%20USA%20Arsenal-2022-brightgreen?style=plastic)](https://www.blackhat.com/us-22/arsenal/schedule/#sharpsccm-27886)

<div align="center"><img src="https://github.com/Mayyhem/SharpSCCM/assets/30671833/fcbd1fc7-28ce-4f5e-ac78-9111fef32cd7" width="600" /></div>

# Tool Overview
SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr, formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI. 

SharpSCCM was initially created to execute user hunting and lateral movement functions ported from PowerSCCM (by @harmj0y, @jaredcatkinson, @enigma0x3, and @mattifestation) and now contains additional functionality to gather credentials and abuse newly discovered attack primitives for coercing NTLM authentication in SCCM sites where automatic site-wide client push installation is enabled.

Please [visit the wiki](https://github.com/Mayyhem/SharpSCCM/wiki) for documentation detailing how to build and use SharpSCCM, supporter, contributors, and defensive recommendations.

### Author
Chris Thompson is the primary author of this project. Duane Michael ([@subat0mik](https://twitter.com/subat0mik)), Evan McBroom ([@EvanMcBroom](https://twitter.com/mcbroom_evan)), Diego Lomellini ([@DiLomSec1](https://twitter.com/DiLomSec1)), and Carsten Sandker ([@0xcsandker](https://twitter.com/0xcsandker)) have made major contributions. Please feel free to reach out on Twitter ([@_Mayyhem](https://twitter.com/_Mayyhem)) with questions, ideas for improvements, etc., and on GitHub with issues and pull requests.

### Warning
This tool was written as a proof of concept in a lab environment and has not been thoroughly tested. There are lots of unfinished bits, terrible error handling, and functions I may never complete. Please be careful and use at your own risk.
