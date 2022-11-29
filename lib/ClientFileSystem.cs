using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.Remoting.Messaging;
using System.Security;
using System.Security.AccessControl;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    static class ClientFileSystem
    {
        public static void AllChecks()
        {
            Console.WriteLine("[+] Client cache contents:");
            //ListDirectoryContents(@"C:\Windows\ccmcache");
            ListDirectoryContents(@"C:\readable-writable");
            Console.WriteLine("[+] Searching logs for UNC paths:");
            //SearchLogs();
        }

        public static bool DoesCurrentUserHaveRights(string path, FileSystemRights fileSystemRights)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0)
            {
                return false;
            }

            // Get the access rules of the specified files (user groups and user names that have access to the file)
            var rules = File.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));

            // Get the identity of the current user and the groups that the user is in.
            var groups = WindowsIdentity.GetCurrent().Groups;
            string sidCurrentUser = WindowsIdentity.GetCurrent().User.Value;

            // Check if writing to the file is explicitly denied for this user or a group the user is in.
            if (rules.OfType<FileSystemAccessRule>().Any(r => (groups.Contains(r.IdentityReference) || r.IdentityReference.Value == sidCurrentUser) && r.AccessControlType == AccessControlType.Deny && (r.FileSystemRights & fileSystemRights) == fileSystemRights))
            {
                return false;
            }

            // Check if writing is allowed
            return rules.OfType<FileSystemAccessRule>().Any(r => (groups.Contains(r.IdentityReference) || r.IdentityReference.Value == sidCurrentUser) && r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & fileSystemRights) == fileSystemRights);
        }

        public static void ListDirectoryContents(string dirPath)
        {
            try
            {
                bool dirReadRights = DoesCurrentUserHaveRights(dirPath, FileSystemRights.ReadData);
                bool dirWriteRights = DoesCurrentUserHaveRights(dirPath, FileSystemRights.WriteData);
                string dirPermissions =
                    (dirReadRights && dirWriteRights)  ? "drw":
                    (dirReadRights && !dirWriteRights) ? "dr-":
                    (!dirReadRights && dirWriteRights) ? "d-w":
                                                         "d--";
                Console.WriteLine($"{dirPermissions} {dirPath}");
                foreach (string filePath in Directory.GetFiles(dirPath))
                {
                    bool fileReadRights = DoesCurrentUserHaveRights(filePath, FileSystemRights.ReadData);
                    bool fileWriteRights = DoesCurrentUserHaveRights(filePath, FileSystemRights.WriteData);
                    string filePermissions =
                        (fileReadRights && fileWriteRights)  ? "-rw":
                        (fileReadRights && !fileWriteRights) ? "-r-":
                        (!fileReadRights && fileWriteRights) ? "--w":
                                                                "---";
                    Console.WriteLine($"{filePermissions} {filePath}");
                }
                foreach (string subdirPath in Directory.GetDirectories(dirPath))
                {
                    ListDirectoryContents(subdirPath);
                }
            }
            /*
            catch (DirectoryNotFoundException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (FileNotFoundException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine(e.Message);
            }
            */
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        public static void GrepFile(string path, string stringToFind)
        {
            string[] lines = File.ReadAllLines(path);
            foreach (string line in lines)
            {
                if (line.Contains(stringToFind))
                {
                    Console.WriteLine(line);
                }
            }
        }

        public static void GrepFileRegex(string path, string regex)
        {
            try
            {
                string[] lines = File.ReadAllLines(path);
                foreach (string line in lines)
                {
                    MatchCollection collection = Regex.Matches(line, regex);
                    if (collection.Count != 0)
                    {
                        Console.WriteLine(line);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void PushLogs(string startTime, string startDate)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("localhost", "root\\cimv2");
            DateTime startDateObj = DateTime.Parse(startDate);
            // To-do
        }

        public static void SearchLogs()
        {
            foreach (string filePath in Directory.GetFiles(@"C:\Windows\CCM\Logs"))
            {
                Console.WriteLine($"[+] {filePath}");
                GrepFileRegex(filePath, @"(\\\\([a-z|A-Z|0-9|-|_|\s]{2,15}){1}(\.[a-z|A-Z|0-9|-|_|\s]{1,64}){0,3}){1}(\\[^\\|\/|\:|\*|\?|""|\<|\>|\|]{1,64}){1,}(\\){0,}");
            }
        }
    }
}