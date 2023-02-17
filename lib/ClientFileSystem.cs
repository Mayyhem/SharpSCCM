using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{
    static class ClientFileSystem
    {
        public static bool DoesCurrentUserHaveRights(string path, FileSystemRights fileSystemRights)
        {
            try
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
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public static string FormatFileSize(long length)
        {
            string[] suffixes ={ "B", "KB", "MB", "GB", "TB", "PB" };
            int counter = 0;
            decimal number = (decimal)length;
            while (Math.Round(number / 1024) >= 1)
            {
                number = number / 1024;
                counter++;
            }
            return string.Format("{0:n1}{1}", number, suffixes[counter]);
        }

        public static void GetDirectoryContentsAndPermissions(string dirPath, bool recurse)
        {
            Console.WriteLine("Perms".PadLeft(9) + "  Size".PadLeft(10) + "  Date modified".PadRight(23) + "  Name");
            try
            {
                bool dirReadRights = DoesCurrentUserHaveRights(dirPath, FileSystemRights.ReadData);
                bool dirWriteRights = DoesCurrentUserHaveRights(dirPath, FileSystemRights.WriteData);
                string dirPermissions =
                    (dirReadRights && dirWriteRights)  ? "drw":
                    (dirReadRights && !dirWriteRights) ? "dr-":
                    (!dirReadRights && dirWriteRights) ? "d-w":
                                                         "d--";
                Console.WriteLine($"{dirPermissions.PadLeft(9)}  {Directory.GetLastWriteTime(dirPath).ToString().PadLeft(31)}  {dirPath}");
                foreach (string filePath in Directory.GetFiles(dirPath))
                {
                    bool fileReadRights = DoesCurrentUserHaveRights(filePath, FileSystemRights.ReadData);
                    bool fileWriteRights = DoesCurrentUserHaveRights(filePath, FileSystemRights.WriteData);
                    string filePermissions =
                        (fileReadRights && fileWriteRights)  ? "-rw":
                        (fileReadRights && !fileWriteRights) ? "-r-":
                        (!fileReadRights && fileWriteRights) ? "--w":
                                                               "---";
                    Console.WriteLine($"{filePermissions.PadLeft(9)}  {FormatFileSize(new FileInfo(filePath).Length).ToString().PadLeft(8)}  {File.GetLastWriteTime(filePath).ToString().PadLeft(21)}  {filePath}");
                }
                if (recurse)
                {
                    foreach (string subdirPath in Directory.GetDirectories(dirPath))
                    {
                        GetDirectoryContentsAndPermissions(subdirPath, true);
                    }
                }
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine($"[!] {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[!] {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        public static void GrepFile(string stringToFind, string filePath)
        {
            try
            {
                bool fileMatched = false;
                List<string> matchLines = new List<string>() { };
                string line = "";
                using (FileStream fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (StreamReader streamReader = new StreamReader(fileStream, Encoding.UTF8))
                    {

                        while ((line = streamReader.ReadLine()) != null)
                        {
                            if (line.Contains(stringToFind))
                            {
                                fileMatched= true;
                                matchLines.Add(line);
                            }
                        }
                    }
                }
                if (fileMatched)
                {
                    Console.WriteLine($"Found match in {filePath}");
                    foreach (string matchValue in matchLines)
                    {
                        Console.WriteLine($"  {matchValue}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public static void GrepFileRegex(string filePath, string regex)
        {
            try
            {
                bool fileMatched = false;
                List<string> matchValues = new List<string>() { };
                using (FileStream fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (StreamReader streamReader = new StreamReader(fileStream, Encoding.UTF8))
                    {
                        string line = "";
                        while ((line = streamReader.ReadLine()) != null)
                        {
                            MatchCollection collection = Regex.Matches(line, regex);
                            if (collection.Count != 0)
                            {
                                fileMatched = true;
                                foreach (Match match in collection)
                                {
                                    matchValues.Add(match.Value);
                                }
                            }       
                        }
                    }
                }
                if (fileMatched)
                {
                    Console.WriteLine($"    Found match in {filePath}");
                    foreach (string matchValue in matchValues.Distinct())
                    {
                        Console.WriteLine($"      {matchValue}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public static void PushLogs(string startTime, string startDate)
        {
            ManagementScope wmiConnection = MgmtUtil.NewWmiConnection("127.0.0.1", "root\\cimv2");
            DateTime startDateObj = DateTime.Parse(startDate);
            // To-do
        }

        public static void SearchClientLogs(string regex)
        {
            foreach (string filePath in Directory.GetFiles(@"C:\Windows\CCM\Logs"))
            {
                GrepFileRegex(filePath, regex);
            }
        }

        public static void Triage()
        {
            Console.WriteLine("[+] Client cache contents and permissions for the current user:");
            GetDirectoryContentsAndPermissions(@"C:\Windows\ccmcache", true);
            Console.WriteLine("\n[+] Searching logs for possible UNC paths:");
            SearchClientLogs(@"(\\\\([a-z|A-Z|0-9|-|_|\s]{2,15}){1}(\.[a-z|A-Z|0-9|-|_|\s]{1,64}){0,3}){1}(\\[^\\|\/|\:|\*|\?|""|\<|\>|\|;|]{1,64}){1,}(\\){0,}");
            Console.WriteLine("\n[+] Searching logs for possible URLs:");
            SearchClientLogs(@"(?<Protocol>\w+):\/\/(?<Domain>[\w@][\w.:@]+)\/?[\w\.?=%&=\-@/$,]*");
            Console.WriteLine();
        }
    }
}