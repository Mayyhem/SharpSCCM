using System;
using System.Management;

namespace SharpSCCM
{
    static class ClientFileSystem
    {
        public static void LocalGrepFile(string path, string stringToFind)
        {
            string[] lines = System.IO.File.ReadAllLines(path);
            foreach (string line in lines)
            {
                if (line.Contains(stringToFind))
                {
                    Console.WriteLine(line);
                }
            }
        }

        public static void LocalPushLogs(string startTime, string startDate)
        {
            ManagementScope sccmConnection = MgmtUtil.NewSccmConnection("\\\\localhost\\root\\cimv2");
            DateTime startDateObj = DateTime.Parse(startDate);
            // To-do
        }
    }
}