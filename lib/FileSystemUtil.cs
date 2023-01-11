using System.IO;
using System;

namespace SharpSCCM
{
    public class FileSystemUtil
    { 
        public static void GetShare(string server, string share)
        {
            string dataLibPath = $"\\\\{server}\\{share}\\DataLib\\";
            DirectoryInfo dataLibDir = new DirectoryInfo(dataLibPath);

            try
            {
                DirectoryInfo[] folders = dataLibDir.GetDirectories();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An exception occurred while accessing {dataLibPath}: {ex.Message}");
            }
        }
    }
}