using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;

namespace SharpSCCM
{
    public static class LDAP
    {
        public static string GetDNFromFQDN(string fqdn)
        {
            string dn;
            DirectoryEntry root = new DirectoryEntry("LDAP://rootDSE");
            string defaultNamingContext = root.Properties["defaultNamingContext"].Value.ToString();
            if (fqdn.EndsWith(defaultNamingContext))
            {
                dn = "DC=" + fqdn.Replace("." + defaultNamingContext, "").Replace(".", ",DC=");
            }
            else
            {
                string[] parts = fqdn.Split('.');
                dn = "DC=" + string.Join(",DC=", parts);
            }
            return dn;
        }

        public static void GetSiteServersFromAD(string domainFqdn)
        {
            // Credit to Garrett Foster (@garrfoster) for discovering this technique for finding site servers
            string domainDistinguishedName = GetDNFromFQDN(domainFqdn);
            string path = $"LDAP://CN=System Management,CN=System,{domainDistinguishedName}";
            DirectoryEntry directoryEntry = new DirectoryEntry(path);
            ActiveDirectorySecurity acl = directoryEntry.ObjectSecurity;
            List<string> securityPrincipals = new List<string>();
            foreach (ActiveDirectoryAccessRule ace in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {

                if (ace.ActiveDirectoryRights == ActiveDirectoryRights.GenericAll)
                {
                    string sid = ace.IdentityReference.Value;
                    if (sid.EndsWith(value: "$"))
                    {
                        securityPrincipals.Add(sid);
                    }
                    else 
                    {
                        SecurityIdentifier sidObj = new SecurityIdentifier(sid);
                        try
                        {
                            NTAccount account = (NTAccount)sidObj.Translate(typeof(NTAccount));
                            if (account.Value.EndsWith("$"))
                            {
                                securityPrincipals.Add(account.Value);
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[!] Error resolving SID {sid}: {e.Message}");
                        }
                    }
                }
            }
            if (securityPrincipals.Count > 0)
            {
                Console.WriteLine($"[!] Found {securityPrincipals.Count} computer account(s) with GenericAll permission on the System Management container:\n");
                foreach (string securityPrincipal in securityPrincipals)
                {
                    Console.WriteLine("      " + securityPrincipal);
                }
                Console.WriteLine("\n[+] These systems are likely to be ConfigMgr site servers");
            }
            else {
                Console.WriteLine("[!] Found 0 computer accounts with GenericAll permission on the System Management container (potential site servers)");
            }
        }
    }
}