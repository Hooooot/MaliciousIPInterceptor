using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using NetFwTypeLib;

namespace MaliciousIPInterceptor
{
    public static class Util
    {
        [DllImport("kernel32")]
        public static extern int GetPrivateProfileString(string section, string key, IntPtr def, StringBuilder retVal, int size, string filePath);

        [DllImport("kernel32.dll")]
        public static extern bool AllocConsole();
        [DllImport("kernel32.dll")]
        public static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool FreeConsole();

        public static string GetSubnet24Ip(string ip)
        {
            int startOffset = ip.LastIndexOf('.');
            return ip.Substring(0, startOffset) + ".0";
        }

        public static void AddToFireWall2(string ruleUUID, string subnet24IP)
        {
            using (RegistryKey rulesKey = 
                Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", true))
            {
                if (!(rulesKey.GetValue(ruleUUID) is string rules))
                    return;

                int offset = rules.LastIndexOf("|Name=banIP|");
                rulesKey.SetValue(ruleUUID, rules.Insert(offset, $"|RA4={subnet24IP}/255.255.255.0"));
                rulesKey.Flush();
                Logger.Info($"IP({subnet24IP}) has been added to the FireWall.");
            }
        }

        public static void AddToFireWall(string ruleName, string subnet24IP)
        {
            INetFwPolicy2 policy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            foreach (INetFwRule item in policy.Rules)
            {
                if (item.Name == ruleName)
                {
                    item.RemoteAddresses += $",{subnet24IP}/255.255.255.0";
                    Logger.Info($"IP({subnet24IP}) has been added to the FireWall.");
                    break;
                }
            }
        }

        //{"status":"success","country":"俄罗斯","countryCode":"RU","region":"MOW","regionName":"Moscow","city":"莫斯科","query":"87.247.158.57"}
        public static string GetIPRegion(string ip)
        {
            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(10);
                try
                {
                    var task = client.GetStringAsync($"http://ip-api.com/json/{ip}?fields=57375&lang=zh-CN");
                    task.Wait();
                    string response = task.Result;
                    int countryStartIndex = response.IndexOf("\"countryCode\":\"");
                    int countryEndIndex = response.IndexOf('\"', countryStartIndex + 15);
                    if (countryStartIndex <= 0 || countryEndIndex <= 0)
                        return null;
                    string countryCode = response.Substring(countryStartIndex + 15, countryEndIndex - countryStartIndex - 15);

                    int regionStartIndex = response.IndexOf("\"regionName\":\"");
                    int regionEndIndex = response.IndexOf('\"', regionStartIndex + 14);
                    if (regionStartIndex <= 0 || regionEndIndex <= 0)
                        return null;
                    string regionName = response.Substring(regionStartIndex + 14, regionEndIndex - regionStartIndex - 14);

                    return countryCode + " " + regionName;
                }
                catch (Exception e)
                {
                    Logger.Error("Get IP region failed: " + e.Message);
                    return null;
                }
            }
        }
    }

}
