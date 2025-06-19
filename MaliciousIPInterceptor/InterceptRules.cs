using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MaliciousIPInterceptor
{
    internal class InterceptRules
    {
        public static bool CheckWhiteList(string whiteListPath, string subnet24IP)
        {
            foreach (var item in File.ReadLines(whiteListPath))
            {
                if (item.Contains(subnet24IP))
                {
                    Logger.Info($"The IP({subnet24IP}) is already on the whitelist.");
                    return true;
                }
            }
            return false;
        }

        public static bool CheckBlackList(string blackListPath, string subnet24IP)
        {
            foreach (var item in File.ReadLines(blackListPath))
            {
                if (item.Contains(subnet24IP))
                {
                    Logger.Info($"The IP({subnet24IP}) is already on the blacklist.");
                    return true;
                }
            }
            return false;
        }

        public static void AddWhiteList(string whiteListPath, string subnet24IP, string countryCodeAndRegion)
        {
            File.AppendAllText(whiteListPath, subnet24IP + " " + countryCodeAndRegion + Environment.NewLine);
            Logger.Info($"IP({subnet24IP}) has been added to the whitelist.");
        }

        public static void AddBlackList(string blackListPath, string subnet24IP, string countryCodeAndRegion)
        {
            File.AppendAllText(blackListPath, subnet24IP + " " + countryCodeAndRegion + Environment.NewLine);
            Logger.Info($"IP({subnet24IP}) has been added to the blacklist.");
        }

        public static void CheckRegion(ConfigIniModel iniModel, string ip, string subnet24IP)
        {
            string countryCodeAndRegion = Util.GetIPRegion(ip);
            if (countryCodeAndRegion == null)
            {
                Logger.Warning("Get IP region failed!");
                return;
            }
            foreach (var item in File.ReadLines(iniModel.WhiteRegionListPath))
            {
                if (countryCodeAndRegion.Contains(item))
                {
                    AddWhiteList(iniModel.WhiteListPath, subnet24IP, countryCodeAndRegion);
                    return;
                }
            }
            AddBlackList(iniModel.BlackListPath, subnet24IP, countryCodeAndRegion);
            Util.AddToFireWall(iniModel.RuleName, subnet24IP);
        }

        public static void CheckIntercept(ConfigIniModel iniModel, string ip)
        {
            string subnet24Ip = Util.GetSubnet24Ip(ip);
            if (CheckWhiteList(iniModel.WhiteListPath, subnet24Ip))
                return;
            if (CheckBlackList(iniModel.BlackListPath, subnet24Ip))
                return;

            CheckRegion(iniModel, ip, subnet24Ip);
        }

        public static void CheckIntercept(ConfigIniModel iniModel, string ip, string workstationName)
        {
            string subnet24Ip = Util.GetSubnet24Ip(ip);
            if (CheckWhiteList(iniModel.WhiteListPath, subnet24Ip))
                return;
            if (CheckBlackList(iniModel.BlackListPath, subnet24Ip))
                return;

            if (workstationName == null || !workstationName.StartsWith(iniModel.AllowedWorkstationNamePrefix))
            {
                AddBlackList(iniModel.BlackListPath, subnet24Ip, "NA Hacker");
                Util.AddToFireWall(iniModel.RuleName, subnet24Ip);
            }
            else
            {
                CheckRegion(iniModel, ip, subnet24Ip);
            }
        }
    }
}
