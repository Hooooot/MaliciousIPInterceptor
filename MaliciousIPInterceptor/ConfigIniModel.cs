using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace MaliciousIPInterceptor
{
    public class ConfigIniModel
    {
        public string RuleName { get; private set; }
        public string AllowedWorkstationNamePrefix { get; private set; }
        public string MonitorFile { get; private set; }
        public string WhiteListPath { get; private set; }
        public string BlackListPath { get; private set; }
        public string WhiteRegionListPath { get; private set; }


        protected ConfigIniModel() { }

        public static ConfigIniModel GetConfig(string iniPath)
        {
            ConfigIniModel config = new ConfigIniModel();
            Type model = config.GetType();
            PropertyInfo[] properties = model.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            foreach (PropertyInfo property in properties)
            {
                StringBuilder sb = new StringBuilder();
                Util.GetPrivateProfileString("Setting", property.Name, IntPtr.Zero, sb, 260, iniPath);
                property.SetValue(config, sb.ToString());
            }

            return config;
        }
    }
}
