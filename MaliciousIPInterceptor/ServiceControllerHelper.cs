using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ServiceProcess;
using System.Configuration.Install;

namespace MaliciousIPInterceptor
{
    public static class ServiceControllerHelper
    {
        public static void InstallService(string servicePath)
        {
            using (AssemblyInstaller installer = new AssemblyInstaller())
            {
                installer.UseNewContext = true;
                installer.Path = servicePath;
                IDictionary savedState = new Hashtable();
                installer.Install(savedState);
                installer.Commit(savedState);
            }
        }

        public static void UninstallService(string servicePath)
        {
            using (AssemblyInstaller installer = new AssemblyInstaller())
            {
                installer.UseNewContext = true;
                installer.Path = servicePath;
                installer.Uninstall(null);
            }
        }

        public static void ServiceStart(string serviceName)
        {
            using (ServiceController control = new ServiceController(serviceName))
            {
                if (control.Status == ServiceControllerStatus.Stopped)
                {
                    control.Start();
                }
            }
        }

        public static void ServiceStop(string serviceName)
        {
            using (ServiceController control = new ServiceController(serviceName))
            {
                if (control.Status == ServiceControllerStatus.Running)
                {
                    control.Stop();
                }
            }
        }
    }
}
