using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace MaliciousIPInterceptor
{
    internal static class Program
    {
        public const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;
        public static readonly string ExePath;
        public static readonly string ExeFolder;
        public static readonly string ServiceName;
        private static readonly Dictionary<string, Tuple<Action<string>, string>> usage;

        private const string DebugFolder = "D:\\debug\\";

        static Program()
        {
            ExeFolder = AppDomain.CurrentDomain.BaseDirectory;
            ExePath = ExeFolder + AppDomain.CurrentDomain.FriendlyName;
            
            ServiceName = "IPInterceptorService";
            usage = new Dictionary<string, Tuple<Action<string>, string>>
            {
                {"install", new Tuple<Action<string>, string>(ServiceControllerHelper.InstallService , ExePath ) },
                {"uninstall", new Tuple<Action<string>, string>(ServiceControllerHelper.UninstallService, ExePath) },
                {"start", new Tuple<Action<string>, string>(ServiceControllerHelper.ServiceStart, ServiceName) },
                {"stop", new Tuple<Action<string>, string>(ServiceControllerHelper.ServiceStop, ServiceName) },
                {"debug", new Tuple<Action<string>, string>(InterceptorService.DebugOnStart, DebugFolder + "config.ini") },
            };
        }

        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += UnhandledExceptionEvent;

            if (args.Length == 0)
            {
                DisplayUsage(string.Empty);
                return;
            }
            if ("service".Equals(args[0]))
            {
                Logger.HasConsole = false;
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                    new InterceptorService(args)
                };
                ServiceBase.Run(ServicesToRun);
            }
            else if (usage.TryGetValue(args[0], out Tuple<Action<string>, string> runner))
            {
                if (!Util.AllocConsole())
                {
                    Util.AttachConsole(ATTACH_PARENT_PROCESS);
                }
                try
                {
                    Logger.HasConsole = true;
                    if (Directory.Exists(DebugFolder))
                    {
                        Logger.LogFilePath = DebugFolder + "mip.log";
                    }
                    runner.Item1(runner.Item2);

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(ex.StackTrace);
                }
                Console.Write("Press any key to exit.");
                Console.ReadKey();
                if ("debug".Equals(args[0]))
                    InterceptorService.DebugOnStop();
                Util.FreeConsole();
            }
            else
            {
                DisplayUsage(args[0]);
            }
        }

        static void DisplayUsage(string arg)
        {
            if (!Util.AllocConsole())
            {
                Util.AttachConsole(ATTACH_PARENT_PROCESS);
            }

            if (!string.Empty.Equals(arg))
            {
                Console.WriteLine($"Unknow command: \"{arg}\"");
            }
            Console.WriteLine("Usage: ");
            foreach (var cmd in usage)
            {
                Console.WriteLine($"    {cmd.Key}");
            }
            Console.Write("Press any key to exit.");
            Console.ReadKey();
            Util.FreeConsole();
        }

        static void UnhandledExceptionEvent(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                Logger.Error(ex.Message + Environment.NewLine + ex.StackTrace);
            }
            else
            {
                Logger.Error("Unknown error!");
            }
        }
    }
}
