using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace MaliciousIPInterceptor
{
    public partial class InterceptorService : ServiceBase
    {
        private static FileSystemWatcher fileWatcher = null;
        private static EventLogWatcher windowsEventWatcher = null;
        private static Timer timer = null;
        private static ConfigIniModel iniModel = null;

        private static int lastFileSize = 0;

        public InterceptorService(string[] args)
        {
            InitializeComponent();
        }

        private static string GetIP(string line)
        {
            if (!line.EndsWith("]"))
                return null;

            int lastIndex = line.LastIndexOf(':');
            if (lastIndex == -1)
                return null;

            int startIndex = line.LastIndexOf('[');
            if (startIndex == -1 || startIndex + 7 > lastIndex)
                return null;

            string ip = line.Substring(startIndex + 1, lastIndex - startIndex - 1);
            if (IPAddress.TryParse(ip, out _))
                return ip;
            return null;
        }

        private static void FileSystemWatcher_ChangedHandler(object sender, FileSystemEventArgs e)
        {
            using (FileStream fs = new FileStream(iniModel.MonitorFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (!fs.CanRead || !fs.CanSeek)
                {
                    lastFileSize = 0;
                    return;
                }
                if (fs.Length < lastFileSize)
                {
                    lastFileSize = 0;
                }
                if (fs.Length == lastFileSize)
                {
                    return;
                }
                byte[] buffer = new byte[fs.Length - lastFileSize];
                fs.Position = lastFileSize;
                fs.Read(buffer, 0, buffer.Length);
                lastFileSize += buffer.Length;
                string log = Encoding.UTF8.GetString(buffer, 0, buffer.Length);
                string[] lines = log.Split('\n');
                foreach (string line in lines)
                {
                    string ip = GetIP(line);
                    if (ip == null)
                        continue;

                    InterceptRules.CheckIntercept(iniModel, ip);
                }
            }
        }

        private static void OnWindowsEventRecordWritten(object obj, EventRecordWrittenEventArgs arg)
        {
            var eventData = arg.EventRecord.Properties;
            string ip = null;
            string workstationName = null;
            if (eventData.Count == 21)
            {
                ip = eventData[19].Value.ToString();
                workstationName = eventData[13].Value.ToString();
            }
            else
            {
                foreach (var item in eventData)
                {
                    if (IPAddress.TryParse(item.Value.ToString(), out _))
                    {
                        ip = item.Value.ToString();
                        break;
                    }
                }
            }
            if (ip == null)
            {
                Logger.Error("Unknown event log, RecordID = " + arg.EventRecord.RecordId.ToString());
                return;
            }
            InterceptRules.CheckIntercept(iniModel, ip, workstationName);
        }

        private static void TimerCallback(object state)
        {
            if (iniModel == null)
                return;
            try
            {
                File.GetLastWriteTime(iniModel.MonitorFile);
            }
            catch (Exception e)
            {
                Logger.Error(e.Message);
            }
        }

        public static void DebugOnStart(string configPath)
        {
            Logger.Info("The service has been started.");
            if (!File.Exists(configPath))
                configPath = Program.ExeFolder + "\\config.ini";

            iniModel = ConfigIniModel.GetConfig(configPath);
            fileWatcher = new FileSystemWatcher
            {
                Path = Path.GetDirectoryName(iniModel.MonitorFile),
                Filter = Path.GetFileName(iniModel.MonitorFile),
                IncludeSubdirectories = false
            };
            fileWatcher.Changed += FileSystemWatcher_ChangedHandler;
            fileWatcher.EnableRaisingEvents = true;
            timer = new Timer(TimerCallback, null, 2 * 1000, 2 * 1000);
            EventLogQuery eventLogQuery = new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4625]");
            windowsEventWatcher = new EventLogWatcher(eventLogQuery);
            windowsEventWatcher.EventRecordWritten += OnWindowsEventRecordWritten;
            windowsEventWatcher.Enabled = true;
        }

        protected override void OnStart(string[] args)
        {
            DebugOnStart(Program.ExeFolder + "\\config.ini");
        }

        public static void DebugOnStop()
        {
            if (windowsEventWatcher != null)
            {
                windowsEventWatcher.Enabled = false;
                windowsEventWatcher.Dispose();
            }
            if (fileWatcher != null)
            {
                fileWatcher.EnableRaisingEvents = false;
                fileWatcher.Dispose();
                fileWatcher = null;
            }
            timer?.Dispose();
            Logger.Info("The service has stopped.");
        }

        protected override void OnStop()
        {
            DebugOnStop();
        }

    }
}
