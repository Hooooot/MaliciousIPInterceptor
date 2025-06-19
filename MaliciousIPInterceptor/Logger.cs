using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace MaliciousIPInterceptor
{
    public static class Logger
    {
        private static string logFilePath;
        private static DateTime LogFileCreateTime = DateTime.Now;

        public static bool HasConsole { get; set; }

        public static string LogFilePath
        { 
            get 
            {
                if (logFilePath == null)
                    logFilePath = Path.ChangeExtension(Program.ExePath, ".log");
                return logFilePath;
            } 
            set
            {
                logFilePath = value;
            } 
        }

        public static void Debug(string msg,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            WriteLog("Debug", msg, memberName, sourceFilePath, sourceLineNumber);
        }

        public static void Info(string msg,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            WriteLog("Info", msg, memberName, sourceFilePath, sourceLineNumber);
        }

        public static void Warning(string msg,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            WriteLog("Warning", msg, memberName, sourceFilePath, sourceLineNumber);
        }

        public static void Error(string msg,
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0)
        {
            WriteLog("Error", msg, memberName, sourceFilePath, sourceLineNumber);
        }

        private static void WriteLog(string level, string msg, string memberName, string sourceFilePath, int sourceLineNumber)
        {
            string sourceFileName= Path.GetFileName(sourceFilePath);
            DateTime now = DateTime.Now;
            if (LogFileCreateTime.Day != now.Day)
            {
                File.Move(LogFilePath, $"{LogFilePath}.{now:yyyy_MM_dd}.log");
                LogFileCreateTime = now;
            }
            using (StreamWriter sw = new StreamWriter(LogFilePath, true))
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(DateTime.Now.ToString("yyyy-MM-dd_HH:mm:ss.f"));
                sb.Append($" [{level}] ");
                sb.Append($" [{sourceFileName}\\{memberName}:{sourceLineNumber}]:");
                sb.Append(msg);
                string m = sb.ToString();
                sw.WriteLine(m);
                sw.Flush();
                if (HasConsole)
                    Console.WriteLine(m);
            }
        }
    }
    
}
