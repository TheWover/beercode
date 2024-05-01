using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class NativeMethods
{
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName,
           string lpCommandLine, IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles, CreateProcessFlags dwCreationFlags,
           IntPtr lpEnvironment, string lpCurrentDirectory,
           ref STARTUPINFO lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern uint SuspendThread(IntPtr hThread);
}

[Flags]
public enum CreateProcessFlags
{
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NEW_CONSOLE = 0x00000010,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_NO_WINDOW = 0x08000000,
    CREATE_PROTECTED_PROCESS = 0x00040000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_SHARED_WOW_VDM = 0x00001000,
    CREATE_SUSPENDED = 0x00000004,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
    DEBUG_PROCESS = 0x00000001,
    DETACHED_PROCESS = 0x00000008,
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
    INHERIT_PARENT_AFFINITY = 0x00010000
}

public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

namespace ThreadObserver
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string processpath = args[0];

            ThreadObserver observer = new ThreadObserver();

            Task.Factory.StartNew(() => observer.Start());

            Process process = Process.Start(processpath);

            observer.pid = process.Id;

            /*
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool success = NativeMethods.CreateProcess(processpath, null,
                IntPtr.Zero, IntPtr.Zero, false,
                CreateProcessFlags.CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out pi);

            observer.pid = Convert.ToInt32(pi.dwProcessId);

            Console.WriteLine("PID: " + observer.pid);

            // Resume the process
            IntPtr ThreadHandle = pi.hThread;
            NativeMethods.ResumeThread(ThreadHandle);
            */

            Console.ReadLine();


        }
    }

    internal class ThreadObserver
    {
        public TraceEventSession session;
        public int pid = 0;

        public ThreadObserver() {
            session = new TraceEventSession("WKL-ETWSession");

            session.EnableProvider("Microsoft-Windows-Kernel-Process", TraceEventLevel.Verbose, 0x20); // Process start and commands
        }

        public void Start()
        {
            Process.GetProcessById(pid);


            // Set up the callbacks 
            session.Source.Dynamic.All += delegate (TraceEvent data) {

                string sEventPID = (string)Convert.ToString(data.PayloadByName("ProcessID"));

                if (data.EventName == "ThreadStart/Start" && sEventPID == Convert.ToString(pid))
                {
                    Console.WriteLine("GOT EVENT {0}", data);
                    //Console.WriteLine(sEventPID);
                }

            };
            session.Source.Process(); // Invoke callbacks for events in the source
        }
    }
}
