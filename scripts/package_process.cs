using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SoftwareManager
{
    public static class PackageProcess
    {
        private const uint KillOnClose = 0x2000;
        private const uint CreateSuspended = 0x4;
        private const uint CreateNoWindow = 0x08000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimit
        {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimit
        {
            public BasicLimit BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Accounting
        {
            public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public uint cb;
            public string lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInfo
        {
            public IntPtr Process, Thread;
            public uint ProcessId, ThreadId;
        }

        public sealed class Result
        {
            public int ExitCode;
            public bool TimedOut, CleanupConfirmed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimit info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint length, IntPtr returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        public static extern int MsiQueryProductState(string productCode);

        private static void SetKillOnClose(IntPtr job, bool enabled)
        {
            ExtendedLimit limit = new ExtendedLimit();
            limit.BasicLimitInformation.LimitFlags = enabled ? KillOnClose : 0;
            if (!SetInformationJobObject(job, 9, ref limit, (uint)Marshal.SizeOf(typeof(ExtendedLimit))))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot configure installer job");
        }

        private static uint ActiveProcesses(IntPtr job)
        {
            Accounting accounting;
            if (!QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect installer job");
            return accounting.ActiveProcesses;
        }

        public static string Quote(string value)
        {
            if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
                return value;
            StringBuilder output = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') output.Append('\\', slashes + 1);
                output.Append('\\', slashes).Append(c);
                slashes = 0;
            }
            return output.Append('\\', slashes * 2).Append('"').ToString();
        }

        public static Result Run(string executable, string arguments, string directory, int seconds, bool waitChildren)
        {
            if (seconds < 5 || seconds > 86400) throw new ArgumentOutOfRangeException("seconds");
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create installer job");
            ProcessInfo process = new ProcessInfo();
            bool assigned = false;
            try
            {
                SetKillOnClose(job, true);
                StartupInfo startup = new StartupInfo();
                startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
                StringBuilder command = new StringBuilder(Quote(executable) + (String.IsNullOrEmpty(arguments) ? "" : " " + arguments));
                if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, false, CreateSuspended | CreateNoWindow,
                    IntPtr.Zero, String.IsNullOrEmpty(directory) ? null : directory, ref startup, out process))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot start installer");
                if (!AssignProcessToJobObject(job, process.Process))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot isolate installer job");
                assigned = true;
                Stopwatch timer = Stopwatch.StartNew();
                if (ResumeThread(process.Thread) == UInt32.MaxValue)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot resume installer");
                while (true)
                {
                    uint root = WaitForSingleObject(process.Process, 0);
                    if (root != 0 && root != 258)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot wait for installer");
                    if (root == 0 && (!waitChildren || ActiveProcesses(job) == 0))
                    {
                        uint code;
                        if (!GetExitCodeProcess(process.Process, out code))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read installer exit code");
                        if (!waitChildren) SetKillOnClose(job, false);
                        return new Result { ExitCode = unchecked((int)code), CleanupConfirmed = waitChildren };
                    }
                    if (timer.Elapsed.TotalSeconds >= seconds)
                    {
                        bool confirmed = false;
                        if (TerminateJobObject(job, 1460))
                        {
                            Stopwatch cleanup = Stopwatch.StartNew();
                            try
                            {
                                while (ActiveProcesses(job) != 0 && cleanup.Elapsed.TotalSeconds < 10) Thread.Sleep(100);
                                confirmed = ActiveProcesses(job) == 0;
                            }
                            catch (Win32Exception) { confirmed = false; }
                        }
                        return new Result { TimedOut = true, CleanupConfirmed = confirmed };
                    }
                    Thread.Sleep(100);
                }
            }
            finally
            {
                if (!assigned && process.Process != IntPtr.Zero) TerminateProcess(process.Process, 1460);
                CloseHandle(job);
                if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
                if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            }
        }
    }
}
