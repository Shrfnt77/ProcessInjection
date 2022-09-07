using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection
{
    internal class Native
    {

        public const uint Commit = 0x1000;
        public const uint ExecuteReadWrite = 0x40;
        public const uint HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;

        public const uint SECTION_ALL_ACCESS = 0xF001F;
        public const uint SEC_COMMIT = 0x8000000;

        public const uint SUSPEND_RESUME = (0x0002);
        public const uint GET_CONTEXT = (0x0008);
        public const uint SET_CONTEXT = (0x0010);
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint CREATE_SUSPENDED = 0x00000004;
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);


        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect( IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr HeapCreate(uint flOptions, uint dwInitialSize, uint dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [DllImport("kernel32.dll")]
        public static extern IntPtr ConvertThreadToFiber(IntPtr lpParameter);


        [DllImport("kernel32.dll")]
        public static extern IntPtr SwitchToFiber(IntPtr lpFiber);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFiber(uint dwStackSize,IntPtr lpStartAddress, IntPtr lpParameter);


        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle,   UInt32 DesiredAccess,  IntPtr ObjectAttributes, ref UInt32 MaximumSize,  UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtMapViewOfSection(   IntPtr SectionHandle,   IntPtr ProcessHandle,   ref IntPtr BaseAddress,   UIntPtr ZeroBits,   UIntPtr CommitSize,   out ulong SectionOffset,   out uint ViewSize,  uint InheritDisposition,   uint AllocationType,  uint Win32Protect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory( IntPtr hProcess,IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
   
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess,  IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);


        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle,    int dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, byte[] PROCESS_INFORMATIONlpProcessInformation);
    }
}
