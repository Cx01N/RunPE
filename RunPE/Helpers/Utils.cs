using System;
using System.Linq;
using System.Runtime.InteropServices;
using RunPE.Internals;

using DInvoke;
using DInvoke.Data;
using DInvoke.DynamicInvoke;
using Native = DInvoke.Data.Native;

using static RunPE.Internals.NativeDeclarations;
using static DInvoke.DynamicInvoke.Native.DELEGATES;
using System.Diagnostics;

namespace RunPE.Helpers
{
    internal static class Utils
    {
        internal static byte[] PatchFunction(string dllName, string funcName, byte[] patchBytes)
        {
#if DEBUG
            Console.WriteLine($"[*] Patching {dllName}!{funcName}");
            var patchString = "";
            foreach (var x in patchBytes)
            {
                patchString += "0x" + x.ToString("X") + " ";
            }

            Console.WriteLine($"[*] PatchBytes: {patchString}");
            Console.WriteLine($"[*] PatchBytes Len: {patchBytes.Length}");
#endif
            var moduleHandle = NativeDeclarations.GetModuleHandle(dllName);
            var pFunc = NativeDeclarations.GetProcAddress(moduleHandle, funcName);
#if DEBUG
            Console.WriteLine($"[*] {dllName}!{funcName} API function at: 0x{pFunc.ToInt64():X}");
#endif
            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(pFunc, originalBytes, 0, patchBytes.Length);

#if DEBUG
            var originalBytesString = "";
            foreach (var x in originalBytes)
            {
                originalBytesString += "0x" + x.ToString("X") + " ";
            }

            Console.WriteLine($"[*] Original bytes: {originalBytesString}");
#endif
            var result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr) patchBytes.Length,
                NativeDeclarations.PAGE_EXECUTE_READWRITE, out var oldProtect);
            if (!result)
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to change memory protections on {dllName}!{funcName}");
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine($"[-] GetLastError: {error}");
#endif
                return null;
            }
#if DEBUG
            else
            {
                Console.WriteLine($"[*] Changed protections on {dllName}!{funcName} to RW");
            }
#endif
            Marshal.Copy(patchBytes, 0, pFunc, patchBytes.Length);

#if DEBUG
            Console.WriteLine($"[+] Patched function {dllName}!{funcName}");
#endif

            result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr) patchBytes.Length, oldProtect, out _);
            if (!result)
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to change memory protections back on {dllName}!{funcName}");
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine($"[-] GetLastError: {error}");
#endif
            }
#if DEBUG
            else
            {
                Console.WriteLine($"[*] Reverted memory protections on {dllName}!{funcName}");
            }
#endif
            return originalBytes;
        }
        public static bool PatchAddress(IntPtr pAddress, IntPtr newValue)
        {
            // Get a handle to the current process.
            IntPtr processHandle = Process.GetCurrentProcess().Handle;

            // Prepare the parameters for the NtProtectVirtualMemory call.
            uint oldProtect = 0;
            uint size = (uint)IntPtr.Size;
            IntPtr baseAddress = pAddress;
            uint newProtect = 0x40; // PAGE_EXECUTE_READWRITE

            // Prepare the delegate parameters.
            object[] funcParams = { processHandle, baseAddress, size, newProtect, oldProtect };

            try
            {
                // Dynamically invoke NtProtectVirtualMemory.
                var ntProtectVirtualMemory = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(
                    DInvoke.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory"),
                    typeof(NtProtectVirtualMemoryDelegate));

                // Change memory protection to RWX so we can write to it.
                uint status = ntProtectVirtualMemory(processHandle, ref baseAddress, ref size, newProtect, out oldProtect);
                if (status != 0) // STATUS_SUCCESS
                {
                    Console.WriteLine("[-] Failed to change memory protection.");
                    return false;
                }

                // Write the new value to the address.
                Marshal.WriteIntPtr(pAddress, newValue);

                // Revert memory protection back to its original state.
                ntProtectVirtualMemory(processHandle, ref baseAddress, ref size, oldProtect, out _);

                Console.WriteLine("[+] Successfully patched address.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Exception during PatchAddressWithDInvoke: {ex.Message}");
                return false;
            }
        }


        internal static bool ZeroOutMemory(IntPtr start, int length)
        {
            var result = NativeDeclarations.VirtualProtect(start, (UIntPtr) length, NativeDeclarations.PAGE_READWRITE,
                out var oldProtect);
            if (!result)
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to change memory protections to RW on at 0x{start.ToInt64():X}");
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine($"[-] GetLastError: {error}");
                return false;
#endif
            }

            var zeroes = new byte[length];
            for (var i = 0; i < zeroes.Length; i++)
            {
                zeroes[i] = 0x00;
            }

            Marshal.Copy(zeroes.ToArray(), 0, start, length);

            result = NativeDeclarations.VirtualProtect(start, (UIntPtr) length, oldProtect, out _);
            if (!result)
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to change memory protections back on at 0x{start.ToInt64():X}");
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine($"[-] GetLastError: {error}");
#endif
                return false;
            }
            
            return true;
        }

        internal static void FreeMemory(IntPtr address)
        {
            NativeDeclarations.VirtualFree(address, 0, NativeDeclarations.MEM_RELEASE);
        }

        internal static IntPtr GetPointerToPeb()
        {
            var currentProcessHandle = NativeDeclarations.GetCurrentProcess();
            var processBasicInformation =
                Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)));
            var outSize = Marshal.AllocHGlobal(sizeof(long));
            var pPEB = IntPtr.Zero;

            var result = NativeDeclarations.NtQueryInformationProcess(currentProcessHandle, 0, processBasicInformation,
                (uint) Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)), outSize);

            NativeDeclarations.CloseHandle(currentProcessHandle);
            Marshal.FreeHGlobal(outSize);

            if (result == 0)
            {
                pPEB = ((NativeDeclarations.PROCESS_BASIC_INFORMATION) Marshal.PtrToStructure(processBasicInformation,
                    typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION))).PebAddress;
            }
            else
            {
                Console.WriteLine($"[-] Unable to NtQueryInformationProcess, error code: {result}");
                var error = NativeDeclarations.GetLastError();
                Console.WriteLine($"[-] GetLastError: {error}");
            }

            Marshal.FreeHGlobal(processBasicInformation);

            return pPEB;
        }

        public static byte[] ReadMemory(IntPtr address, int length)
        {
            var bytes = new byte[length];
            Marshal.Copy(address, bytes, 0, length);
            return bytes;
        }
    }
}