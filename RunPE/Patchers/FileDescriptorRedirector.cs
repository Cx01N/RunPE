using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RunPE.Internals;

using StringTask = System.Threading.Tasks.Task<string>;

namespace RunPE.Patchers
{
    internal class FileDescriptorPair
    {
        public IntPtr Read { get; set; }

        public IntPtr Write { get; set; }
    }

    internal class FileDescriptorRedirector
    {
        private const int STD_INPUT_HANDLE = -10;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const uint BYTES_TO_READ = 1024;

        private IntPtr _oldGetStdHandleOut;
        private IntPtr _oldGetStdHandleIn;
        private IntPtr _oldGetStdHandleError;

        private FileDescriptorPair _kpStdOutPipes;
        private FileDescriptorPair _kpStdInPipes;

        private StringTask _readTask;

        public bool RedirectFileDescriptors()
        {
            _oldGetStdHandleOut = GetStdHandleOut();
            _oldGetStdHandleIn = GetStdHandleIn();
            _oldGetStdHandleError = GetStdHandleError();

#if DEBUG
            Console.WriteLine("[*] Creating STDOut Pipes to redirect to");
#endif
            _kpStdOutPipes = CreateFileDescriptorPipes();
            if (_kpStdOutPipes == null)
            {
                Console.WriteLine("[-] Unable to create STDOut Pipes");
                return false;
            }

#if DEBUG
            Console.WriteLine("[*] Creating STDIn Pipes to redirect to");
#endif
            _kpStdInPipes = CreateFileDescriptorPipes();
            if (_kpStdInPipes == null)
            {
                Console.WriteLine("[-] Unable to create STDIn Pipes");
                return false;
            }

            if (!RedirectDescriptorsToPipes(_kpStdOutPipes.Write, _kpStdInPipes.Write, _kpStdOutPipes.Write))
            {
                Console.WriteLine("[-] Unable redirect descriptors to pipes");
                return false;
            }
            return true;
        }

        public string ReadDescriptorOutput()
        {
#if DEBUG
            Console.WriteLine("[*] Retrieving the 'subprocess' stdout & stderr");
#endif
            while (!_readTask.IsCompleted)
            {
#if DEBUG
                Console.WriteLine("[*] Waiting for the task reading from pipe to finish...");
#endif
                Thread.Sleep(2000);
            }

            return _readTask.Result;
        }

        public void ResetFileDescriptors()
        {
#if DEBUG
            Console.WriteLine("[*] Reset StdError, StdOut, StdIn");
#endif
            RedirectDescriptorsToPipes(_oldGetStdHandleOut, _oldGetStdHandleIn, _oldGetStdHandleError);

            ClosePipes();
        }

        private static IntPtr GetStdHandleOut()
        {
            return NativeDeclarations.GetStdHandle(STD_OUTPUT_HANDLE);
        }

        private static IntPtr GetStdHandleError()
        {
            return NativeDeclarations.GetStdHandle(STD_ERROR_HANDLE);
        }

        internal void ClosePipes()
        {
#if DEBUG
            Console.WriteLine("[*] Closing StdOut pipes");
#endif
            CloseDescriptors(_kpStdOutPipes);
#if DEBUG
            Console.WriteLine("[*] Closing StdIn pipes");
#endif
            CloseDescriptors(_kpStdInPipes);
        }

        internal void StartReadFromPipe()
        {
            _readTask = StringTask.Factory.StartNew(() =>
            {
                StringBuilder output = new StringBuilder();
                byte[] buffer = new byte[BYTES_TO_READ];
                uint bytesRead;

                do
                {
                    bool readSuccessful = NativeDeclarations.ReadFile(_kpStdOutPipes.Read, buffer, BYTES_TO_READ, out bytesRead, IntPtr.Zero);

                    if (bytesRead > 0)
                    {
                        string text = Encoding.Default.GetString(buffer, 0, (int)bytesRead);
                        output.Append(text);
                    }

                    // If ReadFile fails, check if it is because the pipe is broken and terminate if so
                    if (!readSuccessful)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 109) // ERROR_BROKEN_PIPE
                        {
#if DEBUG
                    Console.WriteLine("[*] Subprocess has completed execution. Pipe is broken.");
#endif
                            break; // Exit the reading loop gracefully
                        }
                        else
                        {
                            Console.WriteLine($"[-] Error reading from pipe. Win32 Error Code: {error}");
                            break; // Exit the loop due to unexpected error
                        }
                    }
                }
                while (bytesRead > 0);

                return output.ToString();
            });
        }


        private static IntPtr GetStdHandleIn()
        {
            return NativeDeclarations.GetStdHandle(STD_INPUT_HANDLE);
        }

        private static void CloseDescriptors(FileDescriptorPair stdoutDescriptors)
        {
            try
            {
                // Need to close write before read else it hangs as could still be writing
                if (stdoutDescriptors.Write != IntPtr.Zero)
                {
                    NativeDeclarations.CloseHandle(stdoutDescriptors.Write);
#if DEBUG
                Console.WriteLine("[+] CloseHandle write");
#endif
                }

                if (stdoutDescriptors.Read != IntPtr.Zero)
                {
                    NativeDeclarations.CloseHandle(stdoutDescriptors.Read);
#if DEBUG
                Console.WriteLine("[+] CloseHandle read");
#endif
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error closing handles: {e}");
                Console.WriteLine($"Last error: 0x{NativeDeclarations.GetLastError():X}");
            }
        }

        private static FileDescriptorPair CreateFileDescriptorPipes()
        {
            var lpSecurityAttributes = new NativeDeclarations.SECURITY_ATTRIBUTES();
            lpSecurityAttributes.nLength = Marshal.SizeOf(lpSecurityAttributes);
            lpSecurityAttributes.bInheritHandle = 1;

            var outputStdOut = NativeDeclarations.CreatePipe(out var read, out var write, ref lpSecurityAttributes, 0);
            if (!outputStdOut)
            {
#if DEBUG
                Console.WriteLine("[-] Cannot create File Descriptor pipes");
#endif
                return null;
            }
#if DEBUG
            Console.WriteLine("[+] Created File Descriptor pipes: ");
            Console.WriteLine($"\t[*] Read: 0x{read.ToString("X")}");
            Console.WriteLine($"\t[*] Write: 0x{write.ToString("X")}");
#endif
            return new FileDescriptorPair
            {
                Read = read,
                Write = write
            };
        }

        private static bool RedirectDescriptorsToPipes(IntPtr hStdOutPipes, IntPtr hStdInPipes, IntPtr hStdErrPipes)
        {
            var bStdOut = NativeDeclarations.SetStdHandle(STD_OUTPUT_HANDLE, hStdOutPipes);
            if (bStdOut)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
#endif
            }
            else
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
#endif
                return false;
            }

            var bStdError = NativeDeclarations.SetStdHandle(STD_ERROR_HANDLE, hStdErrPipes);
            if (bStdError)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDERROR to 0x{hStdErrPipes.ToInt64():X}");
#endif
            }
            else
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to SetStdHandle STDERROR  to 0x{hStdErrPipes.ToInt64():X} ");
#endif
                return false;
            }

            var bStdIn = NativeDeclarations.SetStdHandle(STD_INPUT_HANDLE, hStdInPipes);
            if (bStdIn)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
#endif
            }
            else
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
#endif
                return false;
            }

            return true;
        }
    }
}