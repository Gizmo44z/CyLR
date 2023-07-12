using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using CyLR.archive;
using CyLR.read;
using CyLR.src.read;
using Renci.SshNet;
using ArchiveFile = CyLR.archive.File;
using File = System.IO.File;
using System.Threading.Tasks;


namespace CyLR
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Arguments arguments;
            try
            {
                arguments = new Arguments(args);
            }
            catch (ArgumentException e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Unknown error while parsing arguments: {e.Message}");
                return 0;
            }

            if (arguments.HelpRequested)
            {
                Console.WriteLine(arguments.GetHelp(arguments.HelpTopic));
                return 0;
            }

            var additionalPaths = new List<string>();
            if (Platform.IsInputRedirected)
            {
                string input = null;
                while ((input = Console.In.ReadLine()) != null)
                {
                    input = Environment.ExpandEnvironmentVariables(input);
                    additionalPaths.Add(input);
                }
            }


            List<string> paths;
            List<string> nodupes;
            try
            {
                
                paths = CollectionPaths.GetPaths(arguments, additionalPaths, arguments.Usnjrnl, arguments.AntiV, arguments.hash, arguments.noinet, arguments.rec, arguments.desk, arguments.recycle);
                nodupes = new HashSet<string>(paths).ToList();

                

            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Error occured while collecting files:\n{e}");
                return 1;
            }


            var stopwatch = new Stopwatch();
            stopwatch.Start();


            //Legacy zip archiving code, does not attempt 3 time SFTP upload
            //try
            //{
            //    var archiveStream = Stream.Null;
            //    if (!arguments.DryRun)
            //    {
            //        var outputPath = $@"{arguments.OutputPath}/{arguments.OutputFileName}";
            //        if (arguments.UseSftp)
            //        {
            //            var client = CreateSftpClient(arguments);
            //            archiveStream = client.Create(outputPath);
            //        }
            //        else
            //        {
            //            archiveStream = OpenFileStream(outputPath);
            //        }
            //    }
            //    using (archiveStream)
            //    {
            //        CreateArchive(arguments, archiveStream, paths);
            //    }

            //    stopwatch.Stop();
            //    Console.WriteLine("Extraction complete. {0} elapsed", new TimeSpan(stopwatch.ElapsedTicks).ToString("g"));
            //}
            //catch (Exception e)
            //{
            //    Console.Error.WriteLine($"Error occured while collecting files:\n{e}");
            //    return 1;
            //}
            //return 0;

            try
            {
                var archiveStream = Stream.Null;
                var outputPath = $@"{arguments.OutputPath}/{arguments.OutputFileName}";
                if (!arguments.DryRun)
                {
                    archiveStream = OpenFileStream(outputPath);
                }
                using (archiveStream)
                {
                    CreateArchive(arguments, archiveStream, nodupes);
                    File.Delete(@"C:\EXEHash.txt");
                    File.Delete(@"C:\SysInfo.txt");
                    File.Delete(@"C:\prochash.csv");
                }

                System.IO.File.Move(arguments.OutputPath + "\\" + arguments.OutputFileName, arguments.OutputPath + "\\" + $@"{arguments.OutputFileName.Replace("_INCOMPLETE", string.Empty)}");

                stopwatch.Stop();

                if (arguments.UseSftp)
                {
                    // Attempt upload of SFTP.

                    Console.WriteLine(arguments.UserName);
                    Console.WriteLine($"Attempting to upload to SFTP.");
                    SFTPUpload(arguments, outputPath);
                }
            }
            catch (Exception)
            {
               
                return 1;
            }
            return 0;
        }

        /// <summary>
        ///     Creates a zip archive containing all files from provided paths.
        /// </summary>
        /// <param name="arguments">Program arguments.</param>
        /// <param name="archiveStream">The Stream the archive will be written to.</param>
        /// <param name="paths">Map of driveLetter->path for all files to collect.</param>
        private static void CreateArchive(Arguments arguments, Stream archiveStream, IEnumerable<string> paths)
        {
            try
            {
                string ZipLevel = "3";
                if (!String.IsNullOrEmpty(arguments.ZipLevel))
                {
                    ZipLevel = arguments.ZipLevel;
                }
                using (var archive = new SharpZipArchive(archiveStream, arguments.ZipPassword, ZipLevel))
                {
                    var system = arguments.ForceNative ? (IFileSystem)new NativeFileSystem() : new RawFileSystem();

                    var filePaths = paths.SelectMany(path => system.GetFilesFromPath(path)).ToList();
                    foreach (var filePath in filePaths.Where(path => !system.FileExists(path)))
                    {
                        Console.Error.WriteLine($"Warning: file or folder '{filePath}' does not exist.");
                    }
                    var fileHandles = OpenFiles(system, filePaths);

                    archive.CollectFilesToArchive(fileHandles);
                }
            }
            catch(DiskReadException e)
            {
                Console.Error.WriteLine($"Failed to read files, this is usually due to lacking admin privilages.\nError:\n{e}");
            }
        }

        private static IEnumerable<ArchiveFile> OpenFiles(IFileSystem system, IEnumerable<string> files)
        {
            foreach (var file in files)
            {
                if (system.FileExists(file))
                {
                    Stream stream = null;
                    try
                    {
                        stream = system.OpenFile(file);
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"Error: {e.Message}");
                    }
                    if (stream != null)
                    {
                        yield return new ArchiveFile(file, stream, system.GetLastWriteTime(file));
                    }
                }
            }
        }

        /// <summary>
        /// <summary>
        /// Handle the connection to the SFTP server and uploading the resulting
        /// archive file. In the case the upload fails, this method will attempt
        /// to re-upload 3 times, with a 30 second pause between to allow time
        /// for the network to become more stable. If the upload is successful,
        /// the resulting archive file will be removed from the system - unless
        /// the user specified <c>--no-sftpcleanup</c> at invocation.
        /// </summary>
        /// <param name="arguments">User specified arguments with SFTP and other details</param>
        /// <param name="outputPath">Path to the archive file to upload</param>
        /// <param name="logger">Logging object</param>
        private static void SFTPUpload(Arguments arguments, string outputPath)
        {
            bool successfulUpload = false;
            int max_tries = 3;
            int num_tries = 0;
            while (!successfulUpload && (num_tries < max_tries))
            {
                bool attemptSuccess = false;
                try
                {

                    var sftpStream = Stream.Null;
                    var client = CreateSftpClient(arguments);
                    sftpStream = client.Create($@"{arguments.SFTPOutputPath}/{arguments.OutputFileName}");

                    const int bufferSize = 1048576;
                    byte[] buffer = new byte[1048576];
                    int readSize = -1;
                    ulong amountCopied = 0;
                    ulong pctComplete = 0;

                    using (sftpStream)
                    using (FileStream sr = File.OpenRead(outputPath))
                    {
                        do
                        {
                            readSize = sr.Read(buffer, 0, bufferSize);
                            if (readSize > 0)
                            {
                                sftpStream.Write(buffer, 0, readSize);
                            }
                            amountCopied += (ulong)readSize;
                            if (readSize > 0 && (amountCopied % (1048576 * 50)) == 0)
                            {
                                pctComplete = ((ulong)amountCopied * 100) / (ulong)sr.Length;
                            }
                        } while (readSize > 0);
                        if (readSize > 0 && (amountCopied % (1048576 * 50)) == 0)
                        {
                            pctComplete = ((ulong)amountCopied * 100) / (ulong)sr.Length;
                        }
                    }
                    attemptSuccess = true;

                    Task.Factory.StartNew(() => {
                        client.Dispose();
                    });

                }
                catch
                {
                    num_tries++;
                    System.Threading.Thread.Sleep(30 * 1000);
                }

                if (attemptSuccess)
                {
                    successfulUpload = true;
                    Console.WriteLine("Upload complete.");
                    if (arguments.SFTPCleanUp)
                    {
                        File.Delete(outputPath);
                    }
                    Console.WriteLine("Removed local zip file collection.");

                }

            }
            if (!successfulUpload)
            {
                Console.WriteLine("Unable to upload to SFTP. Zip file not removed. Please upload another way.");
                
            }

        }

        /// <summary>
        ///     Create an SFTP client and connect to a server using configuration from the arguments.
        /// </summary>
        /// <param name="arguments">The arguments to use to connect to the SFTP server.</param>
        private static SftpClient CreateSftpClient(Arguments arguments)
        {
            int port;
            var server = arguments.SFTPServer.Split(':');
            try
            {
                port = int.Parse(server[1]);
            }
            catch (Exception)
            {
                port = 22;
            }

            // Will need lots of testing with making SSH key work. Below is a draft of making it work with CyLRUpload account.
//            string privkey = @"-----BEGIN RSA PRIVATE KEY-----
//CyLRUpload Account SSH Key
//-----END RSA PRIVATE KEY-----";
//            var keyfile = new PrivateKeyFile(privkey);
//            var keyFiles = new[] { keyfile };
//            var connectinfo = new ConnectionInfo(server[0], arguments.UserName,
//                new PasswordAuthenticationMethod(arguments.UserName, arguments.UserPassword),
//                new PrivateKeyAuthenticationMethod(arguments.UserName, keyFiles));
//            using (var client = new SftpClient (ConnectionInfo))
//            {
//                client.Connect();
//                return client;
//            }
            var client = new SftpClient(server[0], port, arguments.UserName, arguments.UserPassword);
            client.Connect();
            return client;
        }

        /// <summary>
        ///     Opens a file for reading and writing, creating any missing directories in the path.
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns>The file Stream.</returns>
        private static Stream OpenFileStream(string path)
        {
            var archiveFile = new FileInfo(path);
            if (archiveFile.Directory != null && !archiveFile.Directory.Exists)
            {
                archiveFile.Directory.Create();
            }
            return File.Open(archiveFile.FullName, FileMode.Create, FileAccess.ReadWrite);
        }
    }
}