using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using Microsoft.Win32;

namespace CyLR
{
    internal static class CollectionPaths
    {
        private static List<string> AllFiles;
        private static List<string> tempPaths;

        private static IEnumerable<string> RunCommand(string OSCommand, string CommandArgs)
        {
            var newPaths = new List<string> { };
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = OSCommand,
                    Arguments = CommandArgs,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                yield return  proc.StandardOutput.ReadLine();
            };
        }
        public static List<string> GetPaths(Arguments arguments, List<string> additionalPaths, bool Usnjrnl)
        {
            var defaultPaths = new List<string>
            {
                $@"{Arguments.DriveLet}\Windows\SchedLgU.Txt",
                $@"{Arguments.DriveLet}\Windows\Tasks",
                $@"{Arguments.DriveLet}\Windows\Prefetch",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs",
                $@"{Arguments.DriveLet}\Windows\System32\drivers\etc\hosts",
                $@"{Arguments.DriveLet}\Windows\System32\sru",
                $@"{Arguments.DriveLet}\Windows\System32\winevt\logs",
                $@"{Arguments.DriveLet}\Windows\System32\Tasks",
                $@"{Arguments.DriveLet}\Windows\System32\LogFiles\W3SVC1",
                $@"{Arguments.DriveLet}\Windows\System32\config\SAM",
                $@"{Arguments.DriveLet}\Windows\System32\config\SYSTEM",
                $@"{Arguments.DriveLet}\Windows\System32\config\SOFTWARE",
                $@"{Arguments.DriveLet}\Windows\System32\config\SECURITY",
                $@"{Arguments.DriveLet}\Windows\System32\config\SAM.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\SYSTEM.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\SOFTWARE.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\SECURITY.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\SAM.LOG2",
                $@"{Arguments.DriveLet}\Windows\System32\config\SYSTEM.LOG2",
                $@"{Arguments.DriveLet}\Windows\System32\config\SOFTWARE.LOG2",
                $@"{Arguments.DriveLet}\Windows\System32\config\SECURITY.LOG2",
                $@"{Arguments.DriveLet}\Windows\System32\config\RegBack",
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                $@"{Arguments.DriveLet}\$MFT",
                $@"{Arguments.DriveLet}\Windows\System32\dhcp",
                $@"{Arguments.DriveLet}\Program Files (x86)\TeamViewer\Connections_incoming.txt",
                $@"{Arguments.DriveLet}\Program Files\TeamViewer\Connections_incoming.txt",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve.LOG1",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve.LOG2",
            };
            if (Usnjrnl)
            {
                defaultPaths.Add($@"{Arguments.DriveLet}\$Extend\$UsnJrnl:$J");
            }
            defaultPaths = defaultPaths.Select(Environment.ExpandEnvironmentVariables).ToList();

      			//This section will attempt to collect files or folder locations under each users profile by pulling their ProfilePath from the registry and adding it in front.
      			//Add "defaultPaths.Add($@"{user.ProfilePath}" without the quotes in front of the file / path to be collected in each users profile.
            if (!Platform.IsUnixLike())
            {
                try

                {
                    string UserPath = Arguments.DriveLet + "\\Users\\";
                    string[] WinUserFolders = Directory.GetDirectories(UserPath);
                    if (Directory.Exists(UserPath))
                        foreach (var User in WinUserFolders)
                        {
                            defaultPaths.Add($@"{User}\NTUSER.DAT");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Explorer");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\WebCache\");
							defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\History\");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Cookies"); // add Chrome cookies
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"); // add Chrome Bookmarks
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Extensions"); // add Chrome extensions
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Shortcuts"); // add Chrome shortcuts
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Cookies"); // Chrome Canary collection
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\ConnectedDevicesPlatform");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Office\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Terminal Server Client\Cache");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Mozilla\Firefox\Profiles");
                            defaultPaths.Add($@"{User}\AppData\Roaming\TeamViewer");
                        }
                }

                catch (Exception)
                {
                    //FAIL
                }
            }
            if (Platform.IsUnixLike())
            {
                defaultPaths = new List<string> { };
                tempPaths = new List<string>
                {
                    "/root/.bash_history",
                    "/var/log",
                    "/private/var/log/",
                    "/.fseventsd",
                    "/etc/hosts.allow",
                    "/etc/hosts.deny",
                    "/etc/hosts",
                    "/System/Library/StartupItems",
                    "/System/Library/LaunchAgents",
                    "/System/Library/LaunchDaemons",
                    "/Library/LaunchAgents",
                    "/Library/LaunchDaemons",
                    "/Library/StartupItems",
                    "/etc/passwd",
                    "/etc/group",
                    "/etc/rc.d"
                };
                // Collect file listing
                AllFiles = new List<string> { };
                AllFiles.AddRange(RunCommand("/usr/bin/find", "/ -print"));

                // Find all *.plist files
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("*.plist"))));
                // Find all .bash_history files
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains(".bash_history"))));
                // Find all .sh_history files
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains(".sh_history"))));
                // Find Chrome Preference files
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/History"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Cookies"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Bookmarks"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Extensions"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Last"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Shortcuts"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Top"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("Support/Google/Chrome/Default/Visited"))));

                // Find FireFox Preference Files
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("places.sqlite"))));
                tempPaths.AddRange(AllFiles.Where((stringToCheck => stringToCheck.Contains("downloads.sqlite"))));

                // Fix any spaces to work with MacOS naming conventions
                defaultPaths = tempPaths.ConvertAll(stringToCheck => stringToCheck.Replace(" ", " "));
            }
            var paths = new List<string>(additionalPaths);

            if (arguments.CollectionFilePath != ".")
            {
                if (File.Exists(arguments.CollectionFilePath))
                {
                    paths.AddRange(File.ReadAllLines(arguments.CollectionFilePath).Select(Environment.ExpandEnvironmentVariables));
                }
                else
                {
                    Console.WriteLine("Error: Could not find file: {0}", arguments.CollectionFilePath);
                    Console.WriteLine("Exiting");
                    throw new ArgumentException();
                }
            }

            if (arguments.CollectionFiles != null)
            {
                paths.AddRange(arguments.CollectionFiles);
            }

            if (paths.Count == 1)
            {
                if (paths[0] == "")
                {
                    return defaultPaths;
                }
            }
            return paths.Any() ? paths : defaultPaths;
        }
    }
}
