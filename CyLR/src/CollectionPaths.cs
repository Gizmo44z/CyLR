using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using Microsoft.Win32;
using System.Security.Cryptography;
//using Hyldahl.Hashing;

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
                yield return proc.StandardOutput.ReadLine();
            };
        }
        public static List<string> GetPaths(Arguments arguments, List<string> additionalPaths, bool Usnjrnl, bool AntiV, bool Hash, bool noinet, bool rec, bool desk, bool recycle, bool conly)
        {
            File.Delete(@"C:\EXEHash.txt");
            File.Delete(@"C:\SysInfo.txt");
            File.Delete(@"C:\prochash.csv");
            Console.WriteLine("Identifying collection paths...");

            var defaultPaths = new List<string>
            {

                $@"{Arguments.DriveLet}\Windows\SchedLgU.Txt",
                $@"{Arguments.DriveLet}\Windows\Tasks",
                $@"{Arguments.DriveLet}\Windows\Prefetch",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\install",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\Amcache.hve",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\Amcache.hve.LOG1",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\Amcache.hve.LOG2",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\Amcache.hve.tmp.LOG1",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\Amcache.hve.tmp.LOG2",
                $@"{Arguments.DriveLet}\Windows\Appcompat\Programs\recentfilecache.bcf",
                $@"{Arguments.DriveLet}\Windows\System32\drivers\etc\hosts",
                $@"{Arguments.DriveLet}\Windows\System32\sru",
                $@"{Arguments.DriveLet}\Windows\System32\winevt\logs",
                $@"{Arguments.DriveLet}\Windows\System32\Tasks",
                $@"{Arguments.DriveLet}\Windows\System32\Inetsrv\Config\applicationHost.Config",
                $@"{Arguments.DriveLet}\Windows\System32\LogFiles\W3SVC1",
                $@"{Arguments.DriveLet}\Windows\System32\config\RegBack",
                $@"{Arguments.DriveLet}\Windows\System32\config\userdiff",
                $@"{Arguments.DriveLet}\Windows\System32\config\userdiff.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\userdiff.LOG2",
                $@"{Arguments.DriveLet}\Windows\System32\config\DRIVERS",
                $@"{Arguments.DriveLet}\Windows\System32\config\DRIVERS.LOG1",
                $@"{Arguments.DriveLet}\Windows\System32\config\DRIVERS.LOG2",
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
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                $@"{Arguments.DriveLet}\Windows\System32\dhcp",
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\RAC\PublishedData",
                $@"{Arguments.DriveLet}\Program Files (x86)\TeamViewer\Connections_incoming.txt",
                $@"{Arguments.DriveLet}\Program Files\TeamViewer\Connections_incoming.txt",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve.LOG1",
                $@"{Arguments.DriveLet}\System Volume Information\syscache.hve.LOG2",
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\Network\Downloader\",
                $@"{Arguments.DriveLet}\Windows\System32\bits.log",
                $@"{Arguments.DriveLet}\Windows\System32\Tasks",      
                $@"{Arguments.DriveLet}\Windows\System32\LogFiles\HTTPERR",
                $@"{Arguments.DriveLet}\Windows\System32\wbem\Repository",
                $@"{Arguments.DriveLet}\Windows\debug\NetSetup.LOG",
                $@"{Arguments.DriveLet}\Windows.old\SchedLgU.Txt",
                $@"{Arguments.DriveLet}\Windows.old\Tasks",
                $@"{Arguments.DriveLet}\Windows.old\Prefetch",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\install",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\Amcache.hve",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\Amcache.hve.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\Amcache.hve.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\Amcache.hve.tmp.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\Amcache.hve.tmp.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\Appcompat\Programs\recentfilecache.bcf",
                $@"{Arguments.DriveLet}\Windows.old\System32\drivers\etc\hosts",
                $@"{Arguments.DriveLet}\Windows.old\System32\sru",
                $@"{Arguments.DriveLet}\Windows.old\System32\winevt\logs",
                $@"{Arguments.DriveLet}\Windows.old\System32\Tasks",
                $@"{Arguments.DriveLet}\Windows.old\System32\LogFiles\W3SVC1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\RegBack",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\userdiff",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\userdiff.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\userdiff.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\DRIVERS",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\DRIVERS.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\DRIVERS.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SAM",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SYSTEM",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SOFTWARE",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SECURITY",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SAM.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SYSTEM.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SOFTWARE.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SECURITY.LOG1",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SAM.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SYSTEM.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SOFTWARE.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\config\SECURITY.LOG2",
                $@"{Arguments.DriveLet}\Windows.old\System32\dhcp",
                $@"{Arguments.DriveLet}\Windows.old\System32\bits.log",
                $@"{Arguments.DriveLet}\Windows.old\System32\Tasks",
                $@"{Arguments.DriveLet}\Windows.old\System32\LogFiles\HTTPERR",
                $@"{Arguments.DriveLet}\Windows.old\System32\wbem\Repository",
                $@"{Arguments.DriveLet}\ProgramData\AnyDesk",
                $@"{Arguments.DriveLet}\Windows\System32\LogFiles\SUM",
                $@"{Arguments.DriveLet}\Windows.old\System32\LogFiles\SUM",
                $@"{Arguments.DriveLet}\kworking",
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db",
                $@"{Arguments.DriveLet}\Windows\System32\debug\netlogon.log",
                $@"{Arguments.DriveLet}\ProgramData\LogMeIn",
                $@"{Arguments.DriveLet}\Program Files (x86)\Splashtop\Splashtop Remote\Server\log",
                $@"{Arguments.DriveLet}\Program Files\Splashtop\Splashtop Remote\Server\log",
                $@"{Arguments.DriveLet}\Program Files (x86)\Splashtop\Splashtop Remote\Splashtop Gateway\log",
                $@"{Arguments.DriveLet}\Program Files\Splashtop\Splashtop Remote\Splashtop Gateway\log",
                $@"{Arguments.DriveLet}\ProgramData\Microsoft\Windows Defender\Support",
                $@"{Arguments.DriveLet}\ProgramData\Syncro\logs",
                $@"{Arguments.DriveLet}\Windows\appcompat\pca",
                $@"{Arguments.DriveLet}\Program Files\Microsoft\Exchange Server\V15\Logging\CmdletInfra\Powershell-Proxy\Http",
                $@"{Arguments.DriveLet}\ProgramData\OpenBoxLab\RaiDrive\log",
                $@"{Arguments.DriveLet}\ProgramData\Admin Arsenal\PDQ Inventory\Database.db",

            };

            if (rec == true)
            {
                try
                {
                    string Userpcl = Arguments.DriveLet + "\\Users\\";
                    string[] pclUserFolders = Directory.GetDirectories(Userpcl);

                    
                        foreach (var fol in pclUserFolders)
                        {
                            try
                            {
                                
                                string[] pclfol = Directory.GetFiles($@"{fol}\AppData\Local\Temp", "pCloud_Drive_*", SearchOption.TopDirectoryOnly);
                                if (Directory.Exists(fol))
                                    foreach (var file in pclfol)
                                    {
                                        defaultPaths.Add($@"{file}");
                                    }
                            }
                            catch (Exception)
                            {
                                //FAIL
                            }
                        }
                }
                catch (Exception)
                {
                    //FAIL
                }
                
                try
                    {
                    string Fol = $@"{Arguments.DriveLet}\ProgramData\VMware\VDM\Logs\";
                    string[] vdifol = Directory.GetFiles(Fol, "debug-*", SearchOption.TopDirectoryOnly);
                    if (Directory.Exists(Fol))
                        foreach (var file in vdifol)
                        {
                            defaultPaths.Add($@"{file}");
                        }
                }
                catch (Exception)
                {
                    //FAIL
                }


                try {
                    string[] rcloneFol = Directory.GetFiles(
                        $@"{Arguments.DriveLet}\",
                        "rclone.conf",

                        new EnumerationOptions
                        {
                            RecurseSubdirectories = true

                        });
                    foreach (var file in rcloneFol)
                    {
                        defaultPaths.Add($@"{file}");
                    }
                }
                catch (Exception)
                {
                    //FAIL
                }
                
                try
                {
                    string[] ngrok = Directory.GetFiles(
                    $@"{Arguments.DriveLet}\",
                    "ngrok.yml",

                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true

                    });
                    foreach (var file in ngrok)
                    {
                        defaultPaths.Add($@"{file}");
                    }

                }
                catch (Exception)
                {
                    //FAIL
                }

                try
                {
                    string[] filezFol = Directory.GetFiles(
                    $@"{Arguments.DriveLet}\",
                    "filezilla.xml",

                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true

                    });
                    foreach (var file in filezFol)
                    {
                        defaultPaths.Add($@"{file}");
                    }
                }
                catch (Exception)
                {
                    //FAIL
                }

                try
                {
                    string[] winini = Directory.GetFiles(
                    $@"{Arguments.DriveLet}\",
                    "winscp.ini",

                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true

                    });
                    foreach (var file in winini)
                    {
                        defaultPaths.Add($@"{file}");
                    }
                }
                catch (Exception)
                {
                    //FAIL
                }

            }

            if (noinet == false)
            {
                defaultPaths.Add($@"{Arguments.DriveLet}\inetpub\logs\LogFiles");
            }

            if (Usnjrnl == true)
            {
                defaultPaths.Add($@"{Arguments.DriveLet}\$Extend\$UsnJrnl:$J");
            }
            //AntiV switch is used to add antivirus paths to the collection list (WARNING: Collection may become very large!)
            if (AntiV == true)
            {
                try
                {
                    //AVG
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\AVG\Antivirus\log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\AVG\Antivirus\report");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\AVG\Antivirus\log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\AVG\Antivirus\report");
                    //Avast
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents And Settings\All Users\Application Data\Avast Software\Avast\Log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Avast Software\Avast\Log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Avast Software\Avast\Chest\index.xml");
                    //Avira
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Avira\Antivirus\LOGFILES");
                    //Bitdefender
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Bitdefender\Endpoint Security\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Bitdefender\Desktop\Profiles\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ComboFix.txt");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\crs1\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\apv2\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\crb1\Logs");
                    //ESET
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\ESET\ESET NOD32 Antivirus\Logs");
                    //F-Secure
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\F-Secure\Log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\F-Secure\Antivirus\ScheduledScanReports");
                    //Hitman Pro
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\HitmanPro\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\HitmanPro.Alert\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\HitmanPro.Alert\excalibur.db");
                    //Malwarebytes
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Malwarebytes\MBAMService\logs\mbamservice.log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Malwarebytes\MBAMService\ScanResults");
                    //McAfee
                    defaultPaths.Add($@"{Arguments.DriveLet}\Users\All Users\Application Data\McAfee\DesktopProtection");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\McAfee\DesktopProtection");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\McAfee\Endpoint Security\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\McAfee\Endpoint Security\Logs_Old");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Mcafee\VirusScan");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\McAfee\Endpoint Security\Logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\RogueKiller\logs");
                    //SentinelOne
                    defaultPaths.Add($@"{Arguments.DriveLet}\programdata\sentinel\logs");
                    //Sophos
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\Sophos");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos File Scanner\Logs\");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos Device Control\logs\");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos Data Control\logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos Anti-Virus\logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos Tamper Protection\logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Sophos\Sophos Network Threat Protection\Logs");

                    //Symantec
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine");
                    //TotalAV
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files\TotalAV\logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files (x86)\TotalAV\logs");
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\TotalAV\logs");
                    //TrendMicro
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Trend Micro");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files\Trend Micro\Security Agent\Report");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files (x86)\Trend Micro\Security Agent\Report");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files\Trend Micro\Security Agent\ConnLog");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Program Files (x86)\Trend Micro\Security Agent\ConnLog");
                    //VIPRE
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\VIPRE Business Agent\Logs");
                    //Webroot
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\WRData\WRLog.log");
                    //Defender
                    defaultPaths.Add($@"{Arguments.DriveLet}\ProgramData\Microsoft\Microsoft AntiMalware\Support");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Windows\Temp\MpCmdRun.log");
                    defaultPaths.Add($@"{Arguments.DriveLet}\Windows.old\Windows\Temp\MpCmdRun.log");
                }

                catch (IOException)
                {
                    //FAIL
                }

                catch (Exception)
                {
                    //FAIL
                }

            }
            
            defaultPaths = defaultPaths.Select(Environment.ExpandEnvironmentVariables).ToList();

            
            if (Arguments.usr != string.Empty)
            {
                try
                {

                    string[] CusUserFolders = Directory.GetDirectories(Arguments.usr);

                    if (Directory.Exists(Arguments.usr))
                        foreach (var User in CusUserFolders)
                        {
                            defaultPaths.Add($@"{User}\NTUSER.DAT");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\WebCache");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\IEDownloadHistory");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\INetCookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\ConnectedDevicesPlatform");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Office\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera");
                            defaultPaths.Add($@"{User}\AppData\Local\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Terminal Server Client\Cache");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Mozilla\Firefox\Profiles");
                            defaultPaths.Add($@"{User}\AppData\Roaming\TeamViewer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.rnd");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.ini");
                            defaultPaths.Add($@"{User}\AppData\Local\Putty.rnd");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Web Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\AnyDesk"); // stores connecting IP and file transfer activity
                            defaultPaths.Add($@"{User}\AppData\Roaming\FileZilla");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\OneDrive\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\OneDrive\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\OneDrive\settings");
                            defaultPaths.Add($@"{User}\Avast Software\Avast\Log");
                            defaultPaths.Add($@"{User}\AppData\Local\F-Secure\Log");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\SUPERAntiSpyware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Symantec\Symantec Endpoint Protection\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\VIPRE Business");
                            defaultPaths.Add($@"{User}\AppData\Roaming\GFI Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Sunbelt Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\temp\LogMeInLogs");
                            defaultPaths.Add($@"{User}\AppData\Local\Mega Limited\MEGAsync\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Clipboard");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent.log");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent Init.log");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\wpflog.log");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\data.db");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\data.db1");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\data.db-wal");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
                        }

                }
                catch (Exception)
                {
                    //FAIL
                }
            }

            
            if (Arguments.DriveLet == "C:" & conly == false)
            {
                DriveInfo[] allDrives = DriveInfo.GetDrives();
                foreach (DriveInfo d in allDrives)
                {
                    try
                    {
                        if (d.DriveType == DriveType.Fixed && d.DriveFormat == "NTFS")
                        {
                            defaultPaths.Add($@"{d.Name}$MFT");
                            defaultPaths.Add($@"{d.Name}$LogFile");
                        }
                    }
                    catch (IOException)
                    {
                        File.AppendAllText(Path.Combine(@"C:\SysInfo.txt"), Environment.NewLine + "Data collection could not be performed on " + d.RootDirectory + " due to an IO Exception on the disk.");
                    }
                }

                try
                {
                    Console.WriteLine("Gathering System Information and Hashing Processes...");
                    string strps = @"powershell.exe";
                    string strproc = @" $outPut = @()
                                    foreach ($proc in get-process) 
                                    {
                                      try {
                                            $result = Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
                                            $results = Get-Process -id $proc.id | select id,starttime,name,@{Name=""""""CommandLine"""""";Expr={ $filter = """"""ProcessID = {0}"""""" -f $_.Id; (Get-CimInstance Win32_Process -filter $filter).CommandLine}}
                                            $outPut += New-Object psobject -Property @{
                                                            StartTime = $results.starttime
                                                            PID = $results.id
                                                            Name = $results.name
                                                            CommandLine = $results.commandline
                                                            SHA1 = $result.hash
                                                            Path = $result.path
                                                }
                                            }
                                                    catch { }
                                    }
                                    $outPut | Select StartTime, PID, Name, CommandLine, SHA1, Path | Sort-Object StartTime -Descending | Export-Csv C:\prochash.csv -NoTypeInformation";


                    System.Diagnostics.Process psProcess = new System.Diagnostics.Process();
                    psProcess.StartInfo.FileName = strps;
                    psProcess.StartInfo.Arguments = strproc;

                    psProcess.StartInfo.UseShellExecute = false;
                    psProcess.StartInfo.RedirectStandardOutput = true;

                    psProcess.Start();
                    string strpsOut = psProcess.StandardOutput.ReadToEnd();
                    psProcess.WaitForExit();

                    string strcommand = @"cmd.exe";
                    string strparam = @" /c systeminfo | findstr /c:""Host Name"" /c:""OS Name"" /c:""Original Install Date"" /c:""System Boot Time"" /c:""Time Zone"" /c:""Domain"" /c:""Logon Server"" /c:""OS Version"" & ipconfig | findstr /c:""ipv4""";
                    string ipcon = @" /c ipconfig | findstr /i ""ipv4""";


                    System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
                    pProcess.StartInfo.FileName = strcommand;
                    pProcess.StartInfo.Arguments = strparam;

                    pProcess.StartInfo.UseShellExecute = false;
                    pProcess.StartInfo.RedirectStandardOutput = true;

                    pProcess.Start();
                    string strOutput = pProcess.StandardOutput.ReadToEnd();
                    pProcess.WaitForExit();

                    File.AppendAllText(@"C:\SysInfo.txt", strOutput);

                    System.Diagnostics.Process ipproc = new System.Diagnostics.Process();

                    ipproc.StartInfo.FileName = strcommand;
                    ipproc.StartInfo.Arguments = ipcon;

                    ipproc.StartInfo.UseShellExecute = false;
                    ipproc.StartInfo.RedirectStandardOutput = true;

                    ipproc.Start();
                    string ipinf = ipproc.StandardOutput.ReadToEnd();
                    ipproc.WaitForExit();

                    File.AppendAllText(@"C:\SysInfo.txt", ipinf);
                    File.AppendAllText(Path.Combine(@"C:\SysInfo.txt"), Environment.NewLine + "Times are in LOCAL drive collection format" + Environment.NewLine + "CyLR Version 2023.07.11" +
                        Environment.NewLine + Environment.NewLine + $"Drive Letter: {Arguments.DriveLet}" +
                        Environment.NewLine + $"Skip inet: {arguments.noinet}" +
                        Environment.NewLine + $"Hash Files: {arguments.hash}" +
                        Environment.NewLine + $"Collect Antivirus: {arguments.AntiV}" +
                        Environment.NewLine + $"Output Path: {arguments.OutputPath}" +
                        Environment.NewLine + $"SFTP Server: {arguments.SFTPServer}" +
                        Environment.NewLine + $"User Name: {arguments.UserName}" +
                        Environment.NewLine + $"User Path : {Arguments.usr}" + Environment.NewLine);

                    defaultPaths.Add(@"C:\SysInfo.txt");
                    defaultPaths.Add(@"C:\prochash.csv");
                }
                catch (FileNotFoundException)
                {
                    //FAIL
                }

            }

            //This will collect all fixed drive MFT files if you did not select a specific mounted drive to collect from.
            //Use with -dl if you only want a specific drive collected rather than all fixed drives on a system.
            
            if (Arguments.DriveLet == "C:" & conly == true)                                 
            {        

                try
                {
                    Console.WriteLine("Gathering System Information and Hashing Processes...");
                    string strps = @"powershell.exe";
                    string strproc = @" $outPut = @()
                                    foreach ($proc in get-process) 
                                    {
                                      try {
                                            $result = Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
                                            $results = Get-Process -id $proc.id | select id,starttime,name,@{Name=""""""CommandLine"""""";Expr={ $filter = """"""ProcessID = {0}"""""" -f $_.Id; (Get-CimInstance Win32_Process -filter $filter).CommandLine}}
                                            $outPut += New-Object psobject -Property @{
                                                            StartTime = $results.starttime
                                                            PID = $results.id
                                                            Name = $results.name
                                                            CommandLine = $results.commandline
                                                            SHA1 = $result.hash
                                                            Path = $result.path
                                                }
                                            }
                                                    catch { }
                                    }
                                    $outPut | Select StartTime, PID, Name, CommandLine, SHA1, Path | Sort-Object StartTime -Descending | Export-Csv C:\prochash.csv -NoTypeInformation";


                    System.Diagnostics.Process psProcess = new System.Diagnostics.Process();
                    psProcess.StartInfo.FileName = strps;
                    psProcess.StartInfo.Arguments = strproc;

                    psProcess.StartInfo.UseShellExecute = false;
                    psProcess.StartInfo.RedirectStandardOutput = true;

                    psProcess.Start();
                    string strpsOut = psProcess.StandardOutput.ReadToEnd();
                    psProcess.WaitForExit();

                    string strcommand = @"cmd.exe";
                    string strparam = @" /c systeminfo | findstr /c:""Host Name"" /c:""OS Name"" /c:""Original Install Date"" /c:""System Boot Time"" /c:""Time Zone"" /c:""Domain"" /c:""Logon Server"" /c:""OS Version"" & ipconfig | findstr /c:""ipv4""";
                    string ipcon = @" /c ipconfig | findstr /i ""ipv4""";
                    

                    System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
                    pProcess.StartInfo.FileName = strcommand;
                    pProcess.StartInfo.Arguments = strparam;

                    pProcess.StartInfo.UseShellExecute = false;
                    pProcess.StartInfo.RedirectStandardOutput = true;

                    pProcess.Start();
                    string strOutput = pProcess.StandardOutput.ReadToEnd();
                    pProcess.WaitForExit();

                    File.AppendAllText(@"C:\SysInfo.txt", strOutput);

                    System.Diagnostics.Process ipproc = new System.Diagnostics.Process();

                    ipproc.StartInfo.FileName = strcommand;
                    ipproc.StartInfo.Arguments = ipcon;

                    ipproc.StartInfo.UseShellExecute = false;
                    ipproc.StartInfo.RedirectStandardOutput = true;

                    ipproc.Start();
                    string ipinf = ipproc.StandardOutput.ReadToEnd();
                    ipproc.WaitForExit();

                    File.AppendAllText(@"C:\SysInfo.txt", ipinf);
                    File.AppendAllText(Path.Combine(@"C:\SysInfo.txt"), Environment.NewLine + "Times are in LOCAL drive collection format" + Environment.NewLine + "CyLR Version 2024.01.20" +
                        Environment.NewLine + Environment.NewLine + $"Drive Letter: {Arguments.DriveLet}" +
                        Environment.NewLine + $"Skip inet: {arguments.noinet}" +
                        Environment.NewLine + $"Hash Files: {arguments.hash}" +
                        Environment.NewLine + $"Collect Antivirus: {arguments.AntiV}" +
                        Environment.NewLine + $"Output Path: {arguments.OutputPath}" +
                        Environment.NewLine + $"SFTP Server: {arguments.SFTPServer}" +
                        Environment.NewLine + $"User Name: {arguments.UserName}" +
                        Environment.NewLine + $"User Path : {Arguments.usr}" + Environment.NewLine);

                    defaultPaths.Add(@"C:\$MFT");
                    defaultPaths.Add(@"C:\SysInfo.txt");
                    defaultPaths.Add(@"C:\prochash.csv");
                }
                catch (FileNotFoundException)
                {
                    //FAIL
                }
                
            }

            //Will hash select files on the drive letter provided and add to a file called EXEHash.txt
            
            if (Hash == true)
            {
                Console.WriteLine("Hashing Files...");
                try
                {
                    

                    var pathadd = new List<string>();

                    string[] wexe = Directory.GetFiles($@"{Arguments.DriveLet}\Windows", "*.exe", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(wexe);
                    string[] progexe = Directory.GetFiles($@"{Arguments.DriveLet}\ProgramData", "*.exe", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(progexe);
                    string[] rootexe = Directory.GetFiles($@"{Arguments.DriveLet}\", "*.exe", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(rootexe);

                    string[] wdll = Directory.GetFiles($@"{Arguments.DriveLet}\Windows", "*.dll", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(wdll);
                    string[] progdll = Directory.GetFiles($@"{Arguments.DriveLet}\ProgramData", "*.dll", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(progdll);
                    string[] rootdll = Directory.GetFiles($@"{Arguments.DriveLet}\", "*.dll", SearchOption.TopDirectoryOnly);
                    pathadd.AddRange(rootdll);

                    string[] rconf = Directory.GetFiles($@"{Arguments.DriveLet}\", "*.conf",
                        new EnumerationOptions
                        {
                            RecurseSubdirectories = true
                        });
                    foreach (var file in rconf)
                    {
                        pathadd.Add(file);
                    }

                    if (Directory.Exists($@"{Arguments.DriveLet}\Users"))
                    {
                        string[] uexes = Directory.GetFiles(
                        $@"{Arguments.DriveLet}\Users",
                        "*.exe",

                        new EnumerationOptions
                        {
                            RecurseSubdirectories = true
                        });
                        foreach (var file in uexes)
                        {
                            pathadd.Add(file);
                        }

                        string[] udll = Directory.GetFiles(
                        $@"{Arguments.DriveLet}\Users\",
                        "*.dll",

                        new EnumerationOptions
                        {
                            RecurseSubdirectories = true
                        });
                        foreach (var file in udll)
                        {
                            pathadd.Add(file);
                        }

                    }

                    if (Directory.Exists($@"{Arguments.DriveLet}\perflogs"))
                    {
                        string[] perfexes = Directory.GetFiles(
                    $@"{Arguments.DriveLet}\perflogs",
                    "*.exe",

                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true
                    });
                        foreach (var file in perfexes)
                        {
                            pathadd.Add(file);
                        }
                        string[] perfdll = Directory.GetFiles(
                    $@"{Arguments.DriveLet}\perflogs",
                    "*.dll",

                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true
                    });
                        foreach (var file in perfdll)
                        {
                            pathadd.Add(file);
                        }
                    }

                    //Removes select paths to prevent local downloads of syncing files
                    pathadd.RemoveAll(u => u.Contains("OneDrive"));
                    pathadd.RemoveAll(p => p.Contains("\\.nuget\\"));
                    pathadd.RemoveAll(u => u.Contains("DropBox"));
                    pathadd.RemoveAll(u => u.Contains("Google"));
                    pathadd.RemoveAll(u => u.Contains("Sync"));
                    pathadd.RemoveAll(u => u.Contains("Box"));
                    pathadd.RemoveAll(u => u.Contains("CyLR"));
                    pathadd.RemoveAll(u => u.Contains("Office"));
                    pathadd.RemoveAll(u => u.Contains("Cylr"));
                    pathadd.RemoveAll(u => u.Contains("publish"));
                    pathadd.RemoveAll(u => u.Contains(".vscode"));
                    pathadd.RemoveAll(u => u.Contains("\\DriverStore\\"));
                    pathadd.RemoveAll(u => u.Contains("\\WinSxS\\"));
                    pathadd.RemoveAll(u => u.Contains("\\Microsoft Visual Studio\\"));
                    pathadd.RemoveAll(u => u.Contains("\\FortiClient\\"));
                    pathadd.RemoveAll(u => u.Contains("\\DiskSnapshot.conf"));
                    pathadd.RemoveAll(u => u.Contains("\\Git\\etc\\"));
                    pathadd.RemoveAll(u => u.Contains("\\Imager_Lite_3.1.1\\"));

                    foreach (var file in pathadd)
                    {
                        FileStream f1 = File.OpenRead(file);
                        string chksumSHA1 = BitConverter.ToString(System.Security.Cryptography.SHA1.Create().ComputeHash(f1));
                        FileStream f256 = File.OpenRead(file);
                        string chksum256 = BitConverter.ToString(System.Security.Cryptography.SHA256.Create().ComputeHash(f256));

                        
                        string[] lines = { $@"{file}" + "|" + (new FileInfo(file).Length) + "|" + File.GetLastWriteTimeUtc(file) + "|" + File.GetCreationTimeUtc(file) + "|" + $@"{chksumSHA1.Replace("-", string.Empty)}" + "|" + $@"{chksum256.Replace("-", string.Empty)}" };
                        string[] knhash = { ".conf","filezilla","winscp","rclone","mega","7fcff763279c06aaa41da2a4b65c8d038ebcf63e", "52332ce16ee0c393b8eea6e71863ad41e3caeafd", "b97761358338e640a31eef5e5c5773b633890914", "d373052c6f7492e0dd5f2c705bac6b5afe7ffc24", "162b08b0b11827cc024e6b2eed5887ec86339baa", "c8107e5c5e20349a39d32f424668139a36e6cfd0", "a0bdfac3ce1880b32ff9b696458327ce352e3b1d", "763499b37aacd317e7d2f512872f9ed719aacae1", "f0966985745541ba01800aa213509a89a7fdf716", "793e8c44dc51e6cb73977135af71b437f652154c"};

                        foreach (string line in lines)
                        {
                            foreach (string kn in knhash)
                            {
                                if (line.Contains(kn) == true)
                                {
                                    File.AppendAllText(@"C:\SysInfo.txt", Environment.NewLine + $@"Potentially malicious resident file found at {file}!");
                                }
                            }
                        }

                        File.AppendAllLines(Path.Combine(@"C:\", "EXEHash.txt"), lines);
                    }

                    defaultPaths.Add(@"C:\EXEHash.txt");
                    defaultPaths.Add(@"C:\SysInfo.txt");

                }
                catch (FileNotFoundException)
                {
                    //FAIL
                }

                catch (IOException)
                {
                    File.AppendAllText(@"C:\EXEHash.txt", "File not accessible. File will not be hashed");
                }
            }

            //Collects the Desktop for each user
            if (arguments.desk == true)
            {
                string UserDesk = Arguments.DriveLet + "\\Users\\";
                string[] WinUserDesk = Directory.GetDirectories(UserDesk);

                if (Directory.Exists(UserDesk))
                    foreach (var User in WinUserDesk)
                    {

                        defaultPaths.Add($@"{User}\Desktop");
                    }
            }

            //Enables collection of Recycle Bin data
            if (arguments.recycle == true)
            {
                defaultPaths.Add($@"{Arguments.DriveLet}\$Recycle.Bin\");
            }

            //If -dl switch is used against something other than "C:", only the drive letter variable MFT will be collected.
            if (Arguments.DriveLet != "C:")
            {
                defaultPaths.Add($@"{Arguments.DriveLet}\$MFT");
                defaultPaths.Add($@"{Arguments.DriveLet}\$LogFile");


                Console.WriteLine("Recording CMD Information...");
                
                File.AppendAllText(Path.Combine(@"C:\SysInfo.txt"), Environment.NewLine + "Times are in LOCAL drive collection format" + Environment.NewLine + "CyLR Version 2024.02.25" +
                    Environment.NewLine + Environment.NewLine + $"Drive Letter: {Arguments.DriveLet}" +
                    Environment.NewLine + $"Skip inet: {arguments.noinet}" +
                    Environment.NewLine + $"Hash Files: {arguments.hash}" +
                    Environment.NewLine + $"Collect Antivirus: {arguments.AntiV}" +
                    Environment.NewLine + $"Output Path: {arguments.OutputPath}" +
                    Environment.NewLine + $"SFTP Server: {arguments.SFTPServer}" +
                    Environment.NewLine + $"User Name: {arguments.UserName}" +
                    Environment.NewLine + $"User Path : {Arguments.usr}" + Environment.NewLine);


                defaultPaths.Add(@"C:\SysInfo.txt");

            }

            //This section will attempt to collect files or folder locations under each users profile.
            //Add "defaultPaths.Add($@"{user.ProfilePath}" without the quotes in front of the file / path to be collected in each users profile.
            if (!Platform.IsUnixLike())
            {
                try

                {
                    string UserPath = Arguments.DriveLet + "\\Users\\";
                    string[] WinUserFolders = Directory.GetDirectories(UserPath);
                    string ServicePro = Arguments.DriveLet + "\\Windows\\ServiceProfiles";
                    string[] ServiceFol = Directory.GetDirectories(ServicePro);

                    if (Directory.Exists(UserPath))
                        foreach (var User in WinUserFolders)
                        {

                            defaultPaths.Add($@"{User}\NTUSER.DAT");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\WebCache");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\IEDownloadHistory");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\INetCookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\ConnectedDevicesPlatform");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Office\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera");
                            defaultPaths.Add($@"{User}\AppData\Local\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Terminal Server Client\Cache");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Mozilla\Firefox\Profiles");
                            defaultPaths.Add($@"{User}\AppData\Roaming\TeamViewer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.rnd");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.ini");
                            defaultPaths.Add($@"{User}\AppData\Local\Putty.rnd");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Web Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\AnyDesk\ad.trace");
                            defaultPaths.Add($@"{User}\AppData\Roaming\AnyDesk\Connection_trace.txt");
                            defaultPaths.Add($@"{User}\AppData\Roaming\FileZilla");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\OneDrive\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\OneDrive\logs");
                            defaultPaths.Add($@"{User}\Avast Software\Avast\Log");
                            defaultPaths.Add($@"{User}\AppData\Local\F-Secure\Log");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\SUPERAntiSpyware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Symantec\Symantec Endpoint Protection\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\VIPRE Business");
                            defaultPaths.Add($@"{User}\AppData\Roaming\GFI Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Sunbelt Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\temp\LogMeInLogs");
                            defaultPaths.Add($@"{User}\AppData\Local\Mega Limited\MEGAsync\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Clipboard");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\wpflog.log");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent.log");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent Init.log");
                            defaultPaths.Add($@"{User}\AppData\Roaming\FreeFileSync\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\MEGAsync");
                            defaultPaths.Add($@"{User}\AppData\Local\MEGA");
                        }

                    if (Directory.Exists(ServicePro))
                        foreach (var Serve in ServiceFol)
                        {
                            defaultPaths.Add($@"{Serve}\NTUSER.DAT");
                            defaultPaths.Add($@"{Serve}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{Serve}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\WebCache");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\IEDownloadHistory");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\INetCookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome SxS\User Data\Default\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome SxS\User Data\Default\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome SxS\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Google\Chrome SxS\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{Serve}\AppData\Local\ConnectedDevicesPlatform");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Microsoft\Windows\Recent");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Microsoft\Office\Recent");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Opera");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Terminal Server Client\Cache");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Mozilla\Firefox\Profiles");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\TeamViewer");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\winscp.rnd");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\winscp.ini");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Putty.rnd");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\Web Data");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\AnyDesk\ad.trace");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\AnyDesk\Connection_trace.txt");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\FileZilla");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\OneDrive\logs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\OneDrive\logs");
                            defaultPaths.Add($@"{Serve}\Avast Software\Avast\Log");
                            defaultPaths.Add($@"{Serve}\AppData\Local\F-Secure\Log");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\SUPERAntiSpyware\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Symantec\Symantec Endpoint Protection\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\VIPRE Business");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\GFI Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\Sunbelt Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\temp\LogMeInLogs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Mega Limited\MEGAsync\logs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\Microsoft\Windows\Clipboard");
                            defaultPaths.Add($@"{Serve}\AppData\Local\pCloud\wpflog.log");
                            defaultPaths.Add($@"{Serve}\Citrix WEM Agent.log");
                            defaultPaths.Add($@"{Serve}\Citrix WEM Agent Init.log");
                            defaultPaths.Add($@"{Serve}\AppData\Roaming\FreeFileSync\Logs");
                            defaultPaths.Add($@"{Serve}\AppData\Local\MEGAsync");
                            defaultPaths.Add($@"{Serve}\AppData\Local\MEGA");
                        }
                }

                catch (Exception)
                {
                    //FAIL
                }

                try

                {
                    string UserOld = Arguments.DriveLet + "\\Windows.old\\Users\\";
                    string[] WinUserOld = Directory.GetDirectories(UserOld);
                    if (Directory.Exists(UserOld))
                        foreach (var User in WinUserOld)
                        {
                            defaultPaths.Add($@"{User}\NTUSER.DAT");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{User}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\WebCache");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\IEDownloadHistory");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\INetCookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 1\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\History");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Google\Chrome\User Data\Profile 2\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions");
                            defaultPaths.Add($@"{User}\AppData\Local\Google\Chrome SxS\User Data\Default\Shortcuts");
                            defaultPaths.Add($@"{User}\AppData\Local\ConnectedDevicesPlatform");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Windows\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Office\Recent");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera");
                            defaultPaths.Add($@"{User}\AppData\Local\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Opera Software\Opera Stable");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Terminal Server Client\Cache");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Mozilla\Firefox\Profiles");
                            defaultPaths.Add($@"{User}\AppData\Roaming\TeamViewer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.rnd");
                            defaultPaths.Add($@"{User}\AppData\Roaming\winscp.ini");
                            defaultPaths.Add($@"{User}\AppData\Local\Putty.rnd");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Web Data");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\History");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Microsoft\Internet Explorer");
                            defaultPaths.Add($@"{User}\AppData\Roaming\AnyDesk\ad.trace"); 
                            defaultPaths.Add($@"{User}\AppData\Roaming\AnyDesk\Connection_trace.txt");
                            defaultPaths.Add($@"{User}\AppData\Roaming\FileZilla");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\OneDrive\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\OneDrive\logs");
                            defaultPaths.Add($@"{User}\Avast Software\Avast\Log");
                            defaultPaths.Add($@"{User}\AppData\Local\F-Secure\Log");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\SUPERAntiSpyware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Symantec\Symantec Endpoint Protection\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\VIPRE Business");
                            defaultPaths.Add($@"{User}\AppData\Roaming\GFI Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Roaming\Sunbelt Software\AntiMalware\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\temp\LogMeInLogs");
                            defaultPaths.Add($@"{User}\AppData\Local\Mega Limited\MEGAsync\logs");
                            defaultPaths.Add($@"{User}\AppData\Local\Microsoft\Windows\Clipboard");
                            defaultPaths.Add($@"{User}\AppData\Local\pCloud\wpflog.log");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent.log");
                            defaultPaths.Add($@"{User}\Citrix WEM Agent Init.log");
                            defaultPaths.Add($@"{User}\AppData\Roaming\FreeFileSync\Logs");
                            defaultPaths.Add($@"{User}\AppData\Local\MEGAsync");
                            defaultPaths.Add($@"{User}\AppData\Local\MEGA");
                        }

                }

                catch (Exception)
                {
                    //FAIL
                }

                try

                {
                    string UserPath2k3 = Arguments.DriveLet + "\\Documents and Settings\\";
                    string[] WinUserFolders2k3 = Directory.GetDirectories(UserPath2k3);
                    if (Directory.Exists(UserPath2k3))
                        foreach (var User2k3 in WinUserFolders2k3)
                        {
                            defaultPaths.Add($@"{User2k3}\NTUSER.DAT");
                            defaultPaths.Add($@"{User2k3}\NTUSER.DAT.LOG");
                            defaultPaths.Add($@"{User2k3}\NTUSER.DAT.LOG1");
                            defaultPaths.Add($@"{User2k3}\NTUSER.DAT.LOG2");
                            defaultPaths.Add($@"{User2k3}\Recent\");
                            defaultPaths.Add($@"{User2k3}\PrivacIE\");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG1");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG2");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Microsoft\Terminal Server Client\");
                            defaultPaths.Add($@"{User2k3}\Local Settings\History\History.IE5\");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Microsoft\Windows\WebCache\");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Microsoft\Windows\History\");
                            defaultPaths.Add($@"{User2k3}\Local Settings\Application Data\Google\Chrome\User Data\Default\History\");
                            defaultPaths.Add($@"{User2k3}\Application Data\Opera\");
                            defaultPaths.Add($@"{User2k3}\Application Data\Mozilla\Firefox\Profiles\");
                            defaultPaths.Add($@"{User2k3}\Application Data\TeamViewer\");
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