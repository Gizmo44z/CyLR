[![Build Status](https://travis-ci.org/orlikoski/CyLR.svg?branch=master)](https://travis-ci.org/orlikoski/CyLR)  
## CyLR

CyLR — Live Response Collection tool by Alan Orlikoski and Jason Yegge

## Videos and Media
*  [OSDFCON 2017](http://www.osdfcon.org/presentations/2017/Asif-Matadar_Rapid-Incident-Response.pdf) Slides: Walk-through different techniques that are required to provide forensics results for Windows and *nix environments (Including CyLR and CDQR)

## What is CyLR?
The CyLR tool collects forensic artifacts from hosts with NTFS file systems quickly, securely and minimizes impact to the host.

The main features are:
*  Quick collection (it's really fast)
*  Raw file collection process does not use Windows API
*  Optimized to store the collected artifacts in memory (minimizing or removing entirely the need to write additional artifacts on the host disk)
*  Built in SFTP capability

CyLR uses .NET Core and runs natively on Windows, Linux, and MacOS. Self contained applications for the following are included in releases for version 2.0 and higher.
 - Windows x86
 - Windows x64
 - Linux x64
 - MacOS x64

## SYNOPSIS

```
CyLR.exe [--help] [-od] [-of] [-u] [-p] [-s] [-c] [-zp] [-dl] [-usnjrnl] [-av] [-nohash] [-usr] [-dl] [-noinet]
```

## DESCRIPTION

CyLR tool collects forensic artifacts from hosts with NTFS file systems quickly, securely and minimizes impact to the host.

The standard list of collected artifacts are:

Windows Default
* See "CollectionPaths.txt" above for raw listing of paths\files collected.
* Generates SysInfo.txt with important information about the host (deleted upon collection).
* Generates EXEHash.txt with SHA1 and SHA256 along with LastWrite and Creation dates in specific file locations that house EXE or DLL files (deleted upon collection).

Mac and Linux Default
*  "/var/log",
*  "/private/var/log/",
*  "/.fseventsd",
*  "/etc/hosts.allow",
*  "/etc/hosts.deny",
*  "/etc/hosts",
*  "/System/Library/StartupItems",
*  "/System/Library/LaunchAgents",
*  "/System/Library/LaunchDaemons",
*  "/Library/LaunchAgents",
*  "/Library/LaunchDaemons",
*  "/Library/StartupItems",
*  "/etc/passwd",
*  "/etc/group"
*  All plist files
*  All .bash_history files
*  All .sh_history files
*  Chrome Preference files 
*  FireFox Preference Files

## ARGUMENTS

## OPTIONS
* '-\-help' — Show help message and exit.
* '-od' — Defines the directory that the zip archive will be created in. Defaults to current working directory. (applies to SFTP and local storage options)
* '-of' — Defines the name of the zip archive will be created. Defaults to host machine's name + date\time run.
* '-zp' — If specified, the resulting zip file will be password protected with this password.
* '-dl' -- Will specify which drive letter collection should be collected from (requires ":" to be used i.e. "D:").
* SFTP Options
    * '-u' — SFTP username
    * '-p' — SFTP password
    * '-s' — SFTP Server resolvable hostname or IP address and port. If no port is given then 22 is used by default.  The format is <server name>:<port>.  Usage: -s 8.8.8.8:22"
    * SFTP upload method has been updated to use public release CyLR 3.0 where it will attempt to upload to SFTP 3x and if it fails, it will keep the file at the designated location.
* '-c' — Optional argument to provide custom list of artifact files and directories (one entry per line). NOTE: Must use full path including drive letter on each line.  MFT can be collected by "C:\$MFT" or "D:\$MFT" and so on.  Usage: -c <path to config file>
 * '-dl' - Select drive letter to collect from (Default value is "C:").
 * '-nohash' - Disables the hashing capabilities of exe and dll files in specific directories.
 * '-usr' - specify a directory to collect user related artifacts if they are not stored in the default path (roaming user profiles, mounted VHDX user profiles, etc...). 
  * '-av' - Adds additional collection paths of anti-virus logs (not included by default due to potential size).
  * '-noinet' - Excludes "\inetpub\logs\LogFile" path from default collection in cases of extreme size. Independent collection is recommended for Exchange and Web servers.


## DEPENDENCIES
In general: some kind of administrative rights on the target (root, sudo, administrator,...).

CyLR now uses .NET Core and now runs natively on Windows, Linux, and MacOS as a .NET Core app or a self contained executable.

### Windows
 - None

### Linux/macOS
 - None


## EXAMPLES
Standard collection
    ```
    CyLR.exe
    ```

Linux/macOS collection
    ```
    ./CyLR
    ```

Collect artifacts and store data in "C:\Temp\LRData"
    ```
    CyLR.exe -o "C:\Temp\LRData"
    ```

Collect artifacts and store data in ".\LRData"
    ```
    CyLR.exe -o LRData
    ```

Collect artifacts and send data to SFTP server 8.8.8.8
    ```
    CyLR.exe -u username -p password -s 8.8.8.8
    ```

Collect artifacts on local disk and send data to SFTP server 8.8.8.8, local copy deleted, if successful
    ```
    CyLR.exe -u username -p password -s 8.8.8.8 -m
    ```

Collect artifacts from a mounted image on the E: drive
    ```
    CyLR.exe -mount -dl E:
    ```
    
## AUTHORS
* [Jason Yegge](https://github.com/Lansatac)
* [Alan Orlikoski](https://github.com/rough007)
* [Bryan Hennessey](https://github.com/Gizmo44z)
