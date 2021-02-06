using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Media;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Jarvis_antivirus
{
    public partial class Jarvisantivirus : Form
    {
        public Jarvisantivirus()
        {
            //on load popup scanning form.
            //var form = new Form2();
            //form.Show(this);
            InitializeComponent();
        }
        //initializing variables
        private int highthreats = 0;
        private int lowthreats = 0;
        private int warnings = 0;
        private int buttonselected = 0; //no button selected
        public static string whatdididetect = "";
        public static string processidetected = "";
        public static string whatdididetect2 = "";
        public static string processidetected2 = "";

        private enum RightMaliciousRatio //the percante he has good of 50 files
        {
            hundred,
            ninety,
            eighty,
            seventy,
            sixty,
            fifty,
            fourty,
            thirthy,
            twenty,
            ten
        }

        private static Dictionary<string, RightMaliciousRatio> dangerouswords = new Dictionary<string, RightMaliciousRatio> //this is our dictionary, it has code used in malware
        {
            //all these files have been tested on viruses and on a lot of not viruses to make the false detection rates drop as much as possible.
            //DATABASE PART 1: SUSPICIOUS WORDS
            {"hacked", RightMaliciousRatio.hundred}, //found one actual zoo virus
            {"Hacked", RightMaliciousRatio.hundred}, //above
            {"Hacker", RightMaliciousRatio.hundred},
            {"hacker", RightMaliciousRatio.hundred},
            {"Trojan", RightMaliciousRatio.hundred},
            {"trojan", RightMaliciousRatio.hundred},
            {"Keylogger", RightMaliciousRatio.hundred},
            {"keylogger", RightMaliciousRatio.hundred},
            {"Infected", RightMaliciousRatio.hundred},
            {"infected", RightMaliciousRatio.hundred},
            {"Ransomware", RightMaliciousRatio.hundred},
            {"ransomware", RightMaliciousRatio.hundred},
            {"Botnet", RightMaliciousRatio.hundred},
            {"botnet", RightMaliciousRatio.hundred},
            {"Backdoor", RightMaliciousRatio.hundred}, //found one actual zoo virus
            {"backdoor", RightMaliciousRatio.hundred}, //above},
            {"Nuker", RightMaliciousRatio.hundred},
            {"nuker", RightMaliciousRatio.hundred},
            {"Rootkit", RightMaliciousRatio.hundred},
            {"rootkit", RightMaliciousRatio.hundred},
            {@"\FirewallControlPanel.exe", RightMaliciousRatio.hundred},
            {@"\win-firewall.exe", RightMaliciousRatio.hundred},
            {@"\dwm.exe", RightMaliciousRatio.hundred},
            {@"\adobeflash.exe", RightMaliciousRatio.hundred},
            {@"\desktop.exe", RightMaliciousRatio.hundred},
            {@"\jucheck.exe", RightMaliciousRatio.hundred},
            {@"\jusched.exe", RightMaliciousRatio.hundred},
            {@"\java.exe", RightMaliciousRatio.hundred},
            {@"\chrome.exe", RightMaliciousRatio.hundred},
            {@"\csrss.exe", RightMaliciousRatio.hundred},
            {@"\explorer.exe", RightMaliciousRatio.hundred},
            {@"\iexplore.exe", RightMaliciousRatio.hundred},
            {@"\firefox.exe", RightMaliciousRatio.hundred},
            {@"\lsass.exe", RightMaliciousRatio.hundred},
            {@"\svchost.exe", RightMaliciousRatio.hundred},
            {@"\winlogon.exe", RightMaliciousRatio.hundred},
            {@"\rundll32.exe", RightMaliciousRatio.hundred},
            {@"\taskhost.exe", RightMaliciousRatio.hundred},
            {@"\spoolsv.exe", RightMaliciousRatio.hundred},
            {@"\smss.exe", RightMaliciousRatio.hundred},
            {@"\wininit.exe", RightMaliciousRatio.hundred},
            {@"\Mozilla\4.0", RightMaliciousRatio.hundred},
        };


        private static Dictionary<string, RightMaliciousRatio> BATcommands = new Dictionary<string, RightMaliciousRatio> //this is our dictionary, it has code used in malware
        {
            //DATABASE PART 2: BAT
            { "del /f", RightMaliciousRatio.hundred},
            {"del /f /q", RightMaliciousRatio.hundred},
            {"net stop", RightMaliciousRatio.hundred},
            {"taskkill", RightMaliciousRatio.hundred},
            {"ipconfig /release", RightMaliciousRatio.hundred},
            {"nokeyboard.reg", RightMaliciousRatio.hundred},
            {"Set BatInfect=%%Z > Nul", RightMaliciousRatio.hundred},
            {"Copy /y %0 %BatInfect%", RightMaliciousRatio.hundred},
            {"Open folder to see files... >> %%E:\autorun.inf", RightMaliciousRatio.hundred},
            {"colCDROMs.Item(d).Eject", RightMaliciousRatio.hundred},
            {"opendisk.vbs", RightMaliciousRatio.hundred},
            {"echo %random%", RightMaliciousRatio.hundred},
            {"%random%Spammed Filetype", RightMaliciousRatio.hundred},
            {"net stop “Security Center", RightMaliciousRatio.hundred},
            {"netsh firewall set opmode mode=disable", RightMaliciousRatio.hundred},
            {"tskill", RightMaliciousRatio.hundred},
            {"attrib +h", RightMaliciousRatio.hundred},
            {"start title.wma", RightMaliciousRatio.hundred},
            {"copy %0 %windir%", RightMaliciousRatio.hundred},
            {"/f /s /q", RightMaliciousRatio.hundred},
            {"reg delete", RightMaliciousRatio.hundred},
            {"attrib -r -s -h", RightMaliciousRatio.hundred},
            {"rd/s/q", RightMaliciousRatio.hundred},
            {"ipconfig", RightMaliciousRatio.hundred},
            {"shutdown -s", RightMaliciousRatio.hundred},
        };

        private static Dictionary<string, RightMaliciousRatio> csharpdictionary = new Dictionary<string, RightMaliciousRatio> //this is our dictionary, it has code used in malware
        {
            //DATABASE PART 3: C#
            //3.1 : dangerous commands also used in processes like opera, this is the reason they are listed as warnings and not as viruses.
            {"CreateRemoteThread", RightMaliciousRatio.hundred}, //used in opera but also in nvidia which is malicious
            {"NtUnmapViewOfSection", RightMaliciousRatio.hundred}, //not used because this program is used in opera
            {"Startup", RightMaliciousRatio.hundred}, //used in opera and cmd but also in nvidia and netsession which are malicious

            //3.2 : dangerous commands not yet found in normal or malicious processes, probably good
            {".Shell", RightMaliciousRatio.hundred},
            {".shell", RightMaliciousRatio.hundred},
            {"GetAsyncKeyState", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"RijndaelManaged", RightMaliciousRatio.hundred}, //not found being wrong YET however i think it can also be used for good things like not damaging encryption
            {"MD5CryptoServiceProvider", RightMaliciousRatio.hundred}, //not found being wrong YET however i think it can also be used for good things like not damaging encryption
            {"PRIVMSG", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"R?\n??i??", RightMaliciousRatio.hundred}, //not found being wrong YET - this should work because it is used for creating a random part of something that will be needed for flooding
            {"File.Delete", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"EncryptFile", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"DESCryptoServiceProvider", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"CreateEncryptor", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"FileAttributes.Hidden", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"FileAttributes.System", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"FileAttributes.ReadOnly", RightMaliciousRatio.hundred}, //not fo und being wrong YET
            {"private static LowLevelKeyboardProc _proc = HookCallback;", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"keyboardHookProc", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"globalKeyboardHook", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"printScreen", RightMaliciousRatio.hundred}, //not found being wrong YET
            {".CopyFromScreen", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"CloseMainWindow", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"tcpListener", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"Environment.Exit", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"Cursor.Position", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"SendKeys.Send", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"SpecialFolder.Startup", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"tcpClient.GetStream", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"SendKeys.SendWait", RightMaliciousRatio.hundred}, //not found being wrong YET
            {"WinLocker.exe", RightMaliciousRatio.hundred}, //not found being wrong YET
            {".Kill()", RightMaliciousRatio.hundred}, //found virus one time, no mistakes YET
            {"drivers\\etc\\hosts", RightMaliciousRatio.hundred}, //found virus one time no mistakes YET
            {"File.WriteAllBytes", RightMaliciousRatio.hundred}, //found virus one time no mistakes YET
            {"WriteRegistryValue", RightMaliciousRatio.hundred},
            {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\", RightMaliciousRatio.hundred},
            {"forceDeleteFile", RightMaliciousRatio.hundred},
            {"STARTUPINFO", RightMaliciousRatio.hundred},
            {"DeleteFile(", RightMaliciousRatio.hundred}, //could use DeleteFile( instead
            {"TerminateProcess(", RightMaliciousRatio.hundred},
            {"PROCESS_TERMINATE", RightMaliciousRatio.hundred},
            {"Shellcode.inc", RightMaliciousRatio.hundred},
            {"Shellcode", RightMaliciousRatio.hundred},
            {"delete[]", RightMaliciousRatio.hundred},
            {"DeleteCriticalSection(", RightMaliciousRatio.hundred},
            {"SetThreadPriority", RightMaliciousRatio.hundred},
            {"Windows Host Process", RightMaliciousRatio.hundred},
            {"SERVICE_ALL_ACCESS", RightMaliciousRatio.hundred},
            {"CreateService(", RightMaliciousRatio.hundred},
            {"SERVICE_DEMAND_START", RightMaliciousRatio.hundred},
            {"ElevatedAdmin", RightMaliciousRatio.hundred},
            {"SID_IDENTIFIER_AUTHORITY", RightMaliciousRatio.hundred},
            {"SECURITY_NT_AUTHORITY", RightMaliciousRatio.hundred},
            {"SECURITY_BUILTIN_DOMAIN_RID", RightMaliciousRatio.hundred},
            {"DOMAIN_ALIAS_RID_ADMINS", RightMaliciousRatio.hundred},
            {"AdminMember", RightMaliciousRatio.hundred},
            {"SC_MANAGER_ALL_ACCESS", RightMaliciousRatio.hundred},
            {"DeleteService", RightMaliciousRatio.hundred},
            {"UninstallDriver", RightMaliciousRatio.hundred},
            {"fwrite(", RightMaliciousRatio.hundred}, //might replace with *(Rdriver,
            {"fclose(Driver)", RightMaliciousRatio.hundred},
            {"InstallDriver(", RightMaliciousRatio.hundred},
            {"CreateToolhelp32Snapshot", RightMaliciousRatio.hundred},



            {"Accept", RightMaliciousRatio.hundred},
            {"AdjustTokenPrivileges", RightMaliciousRatio.hundred},
            {"AttachThreadInput", RightMaliciousRatio.hundred},
            {"Bind", RightMaliciousRatio.hundred},
            {"BitBolt", RightMaliciousRatio.hundred},
            {"CallNextHookEx", RightMaliciousRatio.hundred},
            {"CertOpenSystemStore", RightMaliciousRatio.hundred},
            {"CheckRemoteDebuggerPresent", RightMaliciousRatio.hundred},
            {"CpCreateInstance", RightMaliciousRatio.hundred},
            {"Connect", RightMaliciousRatio.hundred},
            {"ConnectNamedPipe", RightMaliciousRatio.hundred},
            {"ControlService", RightMaliciousRatio.hundred},
            {"CreateFile", RightMaliciousRatio.hundred},
            {"CreateFileMapping", RightMaliciousRatio.hundred},
            {"CreateService", RightMaliciousRatio.hundred},
            {"CryptAcquireContext", RightMaliciousRatio.hundred},
            {"DeviceloControl", RightMaliciousRatio.hundred},
            {"DllCanUnloadNow", RightMaliciousRatio.hundred},
            {"DllGetClassObject", RightMaliciousRatio.hundred},
            {"DllInstall", RightMaliciousRatio.hundred},
            {"DllRegisterServer", RightMaliciousRatio.hundred},
            {"DllUnregisterServer", RightMaliciousRatio.hundred},
            {"EnableExecuteProtectionSupport", RightMaliciousRatio.hundred},
            {"EnumProcesses", RightMaliciousRatio.hundred},
            {"EnumProcessModules", RightMaliciousRatio.hundred},
            {"FindFirstFile/FindNextFile", RightMaliciousRatio.hundred},
            {"FindResource", RightMaliciousRatio.hundred},
            {"FindWindow", RightMaliciousRatio.hundred},
            {"FtpPutFile", RightMaliciousRatio.hundred},
            {"GetAdaptersInfo", RightMaliciousRatio.hundred},
            {"GetDC", RightMaliciousRatio.hundred},
            {"gethostbyname", RightMaliciousRatio.hundred},
            {"gethostname", RightMaliciousRatio.hundred},
            {"GetKeyState", RightMaliciousRatio.hundred},
            {"GetModuleFilename", RightMaliciousRatio.hundred},
            {"GetStartupInfo", RightMaliciousRatio.hundred},
            {"GetSystemDefaultLangld", RightMaliciousRatio.hundred},
            {"GetTempPath", RightMaliciousRatio.hundred},
            {"GetThreadContext", RightMaliciousRatio.hundred},
            {"GetVersionEx", RightMaliciousRatio.hundred},
            {"GetWindowsDirectory", RightMaliciousRatio.hundred},
            {"inet_addr", RightMaliciousRatio.hundred},
            {"MapViewOfFile", RightMaliciousRatio.hundred},
            {".write", RightMaliciousRatio.hundred},
            {"IsNTAdmin", RightMaliciousRatio.hundred},
            {"IsDebuggerPresent", RightMaliciousRatio.hundred},
            {"IsWoW64Process", RightMaliciousRatio.hundred},
            {"LdrLoadDll", RightMaliciousRatio.hundred},
            {"LoadResource", RightMaliciousRatio.hundred},
            {"LsaEnumerateLogonSessions", RightMaliciousRatio.hundred},
            {"MapVirtualKey", RightMaliciousRatio.hundred},
            {"MmGetSystemRoutineAddress", RightMaliciousRatio.hundred},
            {"Module32First/Module32Next", RightMaliciousRatio.hundred},
            {"NetScheduleJobAdd", RightMaliciousRatio.hundred},
            {"NetShareEnum", RightMaliciousRatio.hundred},
            {"NtQueryDirectoryFile", RightMaliciousRatio.hundred},
            {"NtQueryInformationProcess", RightMaliciousRatio.hundred},
            {"NtSetInformationProcess", RightMaliciousRatio.hundred},
            {"OleInitialize", RightMaliciousRatio.hundred},
            {"OpenSCManager", RightMaliciousRatio.hundred},
            {"PeekNamedPipe", RightMaliciousRatio.hundred},
            {"Process32First/Process32Next", RightMaliciousRatio.hundred},
            {"QueryPerfomanceCounter", RightMaliciousRatio.hundred},
            {"QueueUserApc", RightMaliciousRatio.hundred},
            {"ReadProcessMemory", RightMaliciousRatio.hundred},
            {"recv", RightMaliciousRatio.hundred},
            {"RegisterHotKey", RightMaliciousRatio.hundred},
            {"ResumeThread", RightMaliciousRatio.hundred},
            {"RtlCreateRegistryKey", RightMaliciousRatio.hundred},
            {"RtlWriteRegistryValue", RightMaliciousRatio.hundred},
            {"SamIConnect", RightMaliciousRatio.hundred},
            {"SamIGetPrivateData", RightMaliciousRatio.hundred},
            {"SamQueryInformationUse", RightMaliciousRatio.hundred},
            {"send", RightMaliciousRatio.hundred},
            {"SetFileTime", RightMaliciousRatio.hundred},
            {"SetThreadContext", RightMaliciousRatio.hundred},
            {"SfcTerminateWatcherThread", RightMaliciousRatio.hundred},
            {"ShellExecute", RightMaliciousRatio.hundred},
            {"StartServiceCtrlDispatcher", RightMaliciousRatio.hundred},
            {"SuspendThread", RightMaliciousRatio.hundred},
            {"system", RightMaliciousRatio.hundred},
            {"Thread32First/Thread32Next", RightMaliciousRatio.hundred},
            {"ToolHelp32ReadProcessMemory", RightMaliciousRatio.hundred},
            {"UrlDownloadToFile", RightMaliciousRatio.hundred},
            {"VirtualAllocEx", RightMaliciousRatio.hundred},
            {"VirtualProtectEx", RightMaliciousRatio.hundred},
            {"WinExec", RightMaliciousRatio.hundred},
            //wlx sas
            {"WlxLoggedOnSAS", RightMaliciousRatio.hundred},
            {"WLX_SAS_", RightMaliciousRatio.hundred},
            {"WlxLogoff", RightMaliciousRatio.hundred},
            {"Wlx*", RightMaliciousRatio.hundred},
            {"WlxQueryConsoleSwitchCredentials", RightMaliciousRatio.hundred},
            {"WlxQueryClientCredentials", RightMaliciousRatio.hundred},
            {"WlxQueryInetConnectorCredentials", RightMaliciousRatio.hundred},
            {"WlxQueryTsLogonCredentials", RightMaliciousRatio.hundred}, //wlx sas end

            {"Wow64DisableWow64FsRedirection", RightMaliciousRatio.hundred},
            {"WriteProcessMemory", RightMaliciousRatio.hundred},
            {"WSAStartup", RightMaliciousRatio.hundred},


            {"GinaDll", RightMaliciousRatio.hundred},

            //malware trafficking
            {@"\\serverName\share", RightMaliciousRatio.hundred},
            {@"\\?\serverName\share", RightMaliciousRatio.hundred},
            {@"\\.\", RightMaliciousRatio.hundred},
            {":Stream:$Data", RightMaliciousRatio.hundred},
            {".GetSpecialFolder(", RightMaliciousRatio.hundred},

            //registry's
            {"HKEY_LOCAL_MACHINE", RightMaliciousRatio.hundred}, //most elevated HKEY
            {"HKEY_CURRENT_USER,", RightMaliciousRatio.hundred},
            {"HKEY_CLASSES_ROOT", RightMaliciousRatio.hundred},
            {"HKEY_CURRENT_CONFIG", RightMaliciousRatio.hundred},
            {"HKEY_USERS", RightMaliciousRatio.hundred}, //most not elevated HKEY (less elevated)
            {@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", RightMaliciousRatio.hundred}, //start on boot subregister (mostly used)
            {"RegOpenKeyEx", RightMaliciousRatio.hundred},
            {"RegSetValueEx", RightMaliciousRatio.hundred},
            {"RegGetValue", RightMaliciousRatio.hundred},
            {"RegRead", RightMaliciousRatio.hundred},
            {"RegWrite", RightMaliciousRatio.hundred},
            {"regcreate", RightMaliciousRatio.hundred},
            {"regkey", RightMaliciousRatio.hundred},
            {"regvalue", RightMaliciousRatio.hundred},
            {"REG_DWORD", RightMaliciousRatio.hundred},
            {"MSKernel32", RightMaliciousRatio.hundred},
            {"Win32DLL", RightMaliciousRatio.hundred},
            {"regget", RightMaliciousRatio.hundred},
            {"regedit", RightMaliciousRatio.hundred},
            {"*.reg", RightMaliciousRatio.hundred}, //registry's end and malware trafficking end

            //malware using the internet to do the dirty work
            {"InternetOpen", RightMaliciousRatio.hundred}, //initialize an internet connection
            {"InternetOpenUrl", RightMaliciousRatio.hundred}, //connect to a specified url
            {"InternetReadFile", RightMaliciousRatio.hundred}, //read data from an internet downloaded file
            {"InternetWriteFile", RightMaliciousRatio.hundred}, //write data to an internet downloaded file
            {"Wininet.dll", RightMaliciousRatio.hundred}, //uses elevated API's - malware using the internet end

            //malware using processes, threads, mutexes and services
            {"CreateProcess", RightMaliciousRatio.hundred}, //create a simple remote shell with just a single function call
            {"CreateThread", RightMaliciousRatio.hundred}, //create a thread within a process which path is given after the function.
            {"ReleaseMutex", RightMaliciousRatio.hundred}, //release the mutex, other threads can continue.
            {"CreateMutex", RightMaliciousRatio.hundred}, //create a new mutex
            {"OpenMutex", RightMaliciousRatio.hundred}, //get acces to a mutex from another process (very malware only)
            {"WIN32_SHARE_PROCESS", RightMaliciousRatio.hundred},
            {"WIN32_OWN_PROCESS", RightMaliciousRatio.hundred},
            {@"HKLM\SYSTEM\CurrentControlSet\Services", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},

            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //{"forceDeleteFile", RightMaliciousRatio.hundred},
            //most duplicated processes

            //a few copys for a easy fill in system (we will put new found parts here at the beginning)

            ////{"File.Delete", RightMaliciousRatio.hundred}, //not found being wrong YET
            ////{"File.Delete", RightMaliciousRatio.hundred}, //not found being wrong YET
            ////{"File.Delete", RightMaliciousRatio.hundred}, //not found being wrong YET
            ////{"File.Delete", RightMaliciousRatio.hundred}, //not found being wrong YET

            //3.3 : dangerous commands which are tested and only found in malicious programs and have maximal one mistake.
            {"GetWindowText", RightMaliciousRatio.hundred}, //found actual malware and got wrong ones (premieropinion.exe)
            {"SetWindowsHookEx", RightMaliciousRatio.hundred}, //found actual malware and not got wrong ones (premieropinion.exe)
            {"GetForegroundWindow", RightMaliciousRatio.hundred}, //found actual malware (premieropionion.exe) and (netsession_win.exe) and (nvidia_web_helper.exe) but also got wrong ones
            {"JOIN", RightMaliciousRatio.hundred}, //found actual malware and (netsession_win.exe and nvidia_web_helper.exe) however got one mistake pointing visual studio as malware - reason set as suspicious but actual trojan
            {"CryptoStream", RightMaliciousRatio.hundred}, //found actual malware and (netsession_win.exe and nvidia_web_helper.exe) however got one mistake pointing visual studio as malware - reason set as suspicious but actual crypter
            {"Start menu", RightMaliciousRatio.hundred}, //found netsession_win.exe without mistakes (yet).
            {"StreamWriter", RightMaliciousRatio.hundred}, //no wrong ones and one right one (this progress)
            {".Startup", RightMaliciousRatio.hundred}, //used in opera and cmd but also in nvidia and netsession which are malicious
        };

        private void button1_Click(object sender, EventArgs e) //select folder
        {
            //part 1: setting our first label to our folder selected
            folderBrowserDialog1.ShowDialog();
            label1.Text = folderBrowserDialog1.SelectedPath;

            //part 2: we start a new scan so reset our variabeles to 0
            highthreats = 0;
            lowthreats = 0;
            warnings = 0;

            //part 3: we start now so we have to show that there are 0 warnings, high treats and low treats at the moment.
            label2.Text = "High threats: " + highthreats.ToString();
            label3.Text = "Low threats: " + lowthreats.ToString();
            label4.Text = "Warning: " + warnings.ToString();

            //we set their color to their default color to, if this code block is not present the color will be reset to gray.
            label2.ForeColor = System.Drawing.Color.Aqua;
            label3.ForeColor = System.Drawing.Color.Aqua;
            label4.ForeColor = System.Drawing.Color.Aqua;

            //we set the progress of the progessbar to 0 of 100
            progressBar1.Value = 0;

            //we clear the listboxes cause we start a new scan.
            listBox1.Items.Clear();
            listBox2.Items.Clear();
            listBox3.Items.Clear();
            listBox4.Items.Clear();
            listBox5.Items.Clear();
            listBox6.Items.Clear();
        }

        private void button2_Click(object sender, EventArgs e) //scan location
        {
            //declare search, an array which contains all files in a map and his subdirectories.
            string[] search = System.IO.Directory.GetFiles(@folderBrowserDialog1.SelectedPath, "*.*", System.IO.SearchOption.AllDirectories);

            //get the progresbar ready
            progressBar1.Maximum = search.Length;

            //for each item in the selected map, read them with streamreader and check if they are equal to a dictionary of our virus database.
            foreach (string item in search)
            {
                try
                {
                    byte[] fileBytes2 = File.ReadAllBytes(item); //get byte
                    string fileStrings2 = Encoding.UTF8.GetString(fileBytes2); //decode it

                    //for each of the words in the dictionary check if they match with a word in the scanning file, with the condition that the file type is something that contain bat commands, update statistics and reasons.
                    foreach (KeyValuePair<string, RightMaliciousRatio> csharpviruspart in csharpdictionary) //search.
                    {
                        if (item.Contains("opera") || item.Contains("Visual Studio")) //filter out or webbrowser and our antivirus project
                        {

                        }
                        else
                        {
                            if (item.Contains(".txt") || item.Contains(".hundred"))
                            {
                                if (fileStrings2.Contains(csharpviruspart.Key))
                                {
                                    if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        highthreats++;
                                        whatdididetect2 = highthreats.ToString() + " this program uses a high risk bat function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = highthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox5.Items.Add(processidetected2);
                                        listBox6.Items.Add(whatdididetect2);
                                        label2.Text = "High threats: " + highthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        warnings++;
                                        whatdididetect2 = warnings.ToString() + " this program uses a word that is a very clear link to hacking: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = warnings.ToString() + " " + item; //in which process did i detect that
                                        listBox1.Items.Add(processidetected2);
                                        listBox2.Items.Add(whatdididetect2);
                                        label4.Text = "Warnings: " + warnings.ToString();
                                    }
                                }
                            }
                            else if (item.Contains(".exe") || item.Contains(".dll") || item.Contains(".cs") || item.Contains(".vbs") || item.Contains(".cpp") || item.Contains(".css") || item.Contains(".js") || item.Contains(".htacces") || item.Contains(".php") || item.Contains(".inc") || item.Contains(".less") || item.Contains(".dat"))
                            {
                                if (fileStrings2.Contains(csharpviruspart.Key))
                                {
                                    if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        highthreats++;
                                        whatdididetect2 = highthreats.ToString() + " this program uses a high risk malware function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = highthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox5.Items.Add(processidetected2);
                                        listBox6.Items.Add(whatdididetect2);
                                        label2.Text = "High threats: " + highthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        highthreats++;
                                        whatdididetect2 = highthreats.ToString() + " this program uses a high risk keylogging function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = highthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox5.Items.Add(processidetected2);
                                        listBox6.Items.Add(whatdididetect2);
                                        label2.Text = "High threats: " + highthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        highthreats++;
                                        whatdididetect2 = highthreats.ToString() + " this program uses a high risk cryptor function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = highthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox5.Items.Add(processidetected2);
                                        listBox6.Items.Add(whatdididetect2);
                                        label2.Text = "High threats: " + highthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        highthreats++;
                                        whatdididetect2 = highthreats.ToString() + " this program uses a high risk bat function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = highthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox5.Items.Add(processidetected2);
                                        listBox6.Items.Add(whatdididetect2);
                                        label2.Text = "High threats: " + highthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        lowthreats++;
                                        whatdididetect2 = lowthreats.ToString() + " this program uses a small risk ransomware function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = lowthreats.ToString() + " " + item; //in which process did i detect that
                                        listBox3.Items.Add(processidetected2);
                                        listBox4.Items.Add(whatdididetect2);
                                        label3.Text = "Low threats: " + lowthreats.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        warnings++;
                                        whatdididetect2 = warnings.ToString() + " this program uses a suspicious function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = warnings.ToString() + " " + item; //in which process did i detect that
                                        listBox1.Items.Add(processidetected2);
                                        listBox2.Items.Add(whatdididetect2);
                                        label4.Text = "Warnings: " + warnings.ToString();
                                    }
                                    else if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                                    {
                                        warnings++;
                                        whatdididetect2 = warnings.ToString() + " this program contains a malicious word: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                        processidetected2 = warnings.ToString() + " " + item; //in which process did i detect that
                                        listBox1.Items.Add(processidetected2);
                                        listBox2.Items.Add(whatdididetect2);
                                        label4.Text = "Warnings: " + warnings.ToString();
                                    }
                                }
                            }
                            if (csharpviruspart.Value == RightMaliciousRatio.hundred) //.hundred
                            {
                                if (item.Contains(csharpviruspart.Key)) //if the name of the file contains a malicious word
                                {
                                    lowthreats++;
                                    whatdididetect2 = lowthreats.ToString() + " this program name contains a malicious word: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected2 = lowthreats.ToString() + " " + item; //in which process did i detect that
                                    listBox3.Items.Add(processidetected2);
                                    listBox4.Items.Add(whatdididetect2);
                                    label3.Text = "Low threats: " + lowthreats.ToString();
                                }
                            }
                        }
                    }
                }
                catch { }
                progressBar1.Increment(1); //put it one higher, located here because it happens ALWAYS
            }
            if (warnings > 0 || lowthreats > 0 || highthreats > 0) //this condition first to save ram when using all conditions at the same time
            {
                if (highthreats > 0) //most important
                {
                    SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\high_threat.wav");
                    nc.Play(); //word closed
                }
                else if (highthreats == 0 && lowthreats > 0) //second most important
                {
                    SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\medium_threath.wav");
                    nc.Play(); //word closed
                }
                else if (highthreats == 0 && lowthreats == 0 && warnings > 0) //third most important.
                {
                    SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\low_threath.wav");
                    nc.Play(); //word closed
                }
                else if (highthreats == 0 && lowthreats == 0 && warnings == 0) //third most important.
                {
                    SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\high_threat.wav");
                    nc.Play(); //word closed
                }
            }
        } //button click end

        private void button3_Click(object sender, EventArgs e) //finish
        {
            this.Close();
        }

        private void button5_Click(object sender, EventArgs e) //the scan tab
        {

        }

        private void button6_Click(object sender, EventArgs e) //computer status
        {

        }

        private void button4_Click(object sender, EventArgs e) //firewall
        {

        }

        private void button7_Click(object sender, EventArgs e) //quarantaine
        {

        }

        private void button8_Click(object sender, EventArgs e) //dictionary
        {

        }

        private void button9_Click(object sender, EventArgs e) //statistics
        {

        }

        private void Jarvisantivirus_Load(object sender, EventArgs e)
        {

        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e) //not used
        {

        }

        private void button10_Click(object sender, EventArgs e) //scan running processes
        {
            //part 1: we start a new scan so reset our variabeles to 0
            highthreats = 0;
            lowthreats = 0;
            warnings = 0;

            //part 2: we start now so we have to show that there are 0 warnings, high treats and low treats at the moment.
            label2.Text = "High threats: " + highthreats.ToString();
            label3.Text = "Low threats: " + lowthreats.ToString();
            label4.Text = "Warning: " + warnings.ToString();

            //part 3: we set their color to their default color to, if this code block is not present the color will be reset to gray.
            label2.ForeColor = System.Drawing.Color.Aqua;
            label3.ForeColor = System.Drawing.Color.Aqua;
            label4.ForeColor = System.Drawing.Color.Aqua;

            //part 4: we set the progress of the progessbar to 0 of 100
            progressBar1.Value = 0;

            //part 5: we clear the listboxes cause we start a new scan.
            listBox1.Items.Clear();
            listBox2.Items.Clear();
            listBox3.Items.Clear();
            listBox4.Items.Clear();
            listBox5.Items.Clear();
            listBox6.Items.Clear();

            //part 6: we actually do scan and detect now
            foreach (Process p in Process.GetProcesses()) //for all processes that he can find that are active
            {
                try
                {
                    string processLocation = p.MainModule.FileName; //get location
                    byte[] fileBytes = File.ReadAllBytes(processLocation); //get byte
                    string fileStrings = Encoding.UTF8.GetString(fileBytes); //decode it
                    foreach (KeyValuePair<string, RightMaliciousRatio> csharpviruspart in csharpdictionary) //search.
                    {
                        if (fileStrings.Contains(csharpviruspart.Key))
                        {
                            if (p.MainModule.FileName.Contains("opera") || p.MainModule.FileName.Contains("Jarvis antivirus") || p.MainModule.FileName.Contains("devenv.exe") || p.MainModule.FileName.Contains("ServiceHub.Host")) //filter out or webbrowser and our antivirus project
                            {

                            }
                            else
                            {
                                if (csharpviruspart.Value == RightMaliciousRatio.hundred) //worst: hightreat
                                {
                                    whatdididetect = highthreats.ToString() + " this program uses a high risk malware function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = highthreats.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox5.Items.Add(processidetected);
                                    listBox6.Items.Add(whatdididetect);
                                    highthreats++;
                                    label2.Text = "High threats: " + highthreats.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = highthreats.ToString() + " this program uses a high risk keylogging function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = highthreats.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox5.Items.Add(processidetected);
                                    listBox6.Items.Add(whatdididetect);
                                    highthreats++;
                                    label2.Text = "High threats: " + highthreats.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = highthreats.ToString() + " this program uses a high risk cryptor function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = highthreats.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox5.Items.Add(processidetected);
                                    listBox6.Items.Add(whatdididetect);
                                    highthreats++;
                                    label2.Text = "High threats: " + highthreats.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = highthreats.ToString() + " this program uses a high risk bat function: [" + csharpviruspart.Key + "] it is coded in .hundred"; //what did i detect
                                    processidetected = highthreats.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox5.Items.Add(processidetected);
                                    listBox6.Items.Add(whatdididetect);
                                    highthreats++;
                                    label2.Text = "High threats: " + highthreats.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = lowthreats.ToString() + " this program uses a small risk ransomware function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = lowthreats.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox3.Items.Add(processidetected);
                                    listBox4.Items.Add(whatdididetect);
                                    lowthreats++;
                                    label3.Text = "Low threats: " + lowthreats.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = warnings.ToString() + " this program uses a suspicious function: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = warnings.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox1.Items.Add(processidetected);
                                    listBox2.Items.Add(whatdididetect);
                                    warnings++;
                                    label4.Text = "Warnings: " + warnings.ToString();
                                }
                                else if (csharpviruspart.Value == RightMaliciousRatio.hundred)
                                {
                                    whatdididetect = warnings.ToString() + " this program contains a malicious word: [" + csharpviruspart.Key + "] it is coded in c sharp"; //what did i detect
                                    processidetected = warnings.ToString() + " " + p.MainModule.FileName; //in which process did i detect that
                                    listBox1.Items.Add(processidetected);
                                    listBox2.Items.Add(whatdididetect);
                                    warnings++;
                                    label4.Text = "Warnings: " + warnings.ToString();
                                }
                            }

                            //p.Kill();
                            //Console.WriteLine("{0}, {1}", csharpviruspart.Key, csharpviruspart.Value);
                        }
                        progressBar1.Increment(1); //put it one higher, located here because it happens ALWAYS
                    }
                } //try end
                catch { }
            } //foreach end
            if (warnings > 0 || lowthreats > 0 || highthreats > 0) //this condition first to save ram when using all conditions at the same time
            {
                if (highthreats > 0) //most important
                {
                    //SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\high_threat.wav");
                    //nc.Play(); //word closed
                }
                else if (highthreats == 0 && lowthreats > 0) //second most important
                {
                    //SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\medium_threath.wav");
                    // nc.Play(); //word closed
                }
                else if (highthreats == 0 && lowthreats == 0 && warnings > 0) //third most important.
                {
                    // SoundPlayer nc = new SoundPlayer(@"C:\Users\Legion\Documents\Visual Studio 2017\Projects\Jarvis antivirus\Jarvis antivirus\voice\low_threath.wav");
                    // nc.Play(); //word closed
                }
            }
        }

        private void button11_Click(object sender, EventArgs e)
        {
            //part 1: we start a new scan so reset our variabeles to 0
            highthreats = 0;
            lowthreats = 0;
            warnings = 0;

            //part 2: we start now so we have to show that there are 0 warnings, high treats and low treats at the moment.
            label2.Text = "High threats: " + highthreats.ToString();
            label3.Text = "Low threats: " + lowthreats.ToString();
            label4.Text = "Warning: " + warnings.ToString();

            //part 3: we set their color to their default color to, if this code block is not present the color will be reset to gray.
            label2.ForeColor = System.Drawing.Color.Aqua;
            label3.ForeColor = System.Drawing.Color.Aqua;
            label4.ForeColor = System.Drawing.Color.Aqua;

            //part 4: we set the progress of the progessbar to 0 of 100
            progressBar1.Value = 0;

            //part 5: we clear the listboxes cause we start a new scan.
            listBox1.Items.Clear();
            listBox2.Items.Clear();
            listBox3.Items.Clear();
            listBox4.Items.Clear();
            listBox5.Items.Clear();
            listBox6.Items.Clear();

            //part 6: the actuall stuff we need
            DirectoryInfo i = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToString()); //our location
            foreach (var file in i.GetFiles("*.exe")) //for each ex file in our location
            {
                //foreach (Process p in Process.GetProcessesByName(file.Name)) //check if the malware is running and if it is running, kill it.
                //{
                //kill
                //}
                highthreats++;
                string found = highthreats.ToString() + " .exe file located in appdata, this is a potential virus and a high treath";
                string location = highthreats.ToString() + " " + file;
                listBox5.Items.Add(location);
                listBox6.Items.Add(found);
                label2.Text = "High threats: " + highthreats.ToString();
                progressBar1.Increment(1); //put it one higher, located here because it happens ALWAYS
            }
            foreach (var file in i.GetFiles("*.hundred")) //for each ex file in our location
            {
                //foreach (Process p in Process.GetProcessesByName(file.Name)) //check if the malware is running and if it is running, kill it.
                //{
                //kill
                //}
                highthreats++;
                string found = highthreats.ToString() + " .hundred file located in appdata, this is a potential virus and a high treath";
                string location = highthreats.ToString() + " " + file;
                listBox5.Items.Add(location);
                listBox6.Items.Add(found);
                label2.Text = "High threats: " + highthreats.ToString();
                progressBar1.Increment(1); //put it one higher, located here because it happens ALWAYS
            }
            progressBar1.Maximum = highthreats;
        }

        private void listBox2_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
