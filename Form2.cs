using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Jarvis_antivirus
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
            cleanRunningProcesses();
            Console.ReadLine();
        }

        private void Form2_Load(object sender, EventArgs e)
        {

        }

        private enum MalwareTypes
        {
            //the different types of malware are keyloggers, trojans and crypters (who try to hide malware)
            Keylogger, // has a dangerous of 5/5 (high)
            Trojan, // has a dangerous of 4/5 (high)
            Crypter, //has a dangerous of 4/5 (high)
            Ransomware, //has a dangerous of 2/5 (low)
            Suspicious //has a dangerous of 1/5 (warning)
        }

        private static Dictionary<string, MalwareTypes> signatures = new Dictionary<string, MalwareTypes> //this is our dictionary, it has code used in malware
        {
            //proved wrong list 

            //{"CreateRemoteThread", MalwareTypes.Trojan}, //used in opera but also in nvidia which is malicious
            //{"NtUnmapViewOfSection", MalwareTypes.Trojan}, //not used because this program is used in opera
            //{"Startup", MalwareTypes.Suspicious}, //not found being wrong YET //used in opera and cmd but also in nvidia and netsession which are malicious

            //not proved wrong list

            {"GetAsyncKeyState", MalwareTypes.Trojan}, //not found being wrong YET
            {"RijndaelManaged", MalwareTypes.Crypter}, //not found being wrong YET however i think it can also be used for good things like not damaging encryption
            {"MD5CryptoServiceProvider", MalwareTypes.Crypter}, //not found being wrong YET however i think it can also be used for good things like not damaging encryption
            {"PRIVMSG", MalwareTypes.Trojan}, //not found being wrong YET
            {"R?\n??i??", MalwareTypes.Ransomware}, //not found being wrong YET - this should work because it is used for creating a random part of something that will be needed for flooding
            {"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET
            {"EncryptFile", MalwareTypes.Crypter}, //not found being wrong YET
            {"DESCryptoServiceProvider", MalwareTypes.Trojan}, //not found being wrong YET
            {"CreateEncryptor", MalwareTypes.Trojan}, //not found being wrong YET
            {"FileAttributes.Hidden", MalwareTypes.Suspicious}, //not found being wrong YET
            {"FileAttributes.System", MalwareTypes.Suspicious}, //not found being wrong YET
            {"FileAttributes.ReadOnly", MalwareTypes.Suspicious}, //not fo und being wrong YET
            {"private static LowLevelKeyboardProc _proc = HookCallback;", MalwareTypes.Keylogger}, //not found being wrong YET
            {"keyboardHookProc", MalwareTypes.Keylogger}, //not found being wrong YET
            {"globalKeyboardHook", MalwareTypes.Keylogger}, //not found being wrong YET
            {"printScreen", MalwareTypes.Trojan}, //not found being wrong YET
            {".CopyFromScreen", MalwareTypes.Trojan}, //not found being wrong YET
            {"CloseMainWindow", MalwareTypes.Trojan}, //not found being wrong YET
            {"tcpListener", MalwareTypes.Keylogger}, //not found being wrong YET
            {"Environment.Exit", MalwareTypes.Trojan}, //not found being wrong YET
            {"Cursor.Position", MalwareTypes.Trojan}, //not found being wrong YET
            {"SendKeys.Send", MalwareTypes.Trojan}, //not found being wrong YET
            {"SpecialFolder.Startup", MalwareTypes.Trojan}, //not found being wrong YET
            {"tcpClient.GetStream", MalwareTypes.Trojan}, //not found being wrong YET

            //{"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET
            //{"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET
            //{"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET
            //{"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET
            //{"File.Delete", MalwareTypes.Trojan}, //not found being wrong YET

            //proved right list

            {"GetWindowText", MalwareTypes.Keylogger}, //found actual malware and not got wrong ones (premieropinion.exe)
            {"SetWindowsHookEx", MalwareTypes.Keylogger}, //found actual malware and not got wrong ones (premieropinion.exe)
            {"GetForegroundWindow", MalwareTypes.Keylogger}, //found actual malware (premieropionion.exe) and (netsession_win.exe) and (nvidia_web_helper.exe)
            {"JOIN", MalwareTypes.Trojan}, //found actual malware and (netsession_win.exe and nvidia_web_helper.exe) however got one mistake pointing visual studio as malware
            {"CryptoStream", MalwareTypes.Crypter}, //found actual malware and (netsession_win.exe and nvidia_web_helper.exe) however got one mistake pointing visual studio as malware
            {"Start menu", MalwareTypes.Suspicious}, //found netsession_win.exe without mistakes (yet).

            {"Hacked", MalwareTypes.Suspicious}, //the following list of commands descriped netsession, another actual malware and our own program (that uses this words to lol)
            {"Hacker", MalwareTypes.Suspicious},
            {"hacked", MalwareTypes.Suspicious},
            {"hacker", MalwareTypes.Suspicious},
            {"Virus", MalwareTypes.Suspicious},
            {"virus", MalwareTypes.Suspicious},
            {"Malware", MalwareTypes.Suspicious},
            {"malware", MalwareTypes.Suspicious},
            {"Trojan", MalwareTypes.Suspicious},
            {"trojan", MalwareTypes.Suspicious},
            {"Keylogger", MalwareTypes.Suspicious},
            {"keylogger", MalwareTypes.Suspicious},
            {"Malicious", MalwareTypes.Suspicious}, //warning word also used in opera crashreporter.
            {"malicious", MalwareTypes.Suspicious},
            {"Infected", MalwareTypes.Suspicious},
            {"infected", MalwareTypes.Suspicious},
            {"Ransomware", MalwareTypes.Suspicious},
            {"ransomware", MalwareTypes.Suspicious},
            {"Botnet", MalwareTypes.Suspicious},
            {"botnet", MalwareTypes.Suspicious},
            {"Backdoor", MalwareTypes.Suspicious},
            {"backdoor", MalwareTypes.Suspicious},
            {"Phishing", MalwareTypes.Suspicious},
            {"phishing", MalwareTypes.Suspicious},
            {"Bruteforce", MalwareTypes.Suspicious},
            {"bruteforce", MalwareTypes.Suspicious},
            {"Injector", MalwareTypes.Suspicious},
            {"injector", MalwareTypes.Suspicious}
        };

        //appdata is the place where most of the malware puts itself, this is done because appdata is hided by default and is not often opened by the user however it contains a lot of information so the malware is hard to find.
        private static void cleanAppdata()
        {
            DirectoryInfo i = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)); //our location
            foreach (var file in i.GetFiles("*.exe")) //for each ex file in our location
            {
                foreach (Process p in Process.GetProcessesByName(file.Name)) //check if the malware is running and if it is running, kill it.
                {
                    //p.Kill();
                }
                //file.Delete();
                Console.WriteLine("Malware --> " + file.Name);
            }
        }

        private static void cleanRunningProcesses()
        {
            foreach (Process p in Process.GetProcesses()) //for all processes that he can find that are active
            {
                try
                {
                    string processLocation = p.MainModule.FileName; //get location
                    byte[] fileBytes = File.ReadAllBytes(processLocation); //get byte
                    string fileStrings = Encoding.UTF8.GetString(fileBytes); //decode it
                    foreach (KeyValuePair<string, MalwareTypes> signature in signatures) //search.
                    {
                        if (fileStrings.Contains(signature.Key))
                        {
                            Console.WriteLine(string.Format("Process is malware -> {0}", p.MainModule.FileName));
                            //p.Kill();
                        }
                    }
                }
                catch { }
            }
        }

        private void timer1_Tick(object sender, EventArgs e) //interval = 30 minutes, function = checking running processes for virus code.
        {

        }
    }
}
