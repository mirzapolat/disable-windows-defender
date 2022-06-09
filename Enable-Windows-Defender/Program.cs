using System;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;

namespace Enable_Windows_Defender
{
    class Program
    {
        static void Main()
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;

            CheckDefender();

            RegistryEdit(@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "1"); //Windows 10 1903 Redstone 6
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "0");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "0");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "0");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", "0");
        }

        private static void RegistryEdit(string regPath, string name, string value)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    if (key == null)
                    {
                        Registry.LocalMachine.CreateSubKey(regPath).SetValue(name, value, RegistryValueKind.DWord);
                        return;
                    }
                    if (key.GetValue(name) != (object)value)
                        key.SetValue(name, value, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        private static void CheckDefender()
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "Get-MpPreference -verbose",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                string line = proc.StandardOutput.ReadLine();

                if (line.StartsWith(@"DisableRealtimeMonitoring") && line.EndsWith("True"))
                    RunPS("Set-MpPreference -DisableRealtimeMonitoring $false"); //real-time protection

                //else if (line.StartsWith(@"DisableBehaviorMonitoring") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableBehaviorMonitoring $false"); //behavior monitoring

                //else if (line.StartsWith(@"DisableBlockAtFirstSeen") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableBlockAtFirstSeen $false");

                //else if (line.StartsWith(@"DisableIOAVProtection") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableIOAVProtection $false"); //scans all downloaded files and attachments

                //else if (line.StartsWith(@"DisablePrivacyMode") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisablePrivacyMode $false"); //displaying threat history

                //else if (line.StartsWith(@"SignatureDisableUpdateOnStartupWithoutEngine") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false"); //definition updates on startup

                //else if (line.StartsWith(@"DisableArchiveScanning") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableArchiveScanning $false"); //scan archive files, such as .zip and .cab files

                //else if (line.StartsWith(@"DisableIntrusionPreventionSystem") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableIntrusionPreventionSystem $false"); // network protection 

                //else if (line.StartsWith(@"DisableScriptScanning") && line.EndsWith("False"))
                //    RunPS("Set-MpPreference -DisableScriptScanning $false"); //scanning of scripts during scans
            }
        }

        private static void RunPS(string args)
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            };
            proc.Start();
        }
    }
}
