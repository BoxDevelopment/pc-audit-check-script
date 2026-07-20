using System.Management;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PCAudit
{
    internal static class Program
    {
        private static bool IsAdmin;

        private static void Main()
        {
            IsAdmin = TestIsElevated();

            var results = new List<(string Label, string Value)>();

            try
            {
                var makeModel = GetAuditMakeModel();
                var winInfo = GetAuditWindowsInfo();
                var avInfo = GetAuditAntivirus();
                var browserInfo = GetAuditInstalledBrowsers();

                results.Add(("Timestamp", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")));
                results.Add(("User", GetAuditCurrentUser()));
                results.Add(("Type", GetAuditDeviceType()));
                results.Add(("Device ID", GetAuditDeviceId()));
                results.Add(("Computer Make", makeModel.Manufacturer));
                results.Add(("Model", makeModel.Model));
                results.Add(("Firewall", GetAuditFirewallStatus()));
                results.Add(("Sign-in Method", GetAuditSignInMethod()));
                results.Add(("Windows System", winInfo.WindowsSystem));
                results.Add(("Windows Version", winInfo.WindowsVersion));
                results.Add(("Windows Build Number", winInfo.WindowsBuild));
                results.Add(("AutoPlay Setting", GetAuditAutoPlaySetting()));
                results.Add(("Windows Auto Updates", GetAuditWindowsUpdateSetting()));
                results.Add(("Antivirus Name", avInfo.AntivirusName));
                results.Add(("Antivirus Version", avInfo.AntivirusVersion));
                results.Add(("Installed Browsers", browserInfo.BrowserNames));
                results.Add(("Browser Versions", browserInfo.BrowserVersions));
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"An unexpected error occurred while aggregating audit results: {ex.Message}");
                Console.ResetColor();

                results.Clear();
                results.Add(("Timestamp", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")));
                results.Add(("User", "Unknown"));
                results.Add(("Type", "Unknown"));
            }

            string rendered = RenderFormatList(results);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=== PC Audit Results ===");
            Console.ResetColor();
            if (!IsAdmin)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("(Running without Administrator privileges - some values may be less complete)");
                Console.ResetColor();
            }
            Console.WriteLine();
            Console.Write(rendered);

            string outputPath = Path.Combine(AppContext.BaseDirectory, "PC_AUDIT.txt");
            try
            {
                File.WriteAllText(outputPath, rendered);
                Console.WriteLine();
                Console.WriteLine($"Saved to: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine($"Failed to write PC_AUDIT.txt: {ex.Message}");
            }
        }


        // mimic format label : value
        private static string RenderFormatList(List<(string Label, string Value)> items)
        {
            if (items.Count == 0) return string.Empty;
            int width = items.Max(i => i.Label.Length);
            var sb = new System.Text.StringBuilder();
            foreach (var (label, value) in items)
            {
                sb.AppendLine($"{label.PadRight(width)} : {value}");
            }
            sb.AppendLine();
            return sb.ToString();
        }

        // ---------- helpers ----------

        private static string SafeValue(object? value)
        {
            if (value is null) return "Unknown";
            string s = value.ToString() ?? string.Empty;
            return string.IsNullOrWhiteSpace(s) ? "Unknown" : s;
        }

        private static bool TestIsElevated()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static ManagementObject? QueryFirst(string wmiClass, string? scope = null)
        {
            try
            {
                var searcher = scope is null
                    ? new ManagementObjectSearcher($"SELECT * FROM {wmiClass}")
                    : new ManagementObjectSearcher(scope, $"SELECT * FROM {wmiClass}");
                foreach (ManagementObject mo in searcher.Get())
                {
                    return mo;
                }
            }
            catch
            {
                // fall through
            }
            return null;
        }

        private static List<ManagementObject> QueryAll(string wmiClass, string? scope = null)
        {
            var list = new List<ManagementObject>();
            try
            {
                var searcher = scope is null
                    ? new ManagementObjectSearcher($"SELECT * FROM {wmiClass}")
                    : new ManagementObjectSearcher(scope, $"SELECT * FROM {wmiClass}");
                foreach (ManagementObject mo in searcher.Get())
                {
                    list.Add(mo);
                }
            }
            catch
            {
                // return whatever we have (likely empty)
            }
            return list;
        }

        // ---------- current user ----------

        private static string GetAuditCurrentUser()
        {
            try
            {
                var cs = QueryFirst("Win32_ComputerSystem");
                var userName = cs?["UserName"] as string;
                if (!string.IsNullOrEmpty(userName))
                {
                    return userName;
                }
                return SafeValue($"{Environment.UserDomainName}\\{Environment.UserName}");
            }
            catch
            {
                try
                {
                    return SafeValue($"{Environment.UserDomainName}\\{Environment.UserName}");
                }
                catch
                {
                    return "Unknown";
                }
            }
        }

        // ---------- device type ----------

        private static string GetAuditDeviceType()
        {
            try
            {
                var cs = QueryFirst("Win32_ComputerSystem");
                if (cs is null) return "Unknown";

                string manufacturer = cs["Manufacturer"] as string ?? string.Empty;
                string model = cs["Model"] as string ?? string.Empty;

                string[] vmSignatures =
                {
                    "VMware", "Virtual Machine", "VirtualBox", "Xen", "KVM",
                    "QEMU", "Hyper-V", "Google Compute Engine", "Amazon EC2"
                };

                foreach (var sig in vmSignatures)
                {
                    if (Regex.IsMatch(manufacturer, Regex.Escape(sig)) || Regex.IsMatch(model, Regex.Escape(sig)))
                    {
                        return "Virtual Machine";
                    }
                }

                int pcSystemType = Convert.ToInt32(cs["PCSystemType"] ?? 0);
                switch (pcSystemType)
                {
                    case 1: return "Desktop";
                    case 2: return "Laptop";
                    case 3: return "Workstation";
                    case 4: return "Server";
                    case 5: return "Server";
                    case 6: return "Appliance PC";
                    case 7: return "Server";
                    case 8: return "Tablet";
                    default:
                        var enclosure = QueryFirst("Win32_SystemEnclosure");
                        if (enclosure is null) return "Unknown";
                        var chassisTypes = enclosure["ChassisTypes"] as ushort[];
                        if (chassisTypes is null || chassisTypes.Length == 0) return "Unknown";
                        int chassisType = chassisTypes[0];

                        int[] laptopTypes = { 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 };
                        int[] desktopTypes = { 3, 4, 5, 6, 7, 15, 16, 35, 36 };

                        if (laptopTypes.Contains(chassisType)) return "Laptop";
                        if (desktopTypes.Contains(chassisType)) return "Desktop";
                        return "Unknown";
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        // ---------- device id ----------

        private static string GetAuditDeviceId()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\SQMClient");
                var machineId = key?.GetValue("MachineId") as string;
                if (!string.IsNullOrEmpty(machineId))
                {
                    return SafeValue(machineId.Replace("{", string.Empty).Replace("}", string.Empty));
                }
            }
            catch
            {
                // fall through to hardware UUID fallback
            }

            try
            {
                var product = QueryFirst("Win32_ComputerSystemProduct");
                return SafeValue(product?["UUID"]);
            }
            catch
            {
                return "Unknown";
            }
        }

        // ---------- make / model ----------

        private sealed class MakeModelResult
        {
            public string Manufacturer = "Unknown";
            public string Model = "Unknown";
        }

        private static MakeModelResult GetAuditMakeModel()
        {
            var result = new MakeModelResult();

            try
            {
                var cs = QueryFirst("Win32_ComputerSystem");
                result.Manufacturer = SafeValue(cs?["Manufacturer"]);
                result.Model = SafeValue(cs?["Model"]);
            }
            catch
            {
                // keep defaults
            }

            string[] junkValues =
            {
                "System Product Name", "To Be Filled By O.E.M.", "Default string",
                "Not Applicable", "None", "Not Specified", ""
            };

            var candidates = new List<string>();

            try
            {
                using var biosKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
                if (biosKey is not null)
                {
                    if (biosKey.GetValue("SystemFamily") is string sf) candidates.Add(sf);
                    if (biosKey.GetValue("SystemVersion") is string sv) candidates.Add(sv);
                    if (biosKey.GetValue("SystemProductName") is string sp) candidates.Add(sp);
                }
            }
            catch
            {
                // ignore and use whatever we already got
            }

            try
            {
                var product = QueryFirst("Win32_ComputerSystemProduct");
                if (product?["Version"] is string ver && !string.IsNullOrEmpty(ver)) candidates.Add(ver);
                if (product?["Name"] is string name && !string.IsNullOrEmpty(name)) candidates.Add(name);
            }
            catch
            {
                // ignore and continue
            }

            foreach (var candidate in candidates)
            {
                string trimmed = candidate.Trim();
                if (trimmed.Length > 0 && !junkValues.Contains(trimmed))
                {
                    result.Model = trimmed;
                    break;
                }
            }

            return result;
        }

        // ---------- firewall ----------

        private static string GetAuditFirewallStatus()
        {
            try
            {
                var profiles = QueryAll("MSFT_NetFirewallProfile", @"root\StandardCimv2");
                if (profiles.Count > 0)
                {
                    bool anyEnabled = profiles.Any(p =>
                    {
                        var val = p["Enabled"];
                        return val is not null && Convert.ToInt32(val) == 1;
                    });
                    return anyEnabled ? "Windows" : "Off";
                }
                throw new InvalidOperationException("No firewall profiles returned");
            }
            catch
            {
                try
                {
                    string[] paths =
                    {
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
                    };
                    foreach (var p in paths)
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(p);
                        var val = key?.GetValue("EnableFirewall");
                        if (val is not null && Convert.ToInt32(val) == 1)
                        {
                            return "Windows";
                        }
                    }
                    return "Off";
                }
                catch
                {
                    return "Unknown";
                }
            }
        }

        // ---------- sign-in method ----------

        private static string GetAuditSignInMethod()
        {
            var methods = new List<string>();

            bool biometricEnrolled = false;
            try
            {
                using var winBioKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBioDatabase");
                if (winBioKey is not null && winBioKey.GetSubKeyNames().Length > 0)
                {
                    biometricEnrolled = true;
                }
            }
            catch
            {
                // requires admin, leave biometricEnrolled false
            }

            if (biometricEnrolled)
            {
                try
                {
                    var bioDevices = QueryAll("Win32_PnPEntity")
                        .Where(d =>
                        {
                            string pnpClass = d["PNPClass"] as string ?? string.Empty;
                            string name = d["Name"] as string ?? string.Empty;
                            return pnpClass == "Biometric" || Regex.IsMatch(name, "Windows Hello|Fingerprint|IR Camera");
                        })
                        .ToList();

                    bool hasFingerprint = bioDevices.Any(d => Regex.IsMatch(d["Name"] as string ?? string.Empty, "Fingerprint"));
                    bool hasFaceCamera = bioDevices.Any(d => Regex.IsMatch(d["Name"] as string ?? string.Empty, "IR Camera|Infrared|Hello Face"));

                    if (hasFaceCamera) methods.Add("Face");
                    if (hasFingerprint) methods.Add("Fingerprint");
                    if (!hasFaceCamera && !hasFingerprint)
                    {
                        methods.Add("Windows Hello (Biometric)");
                    }
                }
                catch
                {
                    methods.Add("Windows Hello (Biometric)");
                }
            }

            try
            {
                string ngcPath = Path.Combine(
                    Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows",
                    @"ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc");
                if (Directory.Exists(ngcPath) && Directory.GetFileSystemEntries(ngcPath).Length > 0)
                {
                    methods.Add("PIN");
                }
            }
            catch
            {
                // ignore and continue without admin
            }

            try
            {
                using var scKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                var scOption = scKey?.GetValue("ScForceOption");
                if (scOption is not null && Convert.ToInt32(scOption) == 1)
                {
                    methods.Add("Smart Card");
                }
            }
            catch
            {
                // ignore and continue
            }

            if (methods.Count > 0)
            {
                return string.Join(", ", methods);
            }

            if (!IsAdmin)
            {
                return "Unknown";
            }
            return "Password";
        }

        // ---------- windows info ----------

        private sealed class WindowsInfoResult
        {
            public string WindowsSystem = "Unknown";
            public string WindowsVersion = "Unknown";
            public string WindowsBuild = "Unknown";
        }

        private static WindowsInfoResult GetAuditWindowsInfo()
        {
            var result = new WindowsInfoResult();

            try
            {
                var os = QueryFirst("Win32_OperatingSystem");
                string caption = os?["Caption"] as string ?? string.Empty;
                string trimmed = Regex.Replace(caption, @"^Microsoft\s+Windows\s+", string.Empty);
                result.WindowsSystem = SafeValue(trimmed);
                result.WindowsBuild = SafeValue(os?["BuildNumber"]);
            }
            catch
            {
                // keep defaults
            }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key?.GetValue("DisplayVersion") is string dv)
                {
                    result.WindowsVersion = SafeValue(dv);
                }
                else if (key?.GetValue("ReleaseId") is string rid)
                {
                    result.WindowsVersion = SafeValue(rid);
                }
            }
            catch
            {
                // keep defaults
            }

            return result;
        }

        // ---------- autoplay ----------

        private static string GetAuditAutoPlaySetting()
        {
            string onOff = "On";
            try
            {
                string[] paths =
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", // HKCU
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"  // HKLM
                };

                bool found = false;

                using (var hkcu = Registry.CurrentUser.OpenSubKey(paths[0]))
                {
                    var val = hkcu?.GetValue("NoDriveTypeAutoRun");
                    if (val is not null)
                    {
                        found = true;
                        onOff = Convert.ToInt32(val) >= 255 ? "Off" : "On";
                    }
                }

                if (!found)
                {
                    using var hklm = Registry.LocalMachine.OpenSubKey(paths[1]);
                    var val = hklm?.GetValue("NoDriveTypeAutoRun");
                    if (val is not null)
                    {
                        found = true;
                        onOff = Convert.ToInt32(val) >= 255 ? "Off" : "On";
                    }
                }

                if (!found)
                {
                    onOff = "On";
                }
            }
            catch
            {
                return "Unknown";
            }

            if (onOff == "On")
            {
                try
                {
                    string? handlerValue = null;
                    using var handlerKey = Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection");
                    if (handlerKey?.GetValue("StorageOnArrival") is string sv)
                    {
                        handlerValue = sv;
                    }

                    if (string.IsNullOrWhiteSpace(handlerValue))
                    {
                        return "On Ask Every Time";
                    }

                    if (Regex.IsMatch(handlerValue, "PromptEachTime")) return "On Ask Every Time";
                    if (Regex.IsMatch(handlerValue, "TakeNoAction")) return "On Take No Action";
                    return "On";
                }
                catch
                {
                    return "On Ask Every Time";
                }
            }

            return onOff;
        }

        // ---------- windows update ----------

        private static string GetAuditWindowsUpdateSetting()
        {
            try
            {
                using var policyKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
                var noAuto = policyKey?.GetValue("NoAutoUpdate");
                if (noAuto is not null)
                {
                    return Convert.ToInt32(noAuto) == 1 ? "Off" : "On";
                }

                using var svc = new ServiceController("wuauserv");
                return svc.StartType == ServiceStartMode.Disabled ? "Off" : "On";
            }
            catch
            {
                return "Unknown";
            }
        }

        // ---------- antivirus ----------

        private sealed class AntivirusResult
        {
            public string AntivirusName = "Unknown";
            public string AntivirusVersion = "Unknown";
        }

        private static AntivirusResult GetAuditAntivirus()
        {
            var result = new AntivirusResult();

            try
            {
                var avProducts = QueryAll("AntiVirusProduct", @"root\SecurityCenter2");
                if (avProducts.Count == 0) throw new InvalidOperationException("No AV products returned");

                ManagementObject? active = avProducts.FirstOrDefault(p =>
                {
                    uint productState = Convert.ToUInt32(p["productState"] ?? 0);
                    string hex = productState.ToString("x6");
                    string bits1213 = hex.Length >= 4 ? hex.Substring(2, 2) : string.Empty;
                    return bits1213 is "10" or "11";
                });

                var chosen = active ?? avProducts.First();
                result.AntivirusName = SafeValue(chosen["displayName"]);

                var exePath = chosen["pathToSignedProductExe"] as string;
                if (!string.IsNullOrEmpty(exePath))
                {
                    string expanded = Environment.ExpandEnvironmentVariables(exePath);
                    if (File.Exists(expanded))
                    {
                        result.AntivirusVersion = SafeValue(
                            System.Diagnostics.FileVersionInfo.GetVersionInfo(expanded).ProductVersion);
                    }
                }

                if (result.AntivirusName.Contains("Defender", StringComparison.OrdinalIgnoreCase)
                    && result.AntivirusVersion == "Unknown")
                {
                    TryGetDefenderVersion(result);
                }
            }
            catch
            {
                try
                {
                    result.AntivirusName = "Microsoft Defender";
                    TryGetDefenderVersion(result);
                }
                catch
                {
                    // leave "Unknown" defaults
                }
            }

            return result;
        }

        private static void TryGetDefenderVersion(AntivirusResult result)
        {
            try
            {
                var mp = QueryFirst("MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender");
                result.AntivirusVersion = SafeValue(mp?["AMProductVersion"]);
            }
            catch
            {
                // Defender WMI class can be unavailable; leave as-is
            }
        }

        // ---------- browsers ----------

        private sealed class BrowserResult
        {
            public string BrowserNames = "Unknown";
            public string BrowserVersions = "Unknown";
        }

        private static BrowserResult GetAuditInstalledBrowsers()
        {
            var result = new BrowserResult();

            // ordered: exe name -> friendly name
            var browserMap = new (string Exe, string Friendly)[]
            {
                ("chrome.exe", "Chrome"),
                ("msedge.exe", "Edge"),
                ("firefox.exe", "Firefox"),
                ("opera.exe", "Opera"),
                ("brave.exe", "Brave"),
                ("iexplore.exe", "Internet Explorer"),
            };

            var foundNames = new List<string>();
            var foundVersions = new List<string>();

            foreach (var (exeName, friendlyName) in browserMap)
            {
                try
                {
                    string?[] appPathsCandidates =
                    {
                        ReadAppPathDefault(Registry.LocalMachine, $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exeName}"),
                        ReadAppPathDefault(Registry.LocalMachine, $@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{exeName}"),
                        ReadAppPathDefault(Registry.CurrentUser, $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exeName}"),
                    };

                    string? exePath = appPathsCandidates.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));

                    if (!string.IsNullOrEmpty(exePath))
                    {
                        string version = System.Diagnostics.FileVersionInfo.GetVersionInfo(exePath).ProductVersion ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(version)) version = "Unknown";

                        foundNames.Add(friendlyName);
                        foundVersions.Add($"{friendlyName} {version}");
                    }
                }
                catch
                {
                    // browser can't be seen, ignore it
                }
            }

            if (foundNames.Count > 0)
            {
                result.BrowserNames = string.Join(", ", foundNames);
                result.BrowserVersions = string.Join("/ ", foundVersions);
            }

            return result;
        }

        private static string? ReadAppPathDefault(RegistryKey hive, string subKeyPath)
        {
            try
            {
                using var key = hive.OpenSubKey(subKeyPath);
                return key?.GetValue(string.Empty) as string;
            }
            catch
            {
                return null;
            }
        }
    }
}
