#requires -Version 5.1
function Test-IsElevated {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# every function fall back to "Unknown"
function ConvertTo-SafeValue {
    param([Parameter(ValueFromPipeline = $true)]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return "Unknown"
    }
    return $Value
}

$script:IsAdmin = Test-IsElevated

# get currently signed in user
function Get-AuditCurrentUser {
    try {
        # Win32_ComputerSystem.UserName grabs the interactively logged-on
        # use domain/user with fall back to ENV if CIM call fails
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.UserName) {
            return $cs.UserName
        }
        return "$env:USERDOMAIN\$env:USERNAME" | ConvertTo-SafeValue
    }
    catch {
        try {
            return "$env:USERDOMAIN\$env:USERNAME" | ConvertTo-SafeValue
        }
        catch {
            return "Unknown"
        }
    }
}

# device type (desktop, laptop, virtual machine, server, etc...)
function Get-AuditDeviceType {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        $manufacturer = [string]$cs.Manufacturer
        $model        = [string]$cs.Model

        # look for virutalisation, manufacturer/model string
        $vmSignatures = @(
            'VMware', 'Virtual Machine', 'VirtualBox', 'Xen', 'KVM',
            'QEMU', 'Hyper-V', 'Google Compute Engine', 'Amazon EC2'
        )
        foreach ($sig in $vmSignatures) {
            if ($manufacturer -match [regex]::Escape($sig) -or $model -match [regex]::Escape($sig)) {
                return "Virtual Machine"
            }
        }

        # system type convertor (func data from official microsoft)
        switch ($cs.PCSystemType) {
            1 { return "Desktop" }
            2 { return "Laptop" }
            3 { return "Workstation" }
            4 { return "Server" }
            5 { return "Server" }
            6 { return "Appliance PC" }
            7 { return "Server" }
            8 { return "Tablet" }
            default {
                # fall back to chassis type from Win32_SystemEnclosure
                $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
                $chassisType = $enclosure.ChassisTypes[0]
                $laptopTypes  = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
                $desktopTypes = @(3, 4, 5, 6, 7, 15, 16, 35, 36)
                if ($laptopTypes -contains $chassisType) { return "Laptop" }
                elseif ($desktopTypes -contains $chassisType) { return "Desktop" }
                else { return "Unknown" }
            }
        }
    }
    catch {
        return "Unknown"
    }
}

# Device ID, standards use GUID held in SQMClient (telemetry)
function Get-AuditDeviceId {
    try {
        $sqmPath = 'HKLM:\SOFTWARE\Microsoft\SQMClient'
        if (Test-Path $sqmPath) {
            $machineId = (Get-ItemProperty -Path $sqmPath -Name MachineId -ErrorAction Stop).MachineId
            if ($machineId) {
                # strip {}
                return ($machineId -replace '[{}]', '') | ConvertTo-SafeValue
            }
        }
    }
    catch {
        # fall through to the hardware UUID fallback below
    }

    try {
        # fallback: the SMBIOS hardware UUID, which is unique per device
        # won't match about settings but safe fallback
        $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        return $product.UUID | ConvertTo-SafeValue
    }
    catch {
        return "Unknown"
    }
}

function Get-AuditMakeModel {
    $result = [PSCustomObject]@{
        Manufacturer = "Unknown"
        Model        = "Unknown"
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $result.Manufacturer = $cs.Manufacturer | ConvertTo-SafeValue
        # grabs raw Win32_ComputerSystem.Model as fall back
        # this value is not as useful as GUID due to it being pretty much internal
        $result.Model = $cs.Model | ConvertTo-SafeValue
    }
    catch {

    }

    # junkvalues that OEMs leave in SMBIOS due to incompetency (held as unsafe and unusable)
    $junkValues = @(
        'System Product Name', 'To Be Filled By O.E.M.', 'Default string',
        'Not Applicable', 'None', 'Not Specified', ''
    )

    # prefer consumer name, held in SMBIOS "System Family" or "System Version" fields
    # held in registry or Win32_ComputerSystemProduct.Version
    $candidates = New-Object System.Collections.Generic.List[string]
    try {
        $biosPath = 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS'
        if (Test-Path $biosPath) {
            $bios = Get-ItemProperty -Path $biosPath -ErrorAction Stop
            if ($bios.PSObject.Properties.Name -contains 'SystemFamily') { $candidates.Add([string]$bios.SystemFamily) }
            if ($bios.PSObject.Properties.Name -contains 'SystemVersion') { $candidates.Add([string]$bios.SystemVersion) }
            if ($bios.PSObject.Properties.Name -contains 'SystemProductName') { $candidates.Add([string]$bios.SystemProductName) }
        }
    }
    catch {
        # ignore and use whatever we already got
    }

    try {
        $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        if ($product.Version) { $candidates.Add([string]$product.Version) }
        if ($product.Name)    { $candidates.Add([string]$product.Name) }
    }
    catch {
        # ignore and continue
    }

    foreach ($candidate in $candidates) {
        $trimmed = $candidate.Trim()
        if ($trimmed -and ($junkValues -notcontains $trimmed)) {
            $result.Model = $trimmed
            break
        }
    }

    return $result
}

# firewalls are registered as a FirewallProduct entry, checks actual profile states
# using firewall components returns no boolean for some reason?
function Get-AuditFirewallStatus {
    try {
        # NetSecurity model func, not third party and reflects win profiles
        $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
        if ($profiles | Where-Object { $_.Enabled -eq $true }) {
            return "Windows"
        }
        return "Off"
    }
    catch {
        try {
            # fallback just grab firewall policy from registry
            $paths = @(
                'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile',
                'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile',
                'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
            )
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $val = (Get-ItemProperty -Path $p -Name EnableFirewall -ErrorAction Stop).EnableFirewall
                    if ($val -eq 1) { return "Windows" }
                }
            }
            return "Off"
        }
        catch {
            return "Unknown"
        }
    }
}

# sign in method is difficult, theres no API that returns this
# use enrollment records with its hardware type. check PIN/NGC container presence
# policy checker methods return "Unknown" if fail
#
# This method is VERY heuristic and uses the most commonly used method if unknown manually check
function Get-AuditSignInMethod {
    $methods = New-Object System.Collections.Generic.List[string]

    # check biometric data enrollment
    $biometricEnrolled = $false
    try {
        $winBioPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBioDatabase'
        if (Test-Path $winBioPath) {
            $entries = Get-ChildItem -Path $winBioPath -ErrorAction Stop
            if ($entries.Count -gt 0) {
                $biometricEnrolled = $true
            }
        }
    }
    catch {
        # requries admin leave biometricEntrolled
    }

    if ($biometricEnrolled) {
        # identify hardware present checking labels like "Face" or "Fingerprint" rather than a catch-all
        # BOTH may be present on one device
        try {
            $bioDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
                Where-Object { $_.PNPClass -eq 'Biometric' -or $_.Name -match 'Windows Hello|Fingerprint|IR Camera' }

            $hasFingerprint = $bioDevices | Where-Object { $_.Name -match 'Fingerprint' }
            $hasFaceCamera  = $bioDevices | Where-Object { $_.Name -match 'IR Camera|Infrared|Hello Face' }

            if ($hasFaceCamera) { $methods.Add("Face") }
            if ($hasFingerprint) { $methods.Add("Fingerprint") }
            if (-not $hasFaceCamera -and -not $hasFingerprint) {
                # enrollment confirmed but not a hardware method
                $methods.Add("Windows Hello (Biometric)")
            }
        }
        catch {
            $methods.Add("Windows Hello (Biometric)")
        }
    }

    # windows hellow pin via NGC container
    try {
        $ngcPath = Join-Path $env:WINDIR 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
        if (Test-Path $ngcPath) {
            $ngcEntries = Get-ChildItem -Path $ngcPath -ErrorAction Stop
            if ($ngcEntries.Count -gt 0) {
                $methods.Add("PIN")
            }
        }
    }
    catch {
        # ignore and continue without admin
    }

    # smart card logon??? uses policy rather than reader presence (laptops dont use that for some reason???)
    #
    try {
        $scPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (Test-Path $scPolicyPath) {
            $scOption = Get-ItemProperty -Path $scPolicyPath -Name ScForceOption -ErrorAction SilentlyContinue
            if ($null -ne $scOption -and [int]$scOption.ScForceOption -eq 1) {
                $methods.Add("Smart Card")
            }
        }
    }
    catch {
        # ignore and continue
    }

    if ($methods.Count -gt 0) {
        return ($methods -join ", ")
    }

    # password as universal fallback but we can't confirm it as the ACTIVE method
    # report it when we've detected that it points to it
    if (-not $script:IsAdmin) {
        return "Unknown"
    }
    return "Password"
}

# win edition, version (feature update) and build num
function Get-AuditWindowsInfo {
    $result = [PSCustomObject]@{
        WindowsSystem = "Unknown"
        WindowsVersion = "Unknown"
        WindowsBuild  = "Unknown"
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        # caption doesn't need to say "microsoft windows" prefix just read the edition and branch
        $caption = [string]$os.Caption
        $trimmed = $caption -replace '^Microsoft\s+Windows\s+', ''
        $result.WindowsSystem = $trimmed | ConvertTo-SafeValue
        $result.WindowsBuild  = $os.BuildNumber | ConvertTo-SafeValue
    }
    catch {

    }

    try {
        # DisplayVersion replaces ReleaseId and is held in registry not WMI
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($props.PSObject.Properties.Name -contains 'DisplayVersion') {
            $result.WindowsVersion = $props.DisplayVersion | ConvertTo-SafeValue
        }
        elseif ($props.PSObject.Properties.Name -contains 'ReleaseId') {
            $result.WindowsVersion = $props.ReleaseId | ConvertTo-SafeValue
        }
    }
    catch {
    }

    return $result
}

# autoplay check boolean
function Get-AuditAutoPlaySetting {
    $onOff = "On"
    try {
        # NoDriveTypeAutoRun controls it per drive,
        # 0xFF (255) disables for all, check per user then machine wide
        $paths = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        )
        $found = $false
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $item = Get-ItemProperty -Path $p -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
                if ($null -ne $item) {
                    $found = $true
                    $onOff = if ([int]$item.NoDriveTypeAutoRun -ge 255) { "Off" } else { "On" }
                    break
                }
            }
        }
        if (-not $found) {
            # no policy = autoplay is ON
            $onOff = "On"
        }
    }
    catch {
        return "Unknown"
    }

    # if autoplay check default handler
    if ($onOff -eq "On") {
        try {
            $handlerPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection'
            if (Test-Path $handlerPath) {
                $handler = Get-ItemProperty -Path $handlerPath -Name 'StorageOnArrival' -ErrorAction SilentlyContinue
                if ($null -ne $handler) {
                    switch -Regex ($handler.StorageOnArrival) {
                        'PromptEachTime' { return "On Ask Every Time" }
                        'TakeNoAction'   { return "On Take No Action" }
                        default          { return "On" }
                    }
                }
            }
        }
        catch {
        }
    }

    return $onOff
}

# win automatic updates
function Get-AuditWindowsUpdateSetting {
    try {
        # if policy disables honor it
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (Test-Path $policyPath) {
            $noAuto = Get-ItemProperty -Path $policyPath -Name NoAutoUpdate -ErrorAction SilentlyContinue
            if ($null -ne $noAuto) {
                if ([int]$noAuto.NoAutoUpdate -eq 1) {
                    return "Off"
                }
                else {
                    return "On"
                }
            }
        }

        # infer from win update service start mode
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        if ($svc.StartType -eq 'Disabled') {
            return "Off"
        }
        return "On"
    }
    catch {
        return "Unknown"
    }
}

# antivirus, check defender, third party products, checked through WMI namespace (Security Center)
function Get-AuditAntivirus {
    $result = [PSCustomObject]@{
        AntivirusName    = "Unknown"
        AntivirusVersion = "Unknown"
    }
    try {
        # root/SecurityCenter2 exposes all registered AV without admin rights
        $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' `
                                       -ClassName AntiVirusProduct -ErrorAction Stop
        if ($avProducts) {
            # if multiple prefer the productState bits 12-13
            $active = $avProducts | Where-Object {
                # not officially documented by microsoft...
                # bits 12-13 of productState (as hex) indicate "on". used widely
                ('{0:x6}' -f $_.productState).Substring(2, 2) -in @('10', '11')
            } | Select-Object -First 1

            $chosen = if ($active) { $active } else { $avProducts | Select-Object -First 1 }
            $result.AntivirusName = $chosen.displayName | ConvertTo-SafeValue

            # productState/displayName dont include version number, read from executable if possible
            $exePath = $chosen.pathToSignedProductExe
            if ($exePath) {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($exePath)
                if (Test-Path $expanded) {
                    $result.AntivirusVersion = (Get-Item $expanded).VersionInfo.ProductVersion | ConvertTo-SafeValue
                }
            }

            # defender uses cmdlet for signature version
            if ($result.AntivirusName -match 'Defender' -and $result.AntivirusVersion -eq 'Unknown') {
                try {
                    $mp = Get-MpComputerStatus -ErrorAction Stop
                    $result.AntivirusVersion = $mp.AMProductVersion | ConvertTo-SafeValue
                }
                catch {
                    # Get-MpComputerStatus can be unavailable leave as previous
                }
            }
        }
    }
    catch {
        # root/SecurityCenter2 unavailable on Server SKUs when Center service is not running
        # grab from Defender as a fallback
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $result.AntivirusName    = "Microsoft Defender"
            $result.AntivirusVersion = $mp.AMProductVersion | ConvertTo-SafeValue
        }
        catch {
            # leave "Unknown" defaults
        }
    }
    return $result
}

# browsers detected by installations using "App Paths" registry keys
# windows maintains these paths for each app no individual parsing needed
# produce parallel strings for browsers and their versions
function Get-AuditInstalledBrowsers {
    $result = [PSCustomObject]@{
        BrowserNames    = "Unknown"
        BrowserVersions = "Unknown"
    }

    # map browser executable to friendly display name
    # also order controls output appearance
    $browserMap = [ordered]@{
        'chrome.exe'   = 'Chrome'
        'msedge.exe'   = 'Edge'
        'firefox.exe'  = 'Firefox'
        'opera.exe'    = 'Opera'
        'brave.exe'    = 'Brave'
        'iexplore.exe' = 'Internet Explorer'
    }

    $foundNames    = New-Object System.Collections.Generic.List[string]
    $foundVersions = New-Object System.Collections.Generic.List[string]

    foreach ($exeName in $browserMap.Keys) {
        try {
            # app paths recordsd install location of apps
            # check both native and WOW6432Node (32x/64x)
            $appPathsCandidates = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exeName",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$exeName",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exeName"
            )

            $exePath = $null
            foreach ($candidate in $appPathsCandidates) {
                if (Test-Path $candidate) {
                    $val = (Get-ItemProperty -Path $candidate -ErrorAction Stop).'(default)'
                    if ($val -and (Test-Path $val)) {
                        $exePath = $val
                        break
                    }
                }
            }

            if ($exePath) {
                $friendlyName = $browserMap[$exeName]
                $version = (Get-Item $exePath -ErrorAction Stop).VersionInfo.ProductVersion
                if ([string]::IsNullOrWhiteSpace($version)) { $version = "Unknown" }

                $foundNames.Add($friendlyName)
                $foundVersions.Add("$friendlyName $version")
            }
        }
        catch {
            # browser can't be seen ignore it
        }
    }

    if ($foundNames.Count -gt 0) {
        $result.BrowserNames    = ($foundNames -join ", ")
        # match name version entries separated by / no comma
        $result.BrowserVersions = ($foundVersions -join "/ ")
    }

    return $result
}

# gather all sections and build output
# each Get-Audit* call error handled internally
# bring aggregation step to prevent any issues
try {
    $makeModel   = Get-AuditMakeModel
    $winInfo     = Get-AuditWindowsInfo
    $avInfo      = Get-AuditAntivirus
    $browserInfo = Get-AuditInstalledBrowsers

    $auditResult = [PSCustomObject]@{
        Timestamp               = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        User                    = Get-AuditCurrentUser
        Type                    = Get-AuditDeviceType
        "Device ID"             = Get-AuditDeviceId
        "Computer Make"         = $makeModel.Manufacturer
        Model                   = $makeModel.Model
        Firewall                = Get-AuditFirewallStatus
        "Sign-in Method"        = Get-AuditSignInMethod
        "Windows System"        = $winInfo.WindowsSystem
        "Windows Version"       = $winInfo.WindowsVersion
        "Windows Build Number"  = $winInfo.WindowsBuild
        "AutoPlay Setting"      = Get-AuditAutoPlaySetting
        "Windows Auto Updates"  = Get-AuditWindowsUpdateSetting
        "Antivirus Name"        = $avInfo.AntivirusName
        "Antivirus Version"     = $avInfo.AntivirusVersion
        "Installed Browsers"    = $browserInfo.BrowserNames
        "Browser Versions"      = $browserInfo.BrowserVersions
    }
}
catch {
    Write-Warning "An unexpected error occurred while aggregating audit results: $($_.Exception.Message)"
    # minimal feedback row for output as fallback
    $auditResult = [PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        User      = "Unknown"
        Type      = "Unknown"
    }
}

# display
Write-Host ""
Write-Host "=== PC Audit Results ===" -ForegroundColor Cyan
if (-not $script:IsAdmin) {
    Write-Host "(Running without Administrator privileges - some values may be less complete)" -ForegroundColor Yellow
}
$auditResult | Format-List
