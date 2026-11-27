$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$clock = [Diagnostics.Stopwatch]::StartNew()
$recordTiming = $env:FLUTTER_VLESS_WINTUN_STAGE_TIMING -eq '1'
$timings = [ordered]@{}
function Record-Timing($name, $start) {
    if ($recordTiming) { $timings[$name] = $clock.ElapsedMilliseconds - $start }
}

function Write-Result($status) {
    [Console]::WriteLine($status)
    if ($recordTiming) {
        $timings['script'] = $clock.ElapsedMilliseconds
        [Console]::WriteLine(($timings | ConvertTo-Json -Compress))
    }
}

function Get-WintunPackages {
    Dism\Get-WindowsDriver -Online | Where-Object {
        [IO.Path]::GetFileName($_.OriginalFileName) -ieq 'wintun.inf'
    }
}

function Test-PinnedPackage($packages) {
    # The official 0.14.1 DLL carries the 0.14.0.0 kernel driver package.
    return [bool]($packages | Where-Object {
        $_.ProviderName -ieq 'WireGuard LLC' -and [string]$_.Version -eq '0.14.0.0'
    })
}

function Get-WintunState($phase) {
    $start = $clock.ElapsedMilliseconds
    $devices = @(PnpDevice\Get-PnpDevice -Class Net -PresentOnly)
    $hasSetupAdapter = ($devices | Where-Object FriendlyName -match '^FlutterVlessSetup-[0-9a-f]{32} Tunnel$') -or
        (NetAdapter\Get-NetAdapter -IncludeHidden | Where-Object Name -match '^FlutterVlessSetup-[0-9a-f]{32}$')
    Record-Timing "${phase}_devices" $start
    if ($hasSetupAdapter) { return 'blocked' }
    $start = $clock.ElapsedMilliseconds
    $packages = @(Get-WintunPackages)
    Record-Timing "${phase}_driver_store" $start
    if (Test-PinnedPackage $packages) { return 'present' }
    if ($packages.Count -ne 0) { return 'blocked' }

    # Check device identities even if their original package is no longer in the store.
    foreach ($device in $devices) {
        if ($device.InstanceId -match '^(SWD|ROOT)\\WINTUN\\' -or
            $device.FriendlyName -match '\bWintun\b') {
            return 'blocked'
        }
        if ($device.InstanceId -match '^ROOT\\NET\\') {
            $ids = PnpDevice\Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_HardwareIds
            if ($ids.Data -icontains 'Wintun') { return 'blocked' }
        }
    }
    return 'absent'
}

function Copy-VerifiedWintun($source, $destination) {
    if ($source -notmatch '^[A-Za-z]:\\[^:]+$') { throw 'Invalid Wintun source' }
    $inputFile = [IO.File]::OpenRead($source)
    try {
        if ($inputFile.Length -ne 427552) { throw 'Unexpected Wintun length' }
        $outputFile = [IO.File]::Open($destination, [IO.FileMode]::CreateNew)
        try { $inputFile.CopyTo($outputFile) }
        finally { $outputFile.Dispose() }
    }
    finally { $inputFile.Dispose() }

    $hash = [Security.Cryptography.SHA256]::Create()
    $dllFile = [IO.File]::OpenRead($destination)
    try {
        $digest = [BitConverter]::ToString($hash.ComputeHash($dllFile)).Replace('-', '')
        if ($digest -ine 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') {
            throw 'Unexpected Wintun digest'
        }
    }
    finally {
        $dllFile.Dispose()
        $hash.Dispose()
    }
}

$failure = 'failed_inventory'
try {
    $start = $clock.ElapsedMilliseconds
    $action = $env:FLUTTER_VLESS_WINTUN_STAGE_ACTION
    if ($action -cnotin @('inspect', 'stage')) { throw 'Unknown operation' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        [Console]::WriteLine('elevation_required')
        exit 1
    }
    $moduleDirectory = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\Modules'
    foreach ($module in 'Dism', 'PnpDevice', 'NetAdapter') {
        Import-Module (Join-Path $moduleDirectory "$module\$module.psd1")
    }
    Record-Timing 'initialization' $start

    $status = Get-WintunState 'initial'
    if ($action -eq 'inspect' -or $status -ne 'absent') {
        Write-Result $status
        if ($status -eq 'blocked') { exit 1 }
        exit 0
    }

    $start = $clock.ElapsedMilliseconds
    $failure = 'failed_scratch'
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $name = 'FlutterVlessSetup-' + [guid]::NewGuid().ToString('N')
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $privateDirectory = Join-Path (Join-Path $windowsDirectory 'Temp') $name
    [void][IO.Directory]::CreateDirectory($privateDirectory, $acl)
    try {
        $env:TEMP = $privateDirectory
        $env:TMP = $privateDirectory
        $dll = Join-Path $privateDirectory 'wintun.dll'
        $failure = 'failed_verify'
        Copy-VerifiedWintun $env:FLUTTER_VLESS_WINTUN_STAGE_DLL $dll
        Record-Timing 'private_copy' $start
        $start = $clock.ElapsedMilliseconds
        $helper = Join-Path $privateDirectory 'stage-wintun.exe'
        # Wintun can queue orphan cleanup from CloseAdapter. The child keeps the
        # DLL loaded until process exit, then this parent removes the staging files.
        $source = @'
using System;
using System.Runtime.InteropServices;

public static class FlutterVlessWintunSetup {
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string exportName);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate IntPtr CreateAdapter(string name, string type, IntPtr guid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void CloseAdapter(IntPtr adapter);

    public static int Main(string[] args) {
        const uint LoadLibrarySearchSystem32 = 0x800;
        try {
            IntPtr module = LoadLibraryExW(args[0], IntPtr.Zero, LoadLibrarySearchSystem32);
            if (module == IntPtr.Zero) return 1;
            IntPtr createAddress = GetProcAddress(module, "WintunCreateAdapter");
            IntPtr closeAddress = GetProcAddress(module, "WintunCloseAdapter");
            if (createAddress == IntPtr.Zero || closeAddress == IntPtr.Zero) return 1;
            var create = (CreateAdapter) Marshal.GetDelegateForFunctionPointer(createAddress, typeof(CreateAdapter));
            var close = (CloseAdapter) Marshal.GetDelegateForFunctionPointer(closeAddress, typeof(CloseAdapter));
            IntPtr adapter = create(args[1], args[1], IntPtr.Zero);
            if (adapter == IntPtr.Zero) return 1;
            close(adapter);
            return 0;
        } catch {
            return 1;
        }
    }
}
'@
        $failure = 'failed_probe'
        $sourceFile = Join-Path $privateDirectory 'stage-wintun.cs'
        [IO.File]::WriteAllText($sourceFile, $source)
        $compiler = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
        & $compiler '/nologo' '/target:exe' '/platform:x64' "/out:$helper" $sourceFile *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Wintun probe compilation failed' }
        Record-Timing 'compile_probe' $start

        # Loading Wintun can itself clean up legacy devices. Recheck before loading it.
        $failure = 'failed_inventory'
        $status = Get-WintunState 'preflight'
        if ($status -eq 'absent') {
            $failure = 'failed_probe'
            $start = $clock.ElapsedMilliseconds
            & $helper $dll $name
            if ($LASTEXITCODE -ne 0) { throw 'Wintun adapter creation failed' }
            Record-Timing 'native_probe' $start
            $failure = 'failed_verify'
            $deadline = [Diagnostics.Stopwatch]::StartNew()
            $start = $clock.ElapsedMilliseconds
            do {
                $adapter = (NetAdapter\Get-NetAdapter -IncludeHidden | Where-Object Name -eq $name) -or
                    (PnpDevice\Get-PnpDevice -Class Net -PresentOnly | Where-Object FriendlyName -eq "$name Tunnel")
                if (!$adapter) { break }
                Start-Sleep -Milliseconds 100
            } while ($deadline.Elapsed.TotalSeconds -lt 5)
            Record-Timing 'verify_devices' $start
            $start = $clock.ElapsedMilliseconds
            if ($adapter -or !(Test-PinnedPackage @(Get-WintunPackages))) {
                throw 'Wintun setup verification failed'
            }
            Record-Timing 'verify_driver_store' $start
            $status = 'staged'
        }
        $failure = 'failed_scratch'
    }
    finally {
        $start = $clock.ElapsedMilliseconds
        [IO.Directory]::Delete($privateDirectory, $true)
        Record-Timing 'cleanup' $start
    }
    Write-Result $status
    if ($status -eq 'blocked') { exit 1 }
}
catch {
    [Console]::WriteLine($failure)
    exit 1
}
