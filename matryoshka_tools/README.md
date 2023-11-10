## Matroyshka tools

This is a collection of Intel Pin tools written to help analyze the Matroyshka loader.  Samples printouts are available in the [examples](/examples/) directory.

Other than **api_log**, these were purpose-built to analyze the current version of the loader binary and will likely need heavy adaptation to be suitable to analyze any future iterations.

This is all experimental demonstration software with no support.  Feel free to fork, copy, modify, redistribute, cut-and-paste pieces you need for other projects -- whatever gets you the most use out of it.

## Building

These tools were test-built using Microsoft Visual Studio 2022 with Intel Pin v3.28, the newest versions available at the time of upload.

Download and extract Intel Pin from:
https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html

Copy the entire **matryoshka_tools** directory into Pin's tools directory (pin\source\tools) and build.sln in x64 Release mode.

## Usage

Usage for individual tools is listed below.  For each of these, make sure *log_file* is writable.  If it can't be opened for writing, an error will be logged to pintool.log and the tool will exit. 
If the tool is dying before it even creates the log file, that's likely the problem.

### api_log

Logs APIs called and their return addresses

```
pin.exe -t api_log.dll [-b exe_base] [-q] [-o log_file] -- target.exe

-b exe_base   Set exe base address for labeling returns into .text
              Typically 0x400000 for x86 or 0x140000000 for x64 disassembly listings
			  Hex addresses must be labeled with 0x

-o log_file   Output file for API call log [default: api_log.txt]

-q            Quiet -- log only calls returning to main exe [default: 0]
              Also suppresses DLL load logging
```

### call_trace

Logs the general nested call structure of the loader.  Can also be used with -a flag to locate which calls provided instructions are part of.

```
pin.exe -t call_trace.dll [-c] [-d c1,c2,...] [-a addr1,addr2,...] [-w c1,c2,...] [-o log_file] -- target.exe

-c                 Use canonical names for recursive calls (eg. MATRYKA_1)

-d c1,c2,...       Log detailed instruction listing for given calls
                   Specified by ecx values (-d 1a,2,...)

-a addr1,addr2,... Locate which calls the given addresses execute within
                   The usual call trace printout is suppressed with this option for readability

-o log_file        Output file for API call log [default: call_trace.txt]
```

### loop_writes

Logs write operations made from within the first primary loop seen in the call trace and displays the destinations grouped together.
This was used to figure out what it's producing and which instructions are responsible.

```
pin.exe -t loop_writes.dll [-o log_file] -- target.exe

-o log_file        Output file for API call log [default: loop_writes.txt]
```

### proc_strings

Examines string writes found while using **loop_writes** in more detail.

```
pin.exe -t proc_strings.dll [-o log_file] -- target.exe

-o log_file        Output file for API call log [default: proc_strings.txt]
```

