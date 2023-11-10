## Example tool results

### api_log

```
pin.exe -t api_log.dll -b 0x140000000 -o api_log0.txt -- Matryoshka.exe
pin.exe -t api_log.dll -b 0x140000000 -q -o api_log1.txt -- Matryoshka.exe
```

### call_trace

```
pin.exe -t call_trace.dll -o call_trace0.txt -- Matryoshka.exe
pin.exe -t call_trace.dll -c -d 5,a -o call_trace1.txt -- Matryoshka.exe
pin.exe -t call_trace.dll -c -a 140001171,1400011FC,140001CA6 -o call_trace2.txt -- Matryoshka.exe
```

### loop_writes

```
pin.exe -t loop_writes.dll -o loop_writes.txt -- Matryoshka.exe
```

### proc_strings

```
pin.exe -t proc_strings.dll -o proc_strings.txt -- Matryoshka.exe
```
