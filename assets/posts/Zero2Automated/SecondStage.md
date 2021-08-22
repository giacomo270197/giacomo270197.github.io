---
title: Second Stage
permalink: posts/Zero2Automated/SecondStage
permalink_name: SecondStage
---

Starting from we left off [in the previous post](/posts/Zero2Automated/SecondStage), we can now go ahead and analyze the dumped executable.
First of all, we have a look at what PEStudio has to tell us about the executable. Seems like another `C++` executable. `kernel32.dll` is loaded and several functions are imported from it.

<a href="/assets/images/Zero2Automated/ss1.png"><img src="/assets/images/Zero2Automated/ss1.png" margin="0 250px 0" width="100%"/></a>

We can now quickly have a look at the executable on Ghidra before we execute it in a debugger. We can immediately identify the address of the `main()` function. Once again this is going to be useful once we start debugging.

<a href="/assets/images/Zero2Automated/ss2.png"><img src="/assets/images/Zero2Automated/ss2.png" margin="0 250px 0" width="100%"/></a>

We can now start debugging. The first thing the sample does is to get the executable file name, with a call to `GetModuleFileNameA` and a `strtok` loop.

At this point, the encoding routine is called. This routine is used to load `kernel32.dll` procedures dynamically. First of all, the function is called and an initialization step is performed. The initialization stores some data at a memory address. This can be replicated with the following Python script, where the `output` variable represents the memory region the initialization writes to.

```python
output = []
var2 = 0
var3 = 0
cnt  = 0
while cnt < 256:
  var3 = cnt >> 1 ^ 0xedb88320
  if (cnt & 1) == 0:
    var3 = cnt >> 1
  var2 = var3 >> 1 ^ 0xedb88320
  if (var3 & 1) == 0:
    var2 = var3 >> 1
  var3 = var2 >> 1 ^ 0xedb88320
  if (var2 & 1) == 0:
    var3 = var2 >> 1
  var2 = var3 >> 1 ^ 0xedb88320
  if (var3 & 1) == 0:
    var2 = var3 >> 1
  var3 = var2 >> 1 ^ 0xedb88320
  if (var2 & 1) == 0:
    var3 = var2 >> 1
  var2 = var3 >> 1 ^ 0xedb88320
  if (var3 & 1) == 0:
    var2 = var3 >> 1
  var3 = var2 >> 1 ^ 0xedb88320
  if (var2 & 1) == 0:
    var3 = var2 >> 1
  var2 = var3 >> 1 ^ 0xedb88320
  if (var3 & 1) == 0:
    var2 = var3 >> 1
  output.append(var2)
  cnt = cnt + 1
```
Once the initialization is complete, a flag is set so that the function will execute the next step when called again.

After that, a function is called which purpose is to load a specific routine. The function first loads `kernel32.dll`, then iterates over all the procedure names exported by the DLL, and passes them as an argument to the encoding routine.

<a href="/assets/images/Zero2Automated/ss4.png"><img src="/assets/images/Zero2Automated/ss4.png" margin="0 250px 0" width="100%"/></a>

At this point, the encoding routine generates a DWORD using the previously initialized memory and the procedure name as an input. The encoding can be reproduced by the following script, where `output` is the initialized memory, and `string` is the procedure name.

```python
string = "the_procedure_name"
result = 0xffffffff
for x in string:
  result = result >> 8 ^ output[result & 0x000000ff ^ ord(x)]

result = result ^ 0xffffffff # Needed because Python NOT works with signed integers
```

The DWORD returned by the encoding routine is then checked against a hardcoded set of values. If the result matches with one of the values execution jump to a call to `GetProcAddress`, and the procedure is loaded.

<a href="/assets/images/Zero2Automated/ss5.png"><img src="/assets/images/Zero2Automated/ss5.png" margin="0 250px 0" width="100%"/></a>

Instead of decoding the hardcoded strings to check what routines will be loaded, we just set a breakpoint on `GetProcAddress`, and by letting the sample run we realize that `IsDebuggerPresent` is loaded. We then set a breakpoint on it in case we miss a call to it while stepping through execution. That's not necessarily needed, however, since the function is called immediately after we return. `IsDebuggerPresent` is easily bypassed by setting `EAX` to 0 after the function execution.

<a href="/assets/images/Zero2Automated/ss6.png"><img src="/assets/images/Zero2Automated/ss6.png" margin="0 250px 0" width="100%"/></a>

We then step into another function, and immediately we see three calls to the routine responsible for decoding and loading. At this point, we know how the routine works so we just step over it and check the return result to see which procedures are being loaded. It seems the sample loads `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW`. 

<a href="/assets/images/Zero2Automated/ss7.png"><img src="/assets/images/Zero2Automated/ss7.png" margin="0 250px 0" width="100%"/></a>

This could be another anti-debugging technique, so we need to be careful.
Execution goes as expected, `CreateToolhelp32Snapshot` is called, then `Process32FirstW` returns a pointer to the first process, and then a loop starts with `Process32NextW` advancing it. The loop is basically a re-implementation of the encoding routine. The memory is initialized when the first process is analyzed (the first process being `system`). Every other process name is then encoded as previously shown, and checked against some hardcoded values. This is what the check looks like in `x32dbg`.

<a href="/assets/images/Zero2Automated/ss8.png"><img src="/assets/images/Zero2Automated/ss8.png" margin="0 250px 0" width="100%"/></a>

So basically, if any of the process names encodes to one of those strings execution jumps out of the loops and terminates. We could try to figure out which processes would cause this behaviour (`x32dbg.exe` does), however, it's faster to just change the `je` instruction responsible for leading to termination, and just make it jump to the next instruction (`001B11C6`). This way the program will continue no matter which process name is encountered. At this point, we execute until return, and sure enough, we get back in the `main` function. The sample is still running, and we are successful!

Immediately after, a function is called that loads `CreateProcessA`, `WriteProcessMemory`, `ResumeThread`, `VirtualAllocEx`, `VirtualAlloc`, `CreateRemoteThread`.

<a href="/assets/images/Zero2Automated/ss9.png"><img src="/assets/images/Zero2Automated/ss9.png" margin="0 250px 0" width="100%"/></a>

The following snippet then decodes the string `C"\Windows\System32\svchost.exe`, which is passed to `CreateProcessA`.

```
001B1D00 | 8A540D D0                | mov dl,byte ptr ss:[ebp+ecx-30]                                      |
001B1D04 | C0C2 04                  | rol dl,4                                                             |
001B1D07 | 80F2 A2                  | xor dl,A2                                                            |
001B1D0A | 88540D D0                | mov byte ptr ss:[ebp+ecx-30],dl                                      |
001B1D0E | 41                       | inc ecx                                                              |
001B1D0F | 3BC8                     | cmp ecx,eax                                                          |
001B1D11 | 7C ED                    | jl first_dump.1B1D00                                                 |
```

The sample then gets a handle to itself, allocates a region of memory in its own process, and copies itself into it. In the image, you can see that the memory region at `00020000`, which is where `VirtualAlloc` allocated memory, is the same size (`18000`) as all the sections and headers of the current executable, which in this case is called "first_dump.exe".

<a href="/assets/images/Zero2Automated/ss10.png"><img src="/assets/images/Zero2Automated/ss10.png" margin="0 250px 0" width="100%"/></a>

The same size is then allocated with `VirtualAllocEx` on the recently spawned `svchost.exe`, and then `WriteProcessMemory` writes the copy of the executable in the new process, at location `00120000`. Finally, a new thread is created to run from address `00121DC0` in the new executable.
At this point, knowing that the sample copied itself in the new process, we could just compute the right offset and analyze the current executable at the location where we know the target will start at. So, knowing that the binary was copied at address `00120000` and starts at `00121DC0`, we can go to address `001B000` (current image base address) + `00001DC0` (offset the copied executable will start from) = `001B1DC0`, and analyze the content.

<a href="/assets/images/Zero2Automated/ss11.png"><img src="/assets/images/Zero2Automated/ss11.png" margin="0 250px 0" width="100%"/></a>

This looks like it could be shellcode, in any case, it will be much easier to analyze it if we can single-step through it. So we go ahead and open a second debugger instance on the new `svchost.exe` process, check the existing threads, and set a breakpoint on `00121DC0`, since we know that's where execution will start from. Then, on the other instance, we set a breakpoint on `NtResumeThread`, run until we hit it and execute the function until return. On the new debugger instance, we then run the sample until we hit the breakpoint we set on the entrypoint.

We are now ready to analyze the third stage, which will be covered in the next post.