---
Title: SeDebugPrivilege
permalink: posts/SeDebugPrivilege
permalink_name: SeDebugPrivilege
---

In the previous posts about [DLL injection](/posts/DLLInjection) and [direct injection](/posts/DirectInjection) I did not talk about how and why to get `SeDebugPrivilege` for your attacker process. Mainly, I felt like this is enough information for a whole post.

`SeDebugPrivilege` is an access right originally designed to allow trusted processes to debug arbitrary memory locations. It is only granted if requested by a high-integrity process and allows to write to remote memory. It is not enabled by default when running a high-integrity process, it has to be specifically enabled. I personally found it hard to understand exactly when `SeDebugPrivilege` is granted, and when it is actually needed to write to remote process memory.

The main issue is that official and unofficial documentation often talks about the access right being granted to "Administrators" only, and is needed to write to remote process memory.
Neither of these statements is 100% correct, so I carried out some tests checking exactly when `SeDebugPrivilege` is needed and who can actually get it.
It turns out that being an Administrator is not enough. You also need to be running a high-integrity process to be able to get this right. Maybe this is nitpicking, but for someone that comes from mainly a Linux background, this feels like something that should be mentioned.
Also, you really don't need it if you want to inject into a process you already own, regardless of whether your user is an admin or not.
So, when DO you need `SeDebugPrivilege`?
 - When you want to write to a higher integrity process, even if owned by the same user
 - When you want to write to a SYSTEM process
 - When you want to write to a process owned by another user, even if running with lower integrity
 
For all other scenarios, you can write to memory without needing any special privilege.

Alright now let's get into how you actually request it.

First of all, we need to get a handle to the access token of the current process, which is what we need to modify to get different privileges. This can be easily done with `GetCurrentProcess` followed by `OpenProcessToken`.

```go
// Get current process (the one I wanna change)
handle, err := windows.GetCurrentProcess()
defer windows.CloseHandle(handle)
if err != nil {
	log.Fatal(err)
}

// Get the current process token
var token windows.Token
err = windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES, &token)
if err != nil {
	log.Fatal(err)
}
```

Next, we want to check what the LUID for `SeDebugPrivilege` is on our system. This can be done with `LookupPrivilegeValue`

```go
// Check the LUID
var luid windows.LUID
seDebugName, err := windows.UTF16FromString("SeDebugPrivilege")
if err != nil {
	fmt.Println(err)
}
err = windows.LookupPrivilegeValue(nil, &seDebugName[0], &luid)
if err != nil {
	log.Fatal(err)
}
```

Now we are ready to use `AdjustTokenPrivileges` to change the privileges of our process. The function takes a `TOKEN_PRIVILEGES` instance as an argument, so we will need to create one where we specify we are only modifying one privilege (`PrivilegeCount` = 1) and that privilege is `SeDebugPrivilege` which will be enabled. This can be done by adding a single entry to the arrays of `LUID_AND_ATTRIBUTES` with the `LUID` we retrieved earlier and the self-explanatory attribute `SE_PRIVILEGE_ENABLED`.

```go
// Modify the token
var tokenPriviledges windows.Tokenprivileges
tokenPriviledges.PrivilegeCount = 1
tokenPriviledges.Privileges[0].Luid = luid
tokenPriviledges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

// Adjust token privs
tokPrivLen := uint32(unsafe.Sizeof(tokenPriviledges))
fmt.Printf("Length is %d\n", tokPrivLen)
err = windows.AdjustTokenPrivileges(token, false, &tokenPriviledges, tokPrivLen, nil, nil)
if err != nil {
	log.Fatal(err)
}
fmt.Println("[+] Debug Priviledge granted")
```

If all went well, you should now have the access right you need. You can confirm that by checking that in "Process Explorer -> ${your_process} -> Properties -> Security" `SeDebugPrivilege` shows as being enabled.
 
