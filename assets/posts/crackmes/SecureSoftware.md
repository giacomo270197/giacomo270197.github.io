---
title: SecureSoftware
permalink: posts/crackmes/SecureSoftware
permalink_name: SecureSoftware
---

I decided to do [this crackme](https://crackmes.one/crackme/60276fb033c5d42c3d016a46) because I wanted to try something that I couldn't easily find an answer to by running the executable in a debugger.
According to the author and to the comment sections, this challenge had some sort of anti-debugging measures implemented, so I decided I would try to solve the whole challenge by just using a disassembler (Ghidra, of course).

Ther is a README to this challenge, long story short, the executable pretends to be a commercial software that needs a key to be unlocked. In order to get the key, we need to "get in touch with the vendor". Of course, we really need to crack it.

If we run the executable, we are met with the following

<img src="/assets/images/crackmes/ss1.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

We are not authorized. Let's load the executable in a Ghidra project. We get no `main` so we go and find `WinMain` from the `entry` function

<img src="/assets/images/crackmes/ss2.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

This leads us to `WinMain`. We copy the signature from Microsoft docs and we are met with the following decompiled function.

```c
int __cdecl WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)

{
  HINSTANCE pHVar1;
  HINSTANCE pHVar2;
  LPCSTR lpDst;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  bool bVar6;
  bool bVar7;
  int local_24 [3];
  HINSTANCE *local_18;
  
  pHVar2 = hPrevInstance;
  pHVar1 = hInstance;
  local_18 = &hInstance;
  FUN_00401ca0();
  lpDst = (LPCSTR)malloc(0xff);
  ExpandEnvironmentStringsA("%USERPROFILE%\\AppData",lpDst,0xff);
  SetCurrentDirectoryA(lpDst);
  free(lpDst);
  bVar6 = pHVar1 == (HINSTANCE)0x0;
  bVar7 = pHVar1 == (HINSTANCE)0x1;
  if (1 < (int)pHVar1) {
    iVar3 = 3;
    pbVar4 = (byte *)pHVar2[1].unused;
    pbVar5 = &DAT_0040405a;
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar6 = *pbVar4 < *pbVar5;
      bVar7 = *pbVar4 == *pbVar5;
      pbVar4 = pbVar4 + 1;
      pbVar5 = pbVar5 + 1;
    } while (bVar7);
    if ((!bVar6 && !bVar7) == bVar6) {
      remove(".\\SecureSoftware(crackme)\\.lock");
      remove(".\\SecureSoftware(crackme)\\.auth");
      remove(".\\SecureSoftware(crackme)\\.KEY");
      RemoveDirectoryA(".\\SecureSoftware(crackme)");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  }
  puts("Initializing...");
  _beginthread((_StartAddress *)&LAB_00401b58,0,(void *)0x0);
  Sleep(2000);
  puts("Successful.\nChecking Authenticity...");
  local_24[0] = 0;
  _beginthread((_StartAddress *)&LAB_00401748,0,local_24);
  Sleep(5000);
  if (local_24[0] == 0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Successful..!");
  Sleep(500);
  puts("The software is now registered! You can now use full features! Good Bye.");
  system("pause");
  return 0;
}
```

First off, we see that the program is changing the working directory to somewhere under the current user's `AppData` folder

```c
ExpandEnvironmentStringsA("%USERPROFILE%\\AppData",lpDst,0xff);
SetCurrentDirectoryA(lpDst);
```

also, we see that if some conditions are met specific files are deleted under the `AppData\SecureSoftware(crackme)` folder.

```c
remove(".\\SecureSoftware(crackme)\\.lock");
remove(".\\SecureSoftware(crackme)\\.auth");
remove(".\\SecureSoftware(crackme)\\.KEY");
```

 The preconditions to be met are likely a check to see if the application is called with an `-r` flag which, according to the author, removes all artefact. Could it be that this is where the application stores its config files? It is.

<img src="/assets/images/crackmes/ss3.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

Nice, now that we know where the file likely searches for a key, we can continue on and see where the key is actually loaded and checked.

First off, we see that execution is passed, right after the "Initializing..." string, to a thread located at a fixed memory address.

```c
 _beginthread((_StartAddress *)&LAB_00401b58,0,(void *)0x0);
```

The assembly bit for this seems to confirm Ghidra decompilation is actually valid in this case. The call to `Sleep` afterwards is probably used to wait for the thread to be done executing.

```
00401659 c7 04 24        MOV        dword ptr [ESP]=>local_40,LAB_00401b58
         58 1b 40 00
00401660 8b 35 f4        MOV        ESI,dword ptr [->MSVCRT.DLL::_beginthread]       = 0000753a
         71 40 00
00401666 ff d6           CALL       ESI=>MSVCRT.DLL::_beginthread
00401668 c7 04 24        MOV        dword ptr [ESP]=>local_40,0x7d0
         d0 07 00 00
```

Checking the decompiled section of the section of code at `LAB_00401b58` we find 

```c
void UndefinedFunction_00401b58(void)
{
  BOOL BVar1;
  LPCSTR lpDst;
  
  FUN_00401ae7(WinMain);
  FUN_00401ae7(UndefinedFunction_00401b58);
  FUN_00401ae7(&LAB_00401748);
  BVar1 = IsDebuggerPresent();
  if (BVar1 == 0) {
    if (_DAT_00406034 != 1) {
      return;
    }
  }
  else {
    _DAT_00406034 = 1;
  }
  printf("Unauthorized modification detected.. Program crashed.");
  lpDst = (LPCSTR)malloc(0xff);
  ExpandEnvironmentStringsA("%USERPROFILE%\\AppData",lpDst,0xff);
  SetCurrentDirectoryA(lpDst);
  free(lpDst);
  fopen(".\\SecureSoftware(crackme)\\.lock","wb");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

This seems like the bit of code that does the execution. As a side note, I believe Ghidra places the `printf("Unauthorized modification detected.. Program crashed.");` statement in the wrong place. Following the assembly, it seems it should only be called right before the `return`. Which also makes more sense logically.
Other things we can see here are:
- IsDebuggerPresent(), the author did indeed try to prevent debugger usage. Of course, this can easily be patched out, but I still want to solve the challenge without using a debugger,
- This bit of code also creates the folder we saw earlier, nice to know it happens here.

Not much else to see here. Back to `WinMain`, another thread is spawned after `puts("Successful.\nChecking Authenticity...");`, seems like this could be what we need.

```c
local_24[0] = 0;
_beginthread((_StartAddress *)&LAB_00401748,0,local_24);
Sleep(5000);
if (local_24[0] == 0) {
                /* WARNING: Subroutine does not return */
exit(0);
}
```

One thing to notice is that the thread is called with an array as a parameter, and the `int` at the beginning of the array (aka the `int` the array pointer actually points to) is checked. If the value is `0` the program exits without printing the success message.
Following the thread memory location, we get to this bit of decompiled code

```c
void UndefinedFunction_00401748(undefined4 *param_1)

{

  ...

  pFVar1 = fopen(".\\SecureSoftware(crackme)\\.KEY","rb");
  if (pFVar1 != (FILE *)0x0) {
    _File = fopen(".\\SecureSoftware(crackme)\\.auth","rb");
    abStack29[0] = 0x36;
    bStack30 = 0x38;
    do {
      fread(abStack29,1,1,_File);
      fread(&bStack30,1,1,pFVar1);
      if (abStack29[0] == 0) {
        fclose(pFVar1);
        fclose(_File);
        fclose(pFStack528);
        remove(".\\SecureSoftware(crackme)\\.lock");
        *param_1 = 1;
        return;
      }
    } while (abStack29[0] % bStack30 == 0x36);
    fclose(pFVar1);
    fclose(_File);
    puts("Critical Error! Authenticity not proved..");
    remove(".\\SecureSoftware(crackme)\\.KEY");
    system("pause");
                    /* WARNING: Subroutine does not return */
    exit(9);
  }
  printf("You are not Authorized. This is the authdata:");
  pFVar1 = fopen(".\\SecureSoftware(crackme)\\.auth","rb");
  uStack352 = 1;
  do {
    fread((_WIN32_FIND_DATAA *)&uStack352,2,1,pFVar1);
    uVar4 = (uint)uStack352;
    printf("%x",uVar4);
  } while (uStack352 != 0);
  fclose(pFVar1);
  fclose(pFStack528);
  remove(".\\SecureSoftware(crackme)\\.lock");
  printf("\nContact XYZ.ltd to obtain a key with this data.",uVar4);
  system("pause");
                    /* WARNING: Subroutine does not return */
  exit(6);
}
```

I left out a bit because the beginning seems to only be checking to see if a `.lock` file is present, and stops the execution if it finds one. This is a non-problem because we can just delete the file whenever we want.

First of all, we see the program tries to open a file named `.KEY` and exits with the message `printf("You are not Authorized. This is the authdata:");`, which is also what we got earlier. Makes sense then, that we will have to create a `.KEY` file for the program to check.

If the program does find a `.KEY` file, it jumps into a `do{}while` loop where 1 byte is read, per iteration, from both the `.KEY` and the `.auth` file. The loop either stops
- when the modulus between the byte read from the `.auth` file and the one read from the `.KEY` file is different than 54 (0x36), in which case the program continues on after the loop and prints the "failed" message (`puts("Critical Error! Authenticity not proved..");`), right before exiting,
- when the byte read from the `.auth` file is 0, in which case the execution returns and set the content of the pointer passed as a parameter to `1`.

Clearly, we want the second option to happen, because we want to avoid the `Critical Error` output and we want to `int` pointed to by the parameter to be different than `0` (to avoid the `exit` in WinMain).
Therefore, the key will have to contain bytes such as given byte `a` at position `n` in the `.auth` file, and byte `b` also at position `n` in the `.KEY` file, `a % b = 54`.
This is basically the solution to this challenge. The condition above can easily be met by subtracting 54 to each byte in `.auth`.
The following script generates a `.KEY` file that meets the requirements

```python
import os

keyfile = open("{}\\AppData\\SecureSoftware(crackme)\\.KEY".format(os.environ['USERPROFILE']), "wb")
authfile = open("{}\\AppData\\SecureSoftware(crackme)\\.auth".format(os.environ['USERPROFILE']), "rb")
auth = authfile.read()
out = []
for x in auth:
    if x > 54:
        out.append((x - 54).to_bytes(1, "little"))
for x in out:
    keyfile.write(x)
keyfile.close()
authfile.close()
```

We run it on a fresh config state, and we got the challenge.

<img src="/assets/images/crackmes/ss4.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>




