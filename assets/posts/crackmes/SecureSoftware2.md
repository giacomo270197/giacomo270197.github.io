---
title: SecureSoftware1.5
permalink: posts/crackmes/SecureSoftware2
permalink_name: SecureSoftware2
---

The second medium rated crackmes I tried was (SecureSoftware1.5)[https://crackmes.one/crackme/6049c26733c5d42c3d016de3], from the same author, (pranav)[https://crackmes.one/user/pranav], as the easy rated "SecureSoftware" challenge.
This crackme is in many ways similar to the previous one, as per the README the environment has to be initialized by calling the executable with the `-i` flag and can be torn down with the `-u` flag.
Initialization will request a key. At this point, any key will do, but if the wrong key is provided, executing the program will result in an "Illegal copy" error message like this.

<a href="/assets/images/crackmes/ssn1.png"><img src="/assets/images/crackmes/ssn1.png" margin="0 250px 0" width="100%"/></a>

The challenge is twofold. The main goal of this crackme is to solve the puzzle by only doing static analysis. Anti-debugging and anti-patching are implemented, and as a bonus question, the author asks to bypass all measures to the point where the program can be run in a debugger. In this post, I will only cover the first point, and in the next one, I will go over the anti-debugging techniques.

We load the executable into Ghidra and we are met with really clear and understandable decompilation, therefore we won't be reading over too much assembly this time.
First off, we want to start making some sense of `WinMain` (which is quite trivial to find).

First off we see the working directory is changed to the user home folder so we expect to see artefacts created there

```c
lpDst = (LPCSTR)malloc(0xff);
ExpandEnvironmentStringsA("%USERPROFILE%",lpDst,0xff);
SetCurrentDirectoryA(lpDst);
free(lpDst);
```

A thread is then started to begin execution at `LAB_0040239f`, pointing to the following code which likely does some time-based anti-debugging.

```c
void UndefinedFunction_0040239f(int param_1)

{
  DWORD DVar1;
  
  if (param_1 == 1) {
    DVar1 = GetTickCount();
  }
  else {
    DVar1 = GetTickCount();
    if ((int3)(DAT_00407614 >> 8) != (int3)(DVar1 >> 8)) {
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  }
  DAT_00407614 = DVar1;
  return;
}
```

At this point, we see pointers to obfuscated, hardcoded strings. The obfuscation is trivial to defeat as it is just a `+1` transposition of ASCII characters, but it does make it impossible to search for informative strings unless you already know what you are looking for.

That being said, we know to see another thread starting at address `LAB_00401bd4` which points to the following code

```c
void UndefinedFunction_00401bd4(void)

{
  FUN_004021c9((byte *)FUN_004017bc);
  FUN_004021c9((byte *)FUN_00401874);
  FUN_00401b69();
  if (((DAT_0040703e != 0) && (DAT_00407034 == 0)) && (DAT_00404024 == 2)) {
    FUN_004021c9((byte *)0x0);
    FUN_00401f18();
    if (((DAT_00404044 == 0) && (DAT_00407038 == 1)) && ((DAT_0040703a == 1 && (DAT_0040703c == 0)))
       ) {
      FUN_00401781(PTR_s_Tvddftt""!Uif!qsphsbn!ibt!cffo!v_0040401c);
      MessageBoxA((HWND)0x0,&DAT_00407420,"",0x40);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  }
  return;
}
```

Deobfuscating the string results in the following message `Success!! The program has been unlocked!`. Likely this is the bit of code that does the checking then, and on which we will focus lots of our reverse engineering efforts.

We then have the flags checking portion of the code. We see a function being called when the `-i` parameter is passed, and another one when the `-u` is. We rename the functions accordingly. We also deobfuscate an error message given when the wrong parameters are passed.

All said and done, we are then left with the following `WinMain` function.

<a href="/assets/images/crackmes/ssn2.png"><img src="/assets/images/crackmes/ssn2.png" margin="0 250px 0" width="100%"/></a>

Before going through the checking procedure, we wanna know how the program sets up its artefacts, so we go and explore the newly renamed `EnvironmentSetup` function.
First off, we see that a new directory, `data` is created. And inside it, a data file is created named `authdata.dat`. It is important not to look at the following variable definitions and `fwrite` call to the handle for `authdata.dat`.

```c
time_t tVar1;
...
byte local_100 [8];
undefined4 local_f8;
char acStack244 [50];
char acStack194 [50];
char local_90 [100];
undefined auStack44 [8];
...
fwrite(local_100,0xdc,1,local_24);
```

We see that 220 bytes (`0xdc`) are written to file starting from `local_100`. When Ghidra decompiles large arrays with the same type like in the code snippet above, it is sometimes the case that in the original code the arrays all belonged to the same, larger, array. This is the case in this scenario, where the memory allocated for the arrays adds up to 220 bytes (`local_f8` is set to `tVar1`, which is 4 bytes in Windows 32 bits), which is the size written to file later.
If we retype `local_100` from `char[8]` to `char[220]`, we can then see that the array contains the data to be written to `authdata.dat`. Exploring the code further, we can pretty easily find out that the 220 bytes written to file are broken down as follows:
- [0-8]     -> Hardcoded 6 chars string (+ unused memory),
- [8-12]    -> Time at `EnviromentSetup` execution star,
- [12-62]   -> Current user's username (+ unused memory),
- [62-112]  -> Hostname (+ unused memory),
- [112-212] -> User provided key (+ unused memory),
- [212-220] -> Hardcoded 6 chars string (+ unused memory)

After the file is populated, a checksum is computed (by simply adding all `char` values) and stored in a file named `checksum`. This is, however, not needed since the challenge can be solved without manually modifying `authdata.dat`, as explained later.

We now move over to the checking function, just to realize all it's doing is to check a bunch of global flags to make sure they are set right for the success message to be printed. We then need to find where the flags are set, and how to set them right. I believe this is the real challenge of this crackme, there are many conditions to be met and it is sometimes hard to keep track of it all.
The flags in the first `if` check are easily recognized by simply checking their references, and we won't have to spend too much time on it:
- `DAT_0040703e` is set (!= 0) if the program is initialized (was ran with `-i`);
- `DAT_00407034` is set (== 0) if the program is being ran with no flags,
- `DAT_00404024` is set (== 2) if the program is not being run in a debugger.

The next function call to `FUN_00401f18()` sets the flags for the following `if` check. If we explore the function, we see that there's a first part that mainly does anti-debugging/anti-patching checks. Notably, a check is done to make sure that the data extracted from `authdata.dat` (referred to as `authdata`) contains the hardcoded string at the start and beginning as explained earlier. If the checks succeed, the flag `authdataEqualsbu1oq_00407038` (`DAT_00407038`) is set to a passing state. The function then falls into the following section of code (which I already annotated)

```c
else {
checkAuthdata(authdata);
bVar1 = false;
local_14 = 0;
while (local_14 < (int)sVar2) {
    if (key[local_14] != -1) {
                /* Illegal copy... Please obtain the key and run with -u and then -i to
                    reinstall with correct key. */
    DecryptFunction(PTR_s_Jmmfhbm!dpqz///!Qmfbtf!pcubjo!ui_00404018);
    MessageBoxA((HWND)0x0,&decryptOutput_00407420,"",0x10);
    bVar1 = true;
    break;
    }
    local_14 = local_14 + 1;
}
if (bVar1) {
    authdataEqualsbu1oq_00407038 = 0;
    strcmpResult_0040703a = 0;
}
else {
    checkingFunctionPassed_0040703c = 0;
}
fclose(_File);
}
```

In short, this section checks the output of the `checkAuthdata`, stored in the "key" section of `authdata`. If the key anything but `-1`, it prints the error message we saw at the beginning and exits. `authdataEqualsbu1oq_00407038` and `strcmpResult_0040703a` (`DAT_0040703a`) are also global flags needed to pass the `if` check, and are reset to a failing state if the key check fails. However, if it succeeds, the flag `checkingFunctionPassed_0040703c` (`DAT_0040703c`) is set to a passing state.
We now need to understand how the `checkAuthdata` function works, and this is honestly the main challenge of this crackme.

I am now going to walk through the main portions of `checkAuthdata`. Note that all this code is already annotated by me.

First of all, we have a check for username and password, as follows

```c
if (strcmpResult_0040703a != 0) {
currentChar = strcmp(authdata + 0xc,(char *)&Username_00407620);
if ((currentChar == 0) &&
    (currentChar = strcmp(authdata + 0x3e,(char *)&Hostname_004076a0), currentChar == 0)) {
    strcmpResult_0040703a = 1;
}
else {
    strcmpResult_0040703a = 0;
}
```

We see that the globals containing the username and password (obtained earlier in the parent function) are checked against the `authdata` offsets that should contain those values (12 and 62, in hex). If the check succeeds, the `strcmpResult_0040703a` is set to a passing state.

We then see that the username and hostname global go through the following transformation. I will only show the code for the username, but the same applies to the hostname.

```c
while (cntUsername < (int)usernameLength) {
bVar1 = (byte)(*(char *)((int)&Username_00407620 + cntUsername) >> 7) >> 4;
*(byte *)((int)&Username_00407620 + cntUsername) =
        (*(char *)((int)&Username_00407620 + cntUsername) + bVar1 & 0xf) - bVar1;
cntUsername = cntUsername + 1;
}
```

The section iterates through each character. First off, we see that a variable is created as the character bit shifted 13 times. Looking at the assembly code explains why Ghidra separated the shifting operations in `>> 7` and `>> 4`. As we can see, a 7-bit shift is done with the `SAR` operation and the rest 4 with `SHR`

```
00401de1 0f b6 00        MOVZX      keyLength,byte ptr [keyLength]=>Username_00407   = NaP
00401de4 89 c2           MOV        EDX,keyLength
00401de6 c0 fa 07        SAR        DL,0x7
00401de9 c0 ea 04        SHR        DL,0x4
```

The character is then added to the new variable, `and`'ed (`&`) with `0xf` (`00001111`). The new variable is then subtracted from the result.
This might seem like a pretty complicated sequence, however, it is much simpler than it looks. The difference between `SAR` and `SHR` is that `SAR` maintains the byte sign when shifting, while `SHR` just appends a `0` at the beginning and does not preserve the sign. However, the bytes we will be working on are all ASCII characters since they are taken from human-readable strings (username and hostname), and will therefore not be anything higher than 127 (top of ASCII table). So for all these bytes that we operate on, the first bit will always be 0. These bit shifting, therefore, will always result in the new variable is 0.
Knowing that we see that this all operation is nothing but a `and` between the byte and `00001111`. This means that the characters will be transformed to a byte with value 0-15.

We then get to the key checking part of the function. The check is done in reverse, but that is zeroed out by the fact that a `strrev` operation reverses the key beforehand anyway.
Each byte of the key is passed through the following function and compared to a string composed of a concatenation of the new username and hostname, in this order.

```c
int __cdecl keySubs(char character)

{
  int iVar1;
  
  if ((byte)character < 0x47) {
    iVar1 = (byte)character - 0x30;
    if (9 < iVar1) {
      iVar1 = (byte)character - 0x37;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}
```

If the function output matches the hostname or username character being analyzed, the key value is set to `-1`. Otherwise, it's set to `\0`.

```c
/* Address is 1 byte before hostname global */
if (currentChar == *(char *)((hostnamelength - cntKey) + 0x40769f)) {
  key[cntKey] = -1;
}
else {
  key[cntKey] = '\0';
}
...
/* Address is 1 byte before username global */
if (currentChar ==
    (char)(&usernameAndHostname)[usernameLength - (cntKey - hostnamelength)]) {
    key[cntKey] = -1;
}
else {
    key[cntKey] = '\0';
}
```

If we manage to provide a key that matches this checking pattern, the `checkingFunctionPassed_0040703c` will be set once execution returns to the parent function (because all key values will be `-1`) and all the flags we need will be set accordingly to print out "Success" message.
To do that, we need to pass a key that, going through the `keySubs` function, will return the modified username and hostname. Luckily, the `keySubs` function has a range of inputs that matches exactly the possible range value of the previous `and` modifications. Byte values 48-70 (0x30 to 0x46) will output exactly those values, and since they are all printable characters we can simply pass the appropriate key string from STDIN when requested, and we don't need to worry about fixing the checksum.

So to compute the right key we need to retrieve the username and hostname, `and` them with 0xf, pass each character through the `keySubs` reverse function (just add 48 if <9 and 55 otherwise) and concatenate the two. The following program will do just that.

```c
#include <windows.h>
#include <stdio.h>
#include <strings.h>

byte reverseKeySubs(byte character){
  if(character > 0x9){
    character += 0x37;
  } else {
    character += 0x30;
  }
  return character;
}

int main(){

  byte    hostname[1024];
  DWORD   hostnameLength = 100;
  GetComputerNameA( hostname, &hostnameLength );
  
  byte    username[1024];
  DWORD   usernameLength = 100;
  GetUserNameA( username, &usernameLength );

  printf("%s\n", username);
  printf("%s\n", hostname);

  int cnt = 0;
  while(cnt < usernameLength-1){
    username[cnt] = username[cnt] & 0xf;
    printf("%c", reverseKeySubs(username[cnt]));
    cnt++;
  }
  cnt = 0;
  while(cnt < hostnameLength){
    hostname[cnt] = hostname[cnt] & 0xf;
    printf("%c", reverseKeySubs(hostname[cnt]));
    cnt++;
  }

  printf("\n");
  return 0;  
}
```

Note that while `GetUserNameA` returns a `NULL` terminated string, the terminator is actually not used in the key checking procedure. `GetComputerNameA` does not return a `NULL` terminated string.

That being said, we can test our keygen and make sure it works.

<a href="/assets/images/crackmes/ssn3.png"><img src="/assets/images/crackmes/ssn3.png" margin="0 250px 0" width="100%"/></a>