---
title: SecureSoftware1.5 (Bonus)
permalink: posts/crackmes/SecureSoftware2B
permalink_name: SecureSoftware2B
---

As anticipated in the [previous post](/posts/crackmes/SecureSoftware2), I am now going to solve the bonus challenge of [SecureSoftware1.5](https://crackmes.one/crackme/6049c26733c5d42c3d016de3). After completing the main crackme by only using static analysis, I am now going to walk through how to defeat anti-debugging and anti-patching measures present in the software.

The first thing we need to do is to figure out how anti-patching works and how it is implemented. If we can defeat that then we can just go ahead and NOP all anti-debugging blocks as well.

One of the few functions we did not touch upon in the previous post, is the one located at `FUN_004021c9`. We see it being called several times, with pointers to functions passed as parameters. Because of this unusual trait, we can reasonably suspect this function could be responsible for anti-patching.
If we explore the function we see it is split into two main functionalities, based on the pointer that is passed as a parameter. 
If a `NULL` pointer is passed, we see the function simply checks the `checksum` file to see if it matches `authdata`. Nothing about anti-patching here.

```c
if (functionPnt == (byte *)0x0) {
                /* Compute checksum and check it */
readfile = fopen(".\\data\\authdata.dat","rb");
if (readfile == (FILE *)0x0) {
    EnvironmentTeardown();
                /* WARNING: Subroutine does not return */
    exit(-1);
}
fread(authdata,0xdc,1,readfile);
checksumCompute = 0;
checksum = 0;
byte_i = 0;
while (byte_i < 0xdc) {
    checksumCompute = checksumCompute + (uint)authdata[byte_i];
    byte_i = byte_i + 1;
}
fclose(readfile);
readfile = fopen(".\\data\\checksum","rb");
if (readfile != (FILE *)0x0) {
    fread(&checksum,4,1,readfile);
}
fclose(readfile);
if (checksumCompute != checksum) {
    EnvironmentTeardown();
}
}
```

The other functionality is the one we are interested in, and it is called when a non `NULL` pointer is passed.

```c
else {
DAT_00407040 = DAT_00407040 + 1;
local_18 = 0;
local_1c = 0;
local_20 = 0;
while (local_20 < 7) {
    if (*param_1 == 0x90) {
    local_20 = local_20 + 1;
    }
    else {
    local_20 = 0;
    local_1c = local_1c + (uint)*param_1;
    }
    param_1 = param_1 + 1;
}
while ((&DAT_00404028)[local_18] != -1) {
    if (local_1c == (&DAT_00404028)[local_18]) {
    (&DAT_00404028)[local_18] = 0;
    }
    local_18 = local_18 + 1;
}
if (((DAT_00404028 == 0) && (DAT_0040402c == 0)) && (DAT_00404030 == 0)) {
    DAT_00404040 = 0;
}
if ((DAT_00404034 == 0) && (DAT_00404038 == 0)) {
    DAT_00404044 = 0;
}
}
```

This bit of code does all the patch checking for this crackme.
First of all, we see a global being incremented, `DAT_00407040`. We see that this global is used as guard, with condition `DAT_00407040 == 5` to the condition that eventually reverses the user-provided key. This is needed for the algorithm to match string up later so we can assume that this function is meant to run five times with function pointers as parameters. If we check the function XREFS, we see that this is indeed the case. One of the calls (`00401c2f`), is called with a `NULL` pointer as a parameter.

```
**************************************************************
*                          FUNCTION                          *
**************************************************************
undefined __cdecl FUN_004021c9(byte * param_1)
...
FUN_004021c9                                    XREF[6]:     FUN_004015c0:0040167d(c), 
                                                            00401be1(c), 00401bed(c), 
                                                            00401c2f(c), 
                                                            FUN_00401f18:00401f87(c), 
                                                            FUN_00401f18:00401fd4(c)  
```

Moving on, we see a `while` loop that iterates over bytes starting from the received parameter and continues until it meets seven `NOP`s in a row. Checking some functions in the program confirms that seven consecutive `NOP`s indicate the end of a function. The loops stores the summation of all the byte it iterates over in a variable which is then compared to a global, `DAT_00404028`, and sets it to `0` if it matches it.
Knowing that this part of the function will be executed five times, seeing that `DAT_00404028` is indexed and contiguous globals are used in the `if` statements at the end, we can safely retype `DAT_00404028` to `int[5]`. Moreover, if we inspect the content of the array, we see hardcoded values that could be functions "checksums". Knowing this, and seeing how the global is used, we assume it contains the hardcoded value of the byte summation for the functions being checked.

```
                        functionsChecksums_00404028[1]                  XREF[4,4]:   antiPatch:0040232e(R), 
                        functionsChecksums_00404028[2]                               antiPatch:0040233d(W), 
                        functionsChecksums_00404028[3]                               antiPatch:0040234f(R), 
                        functionsChecksums_00404028[4]                               antiPatch:0040235b(R), 
                        functionsChecksums_00404028                                  antiPatch:00402364(R), 
                                                                                    antiPatch:0040236d(R), 
                                                                                    antiPatch:00402380(R), 
                                                                                    antiPatch:00402389(R)  
00404028 d9 89 00        int[5]
            00 2c 30 
            00 00 35 
    00404028 [0]                   89D9h,        302Ch,       11B35h,        D21Bh
    00404038 [4]                   E5B5h
```

Two more globals, `DAT_00404040` and `DAT_00404044` are set to `0` if all elements in `DAT_00404028` equal `0`. Elements in `DAT_00404028` when a computed checksum meets the expected value, so we can infer that `DAT_00404040` and `DAT_00404044` will e both set to `0` after the function has executed five times successfully, one for each function.

We see these two variables being used a bit everywhere in the program, and finding all usages would be tedious. Since the anti-patching function sets guards used elsewhere we cannot just patch it out. We can, however, make sure that all the guards will be set right no matter how many times the function completes successfully. This means that `DAT_00407040` must be set to `5` immediately, and `DAT_00404040` and `DAT_00404044` must be set to `0` regardless of the content of `DAT_00404028`. We do the patching accordingly and we are left with the following code.

```c
else {
DAT_00407040 = DAT_00407040 + 5;
local_18 = 0;
local_1c = 0;
local_20 = 0;
while (local_20 < 7) {
    if (*param_1 == 0x90) {
    local_20 = local_20 + 1;
    }
    else {
    local_20 = 0;
    local_1c = local_1c + (uint)*param_1;
    }
    param_1 = param_1 + 1;
}
while ((&DAT_00404028)[local_18] != -1) {
    if (local_1c == (&DAT_00404028)[local_18]) {
    (&DAT_00404028)[local_18] = 0;
    }
    local_18 = local_18 + 1;
}
DAT_00404040 = 0;
DAT_00404044 = 0;
local_28 = DAT_00404028;
}
```

Running this modified version of the program allows us to set up the environment, but fails when checking the key validity (without flags) and presents us with the "Illegal copy" error message.
This is unfortunate, but it tells us that that execution runs all the way to the function that checks `authdata`, which eventually fails. From the previous post, we know that the only patching-related check around the key validation routine is the following `if` statement, where `patchFunCnt` is the global that's incremented in the anti-patching function, and `isPatched1` is `DAT_00404040`.

```c
if ((strcmpResult_0040703a == 1) && (isPatched1 == 0)) {
    if (patchFunCnt == 5) {
        _strrev(key);
    }
    keyLength = strlen(key);
    cntUsername = 0;
    ...
    // Continues on with the username and hostname modification
```

We could go and look where these variables are set other than the ant-patching function we modified, but it is simpler to just remove the `if` statement and let the following block of code execute no matter what.
When we do that, the executable successfully runs until completion as you can see (hash computation in the background to prove the executable was patched).

<a href="/assets/images/crackmes/ssnb1.png"><img src="/assets/images/crackmes/ssnb1.png" margin="0 250px 0" width="100%"/></a>

From here on out, it is all about finding anti-debugging and patching it out.

First of all, we see a pretty obvious call in `WinMain` to `IsDebuggerPresent`. Upon non-zero result, it sets a global flag to `1`. We need it to be `= 2` for our program to work so we just change 

```c
BVar1 = IsDebuggerPresent();
if (BVar1 != 0) {
    noDebuggerPresent_00404024 = 1;
}
```

to

```c
BVar1 = IsDebuggerPresent();
if (BVar1 != 0) {
    noDebuggerPresent_00404024 = 2;
}
```

and we move on. This will of course then not work outside of a debugger, we could've also patched out the `if` check, but this is quicker for now.

In the previous post, I went over a time base anti-debugging measure that was called in `WinMain`, in the initialization function, and in the `authdata` validation routine.
Here's the code

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

Briefly, this is first called from `WinMain` right away with `param_1` set to `1`. This store the output of `GetTickCount` to `DAT_00407614`. The function is then called again in the initialization routine or the `authdata` validation routine, depending on the flag, with `param_1` set to `0`. The function then calls `GetTickCount` again and compares the 8-bit shifted results with the 8-bit shifted `DAT_00407614`. The idea here is that if the program wasn't running in a debugger, the output of the two calls should be small enough to fit in a single byte, and therefore they should both be `0` after `>> 8`. If an analyst takes his time running instructions one by one, the second call to `GetTickCount` will return a number large enough to occupy more than a single byte.
These are all thread calls and just exit the program if they detect a debugger rather than setting a flag to be checked later. We can just `NOP` out all the calls to `createthread` that point to this function.

Once we are done with the extra bit of patching, we are then ready to run the program in a debugger and, as you can see, we get it working.

<a href="/assets/images/crackmes/ssnb2.png"><img src="/assets/images/crackmes/ssnb2.png" margin="0 250px 0" width="100%"/></a>
