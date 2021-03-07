---
title: Crackmes - SimpleCrackme
permalink: posts/crackmes/SimpleCrackme
permalink_name: SimpleCrackme
---

After successfully solving the [FindMySecrect challenge](/posts/crackmes/FindMySecret) I decided to try out another 'easy' rated crackme. The one I went for was [Simple Crackme](https://crackmes.one/crackme/5fec960e33c5d4264e590182).

So again, the challenge looks like so

<img src="/assets/images/crackmes/sc9.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

To solve the crackme, we need to find a password and we only have one attempt to get it right.

Once again, to find the bit of code we are interested in we look for the initial string in Ghidra, to check where it is used.

<img src="/assets/images/crackmes/sc1.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>


This leads us to the following decompiled funtion

```c
undefined8 entry(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  char *_Str;
  char local_88 [13];
  char local_7b;
  
  puts("Crackme 1 - Compiled on Sep 24 2019 at 11:41:15");
  FUN_00400493("Please enter the valid password: ",param_2,param_3,param_4);
  gets_s(local_88,0x80);
  lVar1 = 0;
  do {
    if (local_88[lVar1] != "BGOTHXIY"[*(byte *)(lVar1 + 0x400418) & 7]) goto LAB_00400473;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0xd);
  if (local_7b == '\0') {
    _Str = "Good job on decrypting the password!";
  }
  else {
LAB_00400473:
    _Str = "Don\'t think you have the slightest clue about debugging.";
  }
  puts(_Str);
  return 0;
}
```

We can quite clearly tell that the funtion reads our input, stores it in `local_88` and iterates over every single charachter, 13 of them, to compare it to what we assume is going to be the password. If one character comparison goes wrong, execution jumps to the "you failed" part of the code and exits.
Our next step now is to check how the password is composed and extrapolate it from the code. A quick look at the disassembled code does not reveal much more than what we already know.

<img src="/assets/images/crackmes/sc2.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

It seems charachters are picked directly from memory startring from address `0x400418`. We need to know what's at that address, so we load the executable into a debbugger.
Unfortunately, the PE is compiled for 64 bits so I cannnot use Immunity. I will have to bite the bullet and struggle with WinDBG.

First things first, in WinDBG, we want to find the call to out executable in the process. This can be done as follow

```
0:000> u $exentry
crack_me+0x410:
00000000`00fb0410 56              push    rsi
00000000`00fb0411 4881eca0000000  sub     rsp,0A0h
00000000`00fb0418 488d05f9ffffff  lea     rax,[crack_me+0x418 (00000000`00fb0418)]
00000000`00fb041f 4889c6          mov     rsi,rax
00000000`00fb0422 488d0d42feffff  lea     rcx,[crack_me+0x26b (00000000`00fb026b)]
00000000`00fb0429 e8bd000000      call    crack_me+0x4eb (00000000`00fb04eb)
00000000`00fb042e 488d0d0bfeffff  lea     rcx,[crack_me+0x240 (00000000`00fb0240)]
00000000`00fb0435 e859000000      call    crack_me+0x493 (00000000`00fb0493)
```

We then set a breakpoint to both the entrypoint and the beginning of the checking assembly loop we found. We let the executable run, enter some random password, and end up exactly at the point our password is being checked.

<img src="/assets/images/crackmes/sc3.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

Now we can start single-stepping throught the loop, really paying attention to the following sequence

```assembly
00000000`00a20452 8a540420        mov     dl,byte ptr [rsp+rax+20h]
00000000`00a20456 0fb60c06        movzx   ecx,byte ptr [rsi+rax]
00000000`00a2045a 83e107          and     ecx,7
00000000`00a2045d 423a1401        cmp     dl,byte ptr [rcx+r8]
00000000`00a20461 7510            jne     crack_me+0x473 (00000000`00a20473)
```

which is where the juice of the program is.

So the first instruction loads a byte into the `dl` register. We could check what is located at `rsp+rax+20h` but everytime we run the instruction we see that the `dl` register ends up containing the the n<sup>th</sup> charachter of the password we provided at the n<sup>th</sup> repetition of the loop. We can then safely assume that this register holds the user-provided side of the password comparision.

The `movzx` and `and` instructions are where the correct password is computed then. Modifying the `ecx` register modifies `rcx` as well and `rcx` used in the `cmp` that follows.

As per `movzx`, we notice that `rsi` stays constant, pointing to the same address also referenced in Ghidra decompilation. `rax` is incremented for every cycle

<img src="/assets/images/crackmes/sc4.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

This means that at every cycle of the loop one byte of the following sequence is loaded into `ecx`

<img src="/assets/images/crackmes/sc5.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

Moving onto the `cmp` instruction, we now see that our input in `dl` is compared to a byte referenced by `r8` plus `rcx`, which is a result of the previous two `mov` and `and` instructions. We notice that `r8` is constant, and point to the beginning of an interesting memory region

<img src="/assets/images/crackmes/sc11.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

It seems pretty obvious, at this point, that the final password will a 13-character string composed by the alphabet "BGOTHXIY", and that the order in which letters appear will be dictated by

```assembly
00000000`00a20456 0fb60c06        movzx   ecx,byte ptr [rsi+rax]
00000000`00a2045a 83e107          and     ecx,7
```

and therefore by which values are located at `0x400418`. This is also helps making more sense of the decompilation Ghidra gave us.

At this point we know how the password is computed, but recoposing it would be tedious work. Fortunately WinDBG comes to our help here. When we are about to execute the `cmp` instruction, the debugger tells us the content of `[rcx+r8]`, making it quite easy for us to compare it to the contents of `dl`

<img src="/assets/images/crackmes/sc6.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

At this point we can change the content of the `dl` register to match the result of the password calculation, without having to compute it ourselves. The `cmp` executes, we get to the `jmp`, but we are not sent to the section of code that tells us we got the password wrong. Rather, we cycle back to our breakpoint.

<img src="/assets/images/crackmes/sc7.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

Now we just repeat the process for all 13 cycles, and we note which characther each cycle computes. We do this and we get the password `BXXGYYYBGIBXX`.

<img src="/assets/images/crackmes/sc8.png" alt="SearchingMain" margin="0 250px 0" width="100%"/>

And we got it!
