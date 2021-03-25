---
title: Anti CrackMe
permalink: posts/crackmes/AntiCrackMe
permalink_name: AntiCrackMe
---

For the past 2-3 days I have been busy with a medium rated crackme, [Anti CrackMe](https://crackmes.one/crackme/600098f733c5d42c3d0166c8).
I decided to move on to medium and hard difficulties before switching away from C/C++ samples for Windows.

Compared to the easy rated ones, this was certainly a notch harder. The description of the crackme tells us that the main focus areas of the challenge are anti-debugging and encryption.  

Running the executable you are met with a username/password prompt like so

<a href="/assets/images/crackmes/ac1.png"><img src="/assets/images/crackmes/ac1.png" margin="0 250px 0" width="100%"/></a>

The username seems not to be checked, while the password is. Because of this, I imagine the program likely derives the password from the username (why ask otherwise?).

We start by looking at the disassembly and the decompiling in Ghidra. For this challenge, the decompilation was mostly pretty atrocious, and I figured my time would be better spent going through the disassembly directly rather than trying to improve decompilation.

We go and find the `entry` function, which however looks different than what I usually see. So, instead, I look for the "Enter Your Username:" string, and from there I backtrack until I end up in a function that is referenced in `entry`.
Once I find it, I name it `WinMain` and check the decompilation (changing the signature to the correct one makes no difference)

```c
undefined4 WinMain(void)

{
  code *pcVar1;
  undefined4 uVar2;
  int in_FS_OFFSET;
  
  if (((*(byte *)(*(int *)(in_FS_OFFSET + 0x30) + 0x68) & 0x70) == 0) &&
     ((*(byte *)(*(int *)(in_FS_OFFSET + 0x30) + 0xbc) & 0x70) == 0)) {
    _system("Color 02");
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&lpStartAddress_00402040,
                 (LPVOID)0x0,0,(LPDWORD)0x0);
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress_00402060,(LPVOID)0x0,0,(LPDWORD)0x0);
    MainProgram();
    return 0;
  }
  _exit(0);
  pcVar1 = (code *)swi(3);
  uVar2 = (*pcVar1)();
  return uVar2;
}
```

The call to the function `MainProgram`, which I renamed, is where username and password are processed. We see two calls to `CreateThread` and if we check the memory addresses they start execution from we see, firstly, at `lpStartAddress_00402040` the following decompiled code

```c
void UndefinedFunction_00402040(void)

{
  code *pcVar1;
  BOOL BVar2;
  
  do {
    BVar2 = IsDebuggerPresent();
  } while (BVar2 != 1);
  _exit(0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}
```

Quite clearly, we see that this thread starts a loop that constantly calls `IsDebuggerPresent` and exits the process if one is found. As a confirmation, running the executable in any debugger fails almost immediately.

At memory location `lpStartAddress_00402060`, we see some slightly more complicated decompiled code, which we really don't need to understand. We see that the thread takes a snapshot of running processes (`CreateToolhelp32Snapshot`) and iterates through them. Further on, we see strings representing common debuggers processes names (windbg and cheatengine, mainly), so we can be quite confident that this thread is also meant for anti-debugging, and it does that by checking if a debugger process is running. As a confirmation, we try to run the executable, outside of any debugger, while WinDbg is also running, and sure enough, the program exits prematurely.

Finally, we can check the `if` statement that comes right before the call to `MainProgram`. In this case, the assembly gives us all the information we need to understand what is happening:

```
00402bb0 64 a1 30        MOV        EAX,FS:[0x30]
            00 00 00
00402bb6 f6 40 68 70     TEST       byte ptr [EAX + 0x68],0x70
00402bba 75 48           JNZ        LAB_00402c04
00402bbc f6 80 bc        TEST       byte ptr [EAX + 0xbc],0x70
            00 00 00 70
00402bc3 75 3f           JNZ        LAB_00402c04
```

We see that the PEB is loaded into the `EAX` register and the `NtGlobalFlag` is checked to see if it is set to `0x70`, meaning it is created by a debugger. 

All these anti-debugging methods can be defeated by some measure. We could hook `IsDebuggerPresent`, we could use a debugger the crackme does not check for, and we could easily bypass the `NtGlobalFlag` by modifying the result of the `test` instruction. However, we can also bypass all measures by simply patching out with `NOPs` all the code that causes issues, which is what I decided to do.

<a href="/assets/images/crackmes/ac2.png"><img src="/assets/images/crackmes/ac2.png" margin="0 250px 0" width="100%"/></a>

Once the patch is all done, we can safely run the executable in a debugger, which I very much had to use to understand the rest of the code.

As I mentioned, the decompilation for `MainProgram` is pretty messy, and running the program instruction by instruction really helped me understand what was happening, and when. Since OllyDbg (and Immunity) failed to properly disassemble a `movq` instruction and therefore all subsequent code, I went for WinDbg.

We place a breakpoint at the call to `MainProgram` (`bp Anti_CrackMe+0x25d0`) and start examining from there.

The first interesting bit we see is

```
00672687 8d9578ffffff    lea     edx,[ebp-88h]
0067268d b9c8006a00      mov     ecx,offset Anti_CrackMe+0x300c8 (006a00c8)
00672692 e8b9140000      call    Anti_CrackMe+0x3b50 (00673b50)
00672697 837d8814        cmp     dword ptr [ebp-78h],14h
0067269b 7e34            jle     Anti_CrackMe+0x26d1 (006726d1)
```

This reads the user input, with a function that Ghidra does not recognize, and stores both the input and the input length at `EBP-88h` and `EBP-78h` respectively.

We then have

```
006726d1 8d8578ffffff    lea     eax,[ebp-88h]
006726d7 50              push    eax
006726d8 8d8d5cffffff    lea     ecx,[ebp-0A4h]
006726de e89d050000      call    Anti_CrackMe+0x2c80 (00672c80)
```

Which is actually a `memcpy` call that copies the username input to `EBP-0A4h`. This is important to catch because the username modifications are going to be applied to and from this new location from this point onward.

The next important section appears as follows

```
00672717 8d8d5cffffff    lea     ecx,[ebp-0A4h]
0067271d 83bd70ffffff10  cmp     dword ptr [ebp-90h],10h
00672724 8d855cffffff    lea     eax,[ebp-0A4h]
0067272a 89b574ffffff    mov     dword ptr [ebp-8Ch],esi
00672730 0f438d5cffffff  cmovae  ecx,dword ptr [ebp-0A4h]
00672737 038d6cffffff    add     ecx,dword ptr [ebp-94h]
0067273d 83bd70ffffff10  cmp     dword ptr [ebp-90h],10h
00672744 51              push    ecx
00672745 0f43855cffffff  cmovae  eax,dword ptr [ebp-0A4h]
0067274c 50              push    eax
0067274d e8e2320000      call    Anti_CrackMe+0x5a34 (00675a34)
```

Given that the username I provided (my name, "giacomo") is 7 characters long, the two parameters passed to `call Anti_CrackMe+0x5a34` represent the beginning and the end (`EBP-04Ah` in `EAX` and `EBP-94h` in `ECX` respectively) of the memcpy'd string we saw earlier. If we keep an eye on it after the function call, we see that the string is now reversed. So, in my case specifically, the string at `EBP-04Ah` now contains "omocaig".

Moving on, we see the username being copied in several other places in memory, but the following stands out

```
0067283b 8d8d5cffffff    lea     ecx,[ebp-0A4h]
00672841 e81afaffff      call    Anti_CrackMe+0x2260 (00672260)
```

The reversed username is passed as an argument to `call Anti_CrackMe+0x2260`, which overwrites the "omocaig" string at `EBP-0A4h` with "xvxljrp".
At this point we could go and analyze `Anti_CrackMe+0x2260`, however, I believe there is no need to do that, as it is pretty obvious what the function does. "xvxljrp" is clearly a modification of "omocaig" where each letter is shifted in the alphabet forward by 9 places. This is some ROT-9 substitution cypher, the only thing we need to do is to make sure we understand how it behaves in edge cases. The main concerns are:
- What happens when a non-letter input is provided?
- Does the cypher really roll letters over when they get to the end of the alphabet?
- Can upper-case letters become lower-case and vice-versa?

To answer these questions we can simply try some inputs and check the function outputs. Doing that we find:
- We can only provide letters as input, as specified by the intro banner,
- The cypher does behave like a proper ROT-X cypher,
- Upper case letters always stay upper-cased, and the same goes for lower case ones.

We now skip over some of the code which we don't immediately need to understand until we reach the password prompt, to which we pass the string "password".
Here, we are met with the following code

```
006729b2 e899110000      call    Anti_CrackMe+0x3b50 (00673b50)
006729b7 837dec10        cmp     dword ptr [ebp-14h],10h ss:002b:0019ff10=00000046
006729bb 8d55d8          lea     edx,[ebp-28h]
006729be 8b75b8          mov     esi,dword ptr [ebp-48h]
006729c1 8d45a8          lea     eax,[ebp-58h]
006729c4 0f43d7          cmovae  edx,edi
006729c7 837dbc10        cmp     dword ptr [ebp-44h],10h
006729cb 0f4345a8        cmovae  eax,dword ptr [ebp-58h]
006729cf 3b75e8          cmp     esi,dword ptr [ebp-18h]
006729d2 755c            jne     Anti_CrackMe+0x2a30 (00672a30)
```

In the snippet, the first `call` instruction is the password scanning from STDIN, and the last `jne` is a jump to a section where the "wrong password" message is printed.
Let's go through the instructions starting from the bottom.
We see that the second to last instruction (at `006729cf`), `cmp`, compares two memory locations. First, is the memory pointed to by `ESI`, which at `006729be` is set to point to `EBP-48h`, which in this case contains the value `0x8`. The second is a memory location at `EBP-18h` which contains another non-constant value which, in this specific case, is `0x38` (56). If the two compared values are different, the following `jne` instruction will lead us to fail the challenge.
The content of the two memory locations seems pretty uninformative until we check the `cmovae edx,edi`. If we have a look at what `EDI` (and then `EDX` as well, of course) point to, we see that they refer to a pretty interesting region of memory that contains the following

```
0057a490 30 31 31 31 31 30 30 30 30 31 31 31 30 31 31 30 30 31 31 31 31 30 30 30 30  0111100001110110011110000
0057a4a9 31 31 30 31 31 30 30 30 31 31 30 31 30 31 30 30 31 31 31 30 30 31 30 30 31  1101100011010100111001001
0057a4c2 31 31 30 30 30 30 00 f0 ad ba 0d f0 ad ba 0d f0 ad ba ee fe ee ab ab ab ab  110000..................
```

If we check the length of the sequence of 0's and 1's, we see that it is indeed 56 bytes long.
It is pretty obvious then that the `cmp` instruction at `006729cf` is comparing the length of the candidate password we provided with the length of the actual password before checking whether the two actually match. This can be confirmed by trying to use "01111000011101100111100001101100011010100111001001110000" as a password for user "giacomo", which indeed works.

<a href="/assets/images/crackmes/ac3.png"><img src="/assets/images/crackmes/ac3.png" margin="0 250px 0" width="100%"/></a>

Great! So now we have the password for our user, but as we already expected, the password is derived from the username and the one we found only works with the very specific username input of "giacomo".

So we now want to understand how we went from "giacomo" to "01111000011101100111100001101100011010100111001001110000". This is actually quite simple, however, if we put together all the clues we've picked up so far. Namely, we have seen that the username we provided was manipulated by reversing it and feeding it to a ROT9 function to obtain "xvxljrp". If we look at the actual password, it is pretty clear that it is a bit representation of our 7-characters provided username since it is made of 0's and 1's and it is exactly 7 * 8 = 56 bytes long. If we try to convert "xvxljrp" to a bit string we obtain exactly our password, confirming our idea that the password is a bit representation of the ROT9 of the reverse of the username.

To prove that this is the case, I wrote a little snippet in Python to compute the passwords given a username

```python
import sys

def to_bits(x):
    ret = []
    x = ord(x)
    while x > 0:
        ret.append(str(x % 2))
        x = x // 2
    ret = ret[::-1]
    while len(ret) < 8:
        ret.insert(0, '0')
    ret = ''.join(ret)
    return ret

def rot9(x):
    new = []
    for i in x:
        i = ord(i)
        base = 65 if i < 97 else 97
        i = i - base
        i = (i + 9) % 26
        new.append(chr(i + base))
    new = ''.join(new)
    return new


inp = sys.argv[1]
inp = inp[::-1]
inp = rot9(inp)
inp = [to_bits(x) for x in inp]
inp = ''.join(inp)
print(inp)
```

We can try it with some inputs, like so

```bash
giacomo@giacomo:~$ python3 keygen.py random
011101100111100001101101011101110110101001100001
giacomo@giacomo:~$ python3 keygen.py rAnDoM
010101100111100001001101011101110100101001100001
giacomo@giacomo:~$ python3 keygen.py xyzuser
01100001011011100110001001100100011010010110100001100111
giacomo@giacomo:~$ python3 keygen.py XYZuser
01100001011011100110001001100100010010010100100001000111
```

and checking whether they pass the challenge

<a href="/assets/images/crackmes/ac4.png"><img src="/assets/images/crackmes/ac4.png" margin="0 250px 0" width="100%"/></a>
