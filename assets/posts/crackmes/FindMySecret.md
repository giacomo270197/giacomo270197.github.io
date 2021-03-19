---
title: Crackmes - Find My Secret
permalink: posts/crackmes/FindMySecret
permalink_name: FindMySecret
---

As a part of working on my reverse engineering skills, I decided to do some [crackmes](https://crackmes.one), since they are recommended a bit everywhere. I am currently still focusing on Windows stuff since that is a gap I felt the need to fill. I started with the 'easy' rated ones (because we all start somewhere). I did some 'very easy' ones, but they really are very easy and I don't think they are worth talking about.

So without further ado, let's get into my first (serious-ish) crackmes: [FindMySecret](https://crackmes.one/crackme/6005140733c5d42c3d016718)

Like many crackmes, this challenge is all about getting your hands on a "password". Running the executable we are greeted with the following

<a href="/assets/images/crackmes/fms10.png"><img src="/assets/images/crackmes/fms10.png" alt="FindMySecret" margin="0 250px 0" width="100%"/></a>

So apparently we have to find a number that serves as a password, and the number should be within a certain range.
At this point, I am drawing up some sort of idea about what the program is probably like. I expect to see the welcome string (`Enter the secret number`) repeated in some loop. In the same loop, I expect to find a `scanf` or something akin to it, some routine to check the input, and some code to tell us whether we hit the jackpot or not. Clearly, the checking code is where we hope to find our password.

Loading up the file on Ghidra, unfortunately, I cannot find any function that stands out for being `main()`, so I go searching for the welcome string to see if I can find it. The string shows up as follows:

<a href="/assets/images/crackmes/fms1.png"><img src="/assets/images/crackmes/fms1.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

If we follow the function Ghidra tells us the string is used in we end up to this bit of decompiled code (which I call `main`, even if it might not be at this point)

```c
undefined4 main(undefined param_1)

{
  undefined2 local_18 [6];
  undefined *local_c;
  
  local_c = &param_1;
  FUN_004019c0();
  local_18[0] = 0;
  _beginthread((_StartAddress *)PTR_DAT_00403028,0,local_18);
  do {
  } while( true );
}
```

This doesn't tell us much. It seems some function is called directly with a pointer to memory. Looking at the disassembly is more useful in this case. If we go to the `printf` for our welcome string we are met with something like this

<a href="/assets/images/crackmes/fms2.png"><img src="/assets/images/crackmes/fms2.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

From here on out we can start checking what the function does. We are interested in `cmp` instructions especially or function calls that might lead us to find the password.
The first noteworthy point is a `cmp` between `EAX` (where the output of `scanf` is) and a hardcoded hex value that stands for 9999. Id `EAX` turns out being bigger than that, the `jg` instruction will redirect execution to a section that will print out the out-of-range message. We now know that 9999 is the limit out input goes to.

<a href="/assets/images/crackmes/fms3.png"><img src="/assets/images/crackmes/fms3.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

We then run into a function call that points to the following decompiled function

```c
void __cdecl check(short *param_1)

{
  if (DAT_00406034 == '\0') {
    _DAT_004063e8 = _DAT_004063e8 * 10000.0;
    DAT_00406034 = '\x01';
  }
  if ((_DAT_004063e8 <= (double)*param_1) || ((double)*param_1 <= _DAT_004063e8 - 1.0)) {
    *param_1 = 0;
  }
  else {
    *param_1 = 1;
  }
  return;
}
```

The function seems to multiply a global variable `_DAT_004063e8` by 10000 as a one-off because another global variable `DAT_00406034` is then set to prevent this from happening again. After that, there is a convoluted check to verify that the input to the function (which we know being `scanf` output from the caller) is within a range of <1 to `_DAT_004063e8`. This seems very much like the checking function we were looking for, and we will therefore call it `check`.

Back to the body of our `main` we now see that the output of `check` is fed into the following decompiled function

```c
void __cdecl printResult(int param_1)

{
  if (param_1 == 0) {
    puts("Nope, you have not yet found the secret number.");
  }
  else {
    puts("Success! You have completely reverse engineered and found the secret number!");
  }
  return;
}
```

which confirms that `check` is indeed what we should focus on. Since this function prints the final result, we will call it `printResult``.

At this point, our `main` body looks like this

<a href="/assets/images/crackmes/fms5.png"><img src="/assets/images/crackmes/fms5.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

What we now need to find, is where `_DAT_004063e8` is initialized, and to what. Ghidra shows us that the variable is only used in one other function other than `check`

<a href="/assets/images/crackmes/fms6.png"><img src="/assets/images/crackmes/fms6.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

We follow the function and find this decompiled routine

```c
void setGlobal(void)
{
  double dVar1;
  time_t tVar2;
  
  do {
    tVar2 = time((time_t *)0x0);
    dVar1 = (double)((int)tVar2 % 0x32) / 50.0;
  } while (dVar1 == 0.0);
  _DAT_004063e8 = dVar1;
  return;
}
```

In short, the function initializes a variable to a random number depending on the time of execution, `mod`s it by 50 (0x32 is hex for 50) and divides by 50 so that the result will always be between 0 and 1. It is in a loop because if the global variable ends up being 0 the computation happens again. The creator must have thought that 0 (0 * 10000) would be anyone's initial guess. Since we now know this function initially sets `_DAT_004063e8`, we will call it `setGlobal`.

And this is pretty much it. Only thing that's left to do is to run it, check the memory address containing `_DAT_004063e8` (0x004063e8, conveniently), multiply by 10000 and get the answer.
So let's go and do that, here you can see the memory dump at the specific address on Immunity Debugger (memory dump is low left)

<a href="/assets/images/crackmes/fms7.png"><img src="/assets/images/crackmes/fms7.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

Once we extracted the hex value (`0x3fe280f0197c71a7`) we go and convert it to double online, since Immunity does not seem to recognize it. We get `0.5782` as a result.

<a href="/assets/images/crackmes/fms9.png"><img src="/assets/images/crackmes/fms9.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

Now we multiply `0.5782` by 10000 as we found out the code does, and if we insert `5782` as "secret number" we are welcomed with a success message

<a href="/assets/images/crackmes/fms8.png"><img src="/assets/images/crackmes/fms8.png" alt="SearchingMain" margin="0 250px 0" width="100%"/></a>

And we solved the challenge!