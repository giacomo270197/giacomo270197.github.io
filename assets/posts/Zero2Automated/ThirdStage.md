---
title: Third Stage
permalink: posts/Zero2Automated/ThirdStage
permalink_name: ThirdStage
---


In the [last post](/posts/Zero2Automated/ThirdStage), we left off after attaching a debugger to the new process spawned by our mid-course sample.
Immediately, we can see this is position-independent code. 

The first thing we notice is that the same encoding scheme used in the previous stage is used here as well, and the same decode-to-load function that computed the checksum of all possible procedures in a library and then loads specific ones is used here as well. This is the same executable, after all.
If we allow execution to jump over these function calls, we can see that `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`, and `InternetCloseHandle` are imported from `wininet.dll`.

Jumping a bit ahead, a decoding loop decodes the following URL in memory: `https://pastebin.com/raw/mLem9DGk`

<a href="/assets/images/Zero2Automated/ts1.png"><img src="/assets/images/Zero2Automated/ts1.png" margin="0 250px 0" width="100%"/></a>

If we visit the Pastebin address, we see that it point to another URL: `https://i.ibb.co/KsfqHym/PNG-02-Copy.png`

<a href="/assets/images/Zero2Automated/ts2.png"><img src="/assets/images/Zero2Automated/ts2.png" margin="0 250px 0" width="100%"/></a>

Following this second URL, we see it points to a PNG image.

<a href="/assets/images/Zero2Automated/ts5.png"><img src="/assets/images/Zero2Automated/ts5.png" margin="0 250px 0" width="100%"/></a>

Following the execution, a function is called. The content of the URL is retrieved with `InternetOpenA` and `InternetOpenUrlA`, and `HttpQueryInfoA` is loaded. Memory is also allocated with `VirtualAlloc`, and the page content is stored in it by `InternetReadFile`. Right after, the handles opened by `InternetOpenA` and `InternetOpenUrlA` are closed.

<a href="/assets/images/Zero2Automated/ts3.png"><img src="/assets/images/Zero2Automated/ts3.png" margin="0 250px 0" width="100%"/></a>

<a href="/assets/images/Zero2Automated/ts4.png"><img src="/assets/images/Zero2Automated/ts4.png" margin="0 250px 0" width="100%"/></a>

Before the function can return, it calls itself again to repeat the same actions on the URL retrieved from Pastebin. However this time a new chunk of memory is allocated with `VirtualAlloc`, and the PNG image is copied into it.

<a href="/assets/images/Zero2Automated/ts6.png"><img src="/assets/images/Zero2Automated/ts6.png" margin="0 250px 0" width="100%"/></a>

<a href="/assets/images/Zero2Automated/ts7.png"><img src="/assets/images/Zero2Automated/ts7.png" margin="0 250px 0" width="100%"/></a>

Execution continues in yet another subroutine. This time a string is decoded to `output.jpg`, and the functions `GetTempPathW`, `CreateDirectoryW`, `CreateFile`, `WriteFile` are imported.

<a href="/assets/images/Zero2Automated/ts8.png"><img src="/assets/images/Zero2Automated/ts8.png" margin="0 250px 0" width="100%"/></a>

`GetTempPathW` is called, and then the string `cruloader` (hence the name of the sample) is appended to it. `CreateDirectoryW` is then used to create a "cruloader" directory in the temporary directory. And then, after that, an `output.jpg` file is created within it with `CreateFile` and the PNG image is written in it with `WriteFile`.

<a href="/assets/images/Zero2Automated/ts9.png"><img src="/assets/images/Zero2Automated/ts9.png" margin="0 250px 0" width="100%"/></a>

<a href="/assets/images/Zero2Automated/ts10.png"><img src="/assets/images/Zero2Automated/ts10.png" margin="0 250px 0" width="100%"/></a>

<a href="/assets/images/Zero2Automated/ts11.png"><img src="/assets/images/Zero2Automated/ts11.png" margin="0 250px 0" width="100%"/></a>

Then a string is decoded to `redaolurc` (reverse of `cruloader`) and then a loop is started that iterates over the memory region that contains the PNG and looks for the string in it. In the following image, we can see that ESI contains a pointer into the loaded image.

<a href="/assets/images/Zero2Automated/ts12.png"><img src="/assets/images/Zero2Automated/ts12.png" margin="0 250px 0" width="100%"/></a>

Once the string is found, we see that it contains lots of seemingly obfuscated data following it. We can expect this will somehow be deobfuscated as execution goes on.

<a href="/assets/images/Zero2Automated/ts13.png"><img src="/assets/images/Zero2Automated/ts13.png" margin="0 250px 0" width="100%"/></a>

As expected, execution continues and the content of the PNG following `redaolurc` is XOR'ed with a hardcoded "key" consisting of 16 "a". This also makes sense looking at the data. Most of its contents are "a", which will be set to 0 once XOR'ed with another "a". If we let the decryption routine run, we see that the data in the PNG turns out to be a PE file after all.

<a href="/assets/images/Zero2Automated/ts14.png"><img src="/assets/images/Zero2Automated/ts14.png" margin="0 250px 0" width="100%"/></a>

We could go ahead and dump the file already, but I do want to see how it's used and how execution is passed to it. At this point, I am convinced this is the next stage, though, since the executable contains the strings that are printed once you let the sample run to completion ("FUD 1337 Cruloader Payload Test. Don't upload to VT.", "Uh Oh, Hacked!!"). Since we know this is what we are looking for, we are going to dump the file to analyze it statically later, once we've seen how it's executed. Before dumping the file, we need to let the sample run the decryption routine completely, then also let it complete another loop after it that appends some "a" to the executable.

Inspecting the executable a bit further, it's obvious that execution is passed the same way as it was passed to this stage. An instance of `svchost.exe` is launched, the executable is written into it, and execution is started with `CreateRemoteThread`. This is the same binary as its parent, after all.

If we dump the executable and open it in Ghidra, we can see it only contains the instructions to open the message box we see after letting it run.

<a href="/assets/images/Zero2Automated/ts15.png"><img src="/assets/images/Zero2Automated/ts15.png" margin="0 250px 0" width="100%"/></a>

With the sample fully analyzed, this practical exercise is completed! I will probably post more walkthroughs of other (non-exam) samples provided in the course.