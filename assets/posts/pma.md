---
title: Practical Malware Analysis
permalink: /posts/pma
permalink_name: pma
---

Lately I decided to dive into malware analysis. I have always been interested, and I believe it will be a nice way to combine my software developer and securiy background.

So I went and picked up Practical Malware Analysis by Michael Sikorski.

![Practical Malware Analysis](/assets/images/pma.jpg)

Now the book is great. It might feel somewhat dated when the examples are given on a Windows XP machine, but for starters this covers a lot of ground and goes very in depth. I also learnt a lot about Windows internals, which was definetly not my strongest suit.

The book explains a lot of different techniques malware pieces commonly use, and then goes onto showing how to spot the very same techniques in a disassembler.
This made me think, wouldn't it be easier to understand if some software is trying to do something malicious is I myself know how to program those very same attack methods? I believe yes.

So I went ahead and I decied to implement some of these techniques myself, and I will post a breakdown of the implementations in blog posts as I go along. The code can be found in [this repo](https://github.com/giacomo270197/Malware_Techniques_Implementations).

Also, I decided not to program these in C/C++, but rather in Go. There are several reasons for this. First off I just want to get more familiar with Go, at least as familiar as I am with C (C++, however, I just cannot do). Besides, while there are some wrapper Go packages around Windows native types and API, not everything is implemented. This should force me to really understand what's happening as I go and fill the implementations gaps I need (for example, when I'll need to implement Windows structs and such). Finally, I recently found [this article](https://www.zdnet.com/google-amp/article/go-malware-is-now-common-having-been-adopted-by-both-apts-and-e-crime-groups/) explaining how Go compiled malware has grown by over 2000% in the past few years. I hope this can be of use for those trying to either test their security tools or practicing their reverse engineering on Go binaries.

I hope you'll enjoy the upcoming posts, and if you are interested in this topic, I would definetly consider buying the book.