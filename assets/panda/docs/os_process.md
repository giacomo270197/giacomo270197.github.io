---
title: OS Process
permalink: /panda/docs/os_process
permalink_name: OSProcess
---

A library that contains functions used for interacting with other processes on the system. 

<br/>

`int CreateProcess(string cmd_line)`  

Takes a string as an input, and uses it to spawns a new process. The function returns a handle to the newly created process.