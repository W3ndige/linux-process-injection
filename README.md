Linux process injection
=======================

Proof of concept for injecting simple shellcode via ptrace into a running process. 

Description
-----------

With `ptrace()` we can attach to any running process, allowing us to play with the current state. By looking at the `/proc/PID/maps` file we can find a memory region containing permission to execute, for example `r-xp`. 

If we find such region, we can overwrite it's content using `PTRACE_POKETEXT`, with our shellcode. After that, we can modify the registers and set the value of `rip` register with the address of that memory region found in `maps` file. 

In the end we have to continue execution with `PTRACE_CONT`.

POC
---

![Proof Of Concept](https://raw.githubusercontent.com/W3ndige/linux-process-injection/master/poc.png)