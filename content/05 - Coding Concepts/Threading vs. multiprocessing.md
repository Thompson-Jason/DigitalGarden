---
---

\#coding

A process is an instance of a program  
A process has memory set aside for code and data   
A [Thread](Thread.md) is part of a process with its own register and stack but can access the memory of the process even on different threads  
Different processes can't normally access each others memory unless you use pipes  
At least in python no threads from the same process can run simultaneously 
