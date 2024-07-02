---
---

If you don't release allocated memory after you stop needing it that memory remains reserved for you application this causes a *memory leak* and isn't good this can cause your program to run slow or even crash

`delete pointer;`  
OR  
`delete[] pointer //release block of allocated memory`

You can't just use delete on any pointer it needs to be a pointer that was returned by using the [new keyword](new%20keyword.md)
