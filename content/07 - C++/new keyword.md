---
---

new returns a pointer to the requested memory if successful or else throws an *exception*. When using new you need to specify the data type for which the memory is being allocated:  
`Type* pointer = new Type; //request memory for one element`

You can also specify the number of elements you want to allocate that memory for:  
`Type* pointer = new Type[numOfElements]; //request memory for N element(s)`

*Every allocation using new needs to eventually be released using an equal and opposite deallocation via [delete keyword](delete%20keyword.md)*

`delete pointer;`  
OR  
`delete[] pointer //release block of allocated memory`

Rao, S. (2022). In *Sams Teach yourself C++ in one hour A day*, Pearson Education.
