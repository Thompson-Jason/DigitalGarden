---
title: The Stack
tags:
- memory
- rust
- cpp
- unfinished
---

The Stack and the heap work very closely together. With a main difference between the two being the data structures they use. 

The Stack probably obviously uses a stack data type so things can be pushed on and popped off but not just removed from the middle. This is great as the main (method/function/block) whatever gets executed first in your language gets added to the stack along with its local variables all as one item on the stack. If a function is called from that main block another block is added **ON TOP OF** of the main block. This function block will also have all of its local variables included with it.
