---
tags:
- rust
- coding
- memory
- unfinished
---

Rust has the concept of *ownership* which plays a heavy role in the life of a Box in rust. When creating a variable in Rust that variable is typically created on [The Stack](../05%20-%20Coding%20Concepts/The%20Stack.md) `let x1 = 41`however if you want something not tied to the same stack to have access to that variable you could allocate it on [The Heap](../05%20-%20Coding%20Concepts/The%20Heap.md). One way of doing this is to use a Box `let y1 = Box::new(84)`. Boxes are a great way of allocating a variable onto the heap. However, Boxes can't be copied they are moved to a new owner. In the event that this new owner goes out of scope the Boxed variable becomes inaccessible and is deallocated on the heap.
