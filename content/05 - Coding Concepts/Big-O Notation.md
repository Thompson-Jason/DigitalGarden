---
tags: []
---

# Overview

Big-O notation is the time complexity of an algorithm 

# O(1)

This is constant time so no matter how big the input grows the time does not change

# O(n)

This is linear time it isn't good but it isn't bad. As our input size grows the time the algorithm takes grows proportionally An example of linear time algorithms is looping through an array because you will loop n times through the array to see everything. 

# O(n^2)

Most nested loops are going to be n^2 because you would be going through a list of n elements n times this isn't always true but its good to know

# O(n\*m)

This isn't super common it really only comes into play if you have a 2D array that are different sizes

# O(n^3)

Again not super common but nested loops that are going three deep will be O(n^3) but the more nested loops you add the higher the power will be. This isn't always true but most of the time. 

# O(log(n)) Log n

Is where math gets involved more and the log function is essentially the opposite of ^2. [Binary Search](Binary%20Search.md) is an example of O(log(n)) because you aren't searching the entire array which would be O(n) you are only searching half then dividing that in half again and again this leads to the O(log(n)) time complexity 

# O(n\*log(n))

Most common nlogn algorithms are sorting functions this is a little bit worse than O(n) but not by much

# O(2^n)

This is most common when doing recursion as the work doubles as it goes for instance computing the Fibonacci sequence recursively runs in this time complexity 

# O(sqrt(n))

This is a pretty rare time complexity it really only occurs when you are trying to get all the factors of a number. You would loop through every number from 1 to the sqrt(n) checking if that number is a factor. since you only go up to the sqrt(n) that makes the time complexity O(sqrt(n))

# O(n!)

This is the largest complexity and is also really rare and doesn't come up a lot.
