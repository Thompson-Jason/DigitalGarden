---
tags:
- unfinished
---

In quick sort algorithms you need to pick a pivot. A pivot is typically chosen to be the last element of the list

The pivot is simply the element that other elements are compared to. So if the elements are integers we can pick the last number in the list which lets say is 5 then we can compare the number 5 to be greater-than or less-than the other number. 

In quick sort we will need to keep track of two indices in the array one that starts at the first element in the array (we can call it J) and one that starts 1 before the first element (we can call it I). 

What we need to check is if the value at J is *LESS-THAN* the pivot if J is greater-than or equal to the pivot we don't do anything we just increment J to look at the next number. If J is less-than the pivot we need to increment I then swap the values J and I. 

We then continue this on until we reach the pivot. Once we reach the pivot we know where the pivot needs to be so we increment I and swap that value with the pivot. Now we know everything before the pivot is less-than the pivot and everything after is greater-than the pivot although not necessarily  in the right order. 

Now since Quick sort is a recursive algorithm we need to call the same function two more times once with all the elements on the left side of the pivot and all of the elements on the right side of our pivot but not including the pivot. (0 to pivot and pivot+1 to list.length-1)
