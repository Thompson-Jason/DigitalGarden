---
---

Binary search is a fairly simple search algorithm but it can only be done on *SORTED* data. 

If you have a sorted list you can look in the middle of that list for what you are looking for and determine if what you are looking for would come before or after that middle point. Once you know that it comes after (or before) that middle point then there is no sense to look at the other half of the list so you just ignore it. you can then go in the middle of this new smaller list and do the same thing until you find your number. 
