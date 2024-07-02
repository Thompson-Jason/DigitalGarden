---
---

\#cpp #coding #samsTeachYourself 

A pointer is a variable that stores a memory address in it  
Memory locations are typically addressed using [Hexadecimal](../05%20-%20Coding%20Concepts/Hexadecimal.md)

Pointer declaration syntax

````C++ TI:"Test"
	PointedType* PointerVariableName
````

````
Example:
````

````C++ "Example" "FOLD"
		int* result
````

As is the case with most other variables when you don't initialize a pointer it is given a random value which in this case would be a random address in memory that could be pointing to something important so you would typically initialize a pointer to NULL

````C++ "FOLD"
	int* result = NULL
````

In order to get the memory address for a specific variable you would need to use the [reference operator](reference%20operator.md) (&) 

In order to get the data stored in a memory address you would need to use the [dereference operator](dereference%20operator.md) (\*)

You can use the dereference operator to manipulate the data at the end of the pointer

````C++ "FOLD"
	int age = 24; 
	int* ptr = &age;
	// ptr is an integer pointer that points to the location in memory that stores 'age'
	*ptr = 30;
	//age would now be 30 because you accessed it through the pointer
````
