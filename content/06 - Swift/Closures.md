---
---

Closures are a special type of function that are created in-line so that you can actually pass them to another function. 

%% This sounds kinda like a predicate in Java  %%

I am going to break up a closure statement here so it is a little easier 

````Swift
let add: (Int, Int) -> Int
````

This is how you declare a closure it is essentially the same as declaring a variable but the type is a functions input types and an optional output. But, this is not a complete closure statement this is the same as 

````Swift
let myName: String
````

This doesn't actually define what myName is just declares that it is a variable

Here would be a full closure statement. Which does look very similar to [Swift Functions](Swift%20Functions.md) because it is really just a special type of function

````Swift
let add: (Int, Int) -> Int = { (lhs: Int, rhs: Int) -> Int in
	return lhs + rhs
}
````

What a Closure would most often be used for is passing into another function. This is how a function signature could look when using a Closure

````Swift
func customAdd(lhs: Int, rhs: Int, function: (Int, Int) -> Int) -> Int{
	return function(lhs,rhs)
}
````

which would then look like this when called

````Swift
let addedValue: Int = customAdd(lhs: 20, rhs: 10, function: add)
````
