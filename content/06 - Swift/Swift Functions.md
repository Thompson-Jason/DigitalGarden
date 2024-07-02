---
---

%% Functions in swift are small bits of code that are to be re-run  %%

Functions in [Swift](Swift.md) are started with the keyword *func* so a basic Swift function signature would look like 

````Swift
func noArgumentsAndNoReturnValue(){

}
````

a function signature that would have a return statement would look like this

````Swift
func plusTwo(value: Int) -> Int{
	return value + 2
}
````

Swift functions can have two different labels for a value one internal label and one external label the internal label would be used inside the function for referring to the value the external label would be used when calling the function.

````Swift
func customMinus(leftHandSide lhs: Int, rightHandSide rhs: Int){
	return lhs - rhs
}

let customSubtracted = customMinus(lhs: 20, rhs: 10)
````

The first word before the space will be the external name and then the second word after the space but before the colon(:) would be the internal name.

You can also use an underscore(\_) to denote no name has the external name as shown below  
**Beware if you use the  underscore(\_) you ==CANNOT== have a name when calling the function it will not work**

````Swift
func customMinus(_ leftHandSide: Int, _ rightHandSide: Int){
	return leftHandSide - rightHandSide
}

let customSubtracted = customMinus(20,10)
````

Swift Functions can have default values so you don't have to supply values but you still could 

````Swift
func getFullName(firstName: String = "Foo", lastName: String = "Bar") -> String{
	return "\(firstName) \(lastName)"
}
````

Then you can call it like any of these

````Swift
getFullName()
getFullName(firstName: "Baz")
getFullName(lastName: "Foo")
getFullName(firstName: "Baz", lastName: "Qux")
````
