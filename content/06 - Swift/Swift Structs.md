---
---

A struct is similar to a C++ Struct. You are essentially just creating your own data type

This is what it would look like to declare a struct

````Swift
struct Person{
	let name: String
	let age: Int
}
````

To instantiate a struct variable it would look like this

````Swift
let foo = Person(name: "Foo", age: 20)
````

You can access the properties of a struct using *Dot Notation*

````Swift
foo.name
foo.age
````

For structs constructors are implicitly created so you do not need to declare one although you can. For this structs are preferable over classes in Swift.

This is how you would create a custom constructor for your struct 

````Swift
struct CommodoreComputer{
	let name: String
	let manufacturer: String

	init(name: String){
		self.name = name
		self.manufacturer = "Commodore"
	}
}
````

A constructor will have the keyword "init" which would be the only keyword for this special "function"

Structs also have [Computed Properties](../02%20-%20JavaScript/Computed%20Properties.md)

So far all the structs above have been [immutable](../05%20-%20Coding%20Concepts/Immutable.md) 

How would a *mutable* struct look like?

````Swift
struct Car{
	let currentSpeed: Int
	
	mutating func drive(speed: Int){
		"Driving..."
		currentSpeed = speed
	}
}
````

You need to use the *mutating* keyword before the *func* keyword. This tells the swift compiler that this function is going to be changing the values in the struct. While this can be done this is bad practice and shouldn't really be done in a struct. 

Swift structs do not have [SubClassing](SubClassing.md)
