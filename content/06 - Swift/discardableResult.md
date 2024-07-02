---
---

A discardableResult keyword is used before a function signature if we may not be going to be assigning the return value of the function. 

````Swift
@discardableResult
func getAge() -> Int{
	return 24
}

getAge()
````
