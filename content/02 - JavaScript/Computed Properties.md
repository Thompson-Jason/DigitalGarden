---
---

This is essentially assigning a variable like how a function would seem. I know that sounds confusing but you can see below what I am talking about. the variable would have to be a *var* and not a *let* then it can be assigned inside the curly brackets. 

%% It looks like this is using the implicit return like in a function but I am not sure %%

````JavaScript
struct Person{
	let firstName: String
	let lastName: String
	var fullName: String {
		"\(firstName) \(lastName)"
	}
}
````
