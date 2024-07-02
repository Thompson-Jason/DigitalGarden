---
---

\#coding #cpp #samsTeachYourself

You can create functions with the same name and return type but with different parameters, this is called overloaded functions.

A function can have 'default parameters' however they must be specified at the end of the parameter list unless all parameters have a default expression 

`double Area(double Pi = 3.14, double radius);`  
This will result in a compiler error as the default parameter 'Pi' is not at the end of the parameter list for this to compile it would need to look like  
`double Area(double radius, double Pi = 3.14);`  
OR  
`double Area(double Pi = 3.14, double radius = 0.0);`
