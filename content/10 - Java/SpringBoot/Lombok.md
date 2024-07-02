---
---

The Lombok library helps generate boiler plate code for POJO classes (during compile time)

Lombok has some helpful annotations that can save a lot of time. The main Lombok annotation I would use would be 

@Data

The data annotation will automatically generated the getters/setters/toString methods at compile time. This allows your POJO classes to look much cleaner

````Java
@Data
public class Author {
	private Long id;
	private String name;
	private Integer age;
}
````

This can be the whole class and it would give your complete functionality. 
