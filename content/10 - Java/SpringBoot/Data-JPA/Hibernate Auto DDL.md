---
---

Hibernate creates your db for you so there is no need for a db schema 

In SpringBoot you set the property   
* spring.jpa.hibernate.ddl-auto*

Then you would have one of the following values assigned to that property that would influence how the schema tool management will manipulate the db schema on startup

1. create
1. create-drop
1. validate
1. update
   1. This operation will query the JDBC driver's API to get the db metadata then Hibernate compares the object model it creates based on reading your annotated classes (or HBM XML mappings) and will attempt to adjust the schema on-the-fly
   1. The update operation for example will attempt to add new columns, constraints, etc but will never remove a column or constraint that may have existed previously but no longer does as part of the object model from a prior run. 
   1. Update is typically used in the development environment to automatically modify the schema to add new additions upon restart but this doesn't remove any columns or *constraints*. 

It is generally recommended to NOT use ddl generation in prod

## Stack Overflow answer I got this note from

https://stackoverflow.com/questions/42135114/how-does-spring-jpa-hibernate-ddl-auto-property-exactly-work-in-spring
