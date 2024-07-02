---
---

React comes with a whole bunch of built in hooks with the ability to create our own hooks

## useState()

UseState is using a variable as a state. The useState() method call returns an array which is the variable and the function used to set the variable 

````jsx
const [title, setTitle] = useState("");
````

The value passed into the useState() method will be the default value of the variable returned to the first item in the array (in this case the variable *title*). You can then use the state variables in [React Forms](React%20Form.md) like the below example. In the following example we need to add a little to the \<input> tag first we need to associate the value of the input to our useState() variable. Then we need to also add an "onChange" function which in this case is just an *Arrow Function* that calls the "setValue" function supplied by our useState() variable. This is the name that we assigned to the function when creating the useState variable. 

### Example

````jsx
import "./App.css"
import { useState } from "react"

function App(){

	const [title, setTitle] = useState("");
	const [color, setColor] = useState("#000000") // This default value is the hex code for black

	const submit = (e) => {
		e.preventDefault(); //This prevents the default behavior of the form which in this case is refreshing the page. 
		alert(`${title}, ${color}`)
	}

	return (
		<form onSubmit={submit}>
			<input value={title} onChange={(event) => setTitle(event.target.value)} type="text" placeholder="color title..." />
			<input value={color} onChange={(event) => setColor(event.target.value)} type="color" />
			<button>ADD</button>
		</form>
	)
}

export default App;
````

## useEffect()

## useContext()

## useReducer()

## useCallback()

## useMemo()

## useRef()

Ref is short for "reference". We can use this hook to reach out to an element and check what its value is. UseRef reaches out to some UI element and gets its value. For instance in the example below we create two useRef() hook variables (txtTitle and hexColor) we then assign these variables to the input fields of the [React Form](React%20Form.md). These fields then stay updated with what the input of the form is. You can get the value of an input by using *variableName*.current.value A key difference between this and useState() is that useRef() does **NOT** re-render the page. 

### Example

````jsx
import "./App.css"
import { useRef } from "react"

function App(){

	const txtTitle = useRef();
	const hexColor = useRef();

	const submit = (e) => {
		e.preventDefault(); //This prevents the default behavior of the form which in this case is refreshing the page. 
		const title = txtTitle.current.value;
		const color = hexColor.current.value;
		alert(`${title}, ${color}`)
	}

	return (
		<form onSubmit={submit}>
			<input ref={txtTitle} type="text" placeholder="color title..." />
			<input ref={hexColor} type="color" />
			<button>ADD</button>
		</form>
	)
}

export default App;
````

### Example Rendered
