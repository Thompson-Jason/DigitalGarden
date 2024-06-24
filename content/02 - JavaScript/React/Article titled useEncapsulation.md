---
title: Article titled useEncapsulation
---

Recently, I shared this tweet:

![Kyle-Shevlin-Tweet-For-useEncapsulation-Article.png](../../99%20-%20Meta/Assets/Kyle-Shevlin-Tweet-For-useEncapsulation-Article.png)

This tweet was my response to some refactoring of our codebase, but having more than a month now to practice this a few more times, I’m convinced this pattern is the right way to go. I’ll go further and say **most uses of React hooks should be encapsulated in a custom hook**, and I’m going to try and convince you of that on this post.

Before we get started, it will benefit you greatly if you read my post on [encapsulation](https://kyleshevlin.com/encapsulation) first. In that post, I argue that the primary purpose of a function is to encapsulate all the elements of a concern together into a single structure. We’re going to apply this pattern to how we work with React Hooks.

### The Problem

Given the nature of our work, that requirements change frequently and therefore code changes frequently, too, it is not surprising that our codebases become messy. Our logic gets strewn about like tools left on a workbench. The problem is that hidden in the mess of functions and objects is important information that is getting lost. Important historical decisions left without explanation or context and more. I’ll try to come up with a contrived example quickly.

Imagine we have a `Component` that can be toggled into two states: `off` and `on`. We’ll use React Hooks to set this up.

````jsx
function Component() {
  const [state, setState] = React.useState('off')

  const on = React.useCallback(() => {
    setState('on')
  }, [])

  const off = React.useCallback(() => {
    setState('off')
  }, [])

  const toggle = React.useCallback(() => {
    setState(s => (s === 'on' ? 'off' : 'on'))
  }, [])

  return (
    <div>
      <div>State: {state}</div>
      <div>
        <button type="button" onClick={on}>
          Turn On
        </button>
        <button type="button" onClick={off}>
          Turn Off
        </button>
        <button type="button" onClick={toggle}>
          Toggle
        </button>
      </div>
    </div>
  )
}
````

Alright, so far so good. Our `Component` is pretty simple so far and it feels like all of its concerns are handled in an orderly way. But requirements change and now perhaps our component also needs an input field (don’t ask me why, I told you this is contrived).

````jsx
function Component() {
  const [toggleState, setToggleState] = React.useState('off')
  const [inputState, setInputState] = React.useState('')

  const on = React.useCallback(() => {
    setToggleState('on')
  }, [])

  const off = React.useCallback(() => {
    setToggleState('off')
  }, [])

  const toggle = React.useCallback(() => {
    setToggleState(s => (s === 'on' ? 'off' : 'on'))
  }, [])

  const handleInputChange = React.useCallback(e => {
    setInputState(e.target.value)
  }, [])

  const resetInput = React.useCallback(() => {
    setInputState('')
  }, [])

  return (
    <div>
      <div>State: {toggleState}</div>
      <div>
        <button type="button" onClick={on}>
          Turn On
        </button>
        <button type="button" onClick={off}>
          Turn Off
        </button>
        <button type="button" onClick={toggle}>
          Toggle
        </button>
      </div>
      <div>
        <label htmlFor="randomWord">Random Word</label>
        <input
          type="text"
          id="randomWord"
          onChange={handleInputChange}
          value={inputState}
        />
        <button type="button" onClick={resetInput}>
          Reset Input
        </button>
      </div>
    </div>
  )
}
````

Are you starting to see the problem I’m seeing? Even though we wrote relatively clean and clear code, we have started to create a **gap** between related implementation details.

We *need* to call our hooks in the same order every render of `Component`. Those are the rules. To accomplish this, we’ve followed a common organizational pattern with our declarations of state near the top of our component and our various event handlers further down. But in following this pattern, we’ve separated the toggle state and its event handlers with the interruption of declaring another instance of `useState`. Even worse, our input state is separated from its related handlers by three unrelated function declarations. **Just imagine this in your codebase and I’m sure you’ve seen far worse!** This can quickly become a nightmare.

There is, fortunately, a very simple solution: **custom hooks**.

### Why Custom Hooks are the Solution

A custom hook is *just a function* and functions are structures we can use to encapsulate the related elements of a concern and expose an API to our function’s consumer. In the case of our `Component`, these custom hooks are fairly simple to create.

````jsx
function useOnOff() {
  const [state, setState] = React.useState('off')

  const handlers = React.useMemo(
    () => ({
      on: () => {
        setState('on')
      },
      off: () => {
        setState('off')
      },
      toggle: () => {
        setState(s => (s === 'on' ? 'off' : 'on'))
      },
    }),
    [],
  )

  return [state, handlers]
}

function useInput() {
  const [state, setState] = React.useState('')

  const handlers = React.useMemo(
    () => ({
      handleInputChange: e => {
        setState(e.target.value)
      },
      resetInput: () => {
        setState('')
      },
    }),
    [],
  )

  return [state, handlers]
}

function Component() {
  const [toggleState, { on, off, toggle }] = useOnOff()
  const [inputState, { handleInputChange, resetInput }] = useInput()

  return (
    <div>
      <div>State: {toggleState}</div>
      <div>
        <button type="button" onClick={on}>
          Turn On
        </button>
        <button type="button" onClick={off}>
          Turn Off
        </button>
        <button type="button" onClick={toggle}>
          Toggle
        </button>
      </div>
      <div>
        <label htmlFor="randomWord">Random Word</label>
        <input
          type="text"
          id="randomWord"
          onChange={handleInputChange}
          value={inputState}
        />
        <button type="button" onClick={resetInput}>
          Reset Input
        </button>
      </div>
    </div>
  )
}
````

Take notice, our `Component` now only consumes custom hooks. These custom hooks give us a little more context to what they mean, and we don’t have the implementation details of our state handler functions sitting in the middle of our component function.

Another benefit of this pattern is that dependencies quickly become obvious *because they end up being arguments to our custom hooks*. What if our `useInput` hook should begin with an initial state other than an empty string and we use that for resetting the input as well?

````jsx
function useInput(initialState = '') {
  const [state, setState] = React.useState(initialState)

  const handlers = React.useMemo(
    () => ({
      handleInputChange: e => {
        setState(e.target.value)
      },
      resetInput: () => {
        setState(initialState)
      },
    }),
    [initialState],
  )

  return [state, handlers]
}

function Component({ startingWord }) {
  //...
  const [inputState, { handleInputChange, resetInput }] = useInput(startingWord)
  //...
}
````

There are even more benefits. By adding this layer of abstraction between our component and the standard React hooks, we can change the implementation of our custom hook’s API without changing the component. Perhaps I want to use a reducer instead of `useState` for our `useOnOff` hook: Toggle footnote

````jsx
function onOffReducer(state, action) {
  switch (action) {
    case 'ON':
      return 'on'
    case 'OFF':
      return 'off'
    case 'TOGGLE':
      return state === 'on' ? 'off' : 'on'
    default:
      return state
  }
}

function useOnOff() {
  const [state, dispatch] = React.useReducer(onOffReducer, 'off')

  const handlers = React.useMemo(
    () => ({
      on: () => {
        dispatch('ON')
      },
      off: () => {
        dispatch('OFF')
      },
      toggle: () => {
        dispatch('TOGGLE')
      },
    }),
    [],
  )

  return [state, handlers]
}
````

Obviously, this type of change might be completely unnecessary for my example, but I hope you can recognize where this layer of abstraction might be useful to you when you have to change the implementation details of a hook. We were able to replace the entire state management of our hook without changing the API, which means our component behaves the same way, even though the implementation of that behavior has changed quite a bit.

### How to Enforce this Pattern

What good is a pattern if you can’t come up with a way to get others to use it? To steer them down the good path? We can do that for this pattern with an ESLint plugin and rule. Thus, I give you the `eslint-plugin-use-encapsulation` and the `prefer-custom-hooks` rule! You can find it here: [https://github.com/kyleshevlin/eslint-plugin-use-encapsulation](https://github.com/kyleshevlin/eslint-plugin-use-encapsulation).

Following the installation instructions, you’ll see that `prefer-custom-hooks` will warn you whenever you use a React hook directly inside a component. The only way around the warning (other than disabling the rule), is to use the React hooks from within a custom hook.

### Summary

By opting to write all the hooks consumed by your components as custom ones, you will be providing future devs (including yourself) useful context by encapsulating all the pieces of a concern into a single function. By doing this, you gain all the benefits of proper encapsulation and make your components more declarative. You might even gain a few useful reusable hooks in the process.

### useEncapsulation Talk at CascadiaJS

I recently gave a talk on this topic at the CascadiaJS conference and wanted to share that recording with you. Enjoy!

![](https://youtu.be/cyM70d9IpSg)
