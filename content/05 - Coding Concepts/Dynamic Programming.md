---
tags:
- thingsToKnow
---

Dynamic programming is just dividing a problem into subproblems which can then be brought back together to solve the original problem

1. Define the subproblem
1. Whats the base case?
1. Find recursive formula for general solution

Not every Dynamic Programming problem needs to be solved by [recursion](Recursion.md) it isn't even always the best solution but you can usually solve the problem with recursion

For instance the classic problem of getting the nth Fibonacci number this is easily solved by dynamic programming and is made *WAY* better using *Memoization*

````Python
def fib(n, memo):
	if memo[n] != None:
		return memo[n]
	if n==1 or n==2:
		return 1
	else:
		result = fib(n-1, memo) + fib(n-2, memo)
		memo[n] = result
	return result
````

In order to get the nth number of the Fibonacci sequence you need to know n-1 and n-2. We use memoization to "save" previous computed values so we don't always have to compute them again if they have already been computed. We just save them to the memo list and look them up if needed.
