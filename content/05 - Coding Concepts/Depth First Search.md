---
tags:
- thingsToKnow
---

The Depth First Search (DFS) is the most fundamental search algorithm used to explore nodes and edges of a graph. It runs with a time complexity of O(V+E) where V is vertices and E is edges and is often used as a building block in other algorithms 

In DFS you don't want to revisit nodes that you have previously visited or nodes that are currently being visited. 

DFS is a recursive algorithm 

DFS is a kind of [Graph Traversal](Graph%20Traversal.md)

# Implementation

## Recursive

The "best" way of implementing DFS is a recursive function. In this function you would need the graph(G), the current vertex you are looking at (v) and a list (map?) of boolean values that show what vertices have been visited

````Python
marked = [False] * G.size()

def dfs(G,v):
	visit(v)
	marked[v] = True
	for w in G.neighbors(v):
		if not marked[w]:
			dfs(G,w)
````

## Iterative

The iterative way of this algorithm is fairly similar just we will be using a *stack* to keep track of what nodes to visit. 

````Python
marked = [False] * G.size()

def dfs_iter(G,v):
	stack = [v]
	while len(stack) > 0:
		v = stack.pop()
		if not marked[v]:
			visit(v)
			marked[v] = True
			for w in G.neighbors(v):
				if not marked[w]:
					stack.appened(w)
````

# Preorder vs Postorder

DFS traversal's have two different ways of ordering the nodes

## Preorder

We output a vertex as part of the order when we encounter a new vertex so whenever we visit a vertex we add it to the order

## Postorder

We output a vertex as part of the order only after there is no where else to explore from that vertex
