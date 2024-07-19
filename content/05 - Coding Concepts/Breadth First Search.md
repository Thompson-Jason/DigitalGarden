---
---

Breadth First Search or BFS is a type of [Graph Traversal](Graph%20Traversal.md). 

The idea of BFS is we will start at a vertex then visit *ALL* vertices of distance 1 from that vertex (all vertices that are connected to that vertex) Then move on to the next vertex and repeat until we have checked *ALL* vertices. 

![BFS.gif](../99%20-%20Meta/Assets/BFS.gif)

# Implementation

The implementation of BFS is similar to the iterative implementation of [Depth First Search](Depth%20First%20Search.md)

````python
marked = [False] * G.size()

def bfs(G, v):
	queue = [v]
	while len(queue) > 0:
		v = queue.pop(0)
		if not marked[v]:
			visit(v)
			marked[v] = True
			for w in G.neighbors(v):
				if not marked[w]:
					queue.append(w)
````
