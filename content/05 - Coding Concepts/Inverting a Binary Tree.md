---
---

Inverting a binary tree has kinda become a meme problem so it probably won't show up in an interview but it is a pretty simple problem to understand if you look at a diagram

![Invert_Binary_Tree.png](../99%20-%20Meta/Assets/Invert_Binary_Tree.png)

The root stays the same and you are just [recursively](Recursion.md) swapping the children. 

So you would need to switch the left and right children of the root then recursively call that function again with each child as the root to then swap their children and so on. 

````python
# Definition for a binary tree node.
# class TreeNode:
#	 def __init__(self, val=0, left=None, right=None):
#		self.val = val
#		self.left = left
#		self.right = right

def invertTree(self, root: Optional[TreeNode]) -> Optional[TreeNode]:
	if root:
		temp = root.left
		root.left = root.right
		root.right = temp
		root.left = self.invertTree(root.left)
		root.rigth = self.invertTree(root.right)
	return root
````
