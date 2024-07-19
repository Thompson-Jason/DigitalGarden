---
tags:
- bug
- project
- website
---

# Problem

Automatic Table of Contents Obsidian plugin doesn't get rendered correctly when being exported with [obsidian-export](../../08%20-%20Tech%20I%20Use/Obsidian/obsidian-export.md). This is something I will need to work on probably adding functionality for this in an obsidian-export fork. This will probably also tie into [Dataview Plugin Bug](Dataview%20Plugin%20Bug.md). I have discussed this plan with [Nick Groenen](https://nick.groenen.me/) the creator of obsidian-export. He has a similar workflow using a similar plugin [obsidian-plugin-dynamic-toc](https://github.com/Aidurber/obsidian-plugin-dynamic-toc/). He shared with me his custom postProcessor for this as an example to build off of for my use case. 

# Solution

My plan for right now is to not fix this bug. *Quartz* already has a table of contents on the right side of every file so having one at the top is not needed. If I ever switch away from Quartz I will need to re-visit this problem.
