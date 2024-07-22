---
tags:
- '#bug'
- project
- website
title: Personal Website Refresh Bug
---

# Problem

Site seems to work as expected and when navigating around the site using the buttons (like in the nav bar and such) I can move between pages. However, when refreshing the page (⌘ + r) I would receive a 404 error.

# Solution

Added [.htaccess](../htaccess.md) page to the root folder. This uses the RewriteEngine to rewrite the url to append .html to the path.

## Issues with this solution

* The .htaccess page will need to be updated for every new page added to the website.
* The dynamically rendered project pages are still an issue that needs to be solved

# Reason for the issue

When statically exporting a [NextJS](../../02%20-%20JavaScript/NextJS.md) project it creates a new .html file for each page so the about page would turn into about.html. This isn't an issue and [under the hood](../../99%20-%20Meta/Terms.md#under-the-hood) NextJS knows that about routes to about.html so when you hit a button on the homepage for instance it can route you to the correct page. The issue arrises when you type your address into the address bar (or refresh the page) then NextJS isn't routing your request the browser is just trying to grab the file requested which in this case doesn't exist resulting in the 404 error. This is where the solution comes in which just appends .html to the url path.

# .htaccess file

````haxe
RewriteEngine On

#Pages
RewriteRule ^skills skills.html
RewriteRule ^portfolio portfolio.html
RewriteRule ^contact$ contact.html
````

# Sources

While searching for a solution to this problem I came across this blog post by [Anjanesh Lekshminarayanan](https://anjanesh.dev/). This post helped me find the solution and learn more about what the problem was. I highly suggest checking out Anjanesh and his blog post. 

https://anjanesh.dev/exporting-a-nextjs-app-with-correct-static-page-routes-on-the-server
