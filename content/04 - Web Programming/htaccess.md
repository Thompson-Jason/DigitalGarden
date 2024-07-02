---
---


 > 
 > \[!caution\] Warning  
 > This is a local copy of what can be found on [Wikipedia](https://en.wikipedia.org/wiki/.htaccess) This page isn't updated like the Wikipedia site so for the most up to date information check them out. 

# .htaccess

An **.htaccess** (*[hypertext](https://en.wikipedia.org/wiki/Hypertext "Hypertext") access*) file is a [directory](https://en.wikipedia.org/wiki/Directory_(file_systems) "Directory (file systems)")-level [configuration file](https://en.wikipedia.org/wiki/Configuration_file "Configuration file") supported by several [web servers](https://en.wikipedia.org/wiki/Web_server "Web server"), used for configuration of [website](https://en.wikipedia.org/wiki/Website "Website")-access issues, such as [URL redirection](https://en.wikipedia.org/wiki/URL_redirection "URL redirection"), [URL shortening](https://en.wikipedia.org/wiki/URL_shortening "URL shortening"), [access control](https://en.wikipedia.org/wiki/Computer_access_control "Computer access control") (for different [web pages](https://en.wikipedia.org/wiki/Web_page "Web page") and files), and more. The 'dot' ([period](https://en.wikipedia.org/wiki/Full_stop "Full stop") or [full stop](https://en.wikipedia.org/wiki/Full_stop "Full stop")) before the file name makes it a [hidden file](https://en.wikipedia.org/wiki/Hidden_file_and_hidden_directory "Hidden file and hidden directory") in [Unix](https://en.wikipedia.org/wiki/Unix "Unix")-based environments.

A site could have more than one .htaccess file, and the files are placed inside the web tree (i.e. inside directories and their sub-directories), and hence their other name *distributed configuration files*.[1](https://en.wikipedia.org/wiki/.htaccess#cite_note-1)

.htaccess files act as a subset of the server's global configuration file (like [httpd.conf](https://en.wikipedia.org/wiki/Httpd.conf "Httpd.conf")) for the directory that they are in, or all sub-directories.[2](https://en.wikipedia.org/wiki/.htaccess#cite_note-2)

The original purpose of .htaccess—reflected in its name—was to allow per-directory access control by, for example, requiring a password to access [World Wide Web](https://en.wikipedia.org/wiki/World_Wide_Web "World Wide Web") content. More commonly, however, the .htaccess files define or override many other configuration settings such as content type, [character set](https://en.wikipedia.org/wiki/Character_set "Character set"), [Common Gateway Interface](https://en.wikipedia.org/wiki/Common_Gateway_Interface "Common Gateway Interface") handlers, etc.

## Format and language

.htaccess files are written in the **Apache Directives** variant of the [Perl Compatible Regular Expressions](https://en.wikipedia.org/wiki/Perl_Compatible_Regular_Expressions "Perl Compatible Regular Expressions") (PCRE) language. Learning basic PCRE itself can help in mastering work with these files.

For historical reasons, the format of .htaccess files is a limited subset of the [Apache HTTP server](https://en.wikipedia.org/wiki/Apache_HTTP_server "Apache HTTP server")'s global configuration file [httpd.conf](https://en.wikipedia.org/wiki/Httpd.conf "Httpd.conf")[3](https://en.wikipedia.org/wiki/.htaccess#cite_note-3) even when used with web servers such as [Oracle iPlanet Web Server](https://en.wikipedia.org/wiki/Oracle_iPlanet_Web_Server "Oracle iPlanet Web Server")[4](https://en.wikipedia.org/wiki/.htaccess#cite_note-4) and [Zeus Web Server](https://en.wikipedia.org/wiki/Zeus_Web_Server "Zeus Web Server") which have very different native global configuration files.

## Common usage

* [Authorization](https://en.wikipedia.org/wiki/Authorization), [authentication](https://en.wikipedia.org/wiki/Authentication "Authentication")
  
  * A .htaccess file is often used to specify security restrictions for a directory, hence the filename "access". The .htaccess file is often accompanied by a [.htpasswd](https://en.wikipedia.org/wiki/.htpasswd ".htpasswd") file which stores valid [usernames](https://en.wikipedia.org/wiki/Username "Username") and their [passwords](https://en.wikipedia.org/wiki/Password "Password").[5](https://en.wikipedia.org/wiki/.htaccess#cite_note-5)
* [URL rewriting](https://en.wikipedia.org/wiki/URL_rewriting "URL rewriting")
  
  * Servers often use .htaccess for [rewriting](https://en.wikipedia.org/wiki/Rewriting "Rewriting") long, overly comprehensive URLs to shorter and more memorable ones.
* Blocking (access control)
  
  * Use *allow/deny* to block users by IP address or domain. Also used to block bad bots, rippers and referrers.
* SSI
  
  * Enable [server-side includes](https://en.wikipedia.org/wiki/Server-side_include "Server-side include").
* Directory listing
  
  * Control how the server will react when no specific web page is specified.
* [Customized error responses](https://en.wikipedia.org/wiki/Custom_error_page "Custom error page")
  
  * Changing the page that is shown when a server-side error occurs, for example [HTTP 404 Not Found](https://en.wikipedia.org/wiki/HTTP_404 "HTTP 404") or, to indicate to a search engine that a page has moved, [HTTP 301 Moved Permanently](https://en.wikipedia.org/wiki/HTTP_301 "HTTP 301").[6](https://en.wikipedia.org/wiki/.htaccess#cite_note-6)
* [MIME types](https://en.wikipedia.org/wiki/MIME_types "MIME types")
  
  * Instruct the server how to treat different varying file types.
* Cache control
  
  * .htaccess files allow a server to control [caching](https://en.wikipedia.org/wiki/Web_cache "Web cache") by [web browsers](https://en.wikipedia.org/wiki/Web_browser "Web browser") and [proxies](https://en.wikipedia.org/wiki/Caching_proxy "Caching proxy") to speed up websites,[7](https://en.wikipedia.org/wiki/.htaccess#cite_note-7) reduce [bandwidth](https://en.wikipedia.org/wiki/Bandwidth_(computing) "Bandwidth (computing)") usage, [server](https://en.wikipedia.org/wiki/Web_server "Web server") load, and perceived [lag](https://en.wikipedia.org/wiki/Latency_(engineering) "Latency (engineering)"). .htaccess also adds the cache age to the webpage resources so that on revisiting the page, the elements are reloaded from browser cache till the age mentioned expires, instead of requesting the resource again from the server.
* [HTTPS](https://en.wikipedia.org/wiki/HTTPS "HTTPS") & [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security "HTTP Strict Transport Security")
  
  * Implementation of both HTTPS and HSTS on Apache servers is largely dependent on correct [URL rewriting](https://en.wikipedia.org/wiki/URL_rewriting "URL rewriting") & header information mentioned in .htaccess file. Any incorrect syntax in the file while deploying HTTPS or HSTS leads to a failure in implementation.

## Advantages

### Immediate changes

Because .htaccess files are read on every request, changes made in these files take immediate effect – as opposed to the main configuration file, which requires the server to be restarted for the new settings to take effect.

### Non-privileged users

For servers with multiple users, such as on [shared web hosting](https://en.wikipedia.org/wiki/Shared_web_hosting_service "Shared web hosting service"), it is often desirable to allow individual users the ability to alter their site configuration. The use of .htaccess files allows such individualization, and by unprivileged users – because the main server configuration files do not need to be changed.[8](https://en.wikipedia.org/wiki/.htaccess#cite_note-8)

## Disadvantages

Controlling Apache using the main server configuration file [httpd.conf](https://en.wikipedia.org/wiki/Httpd.conf "Httpd.conf")[9](https://en.wikipedia.org/wiki/.htaccess#cite_note-9) is often preferred for security and performance reasons:[10](https://en.wikipedia.org/wiki/.htaccess#cite_note-10)

### Performance loss

For each [HTTP request](https://en.wikipedia.org/wiki/HTTP_request "HTTP request"), there are additional file-system accesses for parent directories when using .htaccess, to check for possibly existing .htaccess files in those parent directories which are allowed to hold .htaccess files. It is possible to programmatically migrate directives from .htaccess to httpd.conf if this performance loss is a concern.[11](https://en.wikipedia.org/wiki/.htaccess#cite_note-11)

### Security

Allowing individual users to modify the configuration of a server can cause security concerns if not set up properly.[12](https://en.wikipedia.org/wiki/.htaccess#cite_note-12)

### Syntax

.htaccess is usually very sensitive to syntax errors. Due to this any misspellings may lead to [server errors](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_server_errors "List of HTTP status codes") and web resources in the directory with the erroneous .htaccess not being displayed at all.

## In popular culture

Portions of the 2020 video game [Mackerelmedia Fish](https://en.wikipedia.org/wiki/Mackerelmedia_Fish "Mackerelmedia Fish"), which explores themes of Internet culture, have been implemented directly on a website's open .htaccess directories.[13](https://en.wikipedia.org/wiki/.htaccess#cite_note-13)
