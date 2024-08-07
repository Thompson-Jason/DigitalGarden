---
tags:
- project
- rust
---

# Overview

obsidian-export is a tool that I use in my workflow to host my digital garden. You can learn more about it at [obsidian-export](../08%20-%20Tech%20I%20Use/Obsidian/obsidian-export.md). You can find the source code of my fork on my [Github](https://github.com/Thompson-Jason/obsidian-export). 

# My Changes

## Remove Obsidian Comments

I added a new command line flag *--comments=\[keep-unchanged|remove\]* This is implemented as a post_processor removing anything between two % which Obsidian uses to denote comments. However if the comment is within a code block (as seen below) it won't be removed. 

````md
This isn't a comment
%% This is a comment %%
````

I use regex in-order to find the comments in the text. 

### Source Code

````rust
pub fn remove_obsidian_comments(  
    _context: &mut Context,  
    events: &mut MarkdownEvents<'_>,  
) -> PostprocessorResult {  
    let mut output = Vec::with_capacity(events.len());  
    let mut inside_comment = false;  
    let mut inside_codeblock = false;  
    let re = LazyCell::new(|| Regex::new(r"%%.*?%%").unwrap());  
  
    for event in &mut *events {  
        output.push(event.to_owned());  
  
        match event {  
            Event::Text(ref text) => {  
                if !text.contains("%%") {  
                    if inside_comment {  
                        output.pop(); //Inside block comment so remove  
                    }  
                    continue;  
                }  
                if inside_codeblock {  
                    continue; //Skip anything inside codeblocks  
                }  
  
                output.pop();  
  
                if inside_comment {  
                    inside_comment = false;  
                    continue;  
                }  
                if !text.eq(&CowStr::from("%%")) {  
                    let result = re.replace_all(text, "").to_string();  
                    output.push(Event::Text(CowStr::from(result)));  
                    continue;  
                }  
                inside_comment = true;  
            }         
               
            Event::Start(Tag::CodeBlock(_)) => {  
                if inside_comment {  
                    output.pop();  
                } else {  
                    inside_codeblock = true;  
                }            
            }            
                
            Event::End(Tag::CodeBlock(_)) => {  
                if inside_comment {  
                    output.pop();  
                } else {  
                    inside_codeblock = false;  
                }            
            }
                        
            Event::End(Tag::Paragraph) => {  
                if output.len() >= 2  
                    && output.get(output.len() - 2) == Option::from(&Event::Start(Tag::Paragraph))  
                {                    
	                // If the comment was the only item on the line remove the start and end  
                    // paragraph events to remove the \n in the output file.                    output.pop();  
                    output.pop();  
                }            
            }            
                
            _ => {  
                if inside_comment {  
                    output.pop();  
                }            
            }        
        }    
    }    
    *events = output;  
    PostprocessorResult::Continue  
}
````

## Remove table of contents

In my obsidian vault I have a table of contents at the top of most of my notes. However, I currently host my notes through *Quartz* which offers a table of contents on the right side of the screen. Because of this I don't also need a table of contents on the top so I just remove it from the markdown file before publishing. I originally was going to render the table of contents myself (seen here [Automatic Table of Contents Bug](../04%20-%20Web%20Programming/Personal%20Website/Automatic%20Table%20of%20Contents%20Bug.md)) but I decided this wasn't worth the effort and to just use the quartz table of contents.

This code is heavily borrowed from an example provided by Nick Groenen, creator of obsidian-export. This option is invoked through the flag *--remove-table-of-contents*

### Source Code

````rust
pub fn remove_toc(_context: &mut Context, events: &mut MarkdownEvents) -> PostprocessorResult {  
    let mut output = Vec::with_capacity(events.len());  
  
    for event in &mut *events {  
        output.push(event.to_owned());  
        match event {  
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref language_tag))) => {  
                if language_tag != &CowStr::from("toc") && language_tag != &CowStr::from("table-of-contents")  {                    
	                continue;  
            }                
            
            output.pop(); // Remove codeblock start tag that was pushed onto output              
            }  
            
            Event::End(Tag::CodeBlock(CodeBlockKind::Fenced(ref language_tag))) => {  
                if language_tag == &CowStr::from("toc") && language_tag != &CowStr::from("table-of-contents")  {                    
	                // The corresponding codeblock start tag for this is replaced with regular  
                    // text (containing the Hugo shortcode), so we must also pop this end tag.                    
                    output.pop();  
                }            
            }            
            _ => {}  
        }    
    }    
    *events = output;  
    PostprocessorResult::Continue  
}
````
