---
tags:
- project
---


````toc
````

# Remove Obsidian Comments

 > 
 > \[!info\] Info  
 > Examples here have a space between the first and second % this is to avoid them from being removed before the escape character is implemented

I added a new command line flag *--remove-obsidian-comments* This is implemented as a post_processor removing anything between two % which Obsidian uses to denote comments

````md
This isn't a comment
% % This is a comment % %
````

The current version of this post-processor removes in-line comments as-well as block comments but it does not support escape characters yet. The plan is to add the "\\" as the escape character so I can have mock comments in my notes. 

````md
% % This comment would be removed % %

% %
This comment would also be removed 
% %

\% % This comment wouldn't be removed \% %
````

## Source Code

````rust
pub fn remove_obsidian_comments(_context: &mut Context, events: &mut MarkdownEvents) -> PostprocessorResult {  
    let mut output = Vec::with_capacity(events.len());  
    let mut inside_comment = false;  
    for event in &mut *events {  
        output.push(event.to_owned());  
        match event {  
            Event::Text((ref text)) => {  
                if !text.contains("%%"){  
                    if inside_comment{  
                        output.pop();  
                    }                    continue;  
                }  
                output.pop();  
                if inside_comment{  
                    continue;  
                }  
                if !text.eq(&CowStr::from("%%")){  
                    let re = Regex::new(r"").unwrap();  
                    let result = re.replace_all(text, "").to_string();  
                    output.push(Event::Text(CowStr::from(result)));  
                    continue;  
                }  
                inside_comment = true;  
            }            _ => {  
                if inside_comment{  
                    output.pop();  
                }
            }
        }
    }  
    *events = output;  
    PostprocessorResult::Continue  
}
````
