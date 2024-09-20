# BSCP---Notes
Notes and Additional Payloads for Web Application Vulnerabilities Topics covered in PortSwigger Academy
~This is just another Notes Repo for the BSCP Exam, I hope you will find it helpful. For some Topics, I have additional payloads and notes that go beyond BSCP Exam but I decided to include them if somebody is interested in those~
~Topics covered in this Repo are not listed by importance or in order like in PortSwigger Academy~


          _____                    _____                    _____                    _____          
         /\    \                  /\    \                  /\    \                  /\    \         
        /::\    \                /::\____\                /::\    \                /::\    \        
       /::::\    \              /:::/    /               /::::\    \              /::::\    \       
      /::::::\    \            /:::/    /               /::::::\    \            /::::::\    \      
     /:::/\:::\    \          /:::/    /               /:::/\:::\    \          /:::/\:::\    \     
    /:::/__\:::\    \        /:::/    /               /:::/__\:::\    \        /:::/__\:::\    \    
   /::::\   \:::\    \      /:::/    /               /::::\   \:::\    \      /::::\   \:::\    \   
  /::::::\   \:::\    \    /:::/    /      _____    /::::::\   \:::\    \    /::::::\   \:::\    \  
 /:::/\:::\   \:::\ ___\  /:::/____/      /\    \  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\____\ 
/:::/__\:::\   \:::|    ||:::|    /      /::\____\/:::/  \:::\   \:::|    |/:::/  \:::\   \:::|    |
\:::\   \:::\  /:::|____||:::|____\     /:::/    /\::/   |::::\  /:::|____|\::/    \:::\  /:::|____|
 \:::\   \:::\/:::/    /  \:::\    \   /:::/    /  \/____|:::::\/:::/    /  \/_____/\:::\/:::/    / 
  \:::\   \::::::/    /    \:::\    \ /:::/    /         |:::::::::/    /            \::::::/    /  
   \:::\   \::::/    /      \:::\    /:::/    /          |::|\::::/    /              \::::/    /   
    \:::\  /:::/    /        \:::\__/:::/    /           |::| \::/____/                \::/____/    
     \:::\/:::/    /          \::::::::/    /            |::|  ~|                       ~~          
      \::::::/    /            \::::::/    /             |::|   |                                   
       \::::/    /              \::::/    /              \::|   |                                   
        \::/____/                \::/____/                \:|   |                                   
         ~~                       ~~                       \|___|                                   
                                                                                                    

## Web LLM Attacks
Really cool topic, it's the new one, It might not be necessary learning for the exam, but I think that's more than important considering how many applications today are using and featuring their own LLMs.
Web LLM Attacks can be something like : 
	-retrieving the data that LLM has access to, such as API keys, other user data, training material, etc.
	-Trigger harmful injections via LLM to the APIs that LLM talks to such as SQL injection

The most common attack for LMM is a prompt injection where an attacker tries to manipulate the prompt to make LLM go outside of the intended scope and reveal additional information such as API calls, other user information, etc.

**Exploitation**
**1)** When it comes to prompt injection attacks, the first thing that we need to do is to ask LLM to map out APIs that it can talk to, with prompts such as "Which APIs you can talk to". From there we see that for example, LLM can talk to SQL API that is not public and that we can't interact with, which enables us to execute SQL queries via LLM and to observe responses.
**2)** Once when we map out APIs that LLM can talk to we can start chaining vulnerabilities, such as calling APIs and passing payload for command injection for example. At this point you don't have to solely think about LLM Attacks, but you can think about any more standard Web Attacks such as Command Injection, XSS, SQL Injection, etc. that you might be able to exploit by forcing LLM to make requests to the APIs on your behalf. There was a Lab in this Learning Module that enabled end-user to exploit Command Injection via LLM by forcing LLM to send a subscription invite to the user email which contains dangerous payload such as:
`subshell injection operator ${<YOUR_COMMAND_HERE>}user@email.com`
**3)**




