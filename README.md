# PECOFF-fun
This repository will be dedicated to experiments messing with Windows PECOFFs, specifically malformed headers and injecting shellcode.  The primary function of all produced exe's will be self-deletion.  The reason behind this is that the tangible proof of its success is its own removal, providing both an enjoyable sense of irony and lending an impetus to streamline and otherwise automate the creation of these exe's.

Yes, the main.cpp is intentionally incomplete.  Giving away all of the answers is no fun, recreate it yourself, all you need to know is here.

## runshell:

The first in the line.  runshell contains a simple pe header shift with the shellcode located immediately after the DOS header.  The process injection methodology comes courtesy of Rajasekharan Vengalil at Nerdworks Blogorama.
