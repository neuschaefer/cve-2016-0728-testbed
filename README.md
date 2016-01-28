# CVE-2016-0728 testbed

This repository contains a test program for CVE-2016-0728, a refcount leak
and overflow bug in Linux, that leads to a use-after-free.

The bug was [found and explained](http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/)
by Perception Point. I am not affiliated to them.


## Usage

```
Welcome to the CVE-2016-0728 testbed
sizeof(struct msg_msg) == 0x30, sizeof(struct key) == 0xb8

PID: 27673, UID: (1000/1000)
Keyring: 1b66e5d6, "test-1a328d6e"
Usage:   1
Press a key: (f)ork (i)ncref (a)uto-incref (r)evoke (h)eap-spray (s)hell (q)uit
```

On my test system, a root shell could be obtained in the following way:

1. Bring the refcount up to -2; If you incref too often, you will probably
   crash the kernel.
2. Fork twice to overflow it, so the key garbage collector frees the keyring
3. Spray the heap with fake keyrings
4. Call `revoke`
5. `execl("/bin/sh", "sh", NULL)`

I found it useful to run `watch -n0.1 cat /proc/keys` to see what's
happening.


## Portability

This code has only been tested on x86-64, but it should run on other
architectures as well, because I didn't use magic offsets, but copied the
structure definitions from the Linux headers and used `sizeof`
(except that I hard-coded the addresses of `prepare_kernel_cred` and
`commit_creds`).
