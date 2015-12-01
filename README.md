go-check-certs
==============

This is a simple utility written in Go to check SSL certificates for a list of hosts. Each certificate in the host's certificate chain is checked for the following:

* Expiration date. By default, you will be warned if a certificate will expire within 30 days. This can be adjusted with `-years=X`, `-months=X`, and/or `-days=X`.
* Signature algorithm. Some algorithms have already been sunset, others are in the process of being sunset. This can be spammy, so you can disable the check with `-check-sig-alg=false`.

Usage looks something like:

```
./go-check-certs -hosts="./path/to/file/with/hosts"
```

The hosts file is simply a single `hostname:port` per line. Empty lines or lines that start with `#` are ignored.

## Self-signed certificates

go-check-certs is able to validate signature algorithms and expiration dates for self-signed certificates.

Prefix insecure host urls that cannot be verfied against the root CA with "i ".

```
i https://self-signed.example.com
```

go-check-certs will skip verifying `self-signed.example.com`'s cert, but will perform the same signing algorithm and expiration checks on all certs in the bundle. Please be warned that this approach is vulnerable to mitm attacks, as the cert is not verfied against the root CA.

Current limitations:
--------------------

* A certificate must be valid for it to be checked.

License:
--------
```
Copyright (c) 2013, Ryan Rogers
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
