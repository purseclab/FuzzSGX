# Certificate Generation and Signing examples

To test the certgen or csr_example example(s) configure wolfssl with
`./configure --enable-certgen --enable-certreq` or add the defines:

```
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
```

To test the csr_w_ed25519_example configure wolfssl with:
`./configure --enable-certgen --enable-certreq --enable-ed25519 --enable-keygen`
or add the defines:

```
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
#define HAVE_ED25519
#define WOLFSSL_KEY_GEN
```

To build use `make`. To cleanup use `make clean`.

If having issues building please check comments in the Makefile for setting
up your environment


## Certificate Generation Example

To run the test do:

```
./certgen_example
Open and read in der formatted certificate
Successfully read 1198 bytes

Getting the caKey from ./ca-key.der
Successfully read 121 bytes
Init ecc Key
Decode the private key
Successfully retrieved caKey

initializing the rng
Generating a new ecc key
Successfully created new ecc key

Setting new cert issuer to subject of signer
MakeCert returned 479
SignCert returned 570
Successfully created new certificate
Writing newly generated certificate to file "./newCert.der"
Successfully output 570 bytes
Convert the der cert to pem formatted cert
Resulting pem buffer is 826 bytes
Successfully converted the der to pem. Result is in:  ./newCert.pem

Tests passed
```

You should see the following output when the cert is converted to human
readable format.

```
openssl x509 -inform pem -in newCert.pem -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 81179639550048334 (0x1206873ba5ff84e)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com
        Validity
            Not Before: Jul 17 15:53:18 2017 GMT
            Not After : Nov 30 14:53:18 2018 GMT
        Subject: C=US, ST=MT, L=Bozeman, O=yourOrgNameHere, OU=yourUnitNameHere, CN=www.yourDomain.com/emailAddress=yourEmail@yourDomain.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:15:62:0f:87:13:01:97:65:5c:62:a7:1c:92:bc:
                    61:df:24:52:ed:49:89:a1:ed:42:86:ad:dd:bf:1c:
                    a8:35:d3:9d:2c:29:12:cb:ce:05:bd:40:0b:24:f3:
                    d7:e0:61:f2:69:51:2a:20:b3:34:13:33:e7:69:b8:
                    d9:81:19:5f:b8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:75:11:0c:e7:b3:73:20:88:d2:67:69:f2:1a:46:
         fb:d2:67:31:c7:c7:58:b4:9d:e2:48:95:db:bb:1f:1d:24:ab:
         02:21:00:d6:30:b9:c0:32:0d:42:74:56:b0:9e:8f:dc:83:1d:
         e6:a3:af:99:ea:03:97:4c:dc:d0:11:b8:10:a1:5a:29:a5
-----BEGIN CERTIFICATE-----
MIICNTCCAdugAwIBAgIIASBoc7pf+E4wCgYIKoZIzj0EAwIwgZQxCzAJBgNVBAYT
AlVTMRAwDgYDVQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQK
DAhTYXd0b290aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwPd3d3Lndv
bGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMCIYDzIw
MTcwNzE3MTU1MzE4WhgPMjAxODExMzAxNDUzMThaMIGnMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTVQxEDAOBgNVBAcMB0JvemVtYW4xGDAWBgNVBAoMD3lvdXJPcmdO
YW1lSGVyZTEZMBcGA1UECwwQeW91clVuaXROYW1lSGVyZTEbMBkGA1UEAwwSd3d3
LnlvdXJEb21haW4uY29tMScwJQYJKoZIhvcNAQkBFhh5b3VyRW1haWxAeW91ckRv
bWFpbi5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQVYg+HEwGXZVxipxyS
vGHfJFLtSYmh7UKGrd2/HKg1050sKRLLzgW9QAsk89fgYfJpUSogszQTM+dpuNmB
GV+4MAoGCCqGSM49BAMCA0gAMEUCIHURDOezcyCI0mdp8hpG+9JnMcfHWLSd4kiV
27sfHSSrAiEA1jC5wDINQnRWsJ6P3IMd5qOvmeoDl0zc0BG4EKFaKaU=
-----END CERTIFICATE-----

```


## Certificate Signing Request (CSR) Example

```
./csr_example
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyXi4zh0EKTfZv2Mdyz9TR97aY8zmuP/Mt41Y8UczfsoAoGCCqGSM49
AwEHoUQDQgAENfB16kF8KZuVQC0744AgiSY5bpuLRegTXJ4JTgCzSWaSHLXZC+CJ
a/0yDzI6bQtDdzNZ0M+0/O+VolN10GaAZw==
-----END EC PRIVATE KEY-----
-----BEGIN CERTIFICATE REQUEST-----
MIIBSTCB8QIBAjCBjjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk9SMREwDwYDVQQH
DAhQb3J0bGFuZDEOMAwGA1UECgwFeWFTU0wxFDASBgNVBAsMC0RldmVsb3BtZW50
MRgwFgYDVQQDDA93d3cud29sZnNzbC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9A
d29sZnNzbC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ18HXqQXwpm5VA
LTvjgCCJJjlum4tF6BNcnglOALNJZpIctdkL4Ilr/TIPMjptC0N3M1nQz7T875Wi
U3XQZoBnoAAwCgYIKoZIzj0EAwIDRwAwRAIgVh5iGYVmbwR4fhdjzCMI06wn2lGS
SmRM6YTRfMWRoSICIAlMGjRJlBKB9dlmukCdlHH3GXNOiKw1+iP/kApE8tRm
-----END CERTIFICATE REQUEST-----
```


## Certificate Generation Example with alt names

Pretty much the same as the certgen_example but adds some alt names to the cert
Unfortunately wolfSSL does not yet have an API for this but this example shows
how to setup your own ASN.1 format string for using with the wolfSSL certificate
structure. TODO: Add an API for this!

Example of a cert being generated with this example

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            08:1a:be:1b:2e:5a:c5:aa:2c:e5:6d:db:20:22:31:b5
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, ST = Montana, L = Bozeman, O = Sawtooth, OU = Consulting, CN = www.wolfssl.com, emailAddress = info@wolfssl.com
        Validity
            Not Before: May  6 21:14:47 2020 GMT
            Not After : Sep 19 21:14:47 2021 GMT
        Subject: C = US, ST = MT, L = Bozeman, O = yourOrgNameHere, OU = yourUnitNameHere, CN = www.yourDomain.com, emailAddress = yourEmail@yourDomain.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8e:dc:b9:92:59:51:40:2e:3f:33:44:55:70:80:
                    16:bc:41:84:ab:47:3e:8b:93:6a:a0:16:78:0a:e9:
                    49:9a:d5:fe:08:cc:c3:23:2f:26:5a:14:cc:b1:8e:
                    db:94:8d:ad:3c:57:a4:3b:4f:e2:f0:7e:28:33:01:
                    40:57:f0:85:b5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:localhost, DNS:example.com, DNS:127.0.0.1
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:36:08:d9:df:9e:7f:c2:1c:0c:db:06:26:3d:fe:
         8e:82:6e:64:07:6e:9b:fb:47:97:0a:d0:63:f6:6c:59:2a:82:
         02:20:37:5c:00:eb:0d:7d:95:51:5d:8e:e9:06:c7:a5:6f:7d:
         8b:1d:69:8d:8e:f8:5b:ba:13:0e:2a:5f:b4:86:1b:12
-----BEGIN CERTIFICATE-----
MIICbjCCAhWgAwIBAgIQCBq+Gy5axaos5W3bICIxtTAKBggqhkjOPQQDAjCBlDEL
MAkGA1UEBhMCVVMxEDAOBgNVBAgMB01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4x
ETAPBgNVBAoMCFNhd3Rvb3RoMRMwEQYDVQQLDApDb25zdWx0aW5nMRgwFgYDVQQD
DA93d3cud29sZnNzbC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5j
b20wIhgPMjAyMDA1MDYyMTE0NDdaGA8yMDIxMDkxOTIxMTQ0N1owgacxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJNVDEQMA4GA1UEBwwHQm96ZW1hbjEYMBYGA1UECgwP
eW91ck9yZ05hbWVIZXJlMRkwFwYDVQQLDBB5b3VyVW5pdE5hbWVIZXJlMRswGQYD
VQQDDBJ3d3cueW91ckRvbWFpbi5jb20xJzAlBgkqhkiG9w0BCQEWGHlvdXJFbWFp
bEB5b3VyRG9tYWluLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI7cuZJZ
UUAuPzNEVXCAFrxBhKtHPouTaqAWeArpSZrV/gjMwyMvJloUzLGO25SNrTxXpDtP
4vB+KDMBQFfwhbWjMDAuMCwGA1UdEQQlMCOCCWxvY2FsaG9zdIILZXhhbXBsZS5j
b22CCTEyNy4wLjAuMTAKBggqhkjOPQQDAgNHADBEAiA2CNnfnn/CHAzbBiY9/o6C
bmQHbpv7R5cK0GP2bFkqggIgN1wA6w19lVFdjukGx6VvfYsdaY2O+Fu6Ew4qX7SG
GxI=
-----END CERTIFICATE-----
```
