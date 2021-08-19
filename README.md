# CobaltStrike-Keystore-Builder
Generates Java keystores using signed SSL certificates to be used by CobaltStrike.

# Overview
This script concept was taken from HTTPsC2DoneRight by @Killswitch-GUI, but broadly expanded to be much more intuitive and functional.
It will allow for a user to build a Keystore using LetsEncrypt or from a pre-signed SSL certificate.

# OS Support
This script is built to run on Debian-based kernels (mainly through using aptitude to get repos). Can be modified to run on other distributions.

# Usage
Run the script without arguments and it will walk you through the rest.

### Menu

```
==========================================================================
 Cobalt Strike KeyStore builder 
==========================================================================

[!] Please choose whether to build SSL certs with LetsEncrypt or specify if you have your own signed certificate.

1) Build SSL certificates with LetsEncrypt
2) Use already signed certificate
3) Quit

Please select an option:
```
