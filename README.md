# CobaltStrike-Keystore-Builder
Generates Java keystores using signed SSL certificates to be used by CobaltStrike.

# Thanks to
@Killswtch-GUI - for providing the concept
ThreatExpress - for providing a C2 profile template

# Overview
This script concept was taken from HTTPsC2DoneRight by @Killswitch-GUI, but widely expanded to be much more intuitive and functional.
It will allow for a user to build a Keystore using LetsEncrypt or from a pre-signed SSL certificate. This also allows the option to download and set up a Malleable C2 Profile from ThreatExpress to mimic jQuery traffic.

# OS Support
This script is built to run on Debian-based kernels (mainly through using aptitude to get repos). Can be modified to run on other distros.

# Usage
Run the script without arguments and it will walk you through the rest.
Don't judge my bash skills :)

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
