# aci-gw

Receives REST requests from netmaster and performs the corresponding apic configuration. Uses the aci cobra package for interactions with apic.

APIC credentials and other aci info is passed via environment vars.

To build the container, you need access to an APIC. Update the apic url and image version in the Dockerfile and then issue ```docker build -t <tag> .```
