# aci-gw

Receives REST requests from netmaster and performs the corresponding apic configuration. Uses the aci cobra package for interactions with apic.

Building the aci-gw container:

The SDK needs to be downloaded from an APIC. It is not yet available from a Cisco download site.
The following information should be provided as arguments to the docker build.
a) APIC URL.
b) SDK version.

The SDK version corresponding to the APIC software can be found looking at the files at https://<apic_url>/cobra/_downloads/

The command to build the aci-gw container is:
docker build --build-arg APIC_URL=<apic_url> --build-arg APIC_PKG_VERSION=<apic_sdk_version> -t contiv/aci-gw -f Dockerfile .

Example:
docker build --build-arg APIC_URL=172.31.152.18 --build-arg APIC_PKG_VERSION=1.1_1.67-py2.7 -t contiv/aci-gw -f Dockerfile .
