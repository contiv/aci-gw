# aci-gw

Receives REST requests from netmaster and performs the corresponding apic configuration. Uses the aci cobra package for interactions with apic.

### Building the aci-gw container

The SDK needs to be downloaded from an APIC. It is not yet available from a Cisco download site.
The following information should be provided as arguments to the docker build.
a) APIC URL
b) SDK version
c) https_proxy if the environment requires a proxy

The SDK version corresponding to the APIC software can be found looking at the files at https://<apic_url>/cobra/_downloads/

The command to build the aci-gw container is:
```
docker build --build-arg APIC_URL=<apic_url> --build-arg APIC_PKG_VERSION=<apic_sdk_version> \
 --force-rm -t contiv/aci-gw .
```

Example:
```
docker build --build-arg APIC_URL=172.31.152.18 --build-arg APIC_PKG_VERSION=1.1_1.67-py2.7 \
 --build-arg https_proxy="https://proxy.esl.cisco.com:8080" --force-rm \
 -t contiv/aci-gw:09-27-2016.2.0_2g .
```

### Pre-requisites for ACI setup

#### APIC Configuration (Fabric/Access Policies)

```
    1. Create a VLAN Pool under "Fabric" -> "Access Policies" -> "Pools" -> "VLAN". Set allocation mode to
       "Static Allocation".

    2. Create a physical domain under "Fabric" -> "Access Policies" -> "Physical and External Domains" -> "Physical Domains"

    3. Create an Attachable Access Entity Profile(AAEP) and associate with the physical domain created in step #2.

    4. Create a Policy Group (under Interface Policies) and specify the AAEP created in step #3.

    5. Create an Interface Profile and specify the physical interfaces connected from your ToR(s) to the bare metal servers.
       You can create separate Interface Profiles for individual ToRs if you like.

    6. Create a Switch Profile (Switch Policies/Profiles) and specify the appropriate interface profile created in step 5.

    7. Make a note of the full node name of the ToRs you have connected to your servers.
```

### Starting the aci-gw container

The aci-gw container needs to be accessible by netmaster at localhost:5000. In order to ensure that, the aci-gw can be started on the same node as the netmaster, with --net=host option.

In order for the aci-gw to access and configure ACI to match the contiv configuration, the following information need to be passed to the aci-gw via environment variables:

APIC_URL
This is the URL of the APIC.

APIC_USERNAME
This is the login username for the APIC.

APIC_LEAF_NODE
This is the full URI path of the aci leaf nodes where the cluster servers are connected.
e.g. topology/pod-1/node-101. If there are multiple nodes, you can use comma separation.
e.g. topology/pod-1/node-101,topology/pod-1/node-102

APIC_PHYS_DOMAIN
This is the name of the physical domain used for the contiv cluster (Step 2 above).

## Authentication
Both key based authentication and password authentication are supported. Key based authentication is the recommended method.

For password based authentication, you need to pass the password to the aci-gw using the APIC_PASSWORD environment variable.

### key based authentication

 Step 1. Create a key and certicate add the certificate to APIC using the procedure described in http://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/kb/b_KB_Signature_Based_Transactions.pdf.
 
 Step 2. Find the DN of the key that was added to APIC and pass it to the aci-gw via the APIC_CERT_DN environment variable. This DN is of the form**uni/userext/user-admin/usercert-admin** The exact DN can be found from the APIC visore.  e.g. APIC_CERT_DN=uni/userext/user-admin/usercert-admin

 Step 3. Create a directory on the server that hosts aci-gw and copy the key created in the previous step to this directory. 

 Step 4. Share this directory with the aci-gw using the bind mounting option of docker.
e.g. if the keys are copied to /shared/keys directory on the host, use *-v /shared/keys:/aciconfig* option while starting the aci-gw container.

Below is an example of starting the aci-gw with all relevant parameters.
```
/usr/bin/docker run --net=host \
    -e "APIC_URL=https://11.103.101.33" \
    -e "APIC_USERNAME=admin" \
    -e "APIC_LEAF_NODE=topology/pod-1/node-101,topology/pod-1/node-102" \
    -e "APIC_PHYS_DOMAIN=contivPhysDom" \
    -e "APIC_CERT_DN=uni/userext/user-admin/usercert-admin" \
    -v /shared/keys:/aciconfig \
    --name=contiv-aci-gw \
    -t contiv/aci-gw
```
