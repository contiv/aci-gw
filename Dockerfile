FROM ubuntu:15.04

# install python pip, wget etc.
RUN apt-get update
RUN apt-get -y install python-pip wget

# install eazyinstall
ENV https_proxy="https://proxy.esl.cisco.com:8080" 
RUN pip install Flask
RUN wget https://bootstrap.pypa.io/ez_setup.py -O - | python

RUN mkdir ./cobra
WORKDIR ./cobra
COPY apic .

ARG APIC_URL
ARG APIC_PKG_VERSION

# unset proxy and download egg files
RUN unset https_proxy; wget --no-check-certificate https://$APIC_URL/cobra/_downloads/acicobra-$APIC_PKG_VERSION.egg
RUN unset https_proxy; wget --no-check-certificate https://$APIC_URL/cobra/_downloads/acimodel-$APIC_PKG_VERSION.egg

# install python package form egg files
RUN easy_install ./acicobra-$APIC_PKG_VERSION.egg
RUN easy_install ./acimodel-$APIC_PKG_VERSION.egg
ENV https_proxy="" 

CMD /usr/bin/python /cobra/apicagent.py
