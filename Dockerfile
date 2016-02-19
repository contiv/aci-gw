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

# unset proxy and download egg files
# edit apic url and version as appropriate for your build
RUN unset https_proxy; wget --no-check-certificate https://ifav43-ifc1.insieme.local/cobra/_downloads/acicobra-1.2_1b-py2.7.egg
RUN unset https_proxy; wget --no-check-certificate https://ifav43-ifc1.insieme.local/cobra/_downloads/acimodel-1.2_1b-py2.7.egg

# install python package form egg files
RUN easy_install ./acicobra-1.2_1b-py2.7.egg
RUN easy_install ./acimodel-1.2_1b-py2.7.egg
ENV https_proxy="" 

CMD /usr/bin/python /cobra/apicagent.py
