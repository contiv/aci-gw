FROM alpine
MAINTAINER contiv

ARG https_proxy

RUN apk --no-cache add wget python ca-certificates py-pip openssl \
 && pip install --upgrade pip \
 && pip install Flask \
 && mkdir ./cobra \
 && ln -s /usr/bin/easy_install-2.7 /usr/bin/easy_install

WORKDIR ./cobra
COPY apic .

ARG APIC_URL
ARG APIC_PKG_VERSION

# unset proxy and download egg files
RUN unset https_proxy \
 && URL_PREFIX=https://$APIC_URL/cobra/_downloads \
 && wget --no-check-certificate $URL_PREFIX/acicobra-$APIC_PKG_VERSION.egg \
 && wget --no-check-certificate $URL_PREFIX/acimodel-$APIC_PKG_VERSION.egg \
 && easy_install ./acicobra-$APIC_PKG_VERSION.egg \
 && easy_install ./acimodel-$APIC_PKG_VERSION.egg \
 && rm ./acicobra-$APIC_PKG_VERSION.egg \
 && rm ./acimodel-$APIC_PKG_VERSION.egg

CMD /usr/bin/python /cobra/apicagent.py
