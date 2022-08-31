FROM registry.access.redhat.com/rhel7:latest
COPY configure-apic-v10.sh /
USER root
RUN curl -kLo /tmp/gzip-1.5-10.el7.x86_64.rpm http://mirror.centos.org/centos/7/os/x86_64/Packages/gzip-1.5-10.el7.x86_64.rpm
RUN rpm -i /tmp/gzip-1.5-10.el7.x86_64.rpm
RUN curl -kLo /tmp/zip-3.0-11.el7.x86_64.rpm http://mirror.centos.org/centos/7/os/x86_64/Packages/zip-3.0-11.el7.x86_64.rpm
RUN rpm -i /tmp/zip-3.0-11.el7.x86_64.rpm
RUN curl -kLo /tmp/openshift-client-linux-4.10.16.tar.gz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.10.16/openshift-client-linux-4.10.16.tar.gz
RUN tar -xvf /tmp/openshift-client-linux-4.10.16.tar.gz -C /tmp
RUN cp /tmp/oc /usr/bin
RUN oc version
ENTRYPOINT ["./configure-apic-v10.sh"]
