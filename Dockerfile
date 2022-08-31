FROM registry.access.redhat.com/rhel7:latest
COPY configure-apic-v10.sh /
RUN curl -kLo /tmp/openshift-client-linux-4.10.16.tar.gz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.10.16/openshift-client-linux-4.10.16.tar.gz
RUN tar -xvf /tmp/openshift-client-linux-4.10.16.tar.gz -C /tmp
RUN cp /tmp/oc /usr/bin
RUN oc version
ENTRYPOINT ["./configure-apic-v10.sh"]
