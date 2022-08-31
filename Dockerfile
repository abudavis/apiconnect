FROM registry.access.redhat.com/ubi8/nodejs-16-minimal:latest
COPY configure-apic-v10.sh /
USER root
RUN microdnf install yum
RUN yum install jq -y
RUN curl -kLo /tmp/openshift-client-linux-4.10.16.tar.gz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.10.16/openshift-client-linux-4.10.16.tar.gz
RUN tar -xvf /tmp/openshift-client-linux-4.10.16.tar.gz -C /tmp
RUN cp /tmp/oc /usr/bin
RUN oc version
ENTRYPOINT ["./configure-apic-v10.sh"]
