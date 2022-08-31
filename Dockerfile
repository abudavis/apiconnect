FROM registry.access.redhat.com/rhel7:latest
COPY configure-apic-v10.sh /
ENTRYPOINT ["./configure-apic-v10.sh"]
