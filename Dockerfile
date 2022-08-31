FROM registry.access.redhat.com/rhel7:latest
COPY configure-apic-v10.sh /
ENTRYPOINT ["./configure-apic-v10.sh apic apic org apicadmin engageibmAPI1 abu.davis@domain.com smtp.mailtrap.io 2525"]
