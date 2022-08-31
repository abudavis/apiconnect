#!/bin/bash
#******************************************************************************
# NAME: configure-apic-v10.sh
# Example usage: ./configure-apic-v10.sh apic apic org apicadmin engageibmAPI1 abu.davis@domain.com smtp.mailtrap.io 2525
# CAUTION: Before re-running the script, delete the configurator job + delete the secret "cloud-manager-service-creds"
# INITIAL CREATION DATE: Q1 2021
# lAST MODIFIED DATE: August 31, 2022
# AUTHORS:  IBM
#           Abu Davis
# DESCRIPTION:
# 	This script configures API Connect including creation of APIC service, Porg user, Porg, Mail server, Catalogs, Portal Sites.
#******************************************************************************
# PREREQUISITES:
#   - Logged into cluster on the OC CLI (https://docs.openshift.com/container-platform/4.4/cli_reference/openshift_cli/getting-started-cli.html)
#******************************************************************************

if [ -z $1 ] ; then
	echo "Usage: ./configure-apic-v10.sh <namespace> <release_name> <porg_name> <porg_user> <porg_pass> <porg_admin_email> <mail_server_host> <mail_server_port>"
  exit 1
else
  NAMESPACE=$1
  RELEASE_NAME=$2
  PORG_NAME=$3
  PORG_USER=$4
  PORG_PASS=$5
  PORG_ADMIN_EMAIL=$6   # update to recipient of portal site creation email
	MAIL_SERVER_HOST=$7
  MAIL_SERVER_PORT=$8
fi

CURRENT_DIR=$(dirname $0)
tick="\xE2\x9C\x85"
cross="\xE2\x9D\x8C"

#RELEASE_NAME="apic"
#PORG_NAME="org"
#NAMESPACE="${NAMESPACE}"
#PORG_ADMIN_EMAIL=${PORG_ADMIN_EMAIL:-"abu.davis@domain.com"}
#ACE_REGISTRATION_SECRET_NAME="ace-v11-service-creds"              # corresponds to registration obj currently hard-coded in configmap
PROVIDER_SECRET_NAME="cp4i-admin-creds"                           # corresponds to credentials obj currently hard-coded in configmap
REPO="cp.icr.io"
CONFIGURATOR_IMAGE=${CONFIGURATOR_IMAGE:-"${REPO}/cp/apic/ibm-apiconnect-apiconnect-configurator:10.0.5.0"}
#MAIL_SERVER_HOST=${MAIL_SERVER_HOST:-"smtp.mailtrap.io"}
#MAIL_SERVER_PORT=${MAIL_SERVER_PORT:-"2525"}
MAIL_SERVER_USERNAME=${MAIL_SERVER_USERNAME:-""}
MAIL_SERVER_PASSWORD=${MAIL_SERVER_PASSWORD:-""}

#Delete old secrets if any
oc delete secret cloud-manager-service-creds -n $NAMESPACE
oc delete secret $PROVIDER_SECRET_NAME -n $NAMESPACE
oc delete job "$NAMESPACE"-"$RELEASE_NAME"-configurator-post-install -n $NAMESPACE


function usage() {
  echo "Usage: $0 -n <NAMESPACE> -r <RELEASE_NAME>"
}

OUTPUT=""
function handle_res() {
  local body=$1
  local status=$(echo ${body} | jq -r ".status")
  $DEBUG && echo "[DEBUG] res body: ${body}"
  $DEBUG && echo "[DEBUG] res status: ${status}"
  if [[ $status == "null" ]]; then
    OUTPUT="${body}"
  elif [[ $status == "409" ]]; then
    OUTPUT="${body}"
    echo "[INFO]  Resource already exists, continuing..."
  else
    echo -e "[ERROR] ${CROSS} Request failed: ${body}..."
    exit 1
  fi
}

while getopts "n:r:" opt; do
  case ${opt} in
  n)
    NAMESPACE="$OPTARG"
    ;;
  r)
    RELEASE_NAME="$OPTARG"
    ;;
  \?)
    usage
    exit
    ;;
  esac
done

set -e


#echo "Waiting for APIC installation to complete..."
#for i in $(seq 1 120); do
#  APIC_STATUS=$(oc get apiconnectcluster.apiconnect.ibm.com -n $NAMESPACE ${RELEASE_NAME} -o jsonpath='{.status.phase}')
#  if [ "$APIC_STATUS" == "Ready" ]; then
#    printf "$tick"
#    echo "[OK] APIC is ready"
#    break
#  else
#    echo "Waiting for APIC install to complete (Attempt $i of 120). Status: $APIC_STATUS"
#    oc get apic,pods,pvc -n $NAMESPACE
#    echo "Checking again in one minute..."
#    sleep 60
#  fi
#done

#if [ "$APIC_STATUS" != "Ready" ]; then
#  printf "$cross"
#  echo "[ERROR] APIC failed to install"
#  exit 1
#fi

for i in $(seq 1 60); do
  PORTAL_WWW_POD=$(oc get pods -n $NAMESPACE | grep -m1 "${RELEASE_NAME}-ptl.*www" | awk '{print $1}')
  if [ -z "$PORTAL_WWW_POD" ]; then
    echo "Not got portal pod yet"
  else
    PORTAL_WWW_ADMIN_READY=$(oc get pod -n ${NAMESPACE} ${PORTAL_WWW_POD} -o json | jq '.status.containerStatuses[0].ready')
    if [[ "$PORTAL_WWW_ADMIN_READY" == "true" ]]; then
      printf "$tick"
      #echo "PORTAL_WWW_POD (${PORTAL_WWW_POD}) ready, patching..."
      #oc exec -n ${NAMESPACE} ${PORTAL_WWW_POD} -c admin -- bash -ic "sed -i '/^add_uuid_and_alias/a drush \"@\$SITE_ALIAS\" pm-list --type=Module --status=enabled' /opt/ibm/bin/restore_site"
      break
    else
      echo "${PORTAL_WWW_POD} not ready"
    fi
  fi

  echo "Waiting, checking again in one minute... (Attempt $i of 60)"
  sleep 60
done

echo "Pod listing for information"
oc get pod -n $NAMESPACE

# obtain cloud manager credentials secret name
CLOUD_MANAGER_PASS="$(oc get secret -n $NAMESPACE "${RELEASE_NAME}-mgmt-admin-pass" -o jsonpath='{.data.password}' | base64 --decode)"

# obtain endpoint info from APIC v10 routes
APIM_UI_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-mgmt-api-manager -o jsonpath='{.spec.host}')
CMC_UI_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-mgmt-admin -o jsonpath='{.spec.host}')
C_API_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-mgmt-consumer-api -o jsonpath='{.spec.host}')
API_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-mgmt-platform-api -o jsonpath='{.spec.host}')
PTL_WEB_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-ptl-portal-web -o jsonpath='{.spec.host}')

PTL_DIR_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-ptl-portal-director -o jsonpath='{.spec.host}')
A7S_CLIENT_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-a7s-ai-endpoint -o jsonpath='{.spec.host}')
API_GW_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-gw-gateway -o jsonpath='{.spec.host}')
GW_SVC_EP=$(oc get route -n $NAMESPACE ${RELEASE_NAME}-gw-gateway-manager -o jsonpath='{.spec.host}')

# create the k8s resources
echo "Applying manifests"
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-apic-configurator-post-install-sa
imagePullSecrets:
- name: ibm-entitlement-key
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-apic-configurator-post-install-role
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - create
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-apic-configurator-post-install-rolebinding
subjects:
- kind: ServiceAccount
  name: ${RELEASE_NAME}-apic-configurator-post-install-sa
  namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${RELEASE_NAME}-apic-configurator-post-install-role
---
apiVersion: v1
kind: Secret
metadata:
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-default-mail-server-creds
type: Opaque
stringData:
  default-mail-server-creds.yaml: |-
    mail_servers:
      - name: default-mail-server
        credentials:
          username: "${MAIL_SERVER_USERNAME}"
          password: "${MAIL_SERVER_PASSWORD}"
---
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-configurator-base
data:
  configurator-base.yaml: |-
    logger:
      level: trace
    namespace: ${NAMESPACE}
    api_endpoint: https://${API_EP}
    credentials:
      admin:
        secret_name: cloud-manager-service-creds
        registration:
          name: 'cloud-manager'
          title: 'Cloud Manager'
          client_type: 'ibm_cloud'
          client_id: 'cloud-manager'
          state: 'enabled'
          scopes:
            - 'cloud:view'
            - 'cloud:manage'
            - 'provider-org:view'
            - 'provider-org:manage'
            - 'org:view'
            - 'org:manage'
            - 'my:view'
        username: admin
        password: "${CLOUD_MANAGER_PASS}"
      provider:
        secret_name: ${PROVIDER_SECRET_NAME}
    registry_settings:
      #admin_user_registry_urls:
      #- https://${API_EP}/api/user-registries/admin/cloud-manager-lur
      #- https://${API_EP}/api/user-registries/admin/common-services
      #provider_user_registry_urls:
      #- https://${API_EP}/api/user-registries/admin/api-manager-lur
      #- https://${API_EP}/api/user-registries/admin/common-services
    #registrations:
    #  - registration:
    #      name: 'ace-v11'
    #      client_type: 'toolkit'
    #      client_id: 'ace-v11'
    #      client_secret: 'myclientid123'
    #    secret_name: ${ACE_REGISTRATION_SECRET_NAME}
    mail_servers:
      - title: "Default Mail Server"
        name: default-mail-server
        host: "${MAIL_SERVER_HOST}"
        port: ${MAIL_SERVER_PORT}
        # tls_client_profile_url: https://${API_EP}/api/orgs/admin/tls-client-profiles/tls-client-profile-default
    users:
      # cloud_manager:
      api-manager-lur:
        - user:
            username: $PORG_USER
            # configurator will generate a password if it is omitted
            password: $PORG_PASS
            first_name: APIC
            last_name: Administrator
            email: ${PORG_ADMIN_EMAIL}
            # email: $PORG_USER@apiconnect.net
          secret_name: ${PROVIDER_SECRET_NAME}
    orgs:
      - org:
          name: ${PORG_NAME}
          title: ${PORG_NAME}
          org_type: provider
          owner_url: https://${API_EP}/api/user-registries/admin/api-manager-lur/users/$PORG_USER
        members:
          #- name: cs-admin
          #  user:
          #    identity_provider: common-services
          #    url: https://${API_EP}/api/user-registries/admin/common-services/users/admin
          #  role_urls:
          #    - https://${API_EP}/api/orgs/${PORG_NAME}/roles/administrator
        catalogs:
          - catalog:
              name: internet
              title: internet
            settings:
              portal:
                type: drupal
                endpoint: https://${PTL_WEB_EP}/developer
                portal_service_url: https://${API_EP}/api/orgs/${PORG_NAME}/portal-services/portal-service
          - catalog:
              name: internal
              title: internal
            settings:
              portal:
                type: drupal
                endpoint: https://${PTL_WEB_EP}/${PORG_NAME}/internal
                portal_service_url: https://${API_EP}/api/orgs/${PORG_NAME}/portal-services/portal-service
          - catalog:
              name: external
              title: external
            settings:
              portal:
                type: drupal
                endpoint: https://${PTL_WEB_EP}/${PORG_NAME}/external
                portal_service_url: https://${API_EP}/api/orgs/${PORG_NAME}/portal-services/portal-service
    services:
      portal:
        - name: portal-service
          title: portal-service
          endpoint: https://${PTL_DIR_EP}
          web_endpoint_base: https://${PTL_WEB_EP}
      analytics:
        - name: analytics-service
          title: analytics-service
          endpoint: https://${A7S_CLIENT_EP}
      gateway:
        - name: api-gateway-service
          title: api-gateway-service
          gateway_service_type: datapower-api-gateway
          integration_url: https://${API_EP}/api/cloud/integrations/gateway-service/datapower-api-gateway
          visibility:
            type: public
          tls_client_profile_url: https://${API_EP}/api/orgs/admin/tls-client-profiles/tls-client-profile-default
          endpoint: https://${GW_SVC_EP}
          api_endpoint_base: https://${API_GW_EP}
          sni:
            - host: '*'
              tls_server_profile_url: https://${API_EP}/api/orgs/admin/tls-server-profiles/tls-server-profile-default
          analytics_service_url: https://${API_EP}/api/orgs/admin/availability-zones/availability-zone-default/analytics-services/analytics-service
    mail_settings:
      mail_server_url: https://${API_EP}/api/orgs/admin/mail-servers/default-mail-server
      email_sender:
        name: "APIC Administrator"
        address: admin@apiconnect.net
    cloud_settings:
      gateway_service_default_urls:
        - https://${API_EP}/api/orgs/admin/availability-zones/availability-zone-default/gateway-services/api-gateway-service
---
apiVersion: batch/v1
kind: Job
metadata:
  labels:
    app: apic-configurator-post-install
  namespace: ${NAMESPACE}
  name: ${RELEASE_NAME}-apic-configurator-post-install
spec:
  backoffLimit: 1
  template:
    metadata:
      labels:
        app: apic-configurator-post-install
    spec:
      serviceAccountName: ${RELEASE_NAME}-apic-configurator-post-install-sa
      restartPolicy: Never
      containers:
        - name: configurator
          image: ${CONFIGURATOR_IMAGE}
          volumeMounts:
            - name: configs
              mountPath: /app/configs
      volumes:
        - name: configs
          projected:
            sources:
            - configMap:
                name: ${RELEASE_NAME}-configurator-base
                items:
                  - key: configurator-base.yaml
                    path: overrides/configurator-base.yaml
            - secret:
                name: ${RELEASE_NAME}-default-mail-server-creds
                items:
                  - key: default-mail-server-creds.yaml
                    path: overrides/default-mail-server-creds.yaml
EOF

# wait for the job to complete
echo "Waiting for configurator job to complete"
oc wait --for=condition=complete --timeout=12000s -n $NAMESPACE job/${RELEASE_NAME}-apic-configurator-post-install

# pull together any necessary info from in-cluster resources
PROVIDER_CREDENTIALS=$(oc get secret $PROVIDER_SECRET_NAME -n $NAMESPACE -o json | jq .data)
#ACE_CREDENTIALS=$(oc get secret $ACE_REGISTRATION_SECRET_NAME -n $NAMESPACE -o json | jq .data)

# Hard timer, since it could take upto 5-10 minutes to create all the portal sites
for i in $(seq 1 10); do
  PORTAL_WWW_POD=$(oc get pods -n $NAMESPACE | grep -m1 "${RELEASE_NAME}-ptl.*www" | awk '{print $1}')
  PORTAL_SITE_UUID=$(oc exec -n $NAMESPACE -it $PORTAL_WWW_POD -c admin -- /opt/ibm/bin/list_sites | awk '{print $1}' | sort)
  echo "Waiting for all the PORTAL SITE(S) to be available (Attempt $i of 10)."
  echo "Checking again in one minute..."
  echo "--------------------------------"
  oc exec -n $NAMESPACE -it $PORTAL_WWW_POD -c admin -- /opt/ibm/bin/list_sites
  echo "--------------------------------"
  sleep 60
done

for x in $PORTAL_SITE_UUID; do
PORTAL_SITE_RESET_URL=$(oc exec -n $NAMESPACE -it $PORTAL_WWW_POD -c admin -- /opt/ibm/bin/site_login_link $x | tail -1)
if [[ "$PORTAL_SITE_RESET_URL" =~ "https://$PTL_WEB_EP" ]]; then
  printf "$tick"
  echo "[OK] Got the portal_site_password_reset_link"
  echo "--------------------------------"
  echo "portal_site_password_reset_link: $PORTAL_SITE_RESET_URL"
  echo "--------------------------------"
  #break
fi
done

API_MANAGER_USER=$(echo $PROVIDER_CREDENTIALS | jq -r .username | base64 --decode)
API_MANAGER_PASS=$(echo $PROVIDER_CREDENTIALS | jq -r .password | base64 --decode)
#ACE_CLIENT_ID=$(echo $ACE_CREDENTIALS | jq -r .client_id | base64 --decode)
#ACE_CLIENT_SECRET=$(echo $ACE_CREDENTIALS | jq -r .client_secret | base64 --decode)

printf "$tick"
echo "
********** Configuration **********
api_manager_ui: https://$APIM_UI_EP/manager
cloud_manager_ui: https://$CMC_UI_EP/admin
platform_api: https://$API_EP/api
consumer_api: https://$C_API_EP/consumer-api
provider_credentials (api manager):
  username: ${API_MANAGER_USER}
  password: ${API_MANAGER_PASS}
"

