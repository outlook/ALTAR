#!/bin/bash

# This is an incomplete script to automate most of the configuration of resources necessary
# for ALTAR setup. It does not work, but is provided here as a potentially-useful reference
# if the README file is insufficient. There are definitely setup steps that are not, or can
# not, be encompassed by the azure-cli tools. Please do not treat it as authoritative! :)

BOOTSTRAP_LOG="bootstrap.log"

AZ_LOCATION="West US"
AZ_RESOURCE_GROUP_NAME="altar-test-rg"
AZ_APPSVC_PLAN_NAME="altar-test-appsvc"
AZ_APP_NAME="altar"
AZ_VAULT_NAME="altar-test"

SIGNING_KEY_FILE="id_rsa"
SIGNING_PUBKEY_FILE="id_rsa.pub"

# This password must be apprpriate for embedding into a URL; i.e.
#  https://deployerid:${AZ_DEPLOY_PASSWORD}@...
AZ_DEPLOY_PASSWORD=""


set -e
#set -x

az login

echo "Registering the Microsoft.Web provider for your default subscription"
az provider register --namespace Microsoft.Web -o table >$BOOTSTRAP_LOG
giveup=10
while ! az provider show -n Microsoft.Web -o table | grep 'Registered' >/dev/null 2>$BOOTSTRAP_LOG
do
    if [[ giveup == 0 ]]
    then
        echo "Registration not completed in time. Please try again later?"
        exit 2
    fi
    echo "Waiting for Microsoft.Web registration to finish"
    sleep 5
    giveup=$(($giveup-1))
done

echo "Creating the ${AZ_RESOURCE_GROUP_NAME} resource group"
az group create \
    --location "${AZ_LOCATION}" \
    --name "${AZ_RESOURCE_GROUP_NAME}" \
    --output table >$BOOTSTRAP_LOG 2>$BOOTSTRAP_LOG

echo "Creating the ${AZ_APPSVC_PLAN_NAME} app service plan"
az appservice plan create \
    --name "${AZ_APPSVC_PLAN_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP_NAME}" \
    --sku FREE \
    --output table >$BOOTSTRAP_LOG 2>$BOOTSTRAP_LOG

echo "Creating the ${AZ_APP_NAME} web service"
az appservice web create \
    --name "${AZ_APP_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP_NAME}" \
    --plan "${AZ_APPSVC_PLAN_NAME}" \
    --output table >$BOOTSTRAP_LOG 2>$BOOTSTRAP_LOG

# The following asks azure for the URL for the git remote necessary for doing local-git
# deployment. The URLs are of the form:
#
#   https://<deploy_user_id>@${AZ_APP_NAME}.scm.azurewebsites.net:${AZ_APP_NAME}.git
#
# which expects that you have already set up Azure Web Services deployments at some point in
# the past. This may not be true, and the following may bomb horribly. If it does, you can pick
# a ${deploy_user_id}, and run:
#
#     $ az appservice web deployment user set \
#          --user-name ${deploy_user_id} \
#          --password ${AZ_DEPLOY_PASSWORD}
#
# Then, re-run the bootstrap script.

if [[ -z "${AZ_DEPLOY_PASSWORD}" ]]
then
    echo "ERROR: Could not determine the deploy password (and possibly username)"
    echo "You'll need to configure them manually. If you do not know it, you can set it"
    echo "by running the command:"
    echo '$  az appservice web deployment user set --user-name <deployer_id> --password <password>'
    echo "Exiting."
    exit 1
fi

echo "Trying to determine the local deployment url..."
set -x
local_git_url=$(
az appservice web source-control config-local-git \
    --name "${AZ_APP_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP_NAME}" |
sed -nr 's/.*"url": "https:\/\/(.*)@(.*)".*/\1:'${AZ_DEPLOY_PASSWORD}'@\2/p'
)
if [[ -z "${local_git_url}" ]]
then
    echo "ERROR: Could not determine the local deployment git URL!"
    exit 2
fi
set +x

echo "Configuring git for local deploy pushes using a remote named 'azurelocalgit'"
if ! git remote show | grep azurelocalgit >/dev/null 2>/dev/null
then
    git remote add azurelocalgit "https://${local_git_url}" >$BOOTSTRAP_LOG
fi

echo "Getting the object ID for the ${AZ_APP_NAME} Azure Active Directory App registration"
app_obj_id=$(az ad app show --id "https://${AZ_APP_NAME}.azurewebsites.net" | awk -F '"' '/objectId/ {print $4}')

echo "Creating Key Vault to store signing key"
az keyvault create \
    --location "${AZ_LOCATION}" \
    --name "${AZ_VAULT_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP_NAME}" >$BOOTSTRAP_LOG 2>$BOOTSTRAP_LOG

echo "Granting key access permissions to ${AZ_APP_NAME}"
az keyvault set-policy \
    --name "${AZ_VAULT_NAME}" \
    --object-id "${app_obj_id}" \
    --secret-permissions "get" >$BOOTSTRAP_LOG 2>$BOOTSTRAP_LOG

echo "Placing the signing key into the vault"
az keyvault secret set \
    --name "signing-key" \
    --vault-name "${AZ_VAULT_NAME}" \
    --description "ALTAR Signing Key" \
    --file "${SIGNING_KEY_FILE}"

echo "Placing the signing public key into the vault"
az keyvault secret set \
    --name "signing-key.pub" \
    --vault-name "${AZ_VAULT_NAME}" \
    --description "ALTAR Signing Key Public Portion" \
    --file "${SIGNING_PUBKEY_FILE}"
