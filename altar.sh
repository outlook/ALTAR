#!/bin/bash

export AZURE_APP_ID="..."
export AZURE_TENANT_ID="..."
export ALTAR_URL="https://....azurewebsites.net"
export AZURE_USERID="janesmith@prod.contoso.com"
export IDENTITY="~/.ssh/id_rsa"

python altar.py
