
ALTAR: Azure Limited-Time Access Regulator
==========================================

ALTAR is, at its core, a CA for [OpenSSH certificates](https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.10&content-type=text/plain). This was inspired by Netflix' [BLESS](https://github.com/Netflix/bless) tool, and serves a similar function.

ALTAR combines a few different Azure technologies:
* The [Azure Web App](https://azure.microsoft.com/en-us/services/app-service/web/) service provides a PaaS base for the WSGI component of ALTAR that performs its various operations.
* The [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) service is used to store all cryptographic material. In the (near!) future, it will be used to perform key generation and signing operations.
* [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/) is used to restrict access to ALTAR, as well as the provider for identity information about the certificate holder.

By combining these technologies, ALTAR provides a facility for issuance and delivery of SSH certificates that can be used in lieu of pre-shared or authorized key files that also centralizes enforcement of security requirements such as 2FA, regular privilege review, centralized privilege escalation/access logging, and more.

Installation
------------

Installation is not straightforward, but is not difficult.

### App Service and AAD Applications ###

#### App Service Creation ####

First, create your Web App. In the Azure Portal, open the App Services blade. Create a "Web App" service.

Next, in the App's blade, select "Deployment Options". Choose a source appropriate for your environment. For testing, a Local Git Repository is convenient.

#### Web App Creation and Configuration ####

Create a new app, with type "Native" (the type is essential). The redirect URI should be set to the URL of the App Service Web App you've created, with the auth callback endpoint appended (`https://${WEB_APP_NAME}.azurewebsites.net/.auth/login/aad/callback`).

Create a new key, and note the key for later use.

Under Required Permissions, grant the following permissions:
* Windows Azure Active Directory (Microsoft.Azure.ActiveDirectory)
    * Sign in and read user profile (User.Read)
    * Access the directory as the signed-in user (Directory.AccessAsUser.All)
* Azure Key Vault
    * Have full access to the Azure Key Vault service (user_impersonation)

#### App Service Configuration ####

Open the Web App's blade, and select "Authentication/Authorization". Turn on App Service Authentication, and select "Log in with Azure Active Directory" in the drop-down. Click the Azure Active Directory option, and set Management Mode to "Advanced". Enter the `${AD_WEB_APP_NAME}`'s client ID, `https://sts.windows.net/${TENANT_ID}/` as the Issuer URL[, and a client secret created for this Service]. Set an Allowed Token Audience to the URL of your Web App, e.g. `https://${WEB_APP_NAME}.azurewebsites.net`.

Resource Explorer -> config -> authsetting:
[Read/Write]
[Edit]
properties.clientSecret = Web App Key
properties."additionalLoginParams": [ "response_type=id_token code" ],
[PUT]
[Read Only]

Before doing your first deployment of ALTAR, you'll need to upgrade pip. Open the Console in the App Service blade, and run `env\scripts\activate.bat`, followed by `env\scripts\pip.exe install --upgrade pip`.

#### CLI App Creation and Configuration ####

Create another new Azure Active Directory App, with type "Native". The URI here is not used for redirects, and should be set according to your policy.

Under Required Permissions, grant the "Access `${APPSVC_AD_APP_NAME}`" permission.

### Key Vault Creation and Configuration ###

Create a key vault, and grant your Web Service AAD Application read permissions to Secrets. Take note of the vault URL.

Go back to the Web App's blade, and open "Application Settings". In the App Settings section, add a key named "AZURE_KEYVAULT_URL" with a value set to the URL of your Key Vault.

#### Adding Keys ####

> n.b. this uses SSH keys at the present moment, but will soon use built-in Key Vault functionality.

On a trusted device, generate a new 2048-bit RSA key:

```
$ ssh-keygen -t rsa -b 2048 -f ca
```

Do not enter a passphrase.

Create two new secrets and copy the key files into them; the public key file is put in the `signing-pubkey` secret, and the private key file in `signing-key`. Because line endings must be preserved, the most reliable way to do this is to skip the portal and upload programmatically, for example using the Azure CLI.

```
$ az keyvault secret set --name signing-key --file ./ca --vault-name ...
```

### Configuring User Authorization ###

Users authorized to generate SSH certificates (and, likely by extension, log into hosts) are expected to belong to a configurable group. After grouping the users according to your environment, you must configure the Web App. Within the Web App's portal blade, open "Application Settings". In the App Settings section, add a key named "PERMITTED_GROUP", with a value that matches the display name of the group you wish to authorize.

Configuring Hosts
-----------------

ALTAR relies on OpenSSH's `TrustedUserCAKeys` feature, which must be enabled in the SSH server's config file. This option specifies the CA key that will be trusted for user login. Create a file, owned by and writeable (mode 0644 or less) that contains the key. For example, `/etc/ssh/ca.pub`.

The key is available via HTTPS at the `/pubkey` address of your Web Service.

> n.b. ALTAR provides for OpenSSH authentication, but does is not sufficient for user login! OpenSSH will refuse to permit users that present valid certificates but that are not known to the underlying host. For example, if `/etc/nsswitch.conf` has the line `passwd compat ldap`, but the user principal (`user@example.com`) is not in LDAP or in `/etc/passwd`, OpenSSH will reject the login attempt.
>
> If this is a problem, check out [`libnss-aad`](https://github.com/outlook/libnss-aad)!

How to Use ALTAR
----------------

Once the service is configured, users can invoke the `altar.py` command to generate certificates. A wrapper script, `altar.sh` is provided that shows the minimum necessary environment variables (which correspond to options supported by `altar.py`).

The resulting certificate is written to `${IDENTITY}-cert.pub` (e.g. `~/.ssh/id_rsa-cert.pub`) by `altar.py`.

> n.b. The wrapper script will also helpfully add the certificate to the macOS Keychain if the system is Darwin.

Security Considerations
-----------------------

Access to the secrets stored in the Key Vault should only be granted to the AAD Web App. The goal is to restrict any users (human or otherwise) from signing access keys themselves. Pay close attention to the ownership chain for the Key Vault and its Resource Group (as well as subscription administrators), as sufficiently-privileged users could grant themselves access to the secrets by leveraging their resource management privileges.

Access to the client secrets for the AAD Web App are likewise extremely sensitive, as obtaining them could be used to impersonate the Web App and acquire the Key Vault secrets. Bear in mind that any user with read access to the Web Service configuration can obtain this client secret, as it is necessarily stored in plaintext in the `config/authsettings` document. Any user that owns the AAD Web App can create new secrets with equivalent privileges, as well.
