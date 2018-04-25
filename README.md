This plugin automates the process of completing a ``dns-01`` challenge by creating, and subsequently removing, TXT records using the (XML-RPC-based) euserv.com API.

Credentials
-----------
Use of this plugin requires a configuration file containing EUserv API credentials, obtained from your EUserv account's [API Managenment page](https://support.euserv.com/). Create an account with at least `domain` permission.

```ini
# EUserv API credentials used by Certbot
certbot_dns_euserv:dns_euserv_username = 123456.somename
certbot_dns_euserv:dns_euserv_password = seCretPassw0rd
```

The path to this file can be provided interactively or using the `--certbot_dns_euserv:dns-euserv-credentials` command-line argument. Certbot records the path to this file for use during renewal, but does not store the file's contents.

> You should protect these API credentials as you would the password to your EUserv account. Users who can read this file can use these credentials to issue arbitrary API calls on your behalf. Users who can cause Certbot to run using these credentials can complete a ``dns-01`` challenge to acquire new certificates or revoke existing certificates for associated domains, even if those domains aren't being managed by this server. Certbot will emit a warning if it detects that the credentials file can be accessed by other users on your system. The warning reads "Unsafe permissions on credentials configuration file", followed by the path to the credentials file. This warning will be emitted each time Certbot uses the credentials file, including for renewal, and cannot be silenced except by addressing the issue (e.g., by using a command like `chmod 600` to restrict access to the file).

# Usage

## Docker

* **Recommended usage**. Create the credentials file and 2 folders for the certificates and logs and run:
```sh
docker run -it --rm \
  -v $(pwd)/certs:/etc/letsencrypt \
  -v $(pwd)/logs:/var/log/letsencrypt \
  -v $(pwd)/euserv.ini:/euserv.ini \
  kraiz/certbot-dns-euserv certonly \
  -a certbot-dns-euserv:dns-euserv \
  --certbot-dns-euserv:dns-euserv-credentials /euserv.ini \
  --agree-tos \
  --email "your@mail.com" \
  -d "example.com" \
  --test-cert
```
* After a successful run, remove the last parameter `--test-cert` which enabled [staging server](https://letsencrypt.org/docs/staging-environment/) and run again.

## Python

* If you know what you're doing install the plugin into the same python environment like `certbot`. In any other case follow the `Docker` approach above:
```sh
pip install https://github.com/kraiz/certbot-dns-euserv/archive/master.zip
```
* Check that `certbot` discovers the plugin:
```sh
certbot plugins
```
* Now run the command:
```sh
certbot certonly \
  -a certbot-dns-euserv:dns-euserv \
  --certbot-dns-euserv:dns-euserv-credentials ~/.secret/certbot/euserv.ini \
  --agree-tos \
  --email "your@mail.com" \
  -d "example.com" \
  --test-cert
  ```