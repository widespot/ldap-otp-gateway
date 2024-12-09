1. Start the service stack
    ```shell
    docker compose up -d
    docker compose logs -f webadm
    ```
2. Follow the annoying process to get a license, and put the `license.key` file in the [./webadm](./webadm) folder.
3. Install the license file and fix the auto-generated `server.xml` file
   ```shell
   docker compose exec webadm cp /opt/docker/license.key /opt/webadm/conf/license.key
   docker compose exec webadm cp /opt/docker/servers.xml /opt/webadm/conf/servers.xml
   docker compose restart webadm
   ```
   
```shell
python -m ldap_otp_gateway.run
```

## Troubleshoot
```shell
# test backend LDAP basic who am I
ldapwhoami -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password
# test backend LDAP request
ldapsearch -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password -v -b "dc=WebADM"
# test backend LDAP basic who am I with SSL, but disable SSL check
LDAPTLS_REQCERT=never ldapwhoami -x -H ldaps://localhost:636 -D "cn=admin,dc=example,dc=com" -w password
# test backend LDAP basic who am I with SSL
ldapwhoami -x -H ldaps://localhost:636 -D "cn=admin,dc=example,dc=com" -w password

# test LDAP gateway who am I
ldapwhoami -x -H ldap://localhost:10389 -D "cn=admin,dc=example,dc=com" -w password123456
# test LDAP gateway request
ldapsearch -H ldap://localhost:10389 -D "cn=admin,dc=example,dc=com" -w password123456 -v -b "dc=WebADM"
# test LDAP gateway basic who am I with SSL, but disable SSL check
LDAPTLS_REQCERT=never ldapwhoami -x -H ldaps://localhost:10636 -D "cn=admin,dc=example,dc=com" -w password123456
```
