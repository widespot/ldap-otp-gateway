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
python -m ldap-otp-proxy.run
```

ldapwhoami -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w password
LDAPTLS_REQCERT=never ldapwhoami -x -H ldaps://localhost:636 -D "cn=admin,dc=example,dc=com" -w password

ldapwhoami -x -H ldap://localhost:10389 -D "cn=admin,dc=example,dc=com" -w password123456 -d 255
LDAPTLS_REQCERT=never ldapwhoami -x -H ldaps://localhost:10636 -D "cn=admin,dc=example,dc=com" -w password123456 -d 255