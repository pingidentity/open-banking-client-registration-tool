# Open Banking Client Registration Tool

This is a simple Java command line tool that demonstrates how to issue and send client registration requests to ASPSPs. The tool does the following:

- authenticates against the Open Banking directory to obtain an OAuth Access Token
- calls the Open Banking software statement API to obtain a new software statement (with the token just obtained)
- generates a client registration request JWT that embeds the software statement
- submits the request JWT to the ASPSP

# Usage

To run the tool:

- ensure that a software statement has been created using the Open Banking Directory Frontend and that a signing key and network certificate are associated to the software statement (as explained [here] (https://www.pingidentity.com/en/company/blog/posts/2018/enable-open-banking-dynamic-client-registration-with-ping-identity.html))
- download and unzip the source code from GitHub or clone the source
- change the following parameters in the src/main/resources/configuration.properties file:
  - ob.signingKeyId the signing key ID obtained from the Open Banking Directory Frontend
  - ob.softwareStatementId the software statement ID obtained from the Open Banking Directory Frontend
  - ob.organization the organization ID obtained from the Open Banking Directory Frontend
  - aspsp.redirectUri the redirect URI of the TPP app, this must match the redirect URI configured in the OB directory
  - aspsp.audience the audience expected from the ASPSP
  - aspsp.registrationEndpoint the registration endpoint of the ASPSP
  - aspsp.networkCertPassword the password used to protect the p12 network certificate
- the remaining parameters can be left unmodified for the MIT environment
- replace the signing key and the network certificates with yours:
  - signing key: replace the file src/main/resources/dynamic_client_reg_signing.key with your signing private key
  - network certificate: replace the file src/main/resources/dynamic_client_reg_network.p12 with your TPP certificate
- run the following command from the root of the project:

```sh
mvn compile exec:java -Dexec.mainClass="com.pingidentity.openbanking.ClientRegistrationTool"
```