package com.pingidentity.openbanking;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.net.ssl.SSLContext;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationUtils;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.BouncyCastleProviderHelp;
import org.jose4j.lang.JoseException;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;

/**
 * Command line tool that can be used to download software statements from the OB directory and post client registration requests to an ASPSP.
 * 
 * - authenticates against the Open Banking directory to obtain an OAuth Access Token
 * - using the Open Banking access token it calls the Open Banking software statement API to obtain a new software statement
 * - generates a client registration JWT request that embeds the software statement
 * - submits to the ASPSP the request
 * 
 */
public class ClientRegistrationTool {

	private static final String OB_SIGNING_KEY_ID = "ob.signingKeyId";
	private static final String OB_SOFTWARE_STATEMENT_ID = "ob.softwareStatementId";
	private static final String OB_TOKEN_ENDPOINT = "ob.tokenEndpoint";
	private static final String OB_AUDIENCE = "ob.audience";
	private static final String OB_SCOPE = "ob.scope";
	private static final String OB_API_ENDPOINT = "ob.apiEndpoint";
	private static final String OB_ORGANIZATION = "ob.organization";

	private static final String ASPSP_REDIRECT_URI = "aspsp.redirectUri";
	private static final String ASPSP_AUDIENCE = "aspsp.audience";
	private static final String ASPSP_AUTH_METHOD = "aspsp.authMethod";
	private static final String ASPSP_REGISTRATION_ENDPOINT = "aspsp.registrationEndpoint";
	private static final String ASPSP_NETWORK_CERT_PASSWORD = "aspsp.networkCertPassword";
	

	Configuration config;
	
	
	public ClientRegistrationTool() throws Exception {
		config = new PropertiesConfiguration("config.properties");

	}

	public void createClient() throws Exception {
		// Enable Bouncy Castle to support PS256
		BouncyCastleProviderHelp.enableBouncyCastleProvider();

		// Load the private key to sign the request JWT
		PrivateKey signingKey = loadSigningKey();

		// generate the privateKeyJWT to obtain an access token from the OB Directory
		String privateKeyJWT = generatePrivateKeyJWT(signingKey);

		// get the OB access token
		String obAccessToken = getOBAccessToken(privateKeyJWT);

		// download from the OB directory the software statement
		String softwareStatement = getSoftwareStatement(obAccessToken);

		// generate the request JWT
		String requestJwt = generateRequestJwt(signingKey, softwareStatement);

		// post the request JWT to the registration endpoint over MTLS
		postRequest(requestJwt);
	}

	protected String getSoftwareStatement(String obAccessToken) throws Exception {
		// get token endpoint, organization id and software statement id from the property file and build the url
		String ssaEndpoint = config.getString(OB_API_ENDPOINT) + "/tpp/" + config.getProperty(OB_ORGANIZATION) + "/ssa/"
				+ config.getProperty(OB_SOFTWARE_STATEMENT_ID);
		log("SSA endpoint: " + ssaEndpoint);
		
		// make the GET call to the API and return the token, stop if return code is not HTTP 200
		HttpResponse<String> stringResponse = Unirest.get(ssaEndpoint).header("Authorization ", "Bearer " + obAccessToken).asString();
		log("OB SSA endpoint response code " + stringResponse.getStatus() + ", body " + stringResponse.getBody());
		if (stringResponse.getStatus() != 200) {
			throw new Exception("SSA API call error");
		}
		return stringResponse.getBody();
	}

	protected String getOBAccessToken(String privateKeyJWT) throws Exception {
		// send the client_credentials request
		HttpResponse<JsonNode> jsonResponse = Unirest.post(config.getString(OB_TOKEN_ENDPOINT))
				.header(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType())
				.header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType()).field("grant_type", "client_credentials")
				.field("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer").field("client_assertion", privateKeyJWT)
				.field("scope", config.getString(OB_SCOPE)).asJson();

		log("OB Token endpoint response code " + jsonResponse.getStatus() + ", body " + jsonResponse.getBody().toString());

		// stop if response code is not HTTP 200
		if (jsonResponse.getStatus() != 200) {
			throw new Exception("Authentication failed");
		}

		// extract access token if successful
		String accessToken = jsonResponse.getBody().getObject().getString("access_token");
		log("Access token " + accessToken);
		return accessToken;
	}

	protected String generatePrivateKeyJWT(PrivateKey rsaPrivate) throws Exception {
		// generate the claims for the JWT body
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(config.getString(OB_SOFTWARE_STATEMENT_ID));
		claims.setSubject(config.getString(OB_SOFTWARE_STATEMENT_ID));
		claims.setAudience(config.getString(OB_AUDIENCE));
		claims.setExpirationTimeMinutesInTheFuture(5);
		claims.setIssuedAtToNow();
		claims.setGeneratedJwtId();

		// get the signed JWT
		String privateKeyJWT = getJwt(config.getString(OB_SIGNING_KEY_ID), rsaPrivate, claims);
		log("Private key JWT " + privateKeyJWT);
		return privateKeyJWT;
	}

	protected String generateRequestJwt(PrivateKey rsaPrivate, String ssa) throws Exception {
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(config.getString(OB_SOFTWARE_STATEMENT_ID));
		claims.setAudience(config.getString(ASPSP_AUDIENCE));
		// set the software statement obtained from OB
		claims.setClaim("software_statement", ssa);
		// set client specific configuration parameters (auth method, supported grant_types, etc.)
		claims.setStringListClaim("redirect_uris", Arrays.asList(config.getString(ASPSP_REDIRECT_URI)));
		claims.setClaim("token_endpoint_auth_method", config.getString(ASPSP_AUTH_METHOD));
		claims.setStringListClaim("grant_types", Arrays.asList("authorization_code", "refresh_token", "client_credentials", "implicit"));
		claims.setStringListClaim("response_types", Arrays.asList("code id_token"));
		claims.setClaim("id_token_signed_response_alg", "PS256");
		claims.setClaim("request_object_signing_alg", "PS256");
		claims.setClaim("application_type", "Web");
		// set timestamps and JWT id
		claims.setIssuedAtToNow();
		claims.setExpirationTimeMinutesInTheFuture(10);
		claims.setGeneratedJwtId();
		
		// get the signed JWT
		String requestJWT = getJwt(config.getString(OB_SIGNING_KEY_ID), rsaPrivate, claims);
		log("Request JWT generated: " + requestJWT);

		return requestJWT;
	}

	protected String getJwt(String keyId, PrivateKey rsaPrivate, JwtClaims claims) throws JoseException {
		JsonWebSignature jws = new JsonWebSignature();
		// set the payload
		jws.setPayload(claims.toJson());

		// set the signing key
		jws.setKey(rsaPrivate);

		// set header
		jws.setKeyIdHeaderValue(keyId);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// generate and return JWT
		return jws.getCompactSerialization();
	}

	protected void postRequest(String requestJwt) throws Exception {
		Unirest.setHttpClient(getMTLSHttpClient());

		HttpResponse<JsonNode> jsonResponse = Unirest.post(config.getString(ASPSP_REGISTRATION_ENDPOINT))
				.header(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType()).header(HttpHeaders.CONTENT_TYPE, "application/jwt").body(requestJwt)
				.asJson();

		log("Client registration response " + jsonResponse.getStatus() + ", body " + jsonResponse.getBody().toString());
		if (jsonResponse.getStatus() != 201) {
			throw new Exception("Client creation failed");
		}
	}

	protected CloseableHttpClient getMTLSHttpClient() throws Exception {
		String networkCertPassword = config.getString(ASPSP_NETWORK_CERT_PASSWORD);
		File file = ConfigurationUtils.fileFromURL(getClass().getClassLoader().getResource("dynamic_client_reg_network.p12"));
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(file), networkCertPassword.toCharArray());
		SSLContext sslcontext = SSLContexts.custom().loadKeyMaterial(keystore, networkCertPassword.toCharArray()).build();
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new String[] { "TLSv1.2" }, null,
				SSLConnectionSocketFactory.getDefaultHostnameVerifier());
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		return httpclient;
	}

	protected PrivateKey loadSigningKey() throws Exception {
		File file = ConfigurationUtils.fileFromURL(getClass().getClassLoader().getResource("dynamic_client_reg_signing.key"));
		String privateKey = FileUtils.readFileToString(file).replace(System.getProperty("line.separator"), "");
		byte[] decoded = Base64.getDecoder().decode(privateKey);
		return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
	}

	protected static void log(String logMessage) {
		System.out.println(logMessage);
	}

	public static void main(String[] args) throws Exception {
		ClientRegistrationTool regTool = new ClientRegistrationTool();
		regTool.createClient();
	}

}
