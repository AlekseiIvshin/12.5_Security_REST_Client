package client;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.net.www.protocol.http.HttpURLConnection;

public class Hello {

	static final Logger logger = LoggerFactory.getLogger(Hello.class);
	
	private final String clientStorePath = "src/main/resources/client.jks";
	private final String clientTrustStorePath = "src/main/resources/clienttrust.jks";
	private final char[] storePass = "password".toCharArray();
	private final char[] keyPass = "password".toCharArray();

	
	
	public String hello(String address) throws NoSuchAlgorithmException, KeyStoreException,
			CertificateException, IOException, UnrecoverableKeyException,
			KeyManagementException {
		URL url = new URL(address);

		HttpsURLConnection con = getConnection(url);
		String response = getResponse(con);
		logger.info(response);
		return response;
	}
	
	private HttpsURLConnection getConnection(URL url) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException{
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		con.setRequestMethod("GET");

		SSLContext sslContext = SSLContext.getInstance("TLS");
		
		KeyStore clientStore = getKeyStore(clientStorePath, storePass);
		KeyManagerFactory clientKeyManager = getKeyManagerFactory(clientStore, keyPass);
		
		KeyStore clientTrustStore = getKeyStore(clientTrustStorePath, storePass);
		TrustManagerFactory clientTrustKeyManager = getTrustManagerFactory(clientTrustStore, keyPass);
		
		con.setHostnameVerifier(getHostnameVerifier());

		sslContext.init(clientKeyManager.getKeyManagers(), clientTrustKeyManager.getTrustManagers(), null);
		con.setSSLSocketFactory(sslContext.getSocketFactory());
		return con;
	}
	
	private KeyManagerFactory getKeyManagerFactory(KeyStore keyStore, char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, password);
		return kmf;
	}
	
	private TrustManagerFactory getTrustManagerFactory(KeyStore keyStore, char[] password) throws KeyStoreException, NoSuchAlgorithmException{
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(keyStore);
		return tmf;
	}
	
	private KeyStore getKeyStore(String pathToStore,char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream keyStore = new FileInputStream(pathToStore);
		ks.load(keyStore, password);
		return ks;
	}
	
	private HostnameVerifier getHostnameVerifier(){
		return new HostnameVerifier() {
			public boolean verify(String s, SSLSession sslSession) {
				return s.equals(sslSession.getPeerHost());
			}
		};
	}
	
	private String getResponse(HttpsURLConnection con) throws IOException{

		int responseCode = con.getResponseCode();
		InputStream inputStream;
		if (responseCode == HttpURLConnection.HTTP_OK) {
			inputStream = con.getInputStream();
			System.out.println("Connection OK");
		} else {
			inputStream = con.getErrorStream();
			System.out.println("Connection error");
		}

		// Process the response
		BufferedReader reader;
		StringBuilder reslt = new StringBuilder();
		String line = null;
		reader = new BufferedReader(new InputStreamReader(inputStream));
		while ((line = reader.readLine()) != null) {
			reslt.append(line);
		}

		inputStream.close();
		return reslt.toString();
	}
	
}
