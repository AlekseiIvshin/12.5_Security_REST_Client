package client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.net.www.protocol.https.Handler;

public class HelloImpl implements Hello {

	static final Logger logger = LoggerFactory.getLogger(HelloImpl.class);

	@Override
	public void hello() {
		String target = "https://localhost:8443/Rest/webapi/myresource";
		
		HttpsURLConnection con;
		try {
			con = getConnection(target);
		} catch (IOException e) {
			logger.error("Create connection error",e);
			return;
		}
		
		getCertificates(con);
	}

	private void getCertificates(HttpsURLConnection connection) {
		if (connection != null) {
			try {
				logger.info("Response code: {}", connection.getResponseCode());

				logger.info("Cipher Suite: {}", connection.getCipherSuite());
				logger.info("---");

				Certificate[] certs = connection.getServerCertificates();
				for (Certificate cert : certs) {
					logger.info("Cert type: {}", cert.getType());
					logger.info("Cert hash code: {}", cert.hashCode());
					logger.info("Cert public key algorithm: {}", cert
							.getPublicKey().getAlgorithm());
					logger.info("Cert public key format: {}", cert
							.getPublicKey().getFormat());
				}
			} catch (IOException e) {
				logger.error("Certificat error", e);
			}
		}
	}

	private HttpsURLConnection getConnection(String target) throws IOException {
		URL url = new URL(null, target, new Handler());
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		con.setSSLSocketFactory(socketFactory);		
		return con;
	}

}
