package client;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.org.apache.bcel.internal.generic.RET;

import sun.net.www.protocol.https.Handler;

public class HelloImpl implements Hello {

	static final Logger logger = LoggerFactory.getLogger(HelloImpl.class);

	private final KeyManager keyManager;

	public HelloImpl(KeyManager keyManager) {
		this.keyManager = keyManager;
	}

	@Override
	public void hello() {
		String target = "https://localhost:8443/Rest/webapi/myresource";
		try {
			handShake();
		} catch (KeyManagementException | NoSuchAlgorithmException e1) {
			logger.error("Handshake error",e1);
			return;
		}
		HttpsURLConnection con;
		try {
			con = getConnection(target);
		} catch (IOException e) {
			logger.error("Create connection error", e);
			return;
		}
		try {
			con.connect();
			
			
		} catch (IOException e) {
			logger.error("Connection error", e);
		} finally{
			con.disconnect();
		}
	}

	private void handShake() throws KeyManagementException, NoSuchAlgorithmException {
		TrustManager[] trustManager = getTrustManager();
		SSLContext ctx = SSLContext.getInstance("TSL");
		ctx.init(null, trustManager, new SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
	}

	private Certificate[] getServerCertificates(HttpsURLConnection connection) {
		if (connection != null) {
			try {
				return connection.getServerCertificates();
			} catch (SSLPeerUnverifiedException e) {
				logger.error("SSL peer exception", e);
			}
		}
		return null;
	}

	private HttpsURLConnection getConnection(String target) throws IOException {
		URL url = new URL(null, target, new Handler());
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory
				.getDefault();
		con.setSSLSocketFactory(socketFactory);
		return con;
	}

	private void acceptanceCertificates(Certificate[] certificates) {
		Scanner sc = new Scanner(System.in);
		for (Certificate cer : certificates) {

			try {
				if (!keyManager.isTrusted(cer)) {
					showCertificateInfo(cer);
					logger.info("Is this certificate trusted?[yes/no]");
					String choice = sc.next();
					if (choice.equalsIgnoreCase("yes")) {
						keyManager.addToTrust(getCertificateAlias(cer), cer);
					}
				}
			} catch (KeyStoreException e) {
				logger.error("Key store exception", e);
			}
		}
		sc.close();
	}

	private void showCertificateInfo(Certificate certificate) {
		logger.info("Certificate info:\n\tType: {}\nPublic key:\n"
				+ "\t\tAlgorithm: {}\n\t\tFormat: {}", certificate.getType(),
				certificate.getPublicKey().getAlgorithm(), certificate
						.getPublicKey().getFormat());
	}

	private String getCertificateAlias(Certificate certificate) {
		return certificate.getType() + "@" + certificate.hashCode();
	}

	private TrustManager[] getTrustManager() {
		return new TrustManager[] { new X509TrustManager() {

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1)
					throws CertificateException {
			}

			@Override
			public void checkClientTrusted(X509Certificate[] certificates,
					String authType) throws CertificateException {

				Scanner sc = new Scanner(System.in);
				for (int i = certificates.length - 1; i >= 0; i--) {
					try {
						if (!keyManager.isTrusted(certificates[i])) {
							showCertificateInfo(certificates[i]);
							logger.info("Is this certificate trusted?[yes/no]");
							String choice = sc.next();
							if (choice.equalsIgnoreCase("yes")) {
								keyManager.addToTrust(
										getCertificateAlias(certificates[i]),
										certificates[i]);
							}
						}
					} catch (KeyStoreException e) {
						logger.error("KeyStore Exception", e);
						break;
					}
				}
				sc.close();

			}
		} };
	}

}
