package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyManagerImpl implements KeyManager {
	
	private final KeyStore keyStore;
	
	public KeyManagerImpl(File store, String storePassword) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream fis = new FileInputStream(store);
		keyStore.load(fis, storePassword.toCharArray());
		fis.close();
	}
	@Override
	public boolean isTrusted(Certificate certificate) throws KeyStoreException {
		String alias = keyStore.getCertificateAlias(certificate);
		return alias!=null && alias.isEmpty();
	}

	@Override
	public void addToTrust(String alias, Certificate certificate) throws KeyStoreException {
		KeyStore.Entry newEntry = new KeyStore.TrustedCertificateEntry(certificate);
		keyStore.setEntry(alias, newEntry, null);
	}

}
