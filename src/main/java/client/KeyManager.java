package client;

import java.security.KeyStoreException;
import java.security.cert.Certificate;

public interface KeyManager {
	
	boolean isTrusted(Certificate certificate) throws KeyStoreException;
	void addToTrust(String alias, Certificate certificate) throws KeyStoreException;
}
