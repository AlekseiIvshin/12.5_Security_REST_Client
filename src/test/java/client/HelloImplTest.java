package client;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.Test;

public class HelloImplTest {

	@Test
	public void testHello() {
		Hello hello = new Hello();
		String response;
		try {
			response = hello.hello("https://10.27.11.40:8443/HelloWorld");
		} catch (UnrecoverableKeyException | KeyManagementException
				| NoSuchAlgorithmException | KeyStoreException
				| CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fail(e.getMessage());
			return;
		}
		assertNotNull(response);
	}

}
