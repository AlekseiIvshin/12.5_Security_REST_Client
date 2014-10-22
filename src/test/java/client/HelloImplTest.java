package client;

import static org.junit.Assert.*;

import org.junit.Test;

public class HelloImplTest {

	@Test
	public void testHello() {
		HelloImpl hello = new HelloImpl();
		hello.hello();
	}

}
