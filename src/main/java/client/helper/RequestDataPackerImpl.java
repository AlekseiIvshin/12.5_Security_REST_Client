package client.helper;

import java.io.IOException;

import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RequestDataPackerImpl implements RequsetDataPacker {

	static final Logger logger = LoggerFactory.getLogger(RequestDataPackerImpl.class);

	protected final ObjectMapper jsonMapper;

	public RequestDataPackerImpl() {
		jsonMapper = new ObjectMapper();
	}
	
	@Override
	public <T> String packToJsonString(T data) {
		try {
			return jsonMapper.writeValueAsString(data);
		} catch (IOException e1) {
			logger.error("Mapping exception", e1);
			return null;
		}
	}

}
