package client.helper;

import java.io.IOException;

import javax.ws.rs.core.Response;
import javax.xml.ws.http.HTTPException;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResponseParserImpl implements ResponseParser {

	static final Logger logger = LoggerFactory.getLogger(ResponseParserImpl.class);

	protected final ObjectMapper jsonMapper;

	public ResponseParserImpl() {
		jsonMapper = new ObjectMapper();
	}

	@Override
	public <T> T parseResponse(Response response, TypeReference<?> type) {
		if (response.getStatus() == 200) {

			try {
				String entity = response.readEntity(String.class);
				return jsonMapper.readValue(entity, type);
			} catch (IOException e) {
				logger.error("Parse response entity error", e);
				return null;
			}
		} else {
			logger.error("Response status: {}", response.getStatus());
			throw new HTTPException(response.getStatus());
		}
	}

}
