package client.helper;

import javax.ws.rs.core.Response;

import org.codehaus.jackson.type.TypeReference;

public interface ResponseParser {


	<T> T parseResponse(Response response, TypeReference<?> type);
}
