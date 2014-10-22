package client.helper;

public interface RequsetDataPacker {

	<T> String packToJsonString(T data);
}
