package oidc.eduid;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class FaultTolerantResponseErrorHandlerTest {

    private final FaultTolerantResponseErrorHandler errorHandler = new FaultTolerantResponseErrorHandler();

    @Test
    void hasError() {
        assertFalse(errorHandler.hasError(mock(ClientHttpResponse.class)));
    }

    @Test
    void handleError() throws URISyntaxException {
        //ensure no error is thrown
        errorHandler.handleError(new URI("https://example.com"), HttpMethod.GET, mock(ClientHttpResponse.class));
    }
}
