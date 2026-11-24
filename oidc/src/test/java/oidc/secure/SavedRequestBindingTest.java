package oidc.secure;

import oidc.exceptions.UnauthorizedException;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import org.junit.Test;

import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SavedRequestBindingTest {

    private final AuthenticationRequestRepository repository = mock(AuthenticationRequestRepository.class);

    private void saved(String url) {
        when(repository.findById("id")).thenReturn(Optional.of(new AuthenticationRequest("id", new Date(), "client", url)));
    }

    private void assertMatches(Map<String, String> incoming) {
        SavedRequestBinding.assertMatchesSavedRequest(repository, "id", incoming, Set.of("yes"));
    }

    @Test
    public void reorderedAndReEncodedValuesAreAllowed() {
        saved("/oidc/authorize?state=a%2Fb%20c&client_id=client&scope=groups%20openid&acr_values=b+a");
        assertMatches(Map.of("client_id", "client", "scope", "openid  groups", "acr_values", "a b", "state", "a/b c", "yes", "yes"));
    }

    @Test
    public void changedValueIsRejected() {
        saved("/oidc/authorize?client_id=client&scope=openid");
        assertThrows(UnauthorizedException.class, () -> assertMatches(Map.of("client_id", "client", "scope", "openid groups")));
    }

    @Test
    public void addedOrRemovedParameterIsRejected() {
        saved("/oidc/authorize?client_id=client&acr_values=loa3");
        assertThrows(UnauthorizedException.class, () -> assertMatches(Map.of("client_id", "client")));
        saved("/oidc/authorize?client_id=client");
        assertThrows(UnauthorizedException.class, () -> assertMatches(Map.of("client_id", "client", "max_age", "0")));
    }

    @Test
    public void missingSavedRequestIsRejected() {
        when(repository.findById("nope")).thenReturn(Optional.empty());
        assertThrows(UnauthorizedException.class, () ->
            SavedRequestBinding.assertMatchesSavedRequest(repository, "nope", Map.of(), Set.of()));
    }
}
