package oidc.manage;

/**
 * The OAuth spec https://tools.ietf.org/html/rfc6749 dictates:
 * <p>
 * The authorization server MUST support the HTTP Basic
 * authentication scheme for authenticating clients that were issued a
 * client password
 * <p>
 * The HTTP Authentication spec https://tools.ietf.org/html/rfc2617 dictates:
 * <p>
 * userid      = *<TEXT excluding ":">
 * <p>
 * ServiceProviders in the SURFconext federation have an entity-id that we
 * must use to scope the AuthN request. The entity-id by convention contains
 * a ':'. For example: https://oidc.localhost.surfconext.nl
 * <p>
 * We want to use the entity-id of a SP as the client_id of an OAuth / OpenConnect ID
 * client. However this breaks the Basic Authentication must-have.
 * <p>
 * We therefore must translate the client_id to a SP entity-id and vica-versa.
 */
public class ServiceProviderTranslation {

    public static String translateServiceProviderEntityId(String entityId) {
        return entityId.replace("@", "@@").replaceAll(":", "@");
    }

    public static String translateClientId(String clientId) {
        return clientId.replaceAll("(?<!@)@(?!@)", ":").replaceAll("@@", "@");
    }

}
