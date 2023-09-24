/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.social.wecom;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * WeCom social provider. See https://developer.work.weixin.qq.com/document/path/91335
 *
 * @author Potter He
 */
public class WeComIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    public static final String AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    public static final String TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";

    public static final String DEFAULT_SCOPE = "snsapi_base";

    public static final String WWLOGIN_AUTH_URL =  "https://login.work.weixin.qq.com/wwlogin/sso/login";

    public WeComIdentityProvider(KeycloakSession session, WeComIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        //config.setTokenUrl(TOKEN_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        // https://developer.work.weixin.qq.com/document/path/90457#%E4%BC%81%E4%B8%9A%E5%BE%AE%E4%BF%A1%E7%9A%84ua
        String ua = request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
        if (ua.contains("wxwork")) {
            UriBuilder uriBuilder = super.createAuthorizationUrl(request);
            final WeComIdentityProviderConfig wecomConfig = (WeComIdentityProviderConfig) getConfig();

            // todo
            uriBuilder.queryParam("appid", wecomConfig.getAppId());
            uriBuilder.queryParam("agentid", wecomConfig.getAgentId());

            return uriBuilder;
        }

        return createWWLoginAuthorizationUrl(request);
    }

    private UriBuilder createWWLoginAuthorizationUrl(AuthenticationRequest request) {
        final WeComIdentityProviderConfig wecomConfig = (WeComIdentityProviderConfig) getConfig();
        final UriBuilder uriBuilder = UriBuilder.fromUri(WWLOGIN_AUTH_URL)
                .queryParam("login_type", "CorpApp")
                .queryParam("appid", wecomConfig.getAppId())
                .queryParam("agentid", wecomConfig.getAgentId())
                .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

        return uriBuilder;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        // 根据文档 https://developer.work.weixin.qq.com/document/path/98176
        // 返回的是 userid
        String userId = extractTokenFromResponse(response, "userid");
        if (userId == null) {
            throw new IdentityBrokerException("No userid available in OAuth server response: " + response);
        }

        String accessToken = getAccessToken();
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }

        // access-token + userid 获取用户
        BrokeredIdentityContext context = doGetFederatedIdentity2(accessToken, userId);
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    protected BrokeredIdentityContext doGetFederatedIdentity2(String accessToken, String userId) {
        // https://developer.work.weixin.qq.com/document/path/90196
        String profileUrl = "https://qyapi.weixin.qq.com/cgi-bin/user/get";
        try {
            SimpleHttp.Response response = SimpleHttp.doGet(profileUrl, session)
                    .param("access_token", accessToken)
                    .param("userid", userId)
                    .asResponse();

            if (Response.Status.fromStatusCode(response.getStatus()).getFamily() != Response.Status.Family.SUCCESSFUL) {
                logger.warnf("Profile endpoint returned an error (%d): %s", response.getStatus(), response.asString());
                throw new IdentityBrokerException("Profile could not be retrieved from the wecom endpoint");
            }

            JsonNode profile = response.asJson();
            logger.tracef("profile retrieved from wecom: %s", profile);
            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
            return user;

        } catch (Exception e) {
            throw new IdentityBrokerException("Profile could not be retrieved from the wecom endpoint", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        //https://developer.work.weixin.qq.com/document/path/90196
        String userId = getJsonProperty(profile, "userid");
        BrokeredIdentityContext user = new BrokeredIdentityContext(userId);

        user.setUsername(userId);
        user.setFirstName(getJsonProperty(profile, "name"));
        user.setLastName(""); // todo
        user.setEmail(getJsonProperty(profile, "email"));
        //user.setUserAttribute("mobile", getJsonProperty(profile, "mobile"));

        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    private String getAccessToken() {
        // todo 缓存accessToken
        JsonNode j = renewAccessToken();
        String token = getJsonProperty(j, "access_token");
        //long timeout = Integer.parseInt(getJsonProperty(j, "expires_in"));
        return token;
    }

    private JsonNode renewAccessToken() {
        https://developer.work.weixin.qq.com/document/path/91039
        try {
            return SimpleHttp.doGet(TOKEN_URL, session)
                    .param("corpid", getConfig().getClientId())
                    .param("corpsecret", getConfig().getClientSecret())
                    .asJson();
        } catch (Exception e) {
            logger.error(e);
            e.printStackTrace(System.out);
        }
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    protected static class Endpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        private final WeComIdentityProvider provider;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, AbstractOAuth2IdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = (WeComIdentityProvider) provider;
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            // https://developer.work.weixin.qq.com/document/path/98176
            String useridUrl = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo";

            SimpleHttp tokenRequest = SimpleHttp.doGet(useridUrl, session)
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param("access_token", provider.getAccessToken());

            return tokenRequest;
        }
    }

}
