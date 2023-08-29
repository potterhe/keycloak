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

package org.keycloak.social.dingtalk;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.util.HashMap;
import java.util.Map;

public class DingtalkIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    // https://open.dingtalk.com/document/orgapp/tutorial-obtaining-user-personal-information

    // https://open.dingtalk.com/document/orgapp/obtain-identity-credentials
    // https://open.dingtalk.com/document/orgapp/sso-overview
    public static final String AUTH_URL = "https://login.dingtalk.com/oauth2/auth";
    public static final String DEFAULT_SCOPE = "openid";

    //https://open.dingtalk.com/document/orgapp/obtain-user-token
    public static final String TOKEN_URL = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken";

    //https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information
    public static final String PROFILE_URL = "https://api.dingtalk.com/v1.0/contact/users/me";

    public DingtalkIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.getConfig().put("prompt", "consent");
        config.setTokenUrl(TOKEN_URL);
        //config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected String getAccessTokenResponseParameter() {
        return "accessToken";
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        // https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information
        try {
            SimpleHttp.Response response = SimpleHttp.doGet(PROFILE_URL, session)
                    .header("x-acs-dingtalk-access-token", accessToken)
                    .header("Accept", "application/json")
                    .asResponse();

            if (Response.Status.fromStatusCode(response.getStatus()).getFamily() != Response.Status.Family.SUCCESSFUL) {
                // {
                //      "code":"Forbidden.AccessDenied.AccessTokenPermissionDenied",
                //      "requestid":"6E32D367-2DFE-7DDB-B729-1735AE7C2ABE",
                //      "message":"没有调用该接口的权限，接口权限申请参考：https://open.dingtalk.com/document/orgapp-server/add-api-permission",
                //      "accessdenieddetail":{"requiredScopes":["Contact.User.Read"]}
                //  }
                // 设置 prompt 参数后解决。
                logger.warnf("Profile endpoint returned an error (%d): %s", response.getStatus(), response.asString());
                throw new IdentityBrokerException("Profile could not be retrieved from the dingtalk endpoint");
            }

            JsonNode profile = response.asJson();
            logger.tracef("profile retrieved from dingtalk: %s", profile);
            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
            return user;

        } catch (Exception e) {
            throw new IdentityBrokerException("Profile could not be retrieved from the dingtalk endpoint", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        // https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information#h2-tvg-cb5-her
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "openId"));

        String username = getJsonProperty(profile, "mobile"); // 钉钉只支持手机号注册
        user.setUsername(username);
        //user.setName(getJsonProperty(profile, "nick"));
        user.setFirstName(getJsonProperty(profile, "nick"));
        user.setLastName(""); // todo 拆 nick?，前台由用户自己拆?
        user.setEmail(getJsonProperty(profile, "email")); // 只会返回企业邮箱
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    protected static class Endpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        private final AbstractOAuth2IdentityProvider provider;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, AbstractOAuth2IdentityProvider provider) {
            super(callback, realm, event, provider);

            this.provider = provider;
        }

        @GET
        @Override
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam("authCode") String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {

            return super.authResponse(state, authorizationCode, error);
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();

            //https://open.dingtalk.com/document/orgapp/obtain-user-token
            Map<String, String> params = new HashMap<>();
            params.put("clientId", providerConfig.getClientId());
            params.put("clientSecret", providerConfig.getClientSecret());
            params.put(OAUTH2_PARAMETER_CODE, authorizationCode);
            params.put("grantType", OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

            SimpleHttp tokenRequest = SimpleHttp.doPost(providerConfig.getTokenUrl(), session)
                    .json(params);

            return tokenRequest;
        }
    }
}
