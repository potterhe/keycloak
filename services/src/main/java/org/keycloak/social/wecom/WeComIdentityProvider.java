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

import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

/**
 * WeCom social provider. See https://developer.work.weixin.qq.com/document/path/91335
 *
 * @author Potter He
 */
public class WeComIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    public static final String AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    public static final String DEFAULT_SCOPE = "snsapi_base";

    public static final String WWLOGIN_AUTH_URL =  "https://login.work.weixin.qq.com/wwlogin/sso/login";

    public WeComIdentityProvider(KeycloakSession session, WeComIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
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

}
