/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityClaimManager;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus.UNSUCCESS_COMPLETED;
import static org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.constant.SSOConsentConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.PASSWORD_PROVISION_REDIRECTION_TRIGGERED;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SIGN_UP_ENDPOINT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants
        .ErrorMessages.*;

/**
 * This is post authentication handler responsible for JIT provisioning.
 */
public class PostJITProvisioningHandler extends AbstractPostAuthnHandler {

    private static final Log log = LogFactory.getLog(PostJITProvisioningHandler.class);
    private static volatile PostJITProvisioningHandler instance;

    public static PostJITProvisioningHandler getInstance() {

        if (instance == null) {
            synchronized (PostJITProvisioningHandler.class) {
                if (instance == null) {
                    instance = new PostJITProvisioningHandler();
                }
            }
        }
        return instance;
    }

    @Override
    public int getPriority() {

        return 20;
    }

    @Override
    public String getName() {

        return "JITProvisionHandler";
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws PostAuthenticationFailedException {

        SequenceConfig sequenceConfig = context.getSequenceConfig();

        AuthenticatedUser authenticatedUser = sequenceConfig.getAuthenticatedUser();
        if (authenticatedUser == null) {
            return UNSUCCESS_COMPLETED;
        }

        Object object = context.getProperty(PASSWORD_PROVISION_REDIRECTION_TRIGGERED);
        boolean passWordProvisioningRedirectionTriggered = false;
        if (object instanceof Boolean) {
            passWordProvisioningRedirectionTriggered = (boolean) object;
        }

        if (passWordProvisioningRedirectionTriggered) {
            return handleResponseFlow(request, context, sequenceConfig);
        } else {
            return handleRequestFlow(response, context, sequenceConfig);
        }
    }

    /**
     * This method is used to handle response flow, after going through password provisioning.
     *
     * @param request        HttpServlet request.
     * @param context        Authentication context
     * @param sequenceConfig Relevant sequence config.
     * @return Status of PostAuthnHandler flow.
     * @throws PostAuthenticationFailedException Post Authentication Failed Exception
     */
    @SuppressWarnings("unchecked")
    private PostAuthnHandlerFlowStatus handleResponseFlow(HttpServletRequest request, AuthenticationContext context,
            SequenceConfig sequenceConfig) throws PostAuthenticationFailedException {

        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

            if (authenticator instanceof FederatedApplicationAuthenticator) {
                ExternalIdPConfig externalIdPConfig = null;
                String externalIdPConfigName = stepConfig.getAuthenticatedIdP();
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(externalIdPConfigName, context.getTenantDomain());
                } catch (IdentityProviderManagementException e) {
                    handleExceptions(String.format(ERROR_WHILE_GETTING_IDP_BY_NAME.getMessage(), externalIdPConfigName,
                            context.getTenantDomain()), ERROR_WHILE_GETTING_IDP_BY_NAME.getCode(), e);
                }

                context.setExternalIdP(externalIdPConfig);

                final Map<String, String> localClaimValues;
                Object unfilteredLocalClaimValues = context
                        .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
                localClaimValues = unfilteredLocalClaimValues == null ?
                        new HashMap<>() :
                        (Map<String, String>) unfilteredLocalClaimValues;
                Map<ClaimMapping, String> extAttrs = stepConfig.getAuthenticatedUser().getUserAttributes();


                if (externalIdPConfig != null && externalIdPConfig.isProvisioningEnabled() && externalIdPConfig
                        .isPasswordProvisioningEnabled()) {


                    String originalExternalIdpSubjectValueForThisStep = stepConfig.getAuthenticatedUser()
                            .getAuthenticatedSubjectIdentifier();
                    String idpRoleClaimUri = FrameworkUtils.getIdpRoleClaimUri(externalIdPConfig);
                    Map<String, String> originalExternalAttributeValueMap = FrameworkUtils
                            .getClaimMappings(extAttrs, false);

                    List<String> identityProviderMappedUserRolesUnmappedExclusive = FrameworkUtils
                            .getIdentityProvideMappedUserRoles(externalIdPConfig, originalExternalAttributeValueMap,
                                    idpRoleClaimUri, true);

                    RegistryService registryService = FrameworkServiceComponent.getRegistryService();
                    RealmService realmService = FrameworkServiceComponent.getRealmService();
                    UserRealm realm = null;
                    try {
                        realm = AnonymousSessionUtil
                                .getRealmByTenantDomain(registryService, realmService, context.getTenantDomain());
                    } catch (CarbonException e) {
                        handleExceptions(String.format(ERROR_WHILE_GETTING_REALM_IN_POST_AUTHENTICATION.getMessage(),
                                context.getTenantDomain()), ERROR_WHILE_GETTING_REALM_IN_POST_AUTHENTICATION.getCode(),
                                e);
                    }

                    Claim[] claims = null;
                    try {
                        claims = IdentityClaimManager.getInstance().getAllSupportedClaims(realm);
                    } catch (IdentityException e) {
                        handleExceptions(String.format(
                                ERROR_WHILE_TRYING_TO_GET_CLAIMS_WHILE_TRYING_TO_PASSWORD_PROVISION.getMessage(),
                                externalIdPConfigName),
                                ERROR_WHILE_TRYING_TO_GET_CLAIMS_WHILE_TRYING_TO_PASSWORD_PROVISION.getCode(), e);
                    }

                    if (claims != null) {
                        for (Claim claim : claims) {
                            String uri = claim.getClaimUri();
                            String claimValue = request.getParameter(uri);
                            if (StringUtils.isNotBlank(claimValue) && StringUtils.isEmpty(localClaimValues.get(uri))) {
                                localClaimValues.put(uri, claimValue);
                            }
                        }
                    }
                    localClaimValues
                            .put(FrameworkConstants.PASSWORD, request.getParameter(FrameworkConstants.PASSWORD));
                    localClaimValues.put(FrameworkConstants.ASSOCIATED_ID, originalExternalIdpSubjectValueForThisStep);
                    localClaimValues.put(FrameworkConstants.IDP_ID, stepConfig.getAuthenticatedIdP());
                    // Remove role claim from local claims as roles are specifically handled.
                    localClaimValues.remove(FrameworkUtils.getLocalClaimUriMappedForIdPRoleClaim(externalIdPConfig));
                    localClaimValues.remove(USERNAME_CLAIM);
                    String username = sequenceConfig.getAuthenticatedUser().getUserName();

                    try {
                        FrameworkUtils.getStepBasedSequenceHandler()
                                .callJitProvisioning(username, context,
                                        identityProviderMappedUserRolesUnmappedExclusive, localClaimValues);
                    } catch (FrameworkException e) {
                        handleExceptions(String.format(
                                ERROR_WHILE_TRYING_TO_PROVISION_USER_WITH_PASSWORD_PROVISIONING.getMessage(),
                                originalExternalIdpSubjectValueForThisStep, externalIdPConfigName),
                                ERROR_WHILE_TRYING_TO_PROVISION_USER_WITH_PASSWORD_PROVISIONING.getCode(), e);
                    }
                }

            }
        }
        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
    }

    /**
     * To handle the request flow of the post authentication handler.
     *
     * @param response       HttpServlet response.
     * @param context        Authentication context
     * @param sequenceConfig Sequence Config
     * @return Status of this post authentication handler flow.
     * @throws PostAuthenticationFailedException Exception that will be thrown in case of failure.
     */
    @SuppressWarnings("unchecked")
    private PostAuthnHandlerFlowStatus handleRequestFlow(HttpServletResponse response, AuthenticationContext context,
            SequenceConfig sequenceConfig) throws PostAuthenticationFailedException {

        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

            if (authenticator instanceof FederatedApplicationAuthenticator) {

                ExternalIdPConfig externalIdPConfig = null;
                String externalIdPConfigName = stepConfig.getAuthenticatedIdP();
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(externalIdPConfigName, context.getTenantDomain());
                } catch (IdentityProviderManagementException e) {
                    handleExceptions(String.format(ERROR_WHILE_GETTING_IDP_BY_NAME.getMessage(), externalIdPConfigName,
                            context.getTenantDomain()), ERROR_WHILE_GETTING_IDP_BY_NAME.getCode(), e);
                }

                context.setExternalIdP(externalIdPConfig);
                Map<String, String> localClaimValues;
                localClaimValues = (Map<String, String>) context
                        .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
                Map<ClaimMapping, String> extAttrs = stepConfig.getAuthenticatedUser().getUserAttributes();
                if (externalIdPConfig != null && externalIdPConfig.isProvisioningEnabled()) {

                    if (localClaimValues == null) {
                        localClaimValues = new HashMap<>();
                    }

                    String idpRoleClaimUri = FrameworkUtils.getIdpRoleClaimUri(externalIdPConfig);
                    Map<String, String> originalExternalAttributeValueMap = FrameworkUtils
                            .getClaimMappings(extAttrs, false);

                    // Get the mapped user roles according to the mapping in the IDP configuration.
                    // Exclude the unmapped from the returned list.
                    List<String> identityProviderMappedUserRolesUnmappedExclusive = FrameworkUtils
                            .getIdentityProvideMappedUserRoles(externalIdPConfig, originalExternalAttributeValueMap,
                                    idpRoleClaimUri, true);

                    String originalExternalIdpSubjectValueForThisStep = stepConfig.getAuthenticatedUser()
                            .getAuthenticatedSubjectIdentifier();

                    UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
                    String username = null;
                    try {
                        username = userProfileAdmin.getNameAssociatedWith(stepConfig.getAuthenticatedIdP(),
                                originalExternalIdpSubjectValueForThisStep);
                    } catch (UserProfileException e) {
                        handleExceptions(String.format(
                                ErrorMessages.ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getMessage(),
                                externalIdPConfigName),
                                ErrorMessages.ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getCode(), e);
                    }

                    if (externalIdPConfig.isPasswordProvisioningEnabled() && username == null) {
                        try {
                            username = sequenceConfig.getAuthenticatedUser().getUserName();
                            final URIBuilder uriBuilder = new URIBuilder(SIGN_UP_ENDPOINT);
                            uriBuilder.addParameter(FrameworkConstants.USERNAME, username);
                            uriBuilder.addParameter(FrameworkConstants.SKIP_SIGN_UP_ENABLE_CHECK, String.valueOf(true));
                            uriBuilder
                                    .addParameter(FrameworkConstants.SESSION_DATA_KEY, context.getContextIdentifier());
                            localClaimValues.forEach(uriBuilder::addParameter);
                            response.sendRedirect(uriBuilder.build().toString());
                        } catch (URISyntaxException | IOException e) {
                            handleExceptions(String.format(
                                    ErrorMessages.ERROR_WHILE_TRYING_CALL_SIGN_UP_ENDPOINT_FOR_PASSWORD_PROVISIONING
                                            .getMessage(), username, externalIdPConfigName),
                                    ErrorMessages.ERROR_WHILE_TRYING_CALL_SIGN_UP_ENDPOINT_FOR_PASSWORD_PROVISIONING
                                            .getCode(), e);
                        }

                        context.setProperty(PASSWORD_PROVISION_REDIRECTION_TRIGGERED, true);
                        return PostAuthnHandlerFlowStatus.INCOMPLETE;
                    }

                    localClaimValues.put(FrameworkConstants.ASSOCIATED_ID, originalExternalIdpSubjectValueForThisStep);
                    localClaimValues.put(FrameworkConstants.IDP_ID, stepConfig.getAuthenticatedIdP());
                    // Remove role claim from local claims as roles are specifically handled.
                    localClaimValues.remove(FrameworkUtils.getLocalClaimUriMappedForIdPRoleClaim(externalIdPConfig));
                    localClaimValues.remove(USERNAME_CLAIM);
                    try {
                        FrameworkUtils.getStepBasedSequenceHandler().callJitProvisioning(username, context,
                                identityProviderMappedUserRolesUnmappedExclusive, localClaimValues);
                    } catch (FrameworkException e) {
                        handleExceptions(String.format(
                                ERROR_WHILE_TRYING_TO_PROVISION_USER_WITHOUT_PASSWORD_PROVISIONING.getMessage(),
                                username, externalIdPConfigName),
                                ERROR_WHILE_TRYING_TO_PROVISION_USER_WITHOUT_PASSWORD_PROVISIONING.getCode(), e);
                    }
                }

            }
        }
        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
    }

    /**
     * To handle exceptions.
     *
     * @param errorMessage Error Message
     * @param errorCode    Error Code.
     * @param e            Exception that is thrown during a failure.
     * @throws PostAuthenticationFailedException Post Authentication Failed Exception.
     */
    private void handleExceptions(String errorMessage, String errorCode, Exception e)
            throws PostAuthenticationFailedException {
        log.error(errorCode + " - " + errorMessage, e);
        throw new PostAuthenticationFailedException(errorCode, errorMessage, e);
    }

}
