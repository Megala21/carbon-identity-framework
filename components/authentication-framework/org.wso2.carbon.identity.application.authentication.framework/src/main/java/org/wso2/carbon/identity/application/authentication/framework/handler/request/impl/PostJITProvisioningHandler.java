package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;

import static org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
import static org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus.UNSUCCESS_COMPLETED;

public class PostJITProvisioningHandler extends AbstractPostAuthnHandler  {
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
        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

            if (authenticator instanceof FederatedApplicationAuthenticator) {

                ExternalIdPConfig externalIdPConfig = null;
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(stepConfig.getAuthenticatedIdP(), context.getTenantDomain());
                } catch (IdentityProviderManagementException e) {
                    log.error("Exception while getting IdP by name", e);
                }

                context.setExternalIdP(externalIdPConfig);
                Map<String, String> localClaimValues;
                localClaimValues = (Map<String, String>) context
                        .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
                Map<ClaimMapping, String> extAttrs = stepConfig.getAuthenticatedUser().getUserAttributes();
                if (externalIdPConfig != null && externalIdPConfig.isProvisioningEnabled() && externalIdPConfig
                        .isPasswordProvisioningEnabled()) {

                    if (localClaimValues == null) {
                        localClaimValues = new HashMap<>();
                    }

                    String idpRoleClaimUri = getIdpRoleClaimUri(externalIdPConfig);
                    Map<String, String> originalExternalAttributeValueMap = FrameworkUtils
                            .getClaimMappings(extAttrs, false);

                    // Get the mapped user roles according to the mapping in the IDP configuration.
                    // Exclude the unmapped from the returned list.
                    List<String> identityProviderMappedUserRolesUnmappedExclusive = getIdentityProvideMappedUserRoles(
                            externalIdPConfig, originalExternalAttributeValueMap, idpRoleClaimUri, true);

                    String originalExternalIdpSubjectValueForThisStep = stepConfig.getAuthenticatedUser()
                            .getAuthenticatedSubjectIdentifier();

                    localClaimValues.put(FrameworkConstants.ASSOCIATED_ID, originalExternalIdpSubjectValueForThisStep);
                    localClaimValues.put(FrameworkConstants.IDP_ID, stepConfig.getAuthenticatedIdP());
                    // Remove role claim from local claims as roles are specifically handled.
                    localClaimValues.remove(getLocalClaimUriMappedForIdPRoleClaim(externalIdPConfig));

                    RegistryService registryService = FrameworkServiceComponent.getRegistryService();
                    RealmService realmService = FrameworkServiceComponent.getRealmService();
                    UserRealm realm = null;
                    try {
                        realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService,
                                realmService, context.getTenantDomain());
                    } catch (CarbonException e) {
                        e.printStackTrace();
                    }

                    String userStoreDomain = null;
                    try {
                        userStoreDomain = getUserStoreDomain(externalIdPConfig.getProvisioningUserStoreId(), realm);
                    } catch (FrameworkException e) {
                        e.printStackTrace();
                    } catch (UserStoreException e) {
                        e.printStackTrace();
                    }

                    String username = MultitenantUtils.getTenantAwareUsername(originalExternalIdpSubjectValueForThisStep);
                    UserStoreManager userStoreManager = null;
                    try {
                        userStoreManager = getUserStoreManager(realm, userStoreDomain);
                    } catch (UserStoreException e) {
                        e.printStackTrace();
                    } catch (FrameworkException e) {
                        e.printStackTrace();
                    }

                    // Remove userStoreManager domain from username if the userStoreDomain is not primary
                    try {
                        if (realm.getUserStoreManager().getRealmConfiguration().isPrimary()) {
                            username = UserCoreUtil.removeDomainFromName(username);
                        }
                    } catch (UserStoreException e) {
                        e.printStackTrace();
                    }

                    try {
                        if (!userStoreManager.isExistingUser(username)) {
                            URIBuilder uriBuilder = null;
                            try {
                                uriBuilder = new URIBuilder("/accountrecoveryendpoint/signup.do");
                                uriBuilder.addParameter("username", username);
                                uriBuilder.addParameter("skipsignupenablecheck", String.valueOf(true));
                                uriBuilder.addParameter(FrameworkConstants.SESSION_DATA_KEY, context.getContextIdentifier());
                                response.sendRedirect(uriBuilder.build().toString());
                            } catch (URISyntaxException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        return PostAuthnHandlerFlowStatus.INCOMPLETE;
                    } catch (UserStoreException e) {
                        e.printStackTrace();
                    }
                    try {
                        FrameworkUtils.getStepBasedSequenceHandler()
                                .callJitProvisioning(originalExternalIdpSubjectValueForThisStep, context,
                                        identityProviderMappedUserRolesUnmappedExclusive, localClaimValues);
                    } catch (FrameworkException ex) {
                        throw new PostAuthenticationFailedException("Exception while doing JIT provisioning tasks",
                                ex.getMessage(), ex);
                    }
                }

            }
        }
        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;

    }

    private UserStoreManager getUserStoreManager(UserRealm realm, String userStoreDomain)
            throws UserStoreException, FrameworkException {
        UserStoreManager userStoreManager;
        if (userStoreDomain != null && !userStoreDomain.isEmpty()) {
            userStoreManager = realm.getUserStoreManager().getSecondaryUserStoreManager(
                    userStoreDomain);
        } else {
            userStoreManager = realm.getUserStoreManager();
        }

        if (userStoreManager == null) {
            throw new FrameworkException("Specified user store is invalid");
        }
        return userStoreManager;
    }

    private String getUserStoreDomain(String userStoreDomain, UserRealm realm)
            throws FrameworkException, UserStoreException {

        // If the any of above value is invalid, keep it empty to use primary userstore
        if (userStoreDomain != null
                && realm.getUserStoreManager().getSecondaryUserStoreManager(userStoreDomain) == null) {
            throw new FrameworkException("Specified user store domain " + userStoreDomain
                    + " is not valid.");
        }

        return userStoreDomain;
    }

    /**
     * To get the role claim uri of external IDP.
     *
     * @param externalIdPConfig Relevant external IDP config.
     * @return Role claim URI of IDP.
     */
    private String getIdpRoleClaimUri(ExternalIdPConfig externalIdPConfig) {
        // get external identity provider role claim uri.
        String idpRoleClaimUri = externalIdPConfig.getRoleClaimUri();

        if (idpRoleClaimUri == null || idpRoleClaimUri.isEmpty()) {
            // no role claim uri defined
            // we can still try to find it out - lets have a look at the claim
            // mapping.
            ClaimMapping[] idpToLocalClaimMapping = externalIdPConfig.getClaimMappings();

            if (idpToLocalClaimMapping != null && idpToLocalClaimMapping.length > 0) {

                for (ClaimMapping mapping : idpToLocalClaimMapping) {
                    if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI.equals(mapping.getLocalClaim().getClaimUri())
                            && mapping.getRemoteClaim() != null) {
                        return mapping.getRemoteClaim().getClaimUri();
                    }
                }
            }
        }

        return idpRoleClaimUri;
    }

    /**
     * Returns the local claim uri that is mapped for the IdP role claim uri configured.
     * If no role claim uri is configured for the IdP returns the local role claim 'http://wso2.org/claims/role'.
     *
     * @param externalIdPConfig IdP configurations
     * @return local claim uri mapped for the IdP role claim uri.
     */
    private String getLocalClaimUriMappedForIdPRoleClaim(ExternalIdPConfig externalIdPConfig) {
        // get external identity provider role claim uri.
        String idpRoleClaimUri = externalIdPConfig.getRoleClaimUri();
        if (StringUtils.isNotBlank(idpRoleClaimUri)) {
            // Iterate over IdP claim mappings and check for the local claim that is mapped for the remote IdP role
            // claim uri configured.
            ClaimMapping[] idpToLocalClaimMapping = externalIdPConfig.getClaimMappings();
            if (!ArrayUtils.isEmpty(idpToLocalClaimMapping)) {
                for (ClaimMapping mapping : idpToLocalClaimMapping) {
                    if (mapping.getRemoteClaim() != null && idpRoleClaimUri
                            .equals(mapping.getRemoteClaim().getClaimUri())) {
                        return mapping.getLocalClaim().getClaimUri();
                    }
                }
            }
        }

        return FrameworkConstants.LOCAL_ROLE_CLAIM_URI;
    }


    /**
     * Map the external IDP roles to local roles.
     * If excludeUnmapped is true exclude unmapped roles.
     * Otherwise include unmapped roles as well.
     *
     * @param externalIdPConfig
     * @param extAttributesValueMap
     * @param idpRoleClaimUri
     * @param excludeUnmapped
     * @return ArrayList<string>
     */
    private List<String> getIdentityProvideMappedUserRoles(ExternalIdPConfig externalIdPConfig,
            Map<String, String> extAttributesValueMap, String idpRoleClaimUri, Boolean excludeUnmapped) {

        if (idpRoleClaimUri == null) {
            // Since idpRoleCalimUri is not defined cannot do role mapping.
            if (log.isDebugEnabled()) {
                log.debug("Role claim uri is not configured for the external IDP: " + externalIdPConfig.getIdPName()
                        + ", in Domain: " + externalIdPConfig.getDomain() + ".");
            }
            return new ArrayList<>();
        }

        String idpRoleAttrValue = null;
        if (extAttributesValueMap != null) {
            idpRoleAttrValue = extAttributesValueMap.get(idpRoleClaimUri);
        }

        String[] idpRoles;
        if (idpRoleAttrValue != null) {
            idpRoles = idpRoleAttrValue.split(FrameworkUtils.getMultiAttributeSeparator());
        } else {
            // No identity provider role values found.
            if (log.isDebugEnabled()) {
                log.debug("No role attribute value has received from the external IDP: "
                        + externalIdPConfig.getIdPName() + ", in Domain: " + externalIdPConfig.getDomain() + ".");
            }
            return new ArrayList<>();
        }

        Map<String, String> idpToLocalRoleMapping = externalIdPConfig.getRoleMappings();

        List<String> idpMappedUserRoles = new ArrayList<>();
        // If no role mapping is configured in the identity provider.
        if (MapUtils.isEmpty(idpToLocalRoleMapping)) {
            if (log.isDebugEnabled()) {
                log.debug("No role mapping is configured in the external IDP: "
                        + externalIdPConfig.getIdPName() + ", in Domain: " + externalIdPConfig.getDomain() + ".");
            }

            if (excludeUnmapped) {
                return new ArrayList<>();
            }

            idpMappedUserRoles.addAll(Arrays.asList(idpRoles));
            return idpMappedUserRoles;
        }

        for (String idpRole : idpRoles){
            if (idpToLocalRoleMapping.containsKey(idpRole)) {
                idpMappedUserRoles.add(idpToLocalRoleMapping.get(idpRole));
            } else if (!excludeUnmapped) {
                idpMappedUserRoles.add(idpRole);
            }
        }
        return idpMappedUserRoles;
    }

}
