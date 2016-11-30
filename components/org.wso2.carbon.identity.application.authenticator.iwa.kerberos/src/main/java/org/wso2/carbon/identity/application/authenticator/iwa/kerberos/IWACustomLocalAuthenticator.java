/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.iwa.kerberos;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iwa.kerberos.bean.IWAAuthenticatedUserBean;
import org.wso2.carbon.identity.application.authenticator.iwa.kerberos.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.security.PrivilegedActionException;
import java.util.List;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * IWAFederatedAuthenticator authenticates a user from a Kerberos Token (GSS Token) sent by a pre-registered KDC.
 */
public class IWACustomLocalAuthenticator extends AbstractIWAAuthenticator implements LocalApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWAKerberosLocalAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "iwa-kerberos-local";

    private static final long serialVersionUID = -713445365110141169L;
    private static final Log log = LogFactory.getLog(IWACustomLocalAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);

        HttpSession session = request.getSession(false);
        final String gssToken = (String) session.getAttribute(IWAConstants.KERBEROS_TOKEN);
        IWAAuthenticationUtil.invalidateSession(request);

        /*
                Fully Qualified username of the authenticated username (myname@KERBEROS.REALM)
        */
        String authenticatedUser = null;
        String authenticatedTenantDomain = null;
        String authenticatedUserStoreDomain = null;
        byte[] base64DecodedToken = Base64.decode(gssToken);
        try {

            List<String> userStoreDomains;
            boolean isSaasApp = context.getSequenceConfig().getApplicationConfig().isSaaSApp();
            if (isSaasApp) {
                // since this is a saas app we need to try out credentials of each tenant and find the correct tenant
                // domain to which the token was issued for.
                for (String tenantDomain : IWAConfigUtil.getTenants()) {
                    authenticatedUser = getAuthenticatedUserFromToken(tenantDomain, base64DecodedToken);
                    if (authenticatedUser != null) {
                        authenticatedTenantDomain = tenantDomain;
                        break;
                    }
                }

                if (authenticatedUser == null) {
                    throw new AuthenticationFailedException("Cannot decrypt the kerberos token using available " +
                            "credentials.");
                } else {
                    // get the user store domains we have to check the user for.
                    userStoreDomains = IWAConfigUtil.getUserStoreDomains(authenticatedTenantDomain);
                    // check whether user exists in configured user store domains of this tenant
                    authenticatedUserStoreDomain = getAuthenticatedUserStoreDomain(authenticatedUser,
                            authenticatedTenantDomain, userStoreDomains);
                }

            } else {

                authenticatedTenantDomain = context.getTenantDomain();
                authenticatedUser = getAuthenticatedUserFromToken(authenticatedTenantDomain, base64DecodedToken);

                if (authenticatedUser == null) {
                    throw new AuthenticationFailedException("Cannot decrypt the kerberos token using available " +
                            "credentials.");
                } else {
                    // get the user store domains we have to check the user for.
                    userStoreDomains = IWAConfigUtil.getUserStoreDomains(authenticatedTenantDomain);
                    // check whether user exists in configured user store domains of this tenant
                    authenticatedUserStoreDomain = getAuthenticatedUserStoreDomain(authenticatedUser,
                            authenticatedTenantDomain, userStoreDomains);
                }
            }
        } catch (GSSException | LoginException | PrivilegedActionException ex) {
            throw new AuthenticationFailedException("Cannot create kerberos credentials for server.", ex);
        }


        // we have an authenticated user if we come here.
        context.setSubject(createAuthenticatedUser(authenticatedUser, authenticatedUserStoreDomain));
    }

    /*
        Create credentials from the spnName, spnPassword configured for the tenant and decrypt the Kerberos token.
     */
    private String getAuthenticatedUserFromToken(String tenantDomain, byte[] base64DecodedToken) throws LoginException,
            PrivilegedActionException, GSSException {

        GSSCredential gssCredential = createCredentialsForTenant(tenantDomain);
        String authenticatedUser = null;
        try {
            // decrypt the token using credentials created for tenant
            authenticatedUser = getAuthenticatedUserFromToken(gssCredential, base64DecodedToken);
            if (log.isDebugEnabled()) {
                log.debug("Kerberos Token decrypted with credentials of : " + tenantDomain + ". Authenticated User : " +
                        "" + authenticatedUser);
            }

        } catch (GSSException ex) {
            // we failed to decrypt so we will continue trying out other tenant credentials
            if (log.isDebugEnabled()) {
                log.debug("Unable to decrypt the kerberos token with credentials of : " + tenantDomain);
            }
        }

        return authenticatedUser;
    }


    /*
        Create credentials for Identity Server with the spnName and spnPassword configured for the tenantDomain.
     */
    private GSSCredential createCredentialsForTenant(String tenantDomain) throws LoginException,
            PrivilegedActionException, GSSException {

        String spnName = IWAConfigUtil.getSpnName(tenantDomain);
        char[] spnPassword = IWAConfigUtil.getSpnPassword(tenantDomain);
        if (log.isDebugEnabled()) {
            log.debug("Credentials created for '" + tenantDomain + "' tenantDomain.");
        }
        return IWAAuthenticationUtil.createCredentials(spnName, spnPassword);
    }


    private AuthenticatedUser createAuthenticatedUser(String authenticatedUser, String userStoreDomain) {
        String subjectIdentifier = UserCoreUtil.addDomainToName(authenticatedUser, userStoreDomain);
        return AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(subjectIdentifier);
    }

    /*
        Check whether the user exists in the provided userStoreDomain list in the given tenant. If user exists in any
         user store within the scope of search return the userStoreDomain, else throw Exception.
     */
    private String getAuthenticatedUserStoreDomain(String authenticatedUser,
                                                   String authenticatedTenantDomain,
                                                   List<String> userStoreDomains) throws AuthenticationFailedException {
        // check in each user store whether the user exists
        for (String userStoreDomain : userStoreDomains) {
            String tenantAwareUserName = IWAAuthenticationUtil.getDomainAwareUserName(authenticatedUser);
            // if the user exists we set the subject to the context
            if (isUserExistsInUserStore(tenantAwareUserName, authenticatedTenantDomain, userStoreDomain)) {
                if (log.isDebugEnabled()) {
                    log.debug("User '" + authenticatedUser + "' is found in '" + userStoreDomain + "' userstore in '" +
                            authenticatedTenantDomain + "' tenant domain.");
                }
                return userStoreDomain;
            }
        }

        throw new AuthenticationFailedException("Failed to find the user '" + authenticatedUser + "' in" +
                " any user store.");
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }


    private String getAuthenticatedUserFromToken(GSSCredential gssCredentials, byte[] gssToken) throws GSSException {
        return IWAAuthenticationUtil.processToken(gssToken, gssCredentials);

    }

    /**
     * Check whether the authenticated user exists in any user store that belongs to the realm the user belongs to.
     *
     * @param authenticatedUserName
     * @param tenantDomain
     * @param userStoreDomain
     * @return
     */
    private boolean isUserExistsInUserStore(String authenticatedUserName, String tenantDomain, String userStoreDomain)
            throws
            AuthenticationFailedException {
        UserStoreManager userStoreManager;
        try {
            userStoreManager = getPrimaryUserStoreManager(tenantDomain).getSecondaryUserStoreManager(userStoreDomain);
            // String userStoreDomain = IdentityUtil.getPrimaryDomainName();
            authenticatedUserName = IdentityUtil.addDomainToName(authenticatedUserName, userStoreDomain);
            return userStoreManager.isExistingUser(authenticatedUserName);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("IWAApplicationAuthenticator " +
                    "failed to find the user in the userstores", e);
        }
    }

    /**
     * Gets Array of user claims which are associated with the given user.
     *
     * @param userBean
     * @return
     * @throws AuthenticationFailedException
     */
    private Claim[] getUserClaims(IWAAuthenticatedUserBean userBean) throws
            AuthenticationFailedException {
        try {
            return getPrimaryUserStoreManager(userBean.getTenantDomain())
                    .getSecondaryUserStoreManager(userBean.getUserStoreDomain()).getUserClaimValues
                            (userBean.getUser(), "");
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("IWAApplicationAuthenticator failed to get user claims " +
                    "from userstore", e);
        }
    }

    private UserStoreManager getPrimaryUserStoreManager(String tenantDomain) throws UserStoreException {
        RealmService realmService = IWAServiceDataHolder.getInstance().getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        return (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
    }

}

