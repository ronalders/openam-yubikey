/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2010 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted 2013 Ron Alders"
 */

package nl.alders.openam;

import com.iplanet.dpro.session.service.InternalSession;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.*;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.YubicoResponse;
import com.yubico.client.v2.YubicoResponseStatus;
import com.yubico.client.v2.exceptions.YubicoValidationException;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import org.apache.commons.lang.StringUtils;

import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

public class YubikeyModule extends AMLoginModule {
    public static final String MODULE_NAME = "YubikeyModule";
    public static final String BUNDLE_NAME = "amAuthYubikeyModule";
    private static final String AUTHLEVEL = "sunAMAuthYubikeyModuleAuthLevel";

    private static Debug debug = Debug.getInstance(MODULE_NAME);
    private Map options = null;
    private Map sharedState = null;
    private String UUID = null;
    private String userName = null;


    // Module setting parameters
    private static final String CLIENTID = ISAuthConstants.AUTH_ATTR_PREFIX_NEW + "YubikeyModuleClientID";
    private static final String SECRETKEY = ISAuthConstants.AUTH_ATTR_PREFIX_NEW + "YubikeyModuleSecretKey";
    private static final String YUBIKEY_VAL_SERVERS = ISAuthConstants.AUTH_ATTR_PREFIX_NEW + "YubikeyModuleWSApiUrls";
    private static final String YUBIKEY_ATTR = ISAuthConstants.AUTH_ATTR_PREFIX_NEW + "YubikeyModuleYubiKeyAttributeName";


    private int clientId = 0;
    private String secretKey = null;
    private String yubikeyAttrName = null;
    private String wsapiUrls[] = {};

    /**
     * Constructor
     */
    public YubikeyModule() {
        debug.message("In YubikeyModule.YubikeyModule()");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        debug.message("In YubikeyModule.init()");
        this.sharedState = sharedState;
        this.options = options;

        amCache.getResBundle(BUNDLE_NAME, getLoginLocale());
        String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);
        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("Unable to set auth level " + authLevel, e);
            }
        }
        if (options != null) {
            try {
                clientId = Integer.parseInt(CollectionHelper.getMapAttr(options, CLIENTID));
            } catch (NumberFormatException e) {
                debug.error("Unable to set Yubikey Client ID " + clientId, e);
            }
            secretKey = CollectionHelper.getMapAttr(options, SECRETKEY);
            yubikeyAttrName = CollectionHelper.getMapAttr(options, YUBIKEY_ATTR);
            // Validation servers
            Set<String> attrs = (Set<String>) options.get(YUBIKEY_VAL_SERVERS);
            wsapiUrls = attrs.toArray(new String[attrs.size()]);
        }
        //get username from previous authentication
        try {
            userName = (String) sharedState.get(getUserKey());
        } catch (Exception e) {
            debug.error("YubiKey" + ".init() : " + "Unable to get username : ", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        try {
            //check for session and get username and UUID
            if (userName == null || userName.length() == 0) {
                // session upgrade case. Need to find the user ID from the old
                // session
                SSOTokenManager mgr = SSOTokenManager.getInstance();
                InternalSession isess = getLoginState("Yubikey").getOldSession();
                if (isess == null) {
                    throw new AuthLoginException("amAuth", "noInternalSession",
                            null);
                }
                SSOToken token = mgr.createSSOToken(isess.getID().toString());
                UUID = token.getPrincipal().getName();
                userName = token.getProperty("UserToken");
                if (debug.messageEnabled()) {
                    debug.message("OATH" + ".process() : " +
                            "Username from SSOToken : " + userName);
                }

                if (userName == null || userName.length() == 0) {
                    throw new AuthLoginException("amAuth", "noUserName", null);
                }
            }
            switch (state) {
                case ISAuthConstants.LOGIN_START:
                    if (callbacks == null || callbacks.length != 2) {
                        throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
                    }
                    //get OTP and check format
                    String OTP = String.valueOf(((PasswordCallback) callbacks[0]).getPassword());
                    if (!YubicoClient.isValidOTPFormat(OTP)) {
                        debug.error("Yubikey.process() : invalid OTP code");
                        setFailureID(userName);
                        throw new InvalidPasswordException(BUNDLE_NAME, "invalidOTP", null);
                    }

                    //Yubikey OTP validation
                    if (checkOTP(OTP)) {
                        return ISAuthConstants.LOGIN_SUCCEED;
                    } else {
                        setFailureID(userName);
                        throw new InvalidPasswordException("amAuth", "invalidPasswd", null);
                    }
            }
        } catch (SSOException e) {
            debug.error("Yubikey" + ".process() : " + "SSOException", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        return ISAuthConstants.LOGIN_IGNORE;
    }

    private boolean checkOTP(String otp) throws AuthLoginException {
        AMIdentity id = getIdentity(userName);
        if (id == null) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        String yubiKeyId = getYubiKeyId(id);
        if (StringUtils.isEmpty(yubiKeyId)) {
            debug.error("Yubikey.checkOTP() : yubikeyID of user : " + userName + " is not a valid value");
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        try {
            YubicoClient client = YubicoClient.getClient(this.clientId);
            client.setKey(this.secretKey);
            if (wsapiUrls != null && wsapiUrls.length > 0) {
                client.setWsapiUrls(this.wsapiUrls);
            }
            YubicoResponse yubicoResponse = client.verify(otp);
            return yubicoResponse.getStatus().equals(YubicoResponseStatus.OK) && yubicoResponse.getPublicId().equals(yubiKeyId);
        } catch (YubicoValidationException e) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        } catch (YubicoValidationFailure yubicoValidationFailure) {
            throw new AuthLoginException(BUNDLE_NAME, "falidationFailed", new String[]{yubicoValidationFailure.getMessage()});
        } catch (Exception e) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
    }

    /**
     * get YubiKey identification from user profile
     *
     * @param id AMIdentity of user
     * @return yubikey identification for OTP validation
     * @throws AuthLoginException
     */
    private String getYubiKeyId(AMIdentity id) throws AuthLoginException {
        Set<String> yubiKeySet;
        try {
            if (StringUtils.isEmpty(yubikeyAttrName)) {
                debug.error("Yubikey" +
                        ".checkOTP() : " +
                        "invalid secret key attribute name : ");
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
            yubiKeySet = id.getAttribute(yubikeyAttrName);
        } catch (IdRepoException e) {
            debug.error("Yubikey" +
                    ".checkOTP() : " +
                    "error getting secret key attribute : ",
                    e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        } catch (SSOException e) {
            debug.error("Yubikey" +
                    ".checkOTP() : " +
                    "error invalid repo id : " +
                    id,
                    e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        String yubiKey = yubiKeySet.iterator().next();
        //get rid of white space in string (messes with data converter)
        yubiKey = yubiKey.replaceAll("\\s+", "");
        yubiKey = yubiKey.toLowerCase();
        return yubiKey;
    }

    /**
     * Gets the AMIdentity of a user with username equal to uName.
     *
     * @param uName username of the user to get.
     * @return The AMIdentity of user with username equal to uName.
     */
    private AMIdentity getIdentity(String uName) {
        AMIdentity theID = null;
        AMIdentityRepository amIdRepo = getAMIdentityRepository(getRequestOrg());
        IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        // search for the identity
        Set<AMIdentity> results = Collections.EMPTY_SET;
        try {
            idsc.setMaxResults(0);
            IdSearchResults searchResults =
                    amIdRepo.searchIdentities(IdType.USER, uName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }
            if (results == null || results.size() != 1) {
                throw new IdRepoException("Yubikey" +
                        ".getIdentity : " +
                        "More than one user found");

            }
            theID = results.iterator().next();
        } catch (IdRepoException e) {
            debug.error("Yubikey.getIdentity : error searching Identities with username : " + userName, e);
        } catch (SSOException e) {
            debug.error("Yubikey.getIdentity : AuthOATH module exception : ", e);
        }
        return theID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Principal getPrincipal() {
        if (UUID != null) {
            return new YubikeyPrincipal(UUID);
        }
        if (userName != null) {
            return new YubikeyPrincipal(userName);
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroyModuleState() {
        userName = null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void nullifyUsedVars() {
        options = null;
        sharedState = null;
        userName = null;
        clientId = 0;
        secretKey = null;
        yubikeyAttrName = null;

    }

}
