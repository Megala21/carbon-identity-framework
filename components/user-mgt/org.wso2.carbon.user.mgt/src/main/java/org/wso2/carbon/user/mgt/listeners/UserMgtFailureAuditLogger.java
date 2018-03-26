/*
 * Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.user.mgt.listeners;

import org.apache.commons.logging.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.AbstractIdentityUserMgtFailureEventListener;
import org.wso2.carbon.user.api.Permission;

import java.util.Map;

/**
 * This class is responsible for logging the failure events while doing User Management Tasks.
 */
public class UserMgtFailureAuditLogger extends AbstractIdentityUserMgtFailureEventListener {
    private static final Log audit = CarbonConstants.AUDIT_LOG;

    public boolean onAuthenticateFailure(String errorCode, String errorMessage, String userName, Object credential) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Authentication", userName, null, errorCode, errorMessage));
        return true;
    }

    public boolean OnAddUserFailure(String errorCode, String errorMessage, String userName, Object credential,
            String[] roleList, Map<String, String> claims, String profile) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Roles", new JSONArray(roleList));
        dataObject.put("Claims", new JSONObject(claims));
        dataObject.put("Profile", profile);
        audit.warn(createAuditMessage("Add User", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onUpdateCredentialFailure(String errorCode, String errorMessage, String userName, Object newCredential,
            Object oldCredential) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Update Credential", userName, null, errorCode, errorMessage));
        return true;
    }

    public boolean onUpdateCredentialByAdminFailure(String errorCode, String errorMessage, String userName,
            Object newCredential) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Update Credential By Admin", userName, null, errorCode, errorMessage));
        return true;
    }

    public boolean onDeleteUserFailure(String errorCode, String errorMessage, String userName) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Delete User", userName, null, errorCode, errorMessage));
        return true;
    }

    public boolean onSetUserClaimValueFailure(String errorCode, String errorMessage, String userName, String claimURI,
            String claimValue, String profileName) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim URI", claimURI);
        dataObject.put("Claim Value", claimValue);
        audit.warn(createAuditMessage("Set User Claim Value", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onSetUserClaimValuesFailure(String errorCode, String errorMessage, String userName,
            Map<String, String> claims, String profileName) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(
                createAuditMessage("Set User Claim Values", userName, new JSONObject(claims), errorCode, errorMessage));
        return true;
    }

    public boolean onDeleteUserClaimValuesFailure(String errorCode, String errorMessage, String userName, String[] claims,
            String profileName) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Delete User Claim Values", userName, new JSONArray(claims), errorCode,
                errorMessage));
        return true;
    }

    public boolean onDeleteUserClaimValueFailure(String errorCode, String errorMessage, String userName, String claimURI,
            String profileName) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim URI", claimURI);
        dataObject.put("Profile", profileName);
        audit.warn(createAuditMessage("Delete User Claim Value", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onAddRoleFailure(String errorCode, String errorMessage, String roleName, String[] userList,
            Permission[] permissions) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Users", new JSONArray(userList));

        JSONArray permissionsArray = new JSONArray();
        for (Permission permission : permissions) {
            permissionsArray.put(permission.getResourceId());
        }
        dataObject.put("Permissions", permissionsArray);
        audit.warn(createAuditMessage("Add Role", roleName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onDeleteRoleFailure(String errorCode, String errorMessage, String roleName) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Delete Role", roleName, null, errorCode, errorMessage));
        return true;
    }

    public boolean onUpdateRoleNameFailure(String errorCode, String errorMessage, String roleName, String newRoleName) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Update Role Name", roleName, newRoleName, errorCode, errorMessage));
        return true;
    }

    public boolean onUpdateUserListOfRoleFailure(String errorCode, String errorMessage, String roleName,
            String[] deletedUsers, String[] newUsers) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Deleted Users", new JSONArray(deletedUsers));
        dataObject.put("New Users", new JSONArray(newUsers));
        audit.warn(createAuditMessage("Update User List of Role", roleName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onUpdateRoleListOfUserFailure(String errorCode, String errorMessage, String userName,
            String[] deletedRoles, String[] newRoles) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Deleted Roles", new JSONArray(deletedRoles));
        dataObject.put("New Roles", new JSONArray(newRoles));
        audit.warn(createAuditMessage("Update Role List of User", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onGetUserClaimValueFailure(String errorCode, String errorMessage, String userName, String claim,
            String profileName) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim", claim);
        dataObject.put("Profile", profileName);
        audit.info(createAuditMessage("Get User Claim Value", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onGetUserClaimValuesFailure(String errorCode, String errorMessage, String userName, String[] claims,
            String profileName) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Claims", new JSONArray(claims));
        dataObject.put("Profile", profileName);
        audit.info(createAuditMessage("Get User Claim Values", userName, dataObject, errorCode, errorMessage));
        return true;
    }

    public boolean onGetUserListFailure(String errorCode, String errorMessage, String claim, String claimValue,
            String profileName) {
        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim", claim);
        dataObject.put("Claim Value", claimValue);
        dataObject.put("Profile", profileName);
        audit.info(createAuditMessage("Get User Claim Values", null, dataObject, errorCode, errorMessage));
        return true;
    }

    /**
     * To get the current user, who is doing the current task.
     *
     * @return current logged-in user
     */
    private String getUser() {
        String user = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (user != null) {
            user = user + "@" + CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        } else {
            user = CarbonConstants.REGISTRY_SYSTEM_USERNAME;
        }
        return user;
    }

    /**
     * To create an audit message based on provided parameters.
     *
     * @param action       Activity
     * @param target       Target affected by this activity.
     * @param data         Information passed along with the request.
     * @param errorCode    Error Code.
     * @param errorMessage Error Message.
     * @return Relevant audit log in Json format.
     */
    private String createAuditMessage(String action, String target, Object data, String errorCode,
            String errorMessage) {
        String resultField = "Result";
        String failureField = "Failure";
        String errorCodeField = "Error Code";
        String errorMessageField = "Error Message";
        JSONObject outCome = new JSONObject();
        outCome.put(resultField, failureField);
        outCome.put(errorCodeField, errorCode);
        outCome.put(errorMessageField, errorMessage);

        String AUDIT_MESSAGE = "| Initiator : %s | Action : %s| Target : %s | Data : %s | Outcome : %s ";
        return String.format(AUDIT_MESSAGE, getUser(), action, target, data, outCome);
    }
}
