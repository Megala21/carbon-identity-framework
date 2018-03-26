/*
 * Copyright (c) 2015 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.List;
import java.util.Map;

public class UserMgtAuditLogger extends AbstractIdentityUserOperationEventListener {

    private static final Log audit = CarbonConstants.AUDIT_LOG;
    private static final String SUCCESS = "Success";
    private static final String IN_PROGRESS = "In-Progress";
    private static final String RESULT_FIELD = "Result";

    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
            String profile, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject data = new JSONObject();
        data.put("Claims", new JSONObject(claims));
        data.put("Roles", new JSONArray(roleList));

        audit.warn(createAuditMessage("Add User", userName, data, SUCCESS));
        return true;
    }

    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        audit.warn(createAuditMessage("Delete User", userName, null, SUCCESS));
        return true;
    }

    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
            UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim URI", claimURI);
        dataObject.put("Claim Value", claimValue);

        audit.info(createAuditMessage("Trying to Set User Claim Value", userName, dataObject, IN_PROGRESS));
        return true;
    }

    public boolean doPostSetUserClaimValue(String userName, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        audit.warn(createAuditMessage("Set User Claim Value", userName, null, SUCCESS));
        return true;
    }

    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claims", new JSONObject(claims));
        dataObject.put("Profile", profileName);
        audit.warn(createAuditMessage("Set User Claim Values", userName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPreDeleteUserClaimValues(String userName, String[] claims, String profileName,
            UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claims", new JSONObject(claims));
        dataObject.put("Profile", profileName);
        audit.warn(createAuditMessage("Trying to delete user claim values", userName, dataObject, IN_PROGRESS));
        return true;
    }

    public boolean doPostDeleteUserClaimValues(String userName, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Delete user claim values", userName, null, SUCCESS));
        return true;

    }

    public boolean doPreDeleteUserClaimValue(String userName, String claimURI, String profileName,
            UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim", claimURI);
        dataObject.put("Profile", profileName);
        audit.warn(createAuditMessage("Trying to delete user claim value", userName, dataObject, IN_PROGRESS));
        return true;
    }

    public boolean doPostDeleteUserClaimValue(String userName, UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Delete user claim value", userName, null, SUCCESS));
        return true;
    }

    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }
        audit.warn(createAuditMessage("Change Password by User", userName, null, SUCCESS));
        return true;
    }

    public boolean doPostUpdateCredentialByAdmin(String userName, Object newCredential,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }
        audit.info(createAuditMessage("Change Password by Administrator", userName, null, SUCCESS));
        return true;
    }

    public boolean doPostDeleteRole(String roleName, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        audit.warn(createAuditMessage("Delete Role", roleName, null, SUCCESS));
        return true;
    }

    public boolean doPostAddRole(String roleName, String[] userList, Permission[] permissions,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("User List", new JSONArray(userList));

        JSONArray permissionsArray = new JSONArray();
        for (Permission permission : permissions) {
            permissionsArray.put(permission.getResourceId());
        }
        dataObject.put("Permissions", permissionsArray);

        audit.warn(createAuditMessage("Add Role", roleName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostUpdateRoleName(String roleName, String newRoleName, UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("New Role", newRoleName);
        audit.warn(createAuditMessage("Update Role Name", roleName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }
        JSONObject dataObject = new JSONObject();
        dataObject.put("Deleted Users", new JSONArray(deletedUsers));
        dataObject.put("New Users", new JSONArray(newUsers));

        audit.info(createAuditMessage("Update Users of Role", roleName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Deleted Roles", new JSONArray(deletedRoles));
        dataObject.put("New Roles", new JSONArray(newRoles));

        audit.info(createAuditMessage("Update Roles of User", userName, dataObject, toString()));
        return true;
    }

    public boolean doPostGetUserClaimValue(String userName, String claim, List<String> claimValue, String profileName,
            UserStoreManager storeManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim", claim);
        dataObject.put("Claim Values", new JSONArray(claimValue));
        dataObject.put("Profile", profileName);

        audit.info(createAuditMessage("Get User Claim Value", userName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName,
            Map<String, String> claimMap, UserStoreManager storeManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claims", new JSONObject(claimMap));
        dataObject.put("Profile", profileName);

        audit.info(createAuditMessage("Get User Claim Values", userName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostGetUserList(String claimUri, String claimValue, final List<String> returnValues,
            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Claim URI", claimUri);
        dataObject.put("Claim Value", claimValue);
        dataObject.put("User List", new JSONObject(returnValues));

        audit.info(createAuditMessage("Get User Claim Values", null, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostGetRoleListOfUser(String userName, String filter, String[] roleList,
            UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("Filter", filter);
        dataObject.put("Roles", new JSONArray(roleList));

        audit.info(createAuditMessage("Get Role List Of User", userName, dataObject, SUCCESS));
        return true;
    }

    public boolean doPostGetUserListOfRole(String roleName, String[] userList, UserStoreManager userStoreManager) {
        if (!isEnable()) {
            return true;
        }

        JSONObject dataObject = new JSONObject();
        dataObject.put("User List", new JSONArray(userList));

        audit.info(createAuditMessage("Get User List Of Role", roleName, dataObject, SUCCESS));
        return true;
    }

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
     * @param action      Activity
     * @param target      Target affected by this activity.
     * @param data        Information passed along with the request.
     * @param resultField Result value.
     * @return Relevant audit log in Json format.
     */
    private String createAuditMessage(String action, String target, Object data, String resultField) {
        JSONObject outCome = new JSONObject();
        outCome.put(RESULT_FIELD, resultField);

        String AUDIT_MESSAGE = "| Initiator : %s | Action : %s| Target : %s | Data : %s | Outcome : %s ";
        return String.format(AUDIT_MESSAGE, getUser(), action, target, data, outCome);
    }
}
