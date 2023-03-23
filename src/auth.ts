import {
    AccessToken,
    addUserToOrg,
    AddUserToOrgRequest,
    allowOrgToSetupSamlConnection,
    changeUserRoleInOrg,
    ChangeUserRoleInOrgRequest, createAccessToken, CreateAccessTokenRequest,
    createMagicLink,
    CreateMagicLinkRequest,
    createOrg,
    CreateOrgRequest,
    createUser,
    CreateUserRequest,
    deleteOrg,
    deleteUser,
    disableUser,
    disableUser2fa,
    disallowOrgToSetupSamlConnection,
    enableUser,
    fetchBatchUserMetadata,
    fetchOrg,
    fetchOrgByQuery,
    fetchUserMetadataByQuery,
    fetchUserMetadataByUserIdWithIdCheck,
    fetchUsersByQuery,
    fetchUsersInOrg,
    MagicLink,
    migrateUserFromExternalSource,
    MigrateUserFromExternalSourceRequest,
    OrgQuery,
    OrgQueryResponse,
    removeUserFromOrg,
    RemoveUserFromOrgRequest,
    updateOrg,
    UpdateOrgRequest,
    updateUserEmail,
    UpdateUserEmailRequest,
    updateUserMetadata,
    UpdateUserMetadataRequest,
    updateUserPassword,
    UpdateUserPasswordRequest,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
} from "./api"
import {ForbiddenException, UnauthorizedException} from "./exceptions"
import {
    InternalUser,
    Org,
    OrgIdToOrgMemberInfo,
    OrgMemberInfo,
    toUser,
    User,
    UserAndOrgMemberInfo,
    UserMetadata,
} from "./user"
import {validateAuthUrl} from "./validators"
import * as jose from 'jose'
import {KeyLike} from "jose/dist/types/types";

export type AuthOptions = {
    authUrl: string
    apiKey: string
    verifierKey: string
}

export function initAuth(opts: AuthOptions) {
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const apiKey: string = opts.apiKey
    const publicKeyPromise = jose.importSPKI(opts.verifierKey, 'RS256')

    const validateAuthHeaderAndGetUser = wrapValidateAuthorizationHeaderAndGetUser(publicKeyPromise, authUrl.origin)
    const validateAuthHeaderAndGetUserWithOrgInfo = wrapValidateAccessTokenAndGetUserWithOrgInfo(publicKeyPromise, authUrl.origin)
    const validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(publicKeyPromise, authUrl.origin)
    const validateAuthHeaderAndGetUserWithOrgInfoWithExactRole = wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(publicKeyPromise, authUrl.origin)
    const validateAuthHeaderAndGetUserWithOrgInfoWithPermission = wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(publicKeyPromise, authUrl.origin)
    const validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions = wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(publicKeyPromise, authUrl.origin)

    function fetchUserMetadataByUserId(userId: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByUserIdWithIdCheck(authUrl, apiKey, userId, includeOrgs);
    }

    function fetchUserMetadataByEmail(email: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, "email", {
            email: email,
            include_orgs: includeOrgs || false
        })
    }

    function fetchUserMetadataByUsername(username: string, includeOrgs?: boolean): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, "username", {
            username: username,
            include_orgs: includeOrgs || false
        })
    }

    function fetchBatchUserMetadataByUserIds(userIds: string[], includeOrgs?: boolean): Promise<{ [userId: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "user_ids", userIds, (x) => x.userId, includeOrgs || false)
    }

    function fetchBatchUserMetadataByEmails(emails: string[], includeOrgs?: boolean): Promise<{ [email: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "emails", emails, (x) => x.email, includeOrgs || false)
    }

    function fetchBatchUserMetadataByUsernames(usernames: string[], includeOrgs?: boolean): Promise<{ [username: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "usernames", usernames, (x) => x.username || "", includeOrgs || false)
    }

    function fetchOrgWrapper(orgId: string): Promise<Org | null> {
        return fetchOrg(authUrl, apiKey, orgId)
    }

    function fetchOrgsByQueryWrapper(orgQuery: OrgQuery): Promise<OrgQueryResponse> {
        return fetchOrgByQuery(authUrl, apiKey, orgQuery)
    }

    function fetchUsersByQueryWrapper(usersQuery: UsersQuery): Promise<UsersPagedResponse> {
        return fetchUsersByQuery(authUrl, apiKey, usersQuery)
    }

    function fetchUsersInOrgWrapper(usersInOrgQuery: UsersInOrgQuery): Promise<UsersPagedResponse> {
        return fetchUsersInOrg(authUrl, apiKey, usersInOrgQuery)
    }

    function createUserWrapper(createUserRequest: CreateUserRequest): Promise<User> {
        return createUser(authUrl, apiKey, createUserRequest)
    }

    function updateUserMetadataWrapper(userId: string, updateUserMetadataRequest: UpdateUserMetadataRequest): Promise<boolean> {
        return updateUserMetadata(authUrl, apiKey, userId, updateUserMetadataRequest)
    }

    function deleteUserWrapper(userId: string): Promise<boolean> {
        return deleteUser(authUrl, apiKey, userId)
    }

    function disableUserWrapper(userId: string): Promise<boolean> {
        return disableUser(authUrl, apiKey, userId)
    }

    function enableUserWrapper(userId: string): Promise<boolean> {
        return enableUser(authUrl, apiKey, userId)
    }

    function disableUser2faWrapper(userId: string): Promise<boolean> {
        return disableUser2fa(authUrl, apiKey, userId)
    }

    function updateUserEmailWrapper(userId: string, updateUserEmailRequest: UpdateUserEmailRequest): Promise<boolean> {
        return updateUserEmail(authUrl, apiKey, userId, updateUserEmailRequest)
    }

    function updateUserPasswordWrapper(userId: string, updateUserPasswordRequest: UpdateUserPasswordRequest): Promise<boolean> {
        return updateUserPassword(authUrl, apiKey, userId, updateUserPasswordRequest)
    }

    function createMagicLinkWrapper(createMagicLinkRequest: CreateMagicLinkRequest): Promise<MagicLink> {
        return createMagicLink(authUrl, apiKey, createMagicLinkRequest)
    }

    function createAccessTokenWrapper(createAccessTokenRequest: CreateAccessTokenRequest): Promise<AccessToken> {
        return createAccessToken(authUrl, apiKey, createAccessTokenRequest)
    }

    function migrateUserFromExternalSourceWrapper(migrateUserFromExternalSourceRequest: MigrateUserFromExternalSourceRequest): Promise<User> {
        return migrateUserFromExternalSource(authUrl, apiKey, migrateUserFromExternalSourceRequest)
    }

    function createOrgWrapper(createOrgRequest: CreateOrgRequest): Promise<Org> {
        return createOrg(authUrl, apiKey, createOrgRequest)
    }

    function addUserToOrgWrapper(addUserToOrgRequest: AddUserToOrgRequest): Promise<boolean> {
        return addUserToOrg(authUrl, apiKey, addUserToOrgRequest)
    }

    function changeUserRoleInOrgWrapper(changeUserRoleInOrgRequest: ChangeUserRoleInOrgRequest): Promise<boolean> {
        return changeUserRoleInOrg(authUrl, apiKey, changeUserRoleInOrgRequest)
    }

    function removeUserFromOrgWrapper(removeUserFromOrgRequest: RemoveUserFromOrgRequest): Promise<boolean> {
        return removeUserFromOrg(authUrl, apiKey, removeUserFromOrgRequest)
    }

    function updateOrgWrapper(updateOrgRequest: UpdateOrgRequest): Promise<boolean> {
        return updateOrg(authUrl, apiKey, updateOrgRequest)
    }

    function deleteOrgWrapper(orgId: string): Promise<boolean> {
        return deleteOrg(authUrl, apiKey, orgId)
    }

    function allowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return allowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    function disallowOrgToSetupSamlConnectionWrapper(orgId: string): Promise<boolean> {
        return disallowOrgToSetupSamlConnection(authUrl, apiKey, orgId)
    }

    return {
        // validate and fetching functions
        validateAuthHeaderAndGetUser: validateAuthHeaderAndGetUser,
        validateAuthHeaderAndGetUserWithOrgInfo: validateAuthHeaderAndGetUserWithOrgInfo,
        validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole: validateAuthHeaderAndGetUserWithOrgInfoWithMinimumRole,
        validateAuthHeaderAndGetUserWithOrgInfoWithExactRole: validateAuthHeaderAndGetUserWithOrgInfoWithExactRole,
        validateAuthHeaderAndGetUserWithOrgInfoWithPermission: validateAuthHeaderAndGetUserWithOrgInfoWithPermission,
        validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions: validateAuthHeaderAndGetUserWithOrgInfoWithAllPermissions,
        // fetching functions
        fetchUserMetadataByUserId,
        fetchUserMetadataByEmail,
        fetchUserMetadataByUsername,
        fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames,
        fetchOrg: fetchOrgWrapper,
        fetchOrgByQuery: fetchOrgsByQueryWrapper,
        fetchUsersByQuery: fetchUsersByQueryWrapper,
        fetchUsersInOrg: fetchUsersInOrgWrapper,
        // user management functions
        createUser: createUserWrapper,
        updateUserMetadata: updateUserMetadataWrapper,
        updateUserEmail: updateUserEmailWrapper,
        updateUserPassword: updateUserPasswordWrapper,
        createMagicLink: createMagicLinkWrapper,
        migrateUserFromExternalSource: migrateUserFromExternalSourceWrapper,
        deleteUser: deleteUserWrapper,
        disableUser: disableUserWrapper,
        enableUser: enableUserWrapper,
        disableUser2fa: disableUser2faWrapper,

        // org management functions
        createOrg: createOrgWrapper,
        addUserToOrg: addUserToOrgWrapper,
        changeUserRoleInOrg: changeUserRoleInOrgWrapper,
        removeUserFromOrg: removeUserFromOrgWrapper,
        updateOrg: updateOrgWrapper,
        deleteOrg: deleteOrgWrapper,
        allowOrgToSetupSamlConnection: allowOrgToSetupSamlConnectionWrapper,
        disallowOrgToSetupSamlConnection: disallowOrgToSetupSamlConnectionWrapper,
    }
}

// wrapper function with no validation
function wrapValidateAuthorizationHeaderAndGetUser(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAuthorizationHeaderAndGetUser(authorizationHeader: string | null): Promise<User> {
        return extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer)
    }
}

// The following four functions are wrappers around our four validations: isRole, atLeastRole, hasPermission, hasAllPermissions
// Each function returns an OrgMemberInfo object


function wrapValidateAccessTokenAndGetUserWithOrgInfo(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | null,
                                                                   requiredOrgInfo: RequiredOrgInfo): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfo(user, requiredOrgInfo);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | null,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   minimumRole: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user, requiredOrgInfo, minimumRole);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithExactRole(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | null,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   exactRole: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithExactRole(user, requiredOrgInfo, exactRole);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithPermission(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | null,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permission: string): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithPermission(user, requiredOrgInfo, permission);
        return {user, orgMemberInfo}
    }
}

function wrapValidateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(publicKeyPromise: Promise<KeyLike>, issuer: string) {
    return async function validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader: string | null,
                                                                   requiredOrgInfo: RequiredOrgInfo,
                                                                   permissions: string[]): Promise<UserAndOrgMemberInfo> {
        const user = await extractAndVerifyBearerToken(publicKeyPromise, authorizationHeader, issuer);
        const orgMemberInfo = validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user, requiredOrgInfo, permissions);
        return {user, orgMemberInfo}
    }
}


export type RequiredOrgInfo = {
    orgId?: string
    orgName?: string
}

// Validator functions

function validateOrgAccessAndGetOrgMemberInfo(user: User, requiredOrgInfo: RequiredOrgInfo): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithMinimumRole(user: User, requiredOrgInfo: RequiredOrgInfo, minimumRole: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isAtLeastRole(minimumRole)) {
        throw new ForbiddenException(
            `User's roles (${orgMemberInfo.inheritedRolesPlusCurrentRole}) don't contain the minimum role (${minimumRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithExactRole(user: User, requiredOrgInfo: RequiredOrgInfo, exactRole: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.isRole(exactRole)) {
        throw new ForbiddenException(
            `User's assigned role (${orgMemberInfo.assignedRole}) isn't the required role (${exactRole})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithPermission(user: User, requiredOrgInfo: RequiredOrgInfo, permission: string): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasPermission(permission)) {
        throw new ForbiddenException(
            `User's permissions (${orgMemberInfo.permissions}) don't contain the required permission (${permission})`,
        )
    }

    return orgMemberInfo
}

function validateOrgAccessAndGetOrgMemberInfoWithAllPermissions(user: User, requiredOrgInfo: RequiredOrgInfo, permissions: string[]): OrgMemberInfo {
    const orgMemberInfo = getUserInfoInOrg(requiredOrgInfo, user.orgIdToOrgMemberInfo)
    if (!orgMemberInfo) {
        throw new ForbiddenException(`User is not a member of org ${JSON.stringify(requiredOrgInfo)}`)
    }

    if (!orgMemberInfo.hasAllPermissions(permissions)) {
        throw new ForbiddenException(
            `User's permissions (${orgMemberInfo.permissions}) don't contain all the required permissions (${permissions})`,
        )
    }

    return orgMemberInfo
}

// Miscellaneous functions

function getUserInfoInOrg(requiredOrgInfo: RequiredOrgInfo, orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo): OrgMemberInfo | undefined {
    if (!orgIdToOrgMemberInfo) {
        return undefined

    } else if (requiredOrgInfo.orgId) {
        // If we are looking for an orgId, we can do a direct lookup
        if (!orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgInfo.orgId)) {
            return undefined;
        }
        const orgMemberInfo = orgIdToOrgMemberInfo[requiredOrgInfo.orgId]

        // We also need to verify the orgName matches, if specified
        if (requiredOrgInfo.orgName && orgNameMatches(requiredOrgInfo.orgName, orgMemberInfo)) {
            return orgMemberInfo
        } else if (requiredOrgInfo.orgName) {
            return undefined
        } else {
            return orgMemberInfo
        }

    } else if (requiredOrgInfo.orgName) {
        // We know there's no required orgId so just iterate over orgMemberInfos looking for a matching urlSafeOrgName
        for (const orgMemberInfo of Object.values(orgIdToOrgMemberInfo)) {
            if (orgNameMatches(requiredOrgInfo.orgName, orgMemberInfo)) {
                return orgMemberInfo
            }
        }
        return undefined

    } else {
        return undefined
    }
}

function orgNameMatches(orgName: string, orgMemberInfo: OrgMemberInfo) {
    return orgName === orgMemberInfo.orgName || orgName === orgMemberInfo.urlSafeOrgName
}

async function extractAndVerifyBearerToken(publicKeyPromise: Promise<KeyLike>, authorizationHeader: string | null, issuer: string): Promise<User> {
    let publicKey;
    try {
        publicKey = await publicKeyPromise
    } catch (err) {
        console.error("Verifier key is invalid. Make sure it's specified correctly, including the newlines.", err)
        throw new UnauthorizedException("Invalid verifier key")
    }
    const bearerToken = extractBearerToken(authorizationHeader)
    return await verifyToken(bearerToken, publicKey, issuer);
}

function extractBearerToken(authHeader: string | null): string {
    if (!authHeader) {
        throw new UnauthorizedException("No authorization header found.")
    }

    const authHeaderParts = authHeader.split(" ")
    if (authHeaderParts.length !== 2 || authHeaderParts[0].toLowerCase() !== "bearer") {
        throw new UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")
    }

    return authHeaderParts[1]
}

async function verifyToken(bearerToken: string, publicKey: KeyLike, issuer: string): Promise<User> {
    try {
        const {payload} = await jose.jwtVerify(bearerToken, publicKey, {
            issuer,
            algorithms: ['RS256'],
        })

        return toUser(<InternalUser>payload)
    } catch (e) {
        if (e instanceof Error) {
            throw new UnauthorizedException(e.message)
        } else {
            throw new UnauthorizedException("Unable to decode jwt")
        }
    }
}

export type HandleErrorOptions = {
    logError?: boolean,
    returnDetailedErrorToUser?: boolean
}

export type HandleErrorResponse = {
    status: number,
    message: string
}

export function handleError(e: unknown, opts?: HandleErrorOptions): HandleErrorResponse {
    if (opts && opts.logError) {
        console.log(e);
    }

    const detailedError = opts && opts.returnDetailedErrorToUser
    if (e instanceof UnauthorizedException) {
        return {
            status: 401, message: detailedError ? e.message : "Unauthorized"
        }
    } else if (e instanceof ForbiddenException) {
        return {
            status: 403, message: detailedError ? e.message : "Unauthorized"
        }
    } else {
        return {
            status: 401, message: "Unauthorized"
        }
    }
}