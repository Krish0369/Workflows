import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "mapEntraIdClaims",
    name: "MapEntraIDClaims",
    failurePolicy: { action: "stop" },
    trigger: WorkflowTrigger.PostAuthentication,
    bindings: { "kinde.env": {}, url: {} },
};

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const { context, request } = event;
    const { user, is_new_user, authentication } = request;

    // --- Protocol check ---
    const protocol = context?.auth?.provider?.protocol;
    if (!protocol) {
        console.log("No protocol detected — skipping claims mapping");
        return;
    }

    // Only handle OIDC / OAuth2 (Entra ID)
    if (protocol !== "oidc" && protocol !== "oauth2") {
        console.log(`Skipping workflow — unsupported protocol: ${protocol}`);
        return;
    }

    // Safe authentication check
    if (!authentication) {
        console.log("No authentication object — skipping claims mapping");
        return;
    }

    // --- Extract claims ---
    const userProfile = authentication.user_profile || {};
    const claims = userProfile.claims || userProfile;

    // --- Map Entra claims to Kinde user properties ---
    const claimMappings: Record<string, string> = {
        preferred_username: "kp_usr_username", // maps username
        given_name: "kp_usr_first_name",
        family_name: "kp_usr_last_name",
        email: "kp_usr_email",
        name: "kp_usr_display_name",
        oid: "entra_object_id",
        tid: "entra_tenant_id",
        upn: "entra_upn",
        unique_name: "entra_unique_name",
        jobTitle: "job_title",
        department: "department",
        officeLocation: "office_location",
        mobilePhone: "mobile_phone",
        businessPhones: "business_phones",
        city: "city",
        country: "country",
        postalCode: "postal_code",
        state: "state",
        streetAddress: "street_address",
        companyName: "company_name",
        employeeId: "employee_id",
    };

    const propertiesToUpdate: Record<string, string> = {};

    for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
        const claimValue = claims[claimName];
        if (claimValue !== undefined && claimValue !== null && claimValue !== "") {
            propertiesToUpdate[propertyKey] = Array.isArray(claimValue)
                ? claimValue.join(", ")
                : String(claimValue);
            console.log(`Mapping claim ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`);
        }
    }

    if (!Object.keys(propertiesToUpdate).length) {
        console.log("No properties to update");
        return;
    }

    // --- Update user properties via Kinde API ---
    try {
        const kindeAPI = await createKindeAPI(event);
        await kindeAPI.patch({
            endpoint: `users/${user.id}/properties`,
            params: { properties: propertiesToUpdate },
        });
        console.log(`Successfully updated properties for user ${user.id}`);
    } catch (error) {
        console.error("Error updating user properties:", error);
    }
}
