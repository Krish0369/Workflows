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

// Mapping of claims / attributes to Kinde properties
const claimMappings: Record<string, string> = {
    preferred_username: "kp_usr_username",
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

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const { context, request } = event;
    const { user } = context;

    const protocol = context?.auth?.provider?.protocol?.toLowerCase();

    let claims: Record<string, any> = {};

    // --- OIDC / OAuth2 flow ---
    if (protocol === "oidc" || protocol === "oauth2") {
        const authentication = request?.authentication;
        if (!authentication) {
            console.log("No authentication object — skipping OIDC claim mapping");
            return;
        }
        claims = authentication.user_profile?.claims || authentication.user_profile || {};
        console.log("Processing OIDC/OAuth2 claims for user", user.id);
    }

    // --- SAML flow ---
    else if (protocol === "saml") {
        const attributeStatements =
            context?.auth?.provider?.data?.assertion?.attributeStatements;
        if (!attributeStatements?.length) {
            console.log("No SAML attributes found — skipping workflow");
            return;
        }
        // Flatten SAML attributes into a claims object
        claims = attributeStatements
            .flatMap((stmt: any) => stmt.attributes ?? [])
            .reduce((acc: Record<string, any>, attr: any) => {
                const name = attr.name?.toLowerCase().trim();
                if (!name) return acc;
                const values = (attr.values ?? []).map((v: any) => v.value?.trim()).filter(Boolean);
                if (values.length) acc[name] = values.length === 1 ? values[0] : values;
                return acc;
            }, {});
        console.log("Processing SAML attributes for user", user.id);
    }

    // --- Unsupported protocol ---
    else {
        console.log(`Unsupported protocol: ${protocol} — skipping workflow`);
        return;
    }

    // --- Map claims to Kinde user properties ---
    const propertiesToUpdate: Record<string, string> = {};

    for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
        const value = claims[claimName];
        if (value !== undefined && value !== null && value !== "") {
            propertiesToUpdate[propertyKey] = Array.isArray(value) ? value.join(", ") : String(value);
            console.log(`Mapping ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`);
        }
    }

    if (!Object.keys(propertiesToUpdate).length) {
        console.log("No properties to update");
        return;
    }

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
