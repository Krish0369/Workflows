import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "mapEntraIdClaims",
    name: "MapEntraIDSamlClaims",
    failurePolicy: { action: "stop" },
    trigger: WorkflowTrigger.PostAuthentication,
    bindings: { "kinde.env": {}, url: {} },
};

// Map SAML attribute variations to Kinde user properties
const claimMappings: Record<string, string> = {
    // Username
    "preferredusername": "kp_usr_username",
    "preferred_username": "kp_usr_username",
    "upn": "kp_usr_username",
    // Names
    "givenname": "kp_usr_first_name",
    "given_name": "kp_usr_first_name",
    "surname": "kp_usr_last_name",
    "familyname": "kp_usr_last_name",
    "family_name": "kp_usr_last_name",
    "name": "kp_usr_display_name",
    // Email
    "email": "kp_usr_email",
    "mail": "kp_usr_email",
    // Other useful attributes
    "jobtitle": "job_title",
    "department": "department",
    "mobilephone": "mobile_phone",
    "businessphones": "business_phones",
};

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const { context } = event;
    const user = context?.user;
    const protocol = context?.auth?.provider?.protocol?.toLowerCase();

    if (!user || !protocol) return;

    let claims: Record<string, any> = {};

    // --- SAML flow ---
    if (protocol === "saml") {
        const attributeStatements = context?.auth?.provider?.data?.assertion?.attributeStatements;
        if (!attributeStatements?.length) {
            console.log("No SAML attributes found — skipping workflow");
            return;
        }

        claims = attributeStatements
            .flatMap((stmt: any) => stmt.attributes ?? [])
            .reduce((acc: Record<string, any>, attr: any) => {
                const name = attr.name?.toLowerCase().replace(/[^a-z0-9_]/g, ""); // normalize name
                if (!name) return acc;
                const values = (attr.values ?? []).map((v: any) => v.value?.trim()).filter(Boolean);
                if (values.length) acc[name] = values.length === 1 ? values[0] : values;
                return acc;
            }, {});

        console.log("Processing SAML attributes for user", user.id);
    }

    // --- OIDC/OAuth2 flow ---
    else if (protocol === "oidc" || protocol === "oauth2") {
        const authentication = event?.request?.authentication;
        if (!authentication) return;
        claims = authentication.user_profile?.claims || authentication.user_profile || {};
        console.log("Processing OIDC/OAuth2 claims for user", user.id);
    }

    else {
        console.log(`Unsupported protocol: ${protocol} — skipping workflow`);
        return;
    }

    // --- Map claims to Kinde properties ---
    const propertiesToUpdate: Record<string, string> = {};
    for (const [claimKey, kindeKey] of Object.entries(claimMappings)) {
        const value = claims[claimKey];
        if (value !== undefined && value !== null && value !== "") {
            propertiesToUpdate[kindeKey] = Array.isArray(value) ? value.join(", ") : String(value);
            console.log(`Mapping ${claimKey} -> ${kindeKey}: ${propertiesToUpdate[kindeKey]}`);
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
