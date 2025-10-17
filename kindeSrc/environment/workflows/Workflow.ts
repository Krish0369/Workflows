import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "MapPropertiesToKinde",
    failurePolicy: {
        action: "stop",
    },
    trigger: WorkflowTrigger.PostAuthentication,
    bindings: {
        "kinde.env": {},
        url: {},
    },
};

type SamlValue = { value?: string };
type SamlAttribute = { name?: string; values?: SamlValue[] };
type SamlAttributeStatement = { attributes?: SamlAttribute[] };

// Define attribute mapping configuration
const attributeSyncConfig = [
    {
        shortName: "preferred_username",
        kindeKey: "usr_username",
    },
    {
        shortName: "user_city",
        kindeKey: "kp_usr_city",
    },
    // Add more mappings here if needed
];

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    console.log("=== Post-authentication trigger fired ===");

    const protocol = event.context?.auth?.provider?.protocol;
    console.log("Detected protocol:", protocol);

    if (!protocol || protocol !== "saml") {
        console.log("Info: Skipping workflow — unsupported protocol:", protocol);
        return;
    }

    const userId = event.context.user?.id;
    if (!userId) {
        console.error("No user object found, cannot update properties");
        return;
    }

    console.log("Info: Processing SAML attributes for user:", userId);

    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;

    if (!attributeStatements?.length) {
        console.log("Warning: No SAML attribute statements found");
        return;
    }

    console.log("Info: Found SAML attribute statements:", JSON.stringify(attributeStatements, null, 2));

    // Flatten attributes into a map for easier lookup
    const attributes = (attributeStatements ?? [])
        .flatMap((statement) => statement.attributes ?? [])
        .reduce((acc, attr) => {
            const name = attr.name?.toLowerCase().trim();
            if (name) {
                const values = (attr.values ?? [])
                    .map((v) => v.value?.trim())
                    .filter((v): v is string => !!v);
                if (values.length > 0) {
                    acc.set(name, values);
                    console.log(`→ Found SAML attribute: ${name} = ${values.join(", ")}`);
                }
            }
            return acc;
        }, new Map<string, string[]>());

    // Helper to get claim by short name or full URI
    const getClaim = (shortName: string) => {
        return (
            attributes.get(shortName.toLowerCase()) ||
            attributes.get(`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/${shortName.toLowerCase()}`) ||
            attributes.get(`http://schemas.microsoft.com/identity/claims/${shortName.toLowerCase()}`)
        )?.[0]; // take first value if array
    };

    const propertiesToUpdate: Record<string, string> = {};

    // Map all configured attributes
    for (const config of attributeSyncConfig) {
        const value = getClaim(config.shortName);
        if (value) {
            propertiesToUpdate[config.kindeKey] = value;
            console.log(`Matched claim ${config.shortName} → ${config.kindeKey} = ${value}`);
        }
    }

    if (Object.keys(propertiesToUpdate).length === 0) {
        console.log("Info: No matching SAML attributes found to update");
        return;
    }

    console.log("Preparing to update Kinde user:", userId);
    console.log("Properties to update:", JSON.stringify(propertiesToUpdate, null, 2));

    try {
        const kindeAPI = await createKindeAPI(event);
        await kindeAPI.patch({
            endpoint: `users/${userId}/properties`,
            params: { properties: propertiesToUpdate },
        });
        console.log("Successfully updated user properties in Kinde");
    } catch (error) {
        console.error("Failed to update Kinde user properties:", error);
        throw error;
    }
}
