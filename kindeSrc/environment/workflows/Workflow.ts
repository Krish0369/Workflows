import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "MapPreferredUsernameToKinde",
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

const attributeSyncConfig = [
    {
        samlNames: ["preferred_username", "user.userprincipalname", "email"],
        kindeKey: "kp_usr_username",
        multiValue: false,
    },
];

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    console.log("=== Post-authentication trigger fired ===");

    const protocol = event.context?.auth?.provider?.protocol;
    console.log("Detected protocol:", protocol);

    if (!protocol || protocol !== "saml") {
        console.log("Info: Skipping workflow — unsupported protocol:", protocol);
        return;
    }

    console.log("Info: Processing SAML attributes for user:", event.context.user.id);

    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;

    if (!attributeStatements?.length) {
        console.log("Warning: No SAML attribute statements found");
        return;
    }

    console.log("Info: Found SAML attribute statements:", JSON.stringify(attributeStatements, null, 2));

    const samlAttributesMap = (attributeStatements ?? [])
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

    const propertiesToUpdate: Record<string, string> = {};

    for (const config of attributeSyncConfig) {
        console.log(`Checking for attributes: ${config.samlNames.join(", ")}`);

        let foundValues: string[] | undefined;
        for (const name of config.samlNames) {
            const values = samlAttributesMap.get(name.toLowerCase());
            if (values && values.length > 0) {
                foundValues = values;
                console.log(`Matched ${name} → ${config.kindeKey} = ${values[0]}`);
                break;
            }
        }

        if (foundValues) {
            propertiesToUpdate[config.kindeKey] = foundValues[0];
        }
    }

    if (Object.keys(propertiesToUpdate).length === 0) {
        console.log("Info: No matching SAML attributes found to update");
        return;
    }

    const userId = event.context.user.id;
    console.log("Preparing to update Kinde user:", userId);
    console.log("Properties to update:", JSON.stringify(propertiesToUpdate, null, 2));

    try {
        const kindeAPI = await createKindeAPI(event);
        await kindeAPI.patch({
            endpoint: `users/${userId}/properties`,
            params: { properties: propertiesToUpdate },
        });
        console.log("✅ Successfully updated user properties in Kinde");
    } catch (error) {
        console.error("❌ Failed to update Kinde user properties:", error);
        throw error;
    }
}
