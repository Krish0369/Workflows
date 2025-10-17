import {
    onPostAuthenticationEvent,
    WorkflowSettings,
    WorkflowTrigger,
    createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
    id: "postAuthentication",
    name: "MapPreferredUsername",
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
        samlNames: ["preferred_username"],
        kindeKey: "usr_username", // custom Kinde property
        multiValue: false,
    },
];

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
    const protocol = event.context?.auth?.provider?.protocol;
    if (!protocol || protocol !== "saml") return;

    const attributeStatements =
        event.context.auth.provider?.data?.assertion
            ?.attributeStatements as SamlAttributeStatement[] | undefined;
    if (!attributeStatements?.length) return;

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
                }
            }
            return acc;
        }, new Map<string, string[]>());

    const propertiesToUpdate: Record<string, string> = {};

    for (const config of attributeSyncConfig) {
        let foundValues: string[] | undefined;
        for (const name of config.samlNames) {
            const values = samlAttributesMap.get(name);
            if (values && values.length > 0) {
                foundValues = values;
                break;
            }
        }

        if (foundValues) {
            propertiesToUpdate[config.kindeKey] = foundValues[0];
        }
    }

    if (Object.keys(propertiesToUpdate).length === 0) return;

    const kindeAPI = await createKindeAPI(event);
    const userId = event.context.user.id;

    await kindeAPI.patch({
        endpoint: `users/${userId}/properties`,
        params: { properties: propertiesToUpdate },
    });
}
