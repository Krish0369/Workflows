onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
  denyAccess,
} from "@kinde/infrastructure";
import handleSyncNewUser from "../auth/syncNewUser";

// The settings for this workflow
export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "Post user auth",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.auth": {},
    "kinde.env": {},
    "kinde.fetch": {},
    "kinde.mfa": {},
    url: {}
  },
};

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  if (event.context.auth.connectionId === 'conn_0199b75aebb0583f2b8c19255b7c3adb') {
    console.log('Ian Test Connection Event:', JSON.stringify(event));
    const groups = extractGroupsAttribute(event);
    console.log('Groups Attribute:', groups);
    const isNewKindeUser = event.context.auth.isNewUserRecordCreated;
    console.log('Is New Kinde User:', isNewKindeUser);
    if (isNewKindeUser && (groups === null || !groups.includes('87dd713c-440e-43df-8a31-abb3387c62b2'))) {
      console.error(`Calling denyAccess('Your organization has not granted you access to Heidi. Please contact your IT administrator to request access.');`)
      denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
      return;
    }
  }

  // Other unrelated checks ...
}

function extractGroupsAttribute(event: onPostAuthenticationEvent): string[] | null {
  try {
    // Access the provider data from the event context
    const provider = (event.context as any).auth?.provider;

    // Check if this is a SAML provider with the expected structure
    if (provider?.protocol === 'saml' && provider?.data?.assertion?.attributeStatements) {
      for (const statement of provider.data.assertion.attributeStatements) {
        const groups = statement.attributes?.find((attribute) => attribute.name.toLowerCase().endsWith('/claims/groups'))?.values.map((value: any) => value?.value) ?? null;
        if (groups) return groups;
      }
    }

    return null;
  } catch (error) {
    console.error('Error extracting group claims attribute', error);
    return null;
  }
}
