import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  denyAccess,
} from "@kinde/infrastructure";

// Workflow settings
export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "Post user auth",
  failurePolicy: { action: "stop" },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.auth": {},
    "kinde.env": {},
    "kinde.fetch": {},
    "kinde.mfa": {},
    url: {},
  },
};

// Main post-authentication workflow
export default async function handlePostAuth(event: onPostAuthenticationEvent): Promise<void> {
  try {
    const { auth } = event.context;
    const { connectionId, isNewUserRecordCreated: isNewKindeUser } = auth;

    console.debug('Connection ID:', connectionId);
    console.debug('Is New Kinde User:', isNewKindeUser);

    // Only apply access restriction for a specific connection (optional)
    // Remove this if you want to enforce for all connections
    if (connectionId === 'conn_01995a629a9d26f6882c80c3ee5648a8') {
      const groups = extractGroupsAttribute(event);
      console.debug('Groups Attribute:', groups);

      // Deny access if new user has no required group
      if (isNewKindeUser && (!groups || !groups.includes('87dd713c-440e-43df-8a31-abb3387c62b2'))) {
        // Important: return denyAccess to prevent further execution
        return denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
      }
    }

    // Other post-authentication checks can go here...

  } catch (error) {
    console.error('Post-authentication workflow failed', error);
    // Fail gracefully with a user-friendly message
    return denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
  }
}

// Helper: extract group claims from SAML provider
function extractGroupsAttribute(event: onPostAuthenticationEvent): string[] | null {
  try {
    const provider = (event.context as any).auth?.provider;
    if (provider?.protocol === 'saml' && provider?.data?.assertion?.attributeStatements) {
      for (const statement of provider.data.assertion.attributeStatements) {
        const groups = statement.attributes
          ?.find(attr => attr.name?.toLowerCase().endsWith('/claims/groups'))
          ?.values?.map((v: any) => v?.value) ?? null;
        if (groups) return groups;
      }
    }
    return null;
  } catch (err) {
    console.error('Error extracting group claims attribute', err);
    return null;
  }
}
