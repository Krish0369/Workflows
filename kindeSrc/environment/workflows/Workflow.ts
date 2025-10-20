import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
  denyAccess,
} from "@kinde/infrastructure";

// Workflow settings
export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "Post user auth access control",
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

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  const { auth, user } = event.context;

  // Only enforce for your SAML connection
  if (auth.connectionId === 'conn_01995a629a9d26f6882c80c3ee5648a8') {
    const groups = extractGroupsAttribute(event);
    const isNewKindeUser = auth.isNewUserRecordCreated;

    console.debug('Groups Attribute:', groups);
    console.debug('Is New Kinde User:', isNewKindeUser);

    if (isNewKindeUser && (!groups || !groups.includes('87dd713c-440e-43df-8a31-abb3387c62b2'))) {
      console.warn(`Blocking new user ${user.id} due to missing group`);

      try {
        // Disable the user immediately
        await createKindeAPI().users.update(user.id, { active: false });
      } catch (err) {
        console.error('Error disabling new user:', err);
      }

      // Deny access and show custom message
      return denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
    }
  }

  // Other unrelated post-auth checks can continue here...
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
