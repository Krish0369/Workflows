import {
  onPreUserCreationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  denyAccess,
} from "@kinde/infrastructure";

// Workflow settings
export const workflowSettings: WorkflowSettings = {
  id: "preUserCheck",
  name: "Pre-user creation access check",
  failurePolicy: { action: "stop" },
  trigger: WorkflowTrigger.PreUserCreation,
  bindings: {
    "kinde.auth": {},
    "kinde.env": {},
    "kinde.fetch": {},
  },
};

// Main workflow
export default async function handlePreUserCreation(event: onPreUserCreationEvent): Promise<void> {
  try {
    const { auth } = event.context;
    const connectionId = auth.connectionId;

    console.debug('Connection ID:', connectionId);

    // Enforce only for the provided connection ID
    if (connectionId === 'conn_01995a629a9d26f6882c80c3ee5648a8') {
      const groups = extractGroupsAttribute(event);
      console.debug('Groups Attribute:', groups);

      // Deny access if user has no groups or missing required group
      if (!groups || !groups.includes('87dd713c-440e-43df-8a31-abb3387c62b2')) {
        // Prevent user creation and show error message
        return denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
      }
    }

    // Otherwise, user creation proceeds as normal
  } catch (error) {
    console.error('Pre-user creation workflow failed', error);
    return denyAccess('Your organization has not granted you access. Please contact your IT administrator to request access.');
  }
}

// Helper: extract group claims from SAML provider
function extractGroupsAttribute(event: onPreUserCreationEvent): string[] | null {
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
