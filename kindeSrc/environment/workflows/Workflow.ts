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

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  const protocol = event.context?.auth?.provider?.protocol;
  if (!protocol || protocol !== "saml") {
    console.info("Skipping workflow — unsupported protocol:", protocol);
    return;
  }

  console.info("Processing SAML attributes for user:", event.request.user.id);

  const attributes = event.context?.auth?.provider?.attributes || {};
  if (!attributes || Object.keys(attributes).length === 0) {
    console.info("No SAML attributes found");
    return;
  }

  // Helper to get claim by short or full URI form
  const getClaim = (name: string) => {
    return (
      attributes[name] ||
      attributes[`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/${name}`]
    );
  };

  // Flexible claim mapping
  const updates: Record<string, any> = {};

  const preferredUsername = getClaim("preferred_username");
  if (preferredUsername) {
    updates["kp_usr_username"] = preferredUsername;
  }
  const preferredUsername = getClaim("preferred_username");
  if (preferredUsername) {
    updates["usr_username"] = preferredUsername;
  }
  const address = getClaim("User_City");
  if (address) {
    updates["kp_usr_city"] = address;
  }

  if (Object.keys(updates).length === 0) {
    console.info("No properties to update");
    return;
  }

  // Update Kinde user
  const api = createKindeAPI(event);
  await api.users.update(event.request.user.id, updates);

  console.info("Updated user properties:", updates);
}
