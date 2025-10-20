import {
  WorkflowSettings,
  WorkflowTrigger,
  createKindeAPI,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "mapEntraIdClaims",
  name: "MapEntraIdClaims",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    url: {},
    "kinde.mfa": {}
  },
};

export default async function mapEntraIdClaimsWorkflow(
  event: any
) {
  const provider = event.context?.auth?.provider;
  const protocol = provider?.protocol || "";

  console.log("Event data:", JSON.stringify(event, null, 2));

  // Only process OAuth2 connections from Entra ID (Microsoft)
  if (protocol !== "oauth2") {
    console.log("Not an OAuth2 authentication, skipping claims mapping");
    return;
  }

  // Check if this is a Microsoft/Entra ID connection
  const providerName =
    provider?.provider?.toLowerCase() ||
    "";

  if (
    !providerName.includes("microsoft") &&
    !providerName.includes("entra") &&
    !providerName.includes("azure") &&
    !providerName.includes("azure_ad")
  ) {
    console.log(
      `Connection ${providerName} is not a Microsoft/Entra ID connection, skipping`
    );
    return;
  }

  const userId = event.context?.user?.id;
  console.log(`Processing Entra ID OAuth2 claims for user: ${userId}`);

  // Extract claims
  const claims = provider?.data?.idToken?.claims || {};
  console.log("Raw claims received:", claims);

  // Map of Entra ID claims -> Kinde properties
  // Some are examples; adjust based on your needs
  const claimMappings: Record<string, string> = {

    preferred_username: "usr_username",  
    city: "kp_usr_city",

  };

  const propertiesToUpdate: Record<string, string> = {};

  // Map claims to properties
  for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
    const claimValue = claims[claimName];
    if (claimValue) {
      propertiesToUpdate[propertyKey] = Array.isArray(claimValue)
        ? claimValue.join(", ")
        : String(claimValue);
      console.log(
        `Mapping claim ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`
      );
    }
  }

  // Add groups if present
  if (Array.isArray(claims.groups)) {
    propertiesToUpdate["entra_groups"] = claims.groups.join(", ");
  }

  // Always store last sync timestamp
  propertiesToUpdate["entra_last_sync"] = new Date().toISOString();

  // Nothing to update
  if (Object.keys(propertiesToUpdate).length === 0) {
    console.log("No properties to update");
    return;
  }

  // Create the Kinde API client (uses your M2M credentials)
  const kindeAPI = await createKindeAPI(event);

  try {
    await kindeAPI.patch({
      endpoint: `users/${userId}/properties`,
      params: { properties: propertiesToUpdate },
    });

    console.log(
      `Successfully updated ${Object.keys(propertiesToUpdate).length} properties for user ${userId}`
    );
  } catch (error) {
    console.error("Error updating user properties:", error);
  }

  console.log(`Completed Entra ID claims mapping for user ${userId}`);
}
