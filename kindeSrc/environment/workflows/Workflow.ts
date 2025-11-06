import {
  onPostAuthenticationEvent,
  WorkflowSettings,
  WorkflowTrigger,
  accessTokenCustomClaims,
  idTokenCustomClaims,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "postAuthentication",
  name: "IdpTokenWorkflow_Debug",
  trigger: WorkflowTrigger.PostAuthentication,
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.accessToken": {}, // Required to modify access token claims
    "kinde.idToken": {}, // Required to modify ID token claims
  },
};

export default async function handlePostAuth(event: onPostAuthenticationEvent) {
  console.log("🔹 [IdpTokenWorkflow] Starting workflow...");

  const provider = event.context?.auth?.provider;

  // Check that a provider exists
  if (!provider) {
    console.log("⚠️ No provider found in event context — user may not be using a social login.");
    return;
  }

  console.log(`🔸 Provider detected: ${provider.provider}`);
  console.log(`🔸 Protocol: ${provider.protocol}`);

  // Only process OAuth2/OIDC connections
  if (provider.protocol !== "oauth2") {
    console.log("⚠️ Provider is not OAuth2/OIDC. Exiting workflow.");
    return;
  }

  const idTokenClaims = provider.data?.idToken?.claims;

  if (!idTokenClaims) {
    console.log("⚠️ No ID token claims found — this is expected for pure OAuth2 providers like GitHub.");
    return;
  }

  // Log out all the claims we got from the IdP
  console.log("✅ ID token claims received from provider:", idTokenClaims);

  // Create mutable claim objects
  const accessToken = accessTokenCustomClaims<{ idp_email?: string; idp_name?: string }>();
  const idToken = idTokenCustomClaims<{ idp_email?: string; idp_name?: string }>();

  // Add some common claims if available
  if (idTokenClaims.email) {
    accessToken.idp_email = idTokenClaims.email as string;
    idToken.idp_email = idTokenClaims.email as string;
  }

  if (idTokenClaims.name) {
    accessToken.idp_name = idTokenClaims.name as string;
    idToken.idp_name = idTokenClaims.name as string;
  }

  console.log("✅ Custom claims set:");
  console.log("Access token claims:", accessToken);
  console.log("ID token claims:", idToken);

  // Some SDK versions require returning modified objects explicitly
  return {
    accessToken,
    idToken,
  };
}
