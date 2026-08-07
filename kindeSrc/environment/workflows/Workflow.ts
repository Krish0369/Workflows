import {
  WorkflowSettings,
  WorkflowTrigger,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "checkEntraTokens",
  name: "CheckEntraTokens",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "url": {},
  },
};

export default async function checkEntraTokens(event: any) {
  const provider = event.context?.auth?.provider;

  console.log("Provider:", provider?.provider);
  console.log("Protocol:", provider?.protocol);

  const providerData = provider?.data || {};

  // Show available fields only
  console.log(
    "Provider data keys:",
    Object.keys(providerData)
  );

  // Check token availability
  console.log(
    "Has ID token:",
    !!providerData.idToken
  );

  console.log(
    "Has access token:",
    !!providerData.accessToken
  );

  console.log(
    "Has refresh token:",
    !!providerData.refreshToken
  );

  // Also check snake_case possibility
  console.log(
    "Has access_token:",
    !!providerData.access_token
  );

  console.log(
    "Has refresh_token:",
    !!providerData.refresh_token
  );
}
