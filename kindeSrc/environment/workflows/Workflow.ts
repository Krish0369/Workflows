import {
  WorkflowSettings,
  WorkflowTrigger,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "inspectEntraProviderTokens",
  name: "InspectEntraProviderTokens",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "url": {},
  },
};

export default async function inspectEntraProviderTokens(event: any) {
  console.log("========== ENTRA TOKEN INSPECTION START ==========");

  const providerData =
    event.context?.auth?.provider?.data;

  if (!providerData) {
    console.log("❌ No provider data found");
    return;
  }

  console.log(
    "Provider data keys:",
    Object.keys(providerData)
  );


  // Inspect ID token
  const idToken = providerData.idToken;

  console.log("----- ID TOKEN -----");
  console.log(
    "idToken type:",
    typeof idToken
  );

  console.log(
    "idToken keys:",
    idToken && typeof idToken === "object"
      ? Object.keys(idToken)
      : "not object"
  );

  if (idToken?.claims) {
    console.log(
      "ID token claims keys:",
      Object.keys(idToken.claims)
    );

    console.log(
      "Sample claims:",
      JSON.stringify(
        {
          name: idToken.claims.name,
          email: idToken.claims.email,
          preferred_username:
            idToken.claims.preferred_username,
          oid: idToken.claims.oid,
        },
        null,
        2
      )
    );
  }


  // Inspect access token
  const accessToken = providerData.accessToken;

  console.log("----- ACCESS TOKEN -----");

  console.log(
    "accessToken type:",
    typeof accessToken
  );

  console.log(
    "accessToken keys:",
    accessToken &&
      typeof accessToken === "object"
      ? Object.keys(accessToken)
      : "not object"
  );

  console.log(
    "accessToken JSON:",
    JSON.stringify(accessToken, null, 2)
  );


  console.log("========== ENTRA TOKEN INSPECTION END ==========");
}
