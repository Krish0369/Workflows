import {
  WorkflowSettings,
  WorkflowTrigger,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "testEntraGraphAccess",
  name: "TestEntraGraphAccess",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "url": {},
  },
};

export default async function testEntraGraphAccess(event: any) {
  console.log("========== ENTRA GRAPH TEST START ==========");

  const provider = event.context?.auth?.provider;

  console.log("Provider:", provider?.provider);
  console.log("Protocol:", provider?.protocol);

  const accessToken = provider?.data?.accessToken;

  if (!accessToken) {
    console.log("❌ No accessToken found in provider data");
    return;
  }

  console.log("✅ accessToken found");

  // Decode token payload for debugging
  try {
    const payload = accessToken.split(".")[1];

    const decoded = JSON.parse(
      Buffer.from(payload, "base64").toString("utf8")
    );

    console.log("----- TOKEN DETAILS -----");
    console.log("Audience:", decoded.aud);
    console.log("Scopes:", decoded.scp);
    console.log("Roles:", decoded.roles);
    console.log("Issuer:", decoded.iss);
    console.log("-------------------------");

  } catch (error) {
    console.log("⚠️ Unable to decode access token");
  }


  console.log("Calling Microsoft Graph /me endpoint...");

  try {
    const response = await fetch(
      "https://graph.microsoft.com/v1.0/me",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      }
    );

    console.log("Graph HTTP status:", response.status);

    const result = await response.json();

    if (!response.ok) {
      console.log("❌ Graph API Error:");
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    console.log("✅ Graph API Success");

    console.log(
      JSON.stringify(
        {
          id: result.id,
          displayName: result.displayName,
          userPrincipalName: result.userPrincipalName,
          mail: result.mail,
        },
        null,
        2
      )
    );

  } catch (error) {
    console.log("❌ Graph request failed:");
    console.log(error);
  }

  console.log("========== ENTRA GRAPH TEST END ==========");
}
