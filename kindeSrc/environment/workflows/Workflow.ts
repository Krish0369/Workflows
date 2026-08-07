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

function decodeJwtPayload(token: string) {
  try {
    const payload = token.split(".")[1];

    if (!payload) {
      return null;
    }

    // JWT uses base64url
    const base64 = payload
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const decodedPayload = Buffer.from(
      base64,
      "base64"
    ).toString("utf8");

    return JSON.parse(decodedPayload);

  } catch (error) {
    console.log("JWT decode error:", String(error));
    return null;
  }
}

export default async function testEntraGraphAccess(event: any) {
  console.log("========== ENTRA GRAPH TEST START ==========");

  const accessToken =
    event.context?.auth?.provider?.data?.accessToken;

  if (!accessToken) {
    console.log("❌ No access token found");
    return;
  }

  console.log("✅ accessToken found");
  console.log(
    "Token length:",
    accessToken.length
  );

  const tokenPayload = decodeJwtPayload(accessToken);

  if (tokenPayload) {
    console.log("----- TOKEN CLAIMS -----");
    console.log("aud:", tokenPayload.aud);
    console.log("scp:", tokenPayload.scp);
    console.log("roles:", tokenPayload.roles);
    console.log("iss:", tokenPayload.iss);
    console.log("------------------------");
  } else {
    console.log("❌ Could not decode JWT payload");
  }


  console.log("Calling Graph...");

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

    console.log(
      "Graph status:",
      response.status
    );

    const body = await response.text();

    console.log(
      "Graph response:",
      body
    );

  } catch (error) {
    console.log(
      "Graph fetch exception:",
      JSON.stringify(error, null, 2)
    );
  }

  console.log("========== ENTRA GRAPH TEST END ==========");
}
