import {
  WorkflowSettings,
  WorkflowTrigger,
} from "@kinde/infrastructure";

export const workflowSettings: WorkflowSettings = {
  id: "inspectEntraAccessToken",
  name: "InspectEntraAccessToken",
  failurePolicy: {
    action: "stop",
  },
  trigger: WorkflowTrigger.PostAuthentication,
  bindings: {
    "kinde.env": {},
    "url": {},
  },
};

export default async function inspectEntraAccessToken(event: any) {
  console.log("========== TOKEN INSPECTION START ==========");

  const providerData =
    event.context?.auth?.provider?.data;

  if (!providerData) {
    console.log("❌ No provider data");
    return;
  }

  console.log(
    "Provider data keys:",
    Object.keys(providerData)
  );

  const accessToken = providerData.accessToken;

  console.log(
    "accessToken type:",
    typeof accessToken
  );

  console.log(
    "accessToken value keys:",
    typeof accessToken === "object"
      ? Object.keys(accessToken)
      : "not object"
  );

  console.log(
    "accessToken value:",
    JSON.stringify(accessToken, null, 2)
  );

  console.log("========== TOKEN INSPECTION END ==========");
}
