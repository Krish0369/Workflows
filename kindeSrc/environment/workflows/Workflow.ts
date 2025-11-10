import { invalidateFormField } from "@kinde/infrastructure";

export const workflowSettings = {
  id: "onUsernameProvided",
  name: "Validate username",
  trigger: "user:new_username_provided",
  failurePolicy: {
    action: "stop",
  },
  bindings: {
    "kinde.widget": {},
  },
};

export default async function Workflow(event) {
  console.log("Workflow triggered: onUsernameProvided");
  console.log("Event received:", JSON.stringify(event, null, 2));

  const username = event?.context?.auth?.suppliedUsername;
  console.log("Supplied username:", username);

  if (username === "root") {
    console.log("Username 'root' is not allowed — denying authentication.");
    return { auth: { action: "deny" } };
  }

  console.log("Username validated successfully — continuing workflow.");
  return { auth: { action: "allow" } };
}
