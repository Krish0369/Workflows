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

export default async function Workflow(event: any) {
  console.log("Workflow triggered: onUsernameProvided");
  console.log("Event received:", JSON.stringify(event, null, 2));

  const banned = ["admin", "root", "test"];
  console.log("Banned usernames:", banned);

  const username = event?.context?.auth?.suppliedUsername;
  console.log("Extracted username:", username);

  if (banned.includes(username)) {
    console.log("Username is banned. Invalidating form field.");
    invalidateFormField("p_username", "This username is not allowed.");
  } else {
    console.log("Username is allowed.");
  }
}
