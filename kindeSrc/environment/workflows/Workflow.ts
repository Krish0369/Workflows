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
  const username = event?.context?.auth?.suppliedUsername;
  if (username == "root") {
    return { auth: { action: "deny" } };
  }
}
