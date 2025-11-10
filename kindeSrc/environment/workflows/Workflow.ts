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
  console.log("Triggering intentional workflow error...");
  throw new Error("Intentional test failure for workflow handling");
}
