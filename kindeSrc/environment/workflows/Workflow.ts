import {
  WorkflowSettings,
  WorkflowTrigger,
  invalidateFormField
} from "@kinde/infrastructure";


export const workflowSettings = {
  id: "validateUsername",
  name: "Username validation",
  trigger: "user:new_username_provided",
  failurePolicy: { action: "stop" },
  bindings: { "kinde.widget": {} },
};

export default async function Workflow(event) {
  const banned = ["admin", "root", "test"];
  if (banned.includes(event.suppliedUsername)) {
    invalidateFormField("p_username", "This username is not allowed.");
  }
}

