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

// export default async function Workflow(event: any) {
// console.log("Workflow triggered: onUsernameProvided");
// console.log("Event received:", JSON.stringify(event, null, 2));

// const banned = ["admin", "root", "test"];
// console.log("Banned usernames:", banned);

// const username = event?.context?.auth?.suppliedUsername;
// console.log("Extracted username:", username);

// if (banned.includes(username)) {
// console.log("Username is banned. Invalidating form field.");
// invalidateFormField("p_username", "This username is not allowed.");
// } else {
// console.log("Username is allowed.");
// }
// }

export default async function Workflow(event) {
  console.log("Workflow triggered: onUsernameProvided");
  console.log("Event received:", JSON.stringify(event, null, 2));

  const orgCode = event?.context?.organization?.code || event?.context?.organization?.id;
  console.log("User organization:", orgCode);

  // Only apply rule for org1
  if (orgCode !== "TestOrg") {
    console.log(orgcode,"Not TestOrg. Skipping username validation.");
    return;
  }

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

