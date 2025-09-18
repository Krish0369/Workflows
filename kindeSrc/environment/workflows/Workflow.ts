import {
  onUserTokenGeneratedEvent,
  WorkflowSettings,
  WorkflowTrigger,
  accessTokenCustomClaims,
  getEnvironmentVariable,
} from "@kinde/infrastructure";


export const workflowSettings: WorkflowSettings = {
  id: "nonPersistentSessionWorkflow",
  name: "Non Persistent Session Workflow",
  trigger: WorkflowTrigger.UserTokenGeneration,
  bindings: {
    "kinde.accessToken": {},
    "kinde.env": {},
  },
  failurePolicy: {
    action: "stop",
  },
};

export default async function NonPersistentSessionWorkflow(
  event: onUserTokenGeneratedEvent
) {
  const { kinde } = event.bindings;

  const raw = getEnvironmentVariable("NON_PERSISTENT_SESSION_CONNECTION_IDS")?.value || "";
  const nonPersistentConnectionIDs = raw.split(",").map(id => id.trim()).filter(Boolean);

  console.log("nonPersistentConnectionIDs:", nonPersistentConnectionIDs);

  if (nonPersistentConnectionIDs.includes(event.context.auth.connectionId)) {
    console.log("Matched connection, setting sso session policy to non_persistent");
    kinde.ssoSession.setPolicy("non_persistent");
  }
}