import {
  onUserTokenGeneratedEvent,
  WorkflowSettings,
  WorkflowTrigger,
  getEnvironmentVariable,
} from "@kinde/infrastructure";

// Workflow configuration
export const workflowSettings: WorkflowSettings = {
  id: "nonPersistentSessionWorkflow",
  name: "Non Persistent Session Workflow",
  trigger: WorkflowTrigger.UserTokenGeneration,
  bindings: {
    "kinde.accessToken": {},
    "kinde.ssoSession": {},
    "kinde.env": {},
  },
  failurePolicy: {
    action: "stop",
  },
};

export default async function NonPersistentSessionWorkflow(
  event: onUserTokenGeneratedEvent
) {
  try {
    const kinde = event.bindings?.kinde;
    const connectionId = event.context?.auth?.connectionId;

    if (!kinde) {
      console.warn("Bindings.kinde is undefined, skipping workflow");
      return;
    }

//    if (!kinde.ssoSession) {
 //     console.warn("SSO session object not available, skipping workflow");
 //     return;
  //  }

    if (!connectionId) {
      console.warn("Connection ID not found in event.context.auth, skipping workflow");
      return;
    }

    // Environment variable as per manager (no trimming)
    const nonPersistentConnectionIDs =
      getEnvironmentVariable("NON_PERSISTENT_SESSION_CONNECTION_IDS")?.value?.split(",") || [];

    console.log("Non-persistent connection IDs:", nonPersistentConnectionIDs);
    console.log("Current login connectionId:", connectionId);
    console.log("kinde.ssoSession object:", kinde.ssoSession);

    if (nonPersistentConnectionIDs.includes(connectionId)) {
      try {
        console.log("Matched connection, setting SSO session policy to non_persistent");
        kinde.ssoSession.setPolicy("non_persistent");
        console.log("Policy set successfully");
      } catch (err) {
        console.error("Error calling kinde.ssoSession.setPolicy:", err);
      }
    } else {
      console.log("No match, session remains persistent");
    }
  } catch (err) {
    console.error("Workflow caught unexpected error:", err);
  }
}
