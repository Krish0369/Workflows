import {
	invalidateFormField
} from "@kinde/infrastructure";

export const workflowSettings = {
	id: "onUsernameProvided",
	name: 'Validate username',
	trigger: 'user:new_username_provided',
	failurePolicy: {
		action: "stop",
	},
	bindings: {
		"kinde.widget": {}, // Required for accessing the UI
	},
};

//export default async function Workflow(event: any) {
	//invalidateFormField('p_username', 'username format sucks, do better!')
//}
export default async function Workflow(event: any) {
  const banned = ["admin", "root", "test"];
  if (banned.includes(event.suppliedUsername)) {
    invalidateFormField("p_username", "This username is not allowed.");
  }
}
