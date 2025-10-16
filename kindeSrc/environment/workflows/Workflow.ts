/**
 * Kinde Workflow: Map Entra ID OAuth2/OIDC Claims to Kinde User Properties
 *
 * Trigger: user:post_authentication
 * Purpose: Map Microsoft Entra ID claims to Kinde user properties,
 *          including username, email, display name, and optional groups.
 */

export const workflowSettings = {
  id: "mapEntraIdClaims",
  trigger: "user:post_authentication",
};

export default async function mapEntraIdClaimsWorkflow({ request, context }) {
  const { authentication, user, is_new_user, context: eventContext } = request;

  // --- Step 1: Check protocol first to avoid crashes ---
  const protocol = eventContext?.auth?.provider?.protocol;
  if (!protocol) {
    console.log('No protocol detected — skipping claims mapping');
    return;
  }

  if (protocol === 'saml') {
    console.log('SAML login detected — skipping OAuth2 claim mapping');
    return;
  }

  if (protocol !== 'oidc' && protocol !== 'oauth2') {
    console.log(`Unsupported protocol (${protocol}) — skipping claims mapping`);
    return;
  }

  // --- Step 2: Ensure authentication object exists ---
  if (!authentication) {
    console.log('No authentication object found for OAuth2/OIDC login — skipping');
    return;
  }

  // --- Step 3: Extract connection info safely ---
  const connectionMethod = authentication.connection_method?.toLowerCase() || '';
  const connectionName = authentication.connection_name?.toLowerCase() || '';

  if (
    connectionMethod !== 'oauth2' &&
    connectionMethod !== 'oidc' &&
    !connectionName.includes('microsoft') &&
    !connectionName.includes('entra') &&
    !connectionName.includes('azure')
  ) {
    console.log('Connection is not Entra/Microsoft OAuth2/OIDC — skipping');
    return;
  }

  console.log(`Processing Entra ID claims for user: ${user.id}`);
  console.log(`Is new user: ${is_new_user}`);

  // --- Step 4: Extract claims safely ---
  const userProfile = authentication.user_profile || {};
  const claims = userProfile.claims || userProfile;

  // --- Step 5: Map claims to Kinde properties ---
  const claimMappings: Record<string, string> = {
    'given_name': 'kp_usr_first_name',
    'family_name': 'kp_usr_last_name',
    'email': 'kp_usr_email',
    'name': 'kp_usr_display_name',
    'preferred_username': 'kp_usr_username', // maps username
    'oid': 'entra_object_id',
    'tid': 'entra_tenant_id',
    'upn': 'entra_upn',
    'unique_name': 'entra_unique_name',
    'jobTitle': 'job_title',
    'department': 'department',
    'officeLocation': 'office_location',
    'mobilePhone': 'mobile_phone',
    'businessPhones': 'business_phones',
    'city': 'city',
    'country': 'country',
    'postalCode': 'postal_code',
    'state': 'state',
    'streetAddress': 'street_address',
    'companyName': 'company_name',
    'employeeId': 'employee_id',
  };

  const propertiesToUpdate: Record<string, string> = {};

  for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
    const claimValue = claims[claimName];
    if (claimValue !== undefined && claimValue !== null && claimValue !== '') {
      propertiesToUpdate[propertyKey] = Array.isArray(claimValue)
        ? claimValue.join(', ')
        : String(claimValue);

      console.log(`Mapping claim ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`);
    }
  }

  // --- Step 6: Update user properties if any ---
  if (Object.keys(propertiesToUpdate).length > 0) {
    try {
      await context.api.users.updateUserProperties({
        userId: user.id,
        properties: propertiesToUpdate,
      });
      console.log(`Successfully updated ${Object.keys(propertiesToUpdate).length} properties for user ${user.id}`);
    } catch (error) {
      console.error('Error updating user properties:', error);
      throw error;
    }
  } else {
    console.log('No properties to update');
  }

  // --- Step 7: Handle groups claim (optional) ---
  if (claims.groups && Array.isArray(claims.groups)) {
    try {
      await context.api.users.updateUserProperties({
        userId: user.id,
        properties: {
          'entra_groups': claims.groups.join(', '),
        },
      });
      console.log(`Updated Entra ID groups for user ${user.id}`);
    } catch (error) {
      console.error('Error updating groups:', error);
    }
  }

  // --- Step 8: Store last sync timestamp ---
  try {
    await context.api.users.updateUserProperties({
      userId: user.id,
      properties: {
        'entra_last_sync': new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('Error updating last sync timestamp:', error);
  }

  console.log(`Completed Entra ID claims mapping for user ${user.id}`);
}
