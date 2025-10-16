/**
 * Kinde Workflow: Map Entra ID OAuth2 Claims to Kinde User Properties
 * 
 * This workflow triggers after user authentication and maps claims from 
 * Microsoft Entra ID OAuth2 tokens to Kinde user properties.
 * 
 * Trigger: user:post_authentication
 */

export const workflowSettings = {
  id: "mapEntraIdClaims",
  trigger: "user:post_authentication",
};

/**
 * Main workflow function
 */
export default async function mapEntraIdClaimsWorkflow({ request, context }) {
  const { event_type, authentication, user, application, is_new_user } = request;
  
  // === Updated authentication handling ===
  if (!authentication){
    console.log('No authentication object, skipping claims mapping');
    return;
  }
  const connectionMethod = authentication.connection_method;
  const connectionName = authentication.connection_name?.toLowerCase() || '';

  // If it's OAuth2
  if (authentication?.connection_id || connectionMethod === 'oauth2') {
    console.log('Processing OAuth2 authentication...');
  }

  // Else if it's Entra ID but not OAuth2
  else if (
    connectionName.includes('microsoft') ||
    connectionName.includes('entra') ||
    connectionName.includes('azure')
  ) {
    console.log('Processing Entra ID connection (non-OAuth2)');
  }

  // Anything else
  else {
    console.log('Unsupported authentication method, skipping claims mapping');
    return;
  }

  // Continue with the claim mapping process
  console.log(`Processing Entra ID claims for user: ${user.id}`);
  console.log(`Is new user: ${is_new_user}`);

  // Extract claims from the authentication object
  const userProfile = authentication.user_profile || {};
  const claims = userProfile.claims || userProfile;

  // Map of Entra ID claims to Kinde property keys
  const claimMappings = {
    'given_name': 'kp_usr_first_name',
    'family_name': 'kp_usr_last_name',
    'email': 'kp_usr_email',
    'name': 'kp_usr_display_name',
    'preferred_username': 'kp_usr_username',
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

  // Prepare properties to update
  const propertiesToUpdate = {};

  // Map each claim to its corresponding Kinde property
  for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
    const claimValue = claims[claimName];
    
    if (claimValue !== undefined && claimValue !== null && claimValue !== '') {
      if (Array.isArray(claimValue)) {
        propertiesToUpdate[propertyKey] = claimValue.join(', ');
      } else {
        propertiesToUpdate[propertyKey] = String(claimValue);
      }
      console.log(`Mapping claim ${claimName} -> ${propertyKey}: ${propertiesToUpdate[propertyKey]}`);
    }
  }

  // Update user properties if there are any to update
  if (Object.keys(propertiesToUpdate).length > 0) {
    try {
      await context.api.users.updateUserProperties({
        userId: user.id,
        properties: propertiesToUpdate
      });
      console.log(`Successfully updated ${Object.keys(propertiesToUpdate).length} properties for user ${user.id}`);
    } catch (error) {
      console.error('Error updating user properties:', error);
      throw error;
    }
  } else {
    console.log('No properties to update');
  }

  // Handle groups claim if present (for RBAC)
  if (claims.groups && Array.isArray(claims.groups)) {
    console.log(`User has ${claims.groups.length} groups from Entra ID`);
    try {
      await context.api.users.updateUserProperties({
        userId: user.id,
        properties: {
          'entra_groups': claims.groups.join(', ')
        }
      });
      console.log(`Updated Entra ID groups for user ${user.id}`);
    } catch (error) {
      console.error('Error updating groups:', error);
    }
  }

  // Store the last sync timestamp
  try {
    await context.api.users.updateUserProperties({
      userId: user.id,
      properties: {
        'entra_last_sync': new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error updating last sync timestamp:', error);
  }

  console.log(`Completed Entra ID claims mapping for user ${user.id}`);
}
