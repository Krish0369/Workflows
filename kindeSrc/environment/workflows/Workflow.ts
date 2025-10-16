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
  
  // Only process OAuth2 connections from Entra ID (Microsoft)
  if (!authentication?.connection_id || authentication.connection_method !== 'oauth2') {
    console.log('Not an OAuth2 authentication, skipping claims mapping');
    return;
  }

  // Check if this is a Microsoft/Entra ID connection
  const connectionName = authentication.connection_name?.toLowerCase() || '';
  if (!connectionName.includes('microsoft') && !connectionName.includes('entra') && !connectionName.includes('azure')) {
    console.log(`Connection ${authentication.connection_name} is not a Microsoft/Entra ID connection, skipping`);
    return;
  }

  console.log(`Processing Entra ID OAuth2 claims for user: ${user.id}`);
  console.log(`Is new user: ${is_new_user}`);

  // Extract claims from the authentication object
  // Entra ID OAuth2 claims are typically in the authentication.user_profile or similar
  const userProfile = authentication.user_profile || {};
  const claims = userProfile.claims || userProfile;

  // Map of Entra ID claims to Kinde property keys
  // Adjust these mappings based on your actual Kinde properties
  const claimMappings = {
    // Standard Entra ID claims -> Kinde properties
    'given_name': 'kp_usr_first_name',
    'family_name': 'kp_usr_last_name',
    'email': 'kp_usr_email',
    'name': 'kp_usr_display_name',
    'preferred_username': 'kp_usr_username',
    'oid': 'entra_object_id',              // Custom property for Entra Object ID
    'tid': 'entra_tenant_id',              // Custom property for Tenant ID
    'upn': 'entra_upn',                    // User Principal Name
    'unique_name': 'entra_unique_name',    // Unique name
    'jobTitle': 'job_title',               // Custom property for job title
    'department': 'department',            // Custom property for department
    'officeLocation': 'office_location',   // Custom property for office location
    'mobilePhone': 'mobile_phone',         // Custom property for mobile phone
    'businessPhones': 'business_phones',   // Custom property for business phones
    'city': 'city',                        // Custom property for city
    'country': 'country',                  // Custom property for country
    'postalCode': 'postal_code',           // Custom property for postal code
    'state': 'state',                      // Custom property for state
    'streetAddress': 'street_address',     // Custom property for street address
    'companyName': 'company_name',         // Custom property for company name
    'employeeId': 'employee_id',           // Custom property for employee ID
  };

  // Prepare properties to update
  const propertiesToUpdate = {};

  // Map each claim to its corresponding Kinde property
  for (const [claimName, propertyKey] of Object.entries(claimMappings)) {
    const claimValue = claims[claimName];
    
    if (claimValue !== undefined && claimValue !== null && claimValue !== '') {
      // Handle array values (like businessPhones)
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
      // Use Kinde Management API to update user properties
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
    
    // You can map Entra ID groups to Kinde roles or permissions here
    // Example: sync groups as a property or map to Kinde roles
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
