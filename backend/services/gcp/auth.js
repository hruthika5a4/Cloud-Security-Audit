const { Storage } = require('@google-cloud/storage');
const compute = require('@google-cloud/compute');
const { BigQuery } = require('@google-cloud/bigquery');
const { google } = require('googleapis');

/**
 * Validates the raw JSON credentials and returns initialized GCP SDK clients.
 *
 * @param {Object} credentials - The parsed Service Account JSON object
 * @returns {Object} Instantiated SDK clients
 */
const initializeGcpClients = (credentials) => {
  if (!credentials || !credentials.project_id || !credentials.client_email || !credentials.private_key) {
    throw new Error("Invalid GCP Service Account JSON structure.");
  }

  const sdkConfig = {
    projectId: credentials.project_id,
    credentials: {
      client_email: credentials.client_email,
      private_key: credentials.private_key
    }
  };

  try {
    const storageClient = new Storage(sdkConfig);
    const computeClient = new compute.InstancesClient(sdkConfig);
    const networksClient = new compute.NetworksClient(sdkConfig);
    const firewallsClient = new compute.FirewallsClient(sdkConfig);
    const projectClient = new compute.ProjectsClient(sdkConfig);
    const subnetworksClient = new compute.SubnetworksClient(sdkConfig);
    const backendServicesClient = new compute.BackendServicesClient(sdkConfig);
    const bigQueryClient = new BigQuery(sdkConfig);

    // Some specific apis (like Cloud SQL Admin, IAM) are better accessed via googleapis
    const googleAuthClient = new google.auth.GoogleAuth({
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key
      },
      scopes: ['https://www.googleapis.com/auth/cloud-platform']
    });

    return {
      storageClient,
      computeClient,
      networksClient,
      firewallsClient,
      projectClient,
      subnetworksClient,
      backendServicesClient,
      bigQueryClient,
      googleAuthClient,
      projectId: credentials.project_id
    };
  } catch (error) {
    console.error("Failed to initialize GCP Clients:", error);
    throw new Error("Failed to authenticate with provided JSON credentials.");
  }
};

module.exports = {
  initializeGcpClients
};
