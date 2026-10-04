from google.oauth2 import service_account
from google.cloud import storage, bigquery, compute_v1, logging_v2, dataproc_v1, resourcemanager_v3
from googleapiclient import discovery


def initialize_gcp_clients(credentials):
    if not isinstance(credentials, dict):
        raise ValueError("Invalid GCP Service Account JSON structure.")

    if not credentials.get("project_id") or not credentials.get("client_email") or not credentials.get("private_key"):
        raise ValueError("Invalid GCP Service Account JSON structure: missing project_id, client_email or private_key.")

    project_id = credentials["project_id"]

    try:
        scoped_creds = service_account.Credentials.from_service_account_info(
            credentials,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

        storage_client = storage.Client(project=project_id, credentials=scoped_creds)
        bigquery_client = bigquery.Client(project=project_id, credentials=scoped_creds)

        # Google API discovery client for APIs like Cloud SQL, IAM, DNS, KMS, etc.
        google_auth_credentials = scoped_creds

        return {
            "credentials": scoped_creds,
            "projectId": project_id,
            "storageClient": storage_client,
            "bigQueryClient": bigquery_client,
            "googleAuthClient": google_auth_credentials,
        }
    except Exception as e:
        print(f"Failed to initialize GCP Clients: {e}")
        raise ValueError("Failed to authenticate with provided JSON credentials.")
