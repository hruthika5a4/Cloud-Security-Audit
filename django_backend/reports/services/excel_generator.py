import io
import json
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Ordered from Major Core Services to Minor Auxiliary Services
CATEGORY_HIERARCHY = {
    "IAM": 1,
    "Compute": 2,
    "Storage": 3,
    "Cloud SQL": 4,
    "AWS RDS": 4,
    "Networking": 5,
    "Kubernetes": 6,
    "GKE": 6,
    "AWS EKS": 6,
    "Load Balancers": 7,
    "Serverless": 8,
    "BigQuery": 9,
    "KMS": 10,
    "Logging": 11,
    "Dataproc": 12,
    "Cloud DNS": 13,
    "API Keys": 14,
    "Essential Contacts": 15,
    "Deep Networking": 16,
    "General": 99
}

SEVERITY_HIERARCHY = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4
}


def get_category_from_id(finding_id):
    if not finding_id:
        return "General"
    parts = finding_id.split("-")
    prefix = parts[1].upper() if len(parts) > 1 else ""
    mapping = {
        "IAM": "IAM",
        "COMPUTE": "Compute",
        "VM": "Compute",
        "EC2": "Compute",
        "STORAGE": "Storage",
        "S3": "Storage",
        "SQL": "Cloud SQL",
        "RDS": "AWS RDS",
        "NET": "Networking",
        "DNS": "Cloud DNS",
        "FIREWALL": "Networking",
        "FW": "Networking",
        "GKE": "Kubernetes",
        "EKS": "AWS EKS",
        "LB": "Load Balancers",
        "ELB": "Load Balancers",
        "CLOUDRUN": "Serverless",
        "FUNCTION": "Serverless",
        "SERVERLESS": "Serverless",
        "LAMBDA": "Serverless",
        "BQ": "BigQuery",
        "BIGQUERY": "BigQuery",
        "KMS": "KMS",
        "LOG": "Logging",
        "OBS": "Logging",
        "MONITOR": "Logging",
        "DATAPROC": "Dataproc",
        "APIKEY": "API Keys",
        "ESSENTIAL": "Essential Contacts",
    }
    return mapping.get(prefix, "General")


CHECKPOINT_DEFINITIONS = [
    # 1. IAM
    {"prefix": "IAM-USER-OWNER", "name": "IAM User with Owner / Primitive Roles", "rank": 1},
    {"prefix": "IAM-SA-ADMIN", "name": "Service Account with Admin Privileges", "rank": 2},
    {"prefix": "IAM-PROJECT-TOKEN", "name": "Service Account Token Creator & User Impersonation", "rank": 3},
    {"prefix": "IAM-KMS-SOD", "name": "Separation of Duties: KMS Cryptographic Roles", "rank": 4},
    {"prefix": "IAM-NET-SOD", "name": "Separation of Duties: Network Admin Roles", "rank": 5},
    {"prefix": "IAM-USER-KEY", "name": "User-Managed Service Account Keys", "rank": 6},
    {"prefix": "IAM-KEY-ROTATION", "name": "Service Account Key Rotation (90 Days)", "rank": 7},
    {"prefix": "IAM-USER-KEYS", "name": "IAM Access Keys & MFA Policy", "rank": 1},

    # 2. Compute Engine & EC2
    {"prefix": "VM-PUBLIC-IP", "name": "Public IP & Direct Internet Exposure", "rank": 1},
    {"prefix": "EC2-PUBLIC-IP", "name": "Public IP & Direct Internet Exposure", "rank": 1},
    {"prefix": "VM-PROJ-SSH", "name": "Project-Wide SSH Key Blocking", "rank": 2},
    {"prefix": "VM-INST-SSH", "name": "Instance-Level SSH Key Blocking", "rank": 3},
    {"prefix": "VM-PROJ-OSLOGIN", "name": "Centralized OS Login Policy (Project Level)", "rank": 4},
    {"prefix": "VM-INST-OSLOGIN", "name": "Centralized OS Login Policy (Instance Level)", "rank": 5},
    {"prefix": "VM-DEF-SA-FULL", "name": "Default Service Account Full API Access Scope", "rank": 6},
    {"prefix": "VM-DEF-SA", "name": "Default Compute Service Account Usage", "rank": 7},
    {"prefix": "VM-IP-FWD", "name": "IP Forwarding & Packet Routing", "rank": 8},
    {"prefix": "VM-SHIELDED", "name": "Shielded VM (vTPM & Integrity Monitoring)", "rank": 9},
    {"prefix": "VM-SERIAL", "name": "Serial Port Console Connection", "rank": 10},
    {"prefix": "VM-DISK-CMEK", "name": "Customer-Managed Encryption Keys (CMEK Disk)", "rank": 11},
    {"prefix": "VM-CONFIDENTIAL", "name": "Confidential Computing (Memory Encryption)", "rank": 12},
    {"prefix": "VM-DEL-PROT", "name": "VM Deletion Protection", "rank": 13},
    {"prefix": "VM-PREEMPT", "name": "Preemptible / Spot Instance Resilience", "rank": 14},

    # 3. Cloud Storage & S3
    {"prefix": "STORAGE-PUBLIC", "name": "Public Access & Anonymous Bucket Exposure", "rank": 1},
    {"prefix": "S3-PUBLIC-BLOCK", "name": "Public Access & S3 Block Policy", "rank": 1},
    {"prefix": "STORAGE-PAP", "name": "Public Access Prevention (PAP Enforcement)", "rank": 2},
    {"prefix": "STORAGE-UBLA", "name": "Uniform Bucket-Level Access (UBLA)", "rank": 3},
    {"prefix": "STORAGE-CMEK", "name": "Customer-Managed Encryption Keys (CMEK Storage)", "rank": 4},
    {"prefix": "STORAGE-VERS", "name": "Object Versioning & Anti-Ransomware", "rank": 5},
    {"prefix": "STORAGE-LOG", "name": "Storage Access & Audit Logging", "rank": 6},

    # 4. Databases (Cloud SQL & RDS)
    {"prefix": "SQL-PUBLIC", "name": "Public IP & Internet Exposure", "rank": 1},
    {"prefix": "SQL-OPEN", "name": "Open Ingress Network (0.0.0.0/0 Authorized)", "rank": 2},
    {"prefix": "RDS-PUBLIC-ACCESS", "name": "Publicly Accessible RDS Database", "rank": 1},
    {"prefix": "SQL-SSL", "name": "Enforce SSL/TLS In-Transit Encryption", "rank": 3},
    {"prefix": "SQL-BACKUP", "name": "Automated Daily Database Backups", "rank": 4},
    {"prefix": "SQL-PITR", "name": "Point-In-Time Recovery & Binary Logging", "rank": 5},
    {"prefix": "SQL-MY-FLAG-INFILE", "name": "MySQL Flag: local_infile (File Injection Prevention)", "rank": 6},
    {"prefix": "SQL-MY-FLAG-SHOWDB", "name": "MySQL Flag: skip_show_database (Schema Privacy)", "rank": 7},
    {"prefix": "SQL-PG-FLAG", "name": "PostgreSQL Security & Logging Flags", "rank": 8},
    {"prefix": "SQL-MS-FLAG-CHAIN", "name": "SQL Server Flag: Cross-DB Ownership Chaining", "rank": 9},
    {"prefix": "SQL-MS-FLAG-AUTH", "name": "SQL Server Flag: Contained Database Authentication", "rank": 10},

    # 5. Networking & Firewalls
    {"prefix": "FW-OPEN-SSH", "name": "Firewall Rule: Unrestricted Ingress Port 22 (SSH)", "rank": 1},
    {"prefix": "FW-OPEN-RDP", "name": "Firewall Rule: Unrestricted Ingress Port 3389 (RDP)", "rank": 2},
    {"prefix": "NET-PUBLIC-SSH", "name": "Open SSH Access (0.0.0.0/0 Port 22)", "rank": 1},
    {"prefix": "NET-PUBLIC-RDP", "name": "Open RDP Access (0.0.0.0/0 Port 3389)", "rank": 2},
    {"prefix": "FW-OPEN-DB", "name": "Firewall Rule: Unrestricted Database Ingress Ports", "rank": 3},
    {"prefix": "NET-DEFAULT", "name": "Default VPC Network Security Posture", "rank": 4},
    {"prefix": "NET-LEGACY", "name": "Legacy Network Usage", "rank": 5},
    {"prefix": "NET-FLOWLOGS", "name": "Subnet VPC Flow Logs Telemetry", "rank": 6},
    {"prefix": "NET-FLOW-LOGS", "name": "Subnet VPC Flow Logs Telemetry", "rank": 6},
    {"prefix": "NET-PGA", "name": "Private Google Access (PGA)", "rank": 7},
    {"prefix": "NET-LBLOG", "name": "Load Balancer Logging & Ingress Metrics", "rank": 8},

    # 6. Kubernetes (GKE & EKS)
    {"prefix": "GKE-PUBLIC-ENDPOINT-RESTRICTED", "name": "Kubernetes Master Public Authorized Networks", "rank": 1},
    {"prefix": "GKE-PUBLIC-ENDPOINT", "name": "Kubernetes Master Private Endpoint", "rank": 2},
    {"prefix": "EKS-PUBLIC-ENDPOINT", "name": "EKS Cluster Public API Endpoint", "rank": 1},
    {"prefix": "GKE-WORKLOAD-IDENTITY", "name": "Workload Identity Federation", "rank": 3},
    {"prefix": "GKE-LEGACY-ABAC", "name": "Legacy ABAC Authorization", "rank": 4},
    {"prefix": "GKE-SHIELDED-NODES", "name": "Shielded GKE Nodes & Integrity Monitoring", "rank": 5},
    {"prefix": "GKE-BINARY-AUTH", "name": "Binary Authorization & Container Signing", "rank": 6},

    # 7. Load Balancers
    {"prefix": "LB-NO-SSL-POLICY", "name": "Modern SSL / TLS Security Policy", "rank": 1},
    {"prefix": "LB-NO-CLOUD-ARMOR", "name": "Cloud Armor WAF & Anti-DDoS Protection", "rank": 2},
    {"prefix": "LB-NO-HTTPS-REDIRECT", "name": "Enforce HTTPS Redirection", "rank": 3},
    {"prefix": "ELB-NO-DEL-PROTECTION", "name": "Load Balancer Deletion Protection", "rank": 4},

    # 8. Serverless
    {"prefix": "CLOUDRUN-PUBLIC-ACCESS", "name": "Cloud Run Unauthenticated Public Invocation", "rank": 1},
    {"prefix": "LAMBDA-PUBLIC-POLICY", "name": "Lambda Public / Wildcard Execution Policy", "rank": 1},
    {"prefix": "CLOUDRUN-ALLOW-ALL-INGRESS", "name": "Cloud Run Ingress Traffic Filtering", "rank": 2},
    {"prefix": "FUNCTION-ALLOW-ALL-INGRESS", "name": "Cloud Function Ingress Traffic Filtering", "rank": 3},
    {"prefix": "FUNCTION-DEFAULT-SA", "name": "Cloud Function Default Service Account", "rank": 4},

    # 9. BigQuery
    {"prefix": "BQ-DATASET-PUBLIC", "name": "Public / Anonymous Dataset Sharing (allUsers)", "rank": 1},
    {"prefix": "BQ-DATASET-ALLAUTH", "name": "Dataset allAuthenticatedUsers Permissive Sharing", "rank": 2},
    {"prefix": "BQ-DATASET-CMEK", "name": "Customer-Managed Encryption Keys (CMEK Dataset)", "rank": 3},

    # 10. KMS
    {"prefix": "KMS-ROTATION", "name": "Cryptographic Key Automated 90-Day Rotation", "rank": 1},
    {"prefix": "KMS-PROTECTION", "name": "Hardware Security Module (HSM) Protection Level", "rank": 2},
    {"prefix": "KMS-DESTROY", "name": "Key Scheduled Destruction Window Policy", "rank": 3},

    # 11. Logging & Monitoring
    {"prefix": "LOG-AUDIT", "name": "Default Data Access Audit Logging (All APIs)", "rank": 1},
    {"prefix": "LOG-BUCKET-LOCK", "name": "Audit Log Bucket Object Retention Lock", "rank": 2},
    {"prefix": "LOG-SINK", "name": "Centralized Security Export Log Sink", "rank": 3},
    {"prefix": "LOG-METRIC", "name": "CIS Benchmark Metric Alert & Notification Policy", "rank": 4},
    {"prefix": "OBS-ASSET", "name": "Cloud Asset Inventory Telemetry", "rank": 5},
    {"prefix": "OBS-TRANSPARENCY", "name": "Access Transparency Logging", "rank": 6},

    # 12. Auxiliary
    {"prefix": "DATAPROC-NO-ENCRYPTION", "name": "In-Transit & Internal IP Cluster Encryption", "rank": 1},
    {"prefix": "DATAPROC-NO-SHIELDED", "name": "Shielded Cluster Compute Nodes", "rank": 2},
    {"prefix": "DNS-NO-DNSSEC", "name": "DNSSEC Domain Security Extensions", "rank": 1},
    {"prefix": "DNS-RSASHA1", "name": "Strong DNSSEC Cryptographic Algorithm", "rank": 2},
    {"prefix": "APIKEY-NO-RESTRICTIONS", "name": "API Key Application & API Scope Restrictions", "rank": 1},
    {"prefix": "APIKEY-NO-ROTATION", "name": "API Key 90-Day Rotation Policy", "rank": 2},
    {"prefix": "ESSENTIAL-CONTACTS", "name": "Essential Contacts & Incident Notifications", "rank": 1}
]


def get_checkpoint_info(finding_id):
    if not finding_id:
        return {"name": "General Security Check", "rank": 99}
    upper_id = finding_id.upper()
    for defn in CHECKPOINT_DEFINITIONS:
        if defn["prefix"] in upper_id:
            return {"name": defn["name"], "rank": defn["rank"]}
    parts = finding_id.split("-")
    check_type = parts[2].upper() if len(parts) > 2 else "GENERAL"
    return {"name": f"Check: {check_type.title()}", "rank": 99}


def get_checkpoint_name(finding_id):
    return get_checkpoint_info(finding_id)["name"]


def generate_excel_report(scan_data, project_name):
    wb = Workbook()
    wb.properties.creator = "AuditScope"
    wb.properties.lastModifiedBy = "AuditScope"

    # --- 1. Summary Sheet ---
    ws_summary = wb.active
    ws_summary.title = "Summary"

    title_font = Font(name="Arial", size=16, bold=True, color="1E293B")
    label_font = Font(name="Arial", size=11, bold=True)
    light_fill = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")

    ws_summary.column_dimensions['A'].width = 32
    ws_summary.column_dimensions['B'].width = 42

    ws_summary.merge_cells('A1:B1')
    cell_a1 = ws_summary['A1']
    cell_a1.value = f"Security Audit Summary: {project_name}"
    cell_a1.font = title_font
    cell_a1.alignment = Alignment(horizontal="center", vertical="center")
    ws_summary.row_dimensions[1].height = 35

    ws_summary.append([])  # spacer

    # Parse findings
    vulnerabilities = scan_data.get("vulnerabilities")
    if vulnerabilities is None:
        findings_raw = scan_data.get("findings", [])
        if isinstance(findings_raw, str):
            try:
                vulnerabilities = json.loads(findings_raw)
            except Exception:
                vulnerabilities = []
        elif isinstance(findings_raw, list):
            vulnerabilities = findings_raw
        else:
            vulnerabilities = []

    scan_date_val = scan_data.get("createdAt")
    scan_date_str = str(scan_date_val) if scan_date_val else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    score_val = scan_data.get("score", 0)
    scanned_res = scan_data.get("scannedResources") or scan_data.get("scanned") or 0

    crit_cnt = scan_data.get("criticalCount") or len([v for v in vulnerabilities if v.get("severity") == "Critical"])
    high_cnt = scan_data.get("highCount") or len([v for v in vulnerabilities if v.get("severity") == "High"])
    med_cnt = scan_data.get("mediumCount") or len([v for v in vulnerabilities if v.get("severity") == "Medium"])
    low_cnt = (scan_data.get("lowCount") or 0) + len([v for v in vulnerabilities if v.get("severity") == "Low"])

    metrics = [
        ("Project Name", project_name),
        ("Scan Date", scan_date_str),
        ("Overall Security Score", f"{score_val}%"),
        ("Total Resources Scanned", scanned_res),
        ("", ""),
        ("Critical Vulnerabilities", crit_cnt),
        ("High Vulnerabilities", high_cnt),
        ("Medium Vulnerabilities", med_cnt),
        ("Low Vulnerabilities", low_cnt)
    ]

    for m_label, m_val in metrics:
        ws_summary.append([m_label, m_val])
        row_num = ws_summary.max_row
        if m_label:
            cell_label = ws_summary.cell(row=row_num, column=1)
            cell_label.font = label_font
            cell_label.fill = light_fill

    # --- 2. Service-Specific Sheets Ordered by Hierarchy ---
    findings_by_cat = {}
    for v in vulnerabilities:
        cat = get_category_from_id(v.get("id", ""))
        findings_by_cat.setdefault(cat, []).append(v)

    # Sort categories strictly by major to minor service rank
    sorted_categories = sorted(
        findings_by_cat.keys(),
        key=lambda cat: CATEGORY_HIERARCHY.get(cat, 99)
    )

    header_font = Font(name="Arial", size=11, bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    checkpoint_font = Font(name="Arial", size=11, bold=True, color="0F172A")
    checkpoint_fill = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")

    sev_colors = {
        "Critical": Font(name="Arial", size=10, bold=True, color="EF4444"),
        "High": Font(name="Arial", size=10, bold=True, color="F97316"),
        "Medium": Font(name="Arial", size=10, bold=True, color="EAB308"),
        "Low": Font(name="Arial", size=10, bold=True, color="22C55E"),
    }

    for cat_name in sorted_categories:
        cat_findings = findings_by_cat[cat_name]
        # Sort findings in this sheet by Severity (Critical -> High -> Medium -> Low)
        sorted_findings = sorted(
            cat_findings,
            key=lambda f: SEVERITY_HIERARCHY.get(f.get("severity", "Medium"), 9)
        )

        sheet_title = cat_name[:30]
        ws = wb.create_sheet(title=sheet_title)

        ws.column_dimensions['A'].width = 45
        ws.column_dimensions['B'].width = 30
        ws.column_dimensions['C'].width = 16
        ws.column_dimensions['D'].width = 60
        ws.column_dimensions['E'].width = 70

        ws.append(["Checkpoint / Resource", "ID", "Severity", "Issue Description", "Remediation Step"])
        for col_idx in range(1, 6):
            cell = ws.cell(row=1, column=col_idx)
            cell.font = header_font
            cell.fill = header_fill

        # Group by Checkpoint Name
        by_checkpoint = {}
        checkpoint_ranks = {}
        for f in sorted_findings:
            cp_info = get_checkpoint_info(f.get("id", ""))
            cp_name = cp_info["name"]
            if cp_name not in by_checkpoint:
                by_checkpoint[cp_name] = []
                checkpoint_ranks[cp_name] = cp_info["rank"]
            by_checkpoint[cp_name].append(f)

        sorted_cp_names = sorted(
            by_checkpoint.keys(),
            key=lambda name: (checkpoint_ranks.get(name, 99), name)
        )

        for cp_name in sorted_cp_names:
            cp_findings = sorted(
                by_checkpoint[cp_name],
                key=lambda f: (SEVERITY_HIERARCHY.get(f.get("severity", "Medium"), 9), f.get("id", ""))
            )
            ws.append([cp_name.upper(), "", "", "", ""])
            cp_row_idx = ws.max_row
            ws.merge_cells(start_row=cp_row_idx, start_column=1, end_row=cp_row_idx, end_column=5)
            cp_cell = ws.cell(row=cp_row_idx, column=1)
            cp_cell.font = checkpoint_font
            cp_cell.fill = checkpoint_fill

            for f in cp_findings:
                sev = f.get("severity", "Medium")
                ws.append([
                    f.get("resource", ""),
                    f.get("id", ""),
                    sev,
                    f.get("issue", ""),
                    f.get("remediation", "")
                ])
                data_row_idx = ws.max_row
                for c in range(1, 6):
                    ws.cell(row=data_row_idx, column=c).alignment = Alignment(vertical="top", wrap_text=True)

                sev_cell = ws.cell(row=data_row_idx, column=3)
                if sev in sev_colors:
                    sev_cell.font = sev_colors[sev]

            ws.append([])  # small spacer

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
