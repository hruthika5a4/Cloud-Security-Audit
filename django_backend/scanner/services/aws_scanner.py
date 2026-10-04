import json
import boto3
from botocore.exceptions import ClientError


def get_boto_session(credentials):
    region = credentials.get("region") or "us-east-1"
    return boto3.Session(
        aws_access_key_id=credentials.get("accessKeyId"),
        aws_secret_access_key=credentials.get("secretAccessKey"),
        region_name=region
    )


def audit_aws_iam(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")

        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        scanned_count = len(users)

        for user in users:
            user_name = user.get("UserName")
            keys_res = iam.list_access_keys(UserName=user_name)
            keys = keys_res.get("AccessKeyMetadata", [])
            if keys:
                findings.append({
                    "id": f"AWS-IAM-USER-KEYS-{user_name}",
                    "severity": "Medium",
                    "resource": f"IAM User ({user_name})",
                    "issue": "User has active long-term access keys. Temporary credentials (IAM Roles) are preferred.",
                    "remediation": "Rotate keys every 90 days or switch to IAM Roles with temporary security tokens."
                })
    except Exception as err:
        print(f"[AWS IAM] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_ec2(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        ec2 = session.client("ec2")

        # Instances
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    scanned_count += 1
                    instance_id = instance.get("InstanceId")
                    if instance.get("PublicIpAddress"):
                        findings.append({
                            "id": f"AWS-EC2-PUBLIC-IP-{instance_id}",
                            "severity": "High",
                            "resource": f"EC2 Instance ({instance_id})",
                            "issue": "Instance is assigned a public IP address and is reachable from the internet.",
                            "remediation": "Use a NAT Gateway or Elastic Load Balancer for egress/ingress instead of direct public IPs."
                        })

        # Security Groups
        sg_res = ec2.describe_security_groups()
        for sg in sg_res.get("SecurityGroups", []):
            sg_name = sg.get("GroupName")
            for perm in sg.get("IpPermissions", []):
                ip_ranges = perm.get("IpRanges", [])
                is_public = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)
                if is_public:
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    if from_port == 22 or (from_port and to_port and from_port <= 22 <= to_port):
                        findings.append({
                            "id": "AWS-NET-PUBLIC-SSH",
                            "severity": "Critical",
                            "resource": f"Security Group ({sg_name})",
                            "issue": "Inbound SSH (Port 22) is open to the entire internet (0.0.0.0/0).",
                            "remediation": "Restrict SSH access to specific trusted CIDR ranges or use AWS Systems Manager Session Manager."
                        })
                    if from_port == 3389 or (from_port and to_port and from_port <= 3389 <= to_port):
                        findings.append({
                            "id": "AWS-NET-PUBLIC-RDP",
                            "severity": "Critical",
                            "resource": f"Security Group ({sg_name})",
                            "issue": "Inbound RDP (Port 3389) is open to the entire internet (0.0.0.0/0).",
                            "remediation": "Restrict RDP access to trusted IPs or use a VPN/Bastion host."
                        })
    except Exception as err:
        print(f"[AWS EC2] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_s3(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        s3 = session.client("s3")
        buckets_res = s3.list_buckets()
        buckets = buckets_res.get("Buckets", [])
        scanned_count = len(buckets)

        for b in buckets:
            bucket_name = b.get("Name")
            try:
                s3.get_public_access_block(Bucket=bucket_name)
            except ClientError as err:
                error_code = err.response.get("Error", {}).get("Code")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "id": f"AWS-S3-PUBLIC-BLOCK-MISSING-{bucket_name}",
                        "severity": "High",
                        "resource": f"S3 Bucket ({bucket_name})",
                        "issue": "S3 Block Public Access is not configured for this bucket.",
                        "remediation": "Enable 'Block all public access' settings at the bucket or account level."
                    })
    except Exception as err:
        print(f"[AWS S3] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_rds(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                scanned_count += 1
                db_id = db.get("DBInstanceIdentifier")
                if db.get("PubliclyAccessible"):
                    findings.append({
                        "id": f"AWS-RDS-PUBLIC-ACCESS-{db_id}",
                        "severity": "Critical",
                        "resource": f"RDS Instance ({db_id})",
                        "issue": "RDS instance is publicly accessible from the internet.",
                        "remediation": "Modify the instance to disable 'Public Accessibility' and move it to a private subnet."
                    })
    except Exception as err:
        print(f"[AWS RDS] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_eks(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        eks = session.client("eks")
        clusters_res = eks.list_clusters()
        clusters = clusters_res.get("clusters", [])
        scanned_count = len(clusters)

        for name in clusters:
            try:
                cluster_data = eks.describe_cluster(name=name)
                cluster = cluster_data.get("cluster", {})
                vpc_config = cluster.get("resourcesVpcConfig", {})
                if vpc_config.get("endpointPublicAccess"):
                    findings.append({
                        "id": f"AWS-EKS-PUBLIC-ENDPOINT-{name}",
                        "severity": "High",
                        "resource": f"EKS Cluster ({name})",
                        "issue": "EKS cluster endpoint has public access enabled.",
                        "remediation": "Disable public access to the EKS endpoint or restrict it to authorized CIDR ranges."
                    })
            except Exception:
                pass
    except Exception as err:
        print(f"[AWS EKS] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_lb(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        elbv2 = session.client("elbv2")
        lbs_res = elbv2.describe_load_balancers()
        lbs = lbs_res.get("LoadBalancers", [])
        scanned_count = len(lbs)

        for lb in lbs:
            lb_arn = lb.get("LoadBalancerArn")
            lb_name = lb.get("LoadBalancerName")
            try:
                attr_res = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                attrs = attr_res.get("Attributes", [])
                del_prot = any(a.get("Key") == "deletion_protection.enabled" and a.get("Value") == "true" for a in attrs)
                if not del_prot:
                    findings.append({
                        "id": f"AWS-ELB-NO-DEL-PROTECTION-{lb_name}",
                        "severity": "Low",
                        "resource": f"Load Balancer ({lb_name})",
                        "issue": "Deletion protection is disabled for this load balancer.",
                        "remediation": "Enable deletion protection to prevent accidental removal of the load balancer."
                    })
            except Exception:
                pass
    except Exception as err:
        print(f"[AWS ELB] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}


def audit_aws_serverless(credentials):
    findings = []
    scanned_count = 0
    try:
        session = get_boto_session(credentials)
        lambda_client = session.client("lambda")
        apprunner_client = session.client("apprunner")

        # 1. Lambda Audit
        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                functions = page.get("Functions", [])
                scanned_count += len(functions)
                for fn in functions:
                    fn_name = fn.get("FunctionName")
                    try:
                        policy_res = lambda_client.get_policy(FunctionName=fn_name)
                        policy_str = policy_res.get("Policy", "{}")
                        policy = json.loads(policy_str)
                        statements = policy.get("Statement", [])
                        is_public = any(
                            s.get("Principal") == "*" or
                            (isinstance(s.get("Principal"), dict) and (s.get("Principal", {}).get("AWS") == "*" or s.get("Principal", {}).get("Service") == "*"))
                            for s in statements
                        )
                        if is_public:
                            findings.append({
                                "id": f"AWS-LAMBDA-PUBLIC-POLICY-{fn_name}",
                                "severity": "High",
                                "resource": f"Lambda Function ({fn_name})",
                                "issue": 'Lambda function has a resource-based policy that allows access from any principal ("*").',
                                "remediation": "Restrict the resource-based policy to specific AWS accounts or services."
                            })
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. App Runner Audit
        try:
            svc_res = apprunner_client.list_services()
            services = svc_res.get("ServiceSummaryList", [])
            scanned_count += len(services)
        except Exception:
            pass

    except Exception as err:
        print(f"[AWS Serverless] Error: {err}")
    return {"findings": findings, "scannedCount": scanned_count}
