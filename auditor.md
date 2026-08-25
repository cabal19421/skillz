---
name: gcp-exfil-security-review
description: Use when the user asks for a Google Cloud / GCP security review, audit, or threat model with a data-exfiltration focus — including privilege-escalation and service-account impersonation chain analysis, lateral-movement and blast-radius mapping, organization-policy / VPC Service Controls / IAM allow + deny / Principal Access Boundary / Workload Identity Federation review, hybrid cloud-to-on-prem (interconnect, VPN, restricted VIP) exposure, service isolation design, or resource-hierarchy design. Not for AWS or Azure.
---

# GCP Exfiltration-Focused Security Review

## Operating contract

Evidence-based security review of a Google Cloud organization with hybrid connectivity to an on-prem
network. Output is findings and remediation code, not advice.

**The scoring rule that governs every judgement:** score each observation by how much it raises or
lowers the risk that CONFIDENTIAL data leaves an authorized boundary. A control that does not move
that number is not a finding, however untidy; a misconfiguration that moves it is a finding even when
a compliance framework calls it informational.

**The hard output rule:** no finding ships without all three of — (1) a **named resource or scope**
(`projects/data-prod-01`, `organizations/NNNNNNNNNNNN`, a specific bucket / dataset / SA / perimeter
/ firewall rule / pool); (2) a **named control identifier** (`constraints/...`, `roles/...`,
`service.resource.verb`, a VPC-SC rule field, a firewall rule priority, an audit `logType`); (3) a
**remediation snippet** — `gcloud` or Terraform, runnable after substitution. Missing any of the
three, you have an evidence request, not a finding: emit it as an evidence request.

---

## Contents

- [Operating contract](#operating-contract)
- [1. Threat framing — the decision rules you apply](#1-threat-framing--the-decision-rules-you-apply)
- [2. Intake — the artifacts to request](#2-intake--the-artifacts-to-request)
- [3. Phased workflow](#3-phased-workflow)
- [4. Threat model](#4-threat-model)
- [5. Control assessment catalog — the reviewer's checklist](#5-control-assessment-catalog--the-reviewers-checklist)
  - [5.1 Organization Policy](#51-organization-policy) · [5.2 VPC Firewall Policy](#52-vpc-firewall-policy) · [5.3 VPC Service Controls](#53-vpc-service-controls) · [5.4 IAM (allow policies)](#54-iam-allow-policies) · [5.5 IAM Deny](#55-iam-deny) · [5.6 Private Service Connect](#56-private-service-connect) · [5.7 Principal Access Boundary](#57-principal-access-boundary) · [5.8 Workload Identity Federation](#58-workload-identity-federation) · [5.9 Identity](#59-identity) · [5.10 Access](#510-access) · [5.11 Break-glass](#511-break-glass) · [5.12 Audit logging and detection coverage](#512-audit-logging-and-detection-coverage)
- [6. Privilege escalation, the privilege graph, and reachability](#6-privilege-escalation-the-privilege-graph-and-reachability)
  - [6.1 Build the privilege graph](#61-build-the-privilege-graph) · [6.2 Escalation primitive hunt list](#62-escalation-primitive-hunt-list) · [6.3 Chain output format and ranking](#63-chain-output-format-and-ranking) · [6.4 Escalation-primitive reference table](#64-escalation-primitive-reference-table) · [6.5 Graph-extraction helper](#65-graph-extraction-helper)
- [7. Lateral movement and traversal](#7-lateral-movement-and-traversal)
  - [7.0 Firewall evaluation order](#70-firewall-evaluation-order--read-before-scoring-any-network-hop) · [7.1 Cloud → cloud (east-west)](#71-cloud--cloud-east-west) · [7.2 Cloud → on-prem](#72-cloud--on-prem-into-the-soft-interior) · [7.3 On-prem → cloud](#73-on-prem--cloud-pivot-inward) · [7.4 The traversal map, joined to the privilege graph](#74-output-artifact-the-traversal-map-and-joining-it-to-the-privilege-graph)
- [8. Service isolation — enforce by default](#8-service-isolation--enforce-by-default)
  - [8.1 Identity isolation](#81-identity-isolation) · [8.2 Resource and project isolation](#82-resource-and-project-isolation) · [8.3 Network isolation](#83-network-isolation) · [8.4 Service-to-service authentication](#84-service-to-service-authentication) · [8.5 Data-plane isolation](#85-data-plane-isolation) · [8.6 Boundary isolation](#86-boundary-isolation) · [8.7 Enforcement plumbing — all three layers](#87-enforcement-plumbing--every-control-all-three-layers)
- [9. Organization hierarchy — assessment and target design](#9-organization-hierarchy--assessment-and-target-design)
- [10. Extensibility — the supplementary requirements file](#10-extensibility--the-supplementary-requirements-file)
- [11. Output specification, severity rubric, report template, and the anti-fluff gate](#11-output-specification-severity-rubric-report-template-and-the-anti-fluff-gate)
  - [11.1 Severity rubric](#111-severity-rubric) · [11.2 Finding format](#112-finding-format) · [11.3 Attack-chain findings section format](#113-attack-chain-findings-section-format) · [11.4 Report structure and emission](#114-report-structure-and-emission) · [11.5 Remediation roadmap](#115-remediation-roadmap) · [11.6 Anti-fluff enforcement gate](#116-anti-fluff-enforcement-gate)
- [Verify against current docs](#verify-against-current-docs)
- [Skill self-check — run before emitting](#skill-self-check--run-before-emitting)

---

## 1. Threat framing — the decision rules you apply

These are rules, not background. Apply them literally.

They are numbered `TF1`–`TF6` ("threat framing"). Do not confuse them with the log filters `F1`–`F19`
in §4.7.3, which are a different, backticked namespace: a bare `TF3` is this section's classification
rule, a backticked `` `F3` `` is the federated-token-exchange log filter.

### TF1 — Exfil-first scoring

For every control you assess, write the answer to: *"Which specific sequence of API calls does this
stop, and whose data does that sequence move?"* If you cannot name the sequence, the control is out
of scope for this review — drop it rather than padding the report.

Rank two findings against each other by (data tier reached) × (how cheap the attacker's starting
position is) × (how many principals hold the starting position). Hop count is not a ranking input.

### TF2 — Chain-first, never control-first

**A perfect perimeter around a reachable admin identity is not a control.** Before you credit any
boundary control, compute whether an adversary can arrive *inside* it by becoming an identity the
boundary trusts. Concretely:

1. For every perimeter, access level, firewall policy, or ingress rule you are about to score as
   effective, list the principals it admits.
2. For each admitted principal, ask the privilege graph (see §6) which principals can reach it in ≤ 3 hops.
3. If any low-value starting position reaches an admitted principal, the boundary's score is capped
   at the score of the weakest step in that chain. Report the chain, not the boundary.

A control that only blocks the *last* hop of a chain whose earlier hops are unimpeded is reported as
"single-point control on a completed chain", not as "control present".

### TF3 — Data classification is a first-class input

| Tier | What it means here | Required boundary controls | Severity floor for a finding at this tier |
|---|---|---|---|
| `PUBLIC` | Freely shareable; disclosure is not an incident. | None beyond integrity/availability. A `allUsers` binding is *expected*, not a finding. | Low. Escalate only if the resource is mislabeled (contains non-PUBLIC data) — then re-tier and re-score. |
| `INTERNAL` | Internal use, low sensitivity. | Inside an **enforced** perimeter or explicitly exempted with a written reason; no `allUsers` / `allAuthenticatedUsers`; domain-restricted sharing enforced. | Medium. Raise to the CONFIDENTIAL floor if the same principal set also reaches a CONFIDENTIAL store. |
| `CONFIDENTIAL` | Business-sensitive, **broadly accessible inside the org**, not Need-To-Know. **This is the priority optimization target.** | Enforced perimeter with a restricted-services list covering every data API in the project; default-deny egress; Data Access (`DATA_READ`) audit logs on; PAB on every non-human principal that can read it; no project-level `roles/iam.serviceAccountTokenCreator` / `roles/iam.serviceAccountUser`. | High. **Critical** when a complete chain from a realistic starting position terminates here **and** no step of that chain writes an audit-log entry that is currently enabled. |
| `NTK` | Compartmentalized, restricted-access. Fewer principals, tighter perimeter, lower volume. | Dedicated project(s); separate stricter perimeter, bridged only where a documented flow exists; per-compartment CMEK key with key IAM bound only to that compartment's SA; ingress rules naming identities, not just access levels. | High. **Critical** for any path that crosses a compartment boundary or that a principal outside the compartment's authorized set can execute. |

**Why CONFIDENTIAL, not NTK, is the optimization target:** its defining property is broad internal
reach. Every internal principal is therefore a candidate starting position, so the count of viable
starting positions — the multiplier in TF1 — is maximal at this tier, and the data volume behind each
one is large. NTK has tighter access and fewer principals; it is the higher *per-record* loss but the
smaller *attack surface*. When a control decision trades one against the other, protect CONFIDENTIAL.

### TF4 — Unclassified data-bearing resources are findings in their own right

Every data-bearing resource carries an explicit classification as a label or a Resource Manager tag.
A resource without one is a finding with ID prefix **`DC-`**, independent of whether its access
posture is otherwise sound — you cannot score exfil risk for data whose tier is unknown.

Treat these asset classes as data-bearing (asset-type strings take the `SERVICE.googleapis.com/Type`
form; confirm each against the `--asset-types` values your CAI export actually returns — *verify
against current docs*): Cloud Storage buckets, BigQuery datasets and tables, Pub/Sub topics and
subscriptions, Cloud SQL instances, Spanner databases, Firestore/Datastore databases, Bigtable
instances, Filestore instances, Secret Manager secrets, Artifact Registry repositories, persistent
disks and disk snapshots, and Cloud Logging buckets whose sink filter includes
`cloudaudit.googleapis.com%2Fdata_access`.

`DC-` severity procedure: floor **Medium**. Raise to **High** when the unclassified resource also
(a) sits in no enforced perimeter, or (b) carries a binding to `allUsers` / `allAuthenticatedUsers` /
a principal outside the org's domains, or (c) is readable by a principal reachable in ≤ 2 hops from
any adversary starting position. Remediation for every `DC-` finding names the label key the org
already uses (read it off the resources that *are* labeled) and gives the `gcloud`/Terraform snippet
that sets it.

### TF5 — The on-prem interior is an assume-breach zone (the "turtle")

The on-prem environment is hermetic to the public internet — hard shell — and largely flat inside —
soft interior. Adopt an **assume-breach premise for the interior**: model every analysis as though an
adversary already holds a foothold on one interior host, and do not require a proof of initial
access to justify that premise. Three consequences you apply as rules:

1. **CONFIDENTIAL data that flows cloud → interior has left the boundary where controls exist.**
   For every such flow, name the landing system and enumerate the interior egress paths reachable
   from it (proxies, data diodes, media-transfer stations, vendor links, patch/mirror channels). A
   flow whose landing system reaches any sanctioned egress path is scored as a completed exfil path,
   not as an internal transfer.
2. **An interior compromise pivots cloudward.** Enumerate where cloud credentials live on interior
   hosts (SA key files, `~/.config/gcloud/`, config-management secrets, artifact-store secrets, CI
   runner secrets). Each location is a starting position in the threat model with an *interior host
   compromise* precondition — which the assume-breach premise grants for free.
3. **The link is bidirectional and must be mapped in both directions.** Produce, for the link:
   what cloud subnets can originate traffic to the interior and on which ports; what interior
   subnets can originate traffic to cloud and to which endpoints; and which of those the routing
   actually permits today versus what the design document claims. A direction you did not measure is
   reported as unmeasured, not as absent.

### TF6 — Network position is never trust, on either side of the link

Any service that authorizes callers because of *where they connect from* is a finding. The soft
interior makes network position cheap to obtain, so a source-range allowance is an allowance to
everything that can put a packet on that range.

**The test you apply** — run it per service, do not generalize:

1. Name the service and the listener (host:port, or the API surface and its ingress setting).
2. Identify the **credential the service validates on each request**: an OIDC ID token with a
   specific audience, a Google-issued access token evaluated by IAM, an mTLS client certificate
   checked against an authorization policy, a Kerberos/AD ticket, an application session token.
   Read this from the service's auth configuration, not from a description of it.
3. If step 2 yields *"none — access is restricted by the firewall rule / the subnet / the access
   level / because it is on the corporate LAN"*, the service is trusting network position → finding.
4. If step 2 yields a credential but the credential's issuer trusts network position (e.g. a token
   minted for anyone who can reach an unauthenticated token endpoint), recurse to step 1 on the
   issuer.

Instances that always fail this test — flag on sight:
- An Access Context Manager access level whose only condition is `ipSubnetworks`, with no `members`
  and no `devicePolicy`. Anything that can route packets from the corporate LAN inherits it.
- A Cloud Run service or Cloud Run function with `--ingress=internal` and either an `allUsers`
  binding on the invoker role or the invoker IAM check disabled. `internal` also admits Cloud
  Scheduler, Cloud Tasks, Eventarc, Pub/Sub, and Workflows in the same project or perimeter — it is
  not a network ACL.
- A firewall policy rule that authorizes an application flow by source IP range where a secure tag
  or a source service account would express the same intent.
- Any interior service reachable from a cloud subnet whose authentication answer in step 2 is
  "it's on the internal network".

---

## 2. Intake — the artifacts to request

### 2.1 Source-of-truth precedence

Use, in this order:

1. **Terraform / IaC state and code** — authoritative for *intent* and for what will be re-applied
   over any manual fix.
2. **Cloud Asset Inventory exports** — authoritative for *what exists*, at a snapshot time.
3. **Targeted `gcloud` / API dumps** — for anything CAI does not carry, and for live re-checks.

**When they disagree, that is a finding, not a data-quality problem.** Emit it with ID prefix
**`DRIFT-`**, naming the resource, the IaC-declared value, the live value, and the snapshot time of
each. Score it by TF1: drift that widens an exfil boundary (a perimeter resource removed live, a
firewall egress rule added live, an IAM binding added live) is scored as though the live state were
intended, plus a control-plane finding for the process that allowed it. Drift that *narrows* is
scored as a fragility finding — the next `terraform apply` reopens the hole; name the apply pipeline.

### 2.2 Artifact request list

Request all of it. Record which rows arrived and which did not — the "not" list drives the interview
mode below and the evidence appendix.

Substitute: `ORG_ID` numeric organization ID, `FOLDER_ID`, `PROJECT_ID`, `PROJECT_NUMBER`,
`POLICY_NAME` access policy name, `BUCKET` evidence bucket.

| # | Artifact | Why it is load-bearing for exfil analysis | How to produce it |
|---|---|---|---|
| 1 | Resource hierarchy: org node, every folder, every project, and each project's parent chain | Determines what org policy, IAM, deny policy, and firewall policy each project actually inherits. A project moved to a weaker parent sheds all of it in one call. | `gcloud projects get-ancestors PROJECT_ID`; `gcloud asset search-all-resources --scope=organizations/ORG_ID --asset-types='cloudresourcemanager.googleapis.com/Project,cloudresourcemanager.googleapis.com/Folder' --format=json` |
| 2 | Org policy at **org, folder, and project** scope, plus effective evaluation per constraint, plus custom constraints | Overrides at lower nodes are where the baseline is quietly disabled; the disable step is the precursor half of a two-step escalation. | `gcloud org-policies list --organization=ORG_ID --format=json` (repeat with `--folder=` and `--project=` for every node); `gcloud org-policies list-custom-constraints --organization=ORG_ID --format=json`; effective per constraint: `gcloud asset analyze-org-policies --constraint=constraints/CONSTRAINT --scope=organizations/ORG_ID` and `gcloud org-policies describe CONSTRAINT --effective --organization=ORG_ID` |
| 3 | IAM **allow** policies at every node — org, folder, project | The base map for the privilege graph. Org- and folder-level bindings span everything and are invisible from a project's own policy. | `gcloud asset export --organization=ORG_ID --content-type=iam-policy --output-path=gs://BUCKET/iam-policy.json` — note the **lowercase-hyphenated** value; `IAM_POLICY` is the REST enum and is rejected by gcloud. Point check: `gcloud organizations get-iam-policy ORG_ID --format=json` |
| 4 | **Resource-level** IAM: buckets, datasets and tables, Pub/Sub topics and subscriptions, KMS keyrings and keys, secrets, Artifact Registry repos, and **service-account IAM policies** | Where impersonation grants and cross-org shares hide. Resource-level `setIamPolicy` reaches the data without touching project IAM at all, so a project-policy-only review mis-states access. | The `iam-policy` CAI export in row 3 already contains resource-level bindings — read them, do not stop at project scope. Point checks use the per-resource `get-iam-policy` verbs (`gcloud storage buckets get-iam-policy`, `gcloud pubsub topics get-iam-policy`, `gcloud kms keys get-iam-policy`, `gcloud iam service-accounts get-iam-policy`, `gcloud secrets get-iam-policy`, `bq show --format=prettyjson PROJECT_ID:DATASET`) — exact flag spellings: verify against current docs |
| 5 | IAM **deny** policies at every attachment point | Deny evaluates before allow. A review reading only allow policies mis-states effective access in **both** directions. | `gcloud iam policies list --attachment-point=cloudresourcemanager.googleapis.com/projects/PROJECT_NUMBER --kind=denypolicies --format=json`; repeat with `.../folders/FOLDER_ID` and `.../organizations/ORG_ID` |
| 6 | Custom role definitions **and the principals holding each** | `iam.roles.update` on a role a principal already holds is a silent escalation — the binding never changes, so diff-based review misses it. | `gcloud asset search-all-resources --scope=organizations/ORG_ID --asset-types='iam.googleapis.com/Role' --format=json`; holders come from the row-3 export by role name |
| 7 | Principal Access Boundary policies **and their bindings** | PAB caps what a principal can reach regardless of any IAM grant — the only hard stop on the reachability paths you will compute. Absent PAB, IAM drift is unbounded. | `gcloud iam principal-access-boundary-policies list ...` and `gcloud iam policy-bindings list ...` — both GA; **subcommand flags (`--organization`, `--location`): verify against current docs** |
| 8 | Full service-account inventory: user-managed SAs, **default** SAs (Compute Engine, App Engine, and the Cloud Build legacy account `PROJECT_NUMBER@cloudbuild.gserviceaccount.com` in pre-2024 projects), per-service agents; and every key with its creation date | The default Compute Engine SA is the runtime identity for GCE, Cloud Run, Cloud Run functions and (since the 2024 change) Cloud Build. User-managed keys are the durable offline credential the whole review exists to catch. | `gcloud asset search-all-resources --scope=organizations/ORG_ID --asset-types='iam.googleapis.com/ServiceAccount' --format=json`; keys: `gcloud iam service-accounts keys list --iam-account=SA_EMAIL --managed-by=user --format=json` — **`--managed-by=user` is the exfil-relevant filter**; `system` keys are Google-rotated and cannot be exfiltrated |
| 9 | VPC-SC: perimeters (`status` **and** `spec`), restricted-services lists, ingress/egress policies, access levels, bridges, and dry-run state | The primary GCP exfil control. A perimeter with a populated `spec` and an empty `status` enforces nothing while looking configured. | `gcloud asset export --organization=ORG_ID --content-type=access-policy --output-path=gs://BUCKET/access-policy.json`; plus `gcloud access-context-manager perimeters list --policy=POLICY_NAME --format=json`, `gcloud access-context-manager perimeters describe PERIMETER --policy=POLICY_NAME --format=json`, and **`gcloud access-context-manager perimeters dry-run list --policy=POLICY_NAME`** |
| 10 | Firewall: hierarchical policies, network firewall policies, legacy VPC rules, the **effective** merged rule set, secure/network tags in use, and logging config | Egress posture is the network-side exfil control; east-west posture is the lateral-movement control. The two policy families are different objects and both apply. | Hierarchical (org/folder only): `gcloud compute firewall-policies list --organization=ORG_ID`; network policies: `gcloud compute network-firewall-policies list --project=PROJECT_ID`; legacy: `gcloud compute firewall-rules list --project=PROJECT_ID --format=json`; **merged, and the one that matters**: `gcloud compute networks get-effective-firewalls NETWORK --project=PROJECT_ID` and `gcloud compute instances network-interfaces get-effective-firewalls INSTANCE --network-interface=nic0 --zone=ZONE`. `firewall-rules list` alone misses every policy rule. Tags: `gcloud resource-manager tags keys list --parent=organizations/ORG_ID` (flags: verify against current docs). Exact `get-effective-firewalls` and `firewall-policies list` flag lists: verify against current docs |
| 11 | Hybrid topology: Interconnect / VPN inventory, Cloud Routers, **BGP advertisements and effective routes in BOTH directions** | The link is a bidirectional exfil and traversal channel. What is advertised is what is reachable; the design document is not evidence. | `gcloud compute routes list --project=PROJECT_ID --format=json`; `gcloud compute routers get-status ROUTER --project=PROJECT_ID --region=REGION` (**synopsis and flags: verify against current docs**); per-session both directions: `gcloud compute routers list-bgp-routes ROUTER --region=REGION --peer=PEER --route-direction=ADVERTISED --policy-applied` and the same with `--route-direction=LEARNED`. Also capture `--advertisement-mode` / `--set-advertisement-groups` / `--set-advertisement-ranges` on each router and BGP session: a custom advertisement on a session **overrides all router-level advertisements** |
| 12 | Private Google Access and restricted-VIP usage, **cloud side and on-prem side** | `private.googleapis.com` where `restricted.googleapis.com` was intended silently reopens every API that VPC-SC does not support. On-prem resolving `*.googleapis.com` publicly bypasses the perimeter's network context entirely. | Cloud side: subnet `private_ip_google_access` / `gcloud compute networks subnets describe`. DNS: see row 13. On-prem side, from an interior host: resolve `storage.googleapis.com` and record the answer — `199.36.153.4`–`.7` (`restricted`, `199.36.153.4/30`) vs `199.36.153.8`–`.11` (`private`, `199.36.153.8/30`) vs a public Google front-end address. Then confirm Cloud Router advertises `199.36.153.4/30` (IPv6 `2600:2d00:0002:1000::/56`) over the tunnel/attachment — **DNS alone and BGP alone are each insufficient; both are required** |
| 13 | Cloud DNS: private zones, inbound/outbound server policies, forwarding targets, response policies | A forwarding policy or outbound server policy pointed at an attacker resolver is a DNS-tunnelling exfil channel that no port-53 egress deny catches — Cloud DNS sends those packets from `35.199.192.0/19`, not from the VM. Response policies are also how `*.googleapis.com` pinning is enforced *or* subverted. | `gcloud dns managed-zones list --format=json` and `--filter="visibility=private"`; `gcloud dns policies list --format=json`; `gcloud dns response-policies list --format=json` (**GA status and `response-policy-rules` nesting: verify against current docs**) |
| 14 | Private Service Connect: endpoints, backends, service attachments, NEGs, and the Google-APIs bundle in use | A PSC endpoint is an internal IP in your own VPC: an egress `deny 0.0.0.0/0` with an RFC1918 allow leaves it wide open, NAT hides the destination, and the producer can be in another organization. `all-apis` bundle endpoints reach APIs VPC-SC cannot police. | `gcloud compute forwarding-rules list --filter="target~serviceAttachments OR pscConnectionId:*" --format=json`; `gcloud compute service-attachments list --format=json`; for Google-APIs endpoints record `--target-google-apis-bundle` (**`all-apis`** = reaches unprotected APIs, **`vpc-sc`** = the one to require). Check every endpoint's target organization |
| 15 | Compute: VM inventory with attached SAs, access scopes, external IPs; project-wide and per-instance metadata; OS Login state | This is the `actAs` escalation surface. `compute.instances.setMetadata` on an existing privileged VM is root on that VM and therefore its SA token; `compute.projects.setCommonInstanceMetadata` is that for every VM in the project. | `gcloud compute instances list --project=PROJECT_ID --format="json(name,zone,serviceAccounts,networkInterfaces,metadata)"`; `gcloud compute project-info describe --project=PROJECT_ID --format=json` — read `enable-oslogin`, `ssh-keys`, `serial-port-enable`. Note that `enable-oslogin=FALSE` in **instance** metadata defeats `TRUE` in project metadata |
| 16 | GKE: cluster configs — Workload Identity Federation for GKE, node-pool `workloadMetadataConfig`, node SAs, RBAC bindings, NetworkPolicy, Binary Authorization, all three control-plane endpoint states | With `--workload-metadata=GCE_METADATA` any pod reads the node SA token from `169.254.169.254`; if the node pool runs the default Compute SA with `roles/editor` that is project takeover from one container. Pod-to-pod is open by default. | `gcloud container clusters describe CLUSTER --location=LOCATION --format=json` — read `workloadIdentityConfig.workloadPool`, each node pool's `workloadMetadataConfig.mode`, `nodeConfig.serviceAccount`, `binaryAuthorization`, and **all three** of private-nodes / IP-based endpoint / DNS-based endpoint (checking `--enable-private-endpoint` and authorized networks alone is no longer sufficient). In-cluster: `kubectl get clusterrolebindings -o json`, `kubectl get networkpolicies -A -o json`, `kubectl get pods -A -o json` for `hostNetwork`/`privileged`/`hostPath` |
| 17 | Cloud Run services and jobs, Cloud Run functions: runtime SA, invoker bindings, `--ingress`, `--vpc-egress` | Default runtime identity is the **Compute Engine default SA**. `allUsers` on the invoker role is public unauthenticated access. `--vpc-egress=private-ranges-only` means public egress bypasses the VPC entirely — your NGFW policies, NAT logs and flow logs never see it. | `gcloud run services list --format=json`; `gcloud run services describe SERVICE --region=REGION --format=json`; `gcloud run services get-iam-policy SERVICE --region=REGION --format=json` (search for `allUsers` on `roles/run.invoker` and `roles/cloudfunctions.invoker`) |
| 18 | Cloud Build triggers and **the SA each build runs as** | The over-privilege moved rather than disappearing: new projects' builds default to the **Compute Engine default SA**, not the legacy Cloud Build account. Anyone who can modify build config or the triggering branch inherits that identity. | `gcloud builds triggers list --project=PROJECT_ID --format=json` — read the service account field per trigger; then check that SA's roles in the row-3 export. Also check `constraints/cloudbuild.useBuildServiceAccount` and `constraints/cloudbuild.useComputeServiceAccount` |
| 19 | Composer, Dataflow, Dataproc, Vertex AI Workbench / notebooks, Cloud Scheduler, Cloud Tasks, Deployment Manager — environments/jobs and their attached SAs | Each is an `actAs` surface: create a workload that runs as a more privileged SA, read the token. A Dataflow job in particular is arbitrary attacker code holding a worker SA that can read any source and write any sink. | One command per service, per project — asset-type strings vary by service, so do not rely on a single CAI sweep (asset-type strings: verify against current docs). `gcloud composer environments list --locations=LOCATION --format=json`; `gcloud dataflow jobs list --region=REGION --format=json`; `gcloud dataproc clusters list --region=REGION --format="table(clusterName,config.gceClusterConfig.serviceAccount)"`; `gcloud workbench instances list --location=LOCATION --format=json` (command spelling: verify against current docs); `gcloud scheduler jobs list --location=LOCATION --format="table(name,httpTarget.oidcToken.serviceAccountEmail,httpTarget.oauthToken.serviceAccountEmail)"`; `gcloud tasks queues list --location=LOCATION --format=json` then read each task's `oidcToken`/`oauthToken` service account; `gcloud deployment-manager deployments list --format=json` (legacy — if any deployment exists, record that it runs as `PROJECT_NUMBER@cloudservices.gserviceaccount.com`). Then per-service `describe` for the SA field. **The same enumeration is repeated in §7.1.1 — collect once, cite both places.** |
| 20 | Workload Identity Federation: pools, providers, **attribute mappings and attribute conditions**, and the SAs federated principals may impersonate | The top exfil bridge from outside into GCP. An empty or permissive `attributeCondition` on an external OIDC issuer means any principal from that IdP can assume the mapped identity. | `gcloud iam workload-identity-pools list --location=global --show-deleted --format=json`; `gcloud iam workload-identity-pools providers list --workload-identity-pool=POOL --location=global --format=json` — read `attributeMapping` and `attributeCondition`. Impersonation targets: grep the row-3 export for `principalSet://iam.googleapis.com/projects/.../workloadIdentityPools/` members and `roles/iam.workloadIdentityUser` |
| 21 | Identity: Cloud Identity / Workspace configuration, SSO and MFA (2SV) enforcement, **super-admin inventory**, delegated-admin role assignments, human-vs-non-human split, group membership **and nesting** | Super admins are implicitly able to modify the org node's IAM policy and to grant themselves any role — they sit **above** org policy, perimeters, sinks, and bucket locks. Group-write grants roles without any IAM change appearing in a project's policy. | Super admins: Admin SDK Directory API `GET https://admin.googleapis.com/admin/directory/v1/users?domain=DOMAIN&query=isAdmin=true` — **returns super admins only**, and can be up to 36 h stale. Delegated admins (Groups Admin, Security Settings) are **not** returned: enumerate Admin SDK `roleAssignments` as well (**exact endpoints: verify against current docs**). Group nesting: Cloud Identity Groups API `groups.memberships.searchTransitiveMemberships()`. 2SV: Admin console → Security → Authentication → 2-step verification; session length: Security → Access and data control → Google Cloud session control |
| 22 | Break-glass identities and roles: who/what they are, how they are stored, what gates their use, what alerts on it, and **whether they bypass VPC-SC** | A break-glass identity in a perimeter's ingress rule or access level is a standing exfil path with a legitimate-looking name. | No single API. Request the runbook, then verify it against evidence: the principal's bindings in the row-3 export, its presence in any perimeter `ingressPolicies` / access level `members`, any IAM Deny exception naming it, and the alerting policy that fires on its use |
| 23 | Audit-log configuration: `auditConfigs` per node, sinks at **every** scope, log-bucket retention and lock state, and who can modify sinks | Data Access logs are **off by default** for everything except BigQuery — which means most of the read activity that constitutes exfil is invisible. Policy Denied logs (every VPC-SC violation) expire at 30 days unless routed. An org sink is invisible to `gcloud logging sinks list --project=X`. | `gcloud projects get-iam-policy PROJECT_ID --format=json` (and folder/org equivalents) — read `auditConfigs`, checking `logType` ∈ {`ADMIN_READ`,`DATA_READ`,`DATA_WRITE`} and treating any non-empty `exemptedMembers` as an audit-evasion primitive. `gcloud logging sinks list --organization=ORG_ID`, then repeat with `--folder=`, `--project=`, `--billing-account=` for **every** node; `gcloud logging sinks describe SINK --organization=ORG_ID` for `writerIdentity`, `includeChildren`, `filter`, `exclusions`, `disabled`; `gcloud logging buckets list --project=DEST_PROJECT` for `retentionDays` and locked state |
| 24 | CI/CD and IaC control plane: which repos/pipelines deploy to which projects, what identity each assumes, who approves and who can bypass approval, where Terraform state lives and who can read it | The pipeline is a standing `actAs` grant into every project it deploys to. Terraform state routinely contains secrets — the state bucket's read ACL is a data-tier finding, not an ops detail. | Repo/pipeline → project map and workflow definitions from the IaC repo; deploy identity from the pipeline config; state bucket IAM from row 4. Branch protection / required-reviewer settings from the GHES repo settings |
| 25 | GHES specifics: self-hosted runner **placement**, and exactly how runners obtain cloud credentials | In an air-gapped GHES estate this is the crossing point between the soft interior and cloud. GHES OIDC → WIF requires Google to fetch JWKS from a publicly routable issuer, so in a genuinely air-gapped deployment **WIF is not achievable and key-based auth is what these environments actually run** — which makes the SA key the primary exfil primitive. | Ask (literal questions in the interview bank below) and verify: runner host inventory (GCE VM / GKE pod / on-prem hardware), whether runners are per-repo or shared, the secret names injected into workflows, and whether any `*.json` SA key is delivered as an Actions secret. If a runner uses WIF, read the provider's `attributeCondition` and confirm it pins repo **and** ref/environment. **GHES-with-static-JWKS as a workaround: verify against current docs and require a proof-of-concept before designing around it** |
| 26 | The data classification map: which resources hold which tier | Without it, TF1 has no multiplier and every finding degrades to generic hygiene. | Preferred: the org's own map (file/spreadsheet/tag taxonomy). Derive and cross-check from labels/tags: `gcloud asset search-all-resources --scope=organizations/ORG_ID --asset-types='storage.googleapis.com/Bucket,bigquery.googleapis.com/Dataset' --query="labels.CLASSIFICATION_KEY:*" --format=json`. Where coverage is thin, Sensitive Data Protection **discovery** data profiles (sensitivity level + data risk level per resource) are the only scalable way to rank thousands of tables — `gcloud dlp` syntax: verify against current docs |
| 27 | On-prem interior facts | Required by the traversal analysis and the assume-breach premise. | Interview + network documentation, then verify what you can from the cloud side (row 11). Minimum: which interior subnets are reachable from cloud and on which ports; whether interior east-west segmentation exists; which interior services authenticate callers vs trust network position (apply the TF6 test per service); where cloud credentials live on interior hosts; what interior egress paths exist and who can reach each |

### 2.3 Minimum viable evidence set

Rows 1–9 are the artifacts that make the review *evidence-derived*. Ask for all of them, and record
which arrived. **Missing one is never a reason to stop — it is a reason to switch that row's control
area to interview mode.** The column below states the cost of each absence, which you carry into the
scope statement and into every finding that area emits.

| Have | Cost if missing |
|---|---|
| Rows 1–3 (hierarchy, org policy at all three scopes, IAM allow export) | The only rows whose absence also degrades §6: without them the privilege graph is partial, so §6's output is the primitive-hunt list (§6.2) answered from interviews, not a computed closure. Name that limitation; do not skip §6. Ask for the org-policy and hierarchy blocks in §2.5.2 and re-ask the IAM questions per project. |
| Row 5 (deny policies) **or** an explicit written statement that no deny policies exist | Effective access is unknown in both directions. This is one command — press for it. Absent both, work the IAM Deny question block and treat every deny-dependent remediation as unverified. |
| Row 8 (SA inventory + user-managed key list) | The single highest-yield artifact for offline-credential exfil. Absent it, work the Identity question block; every `ID-08`/`ID-09` finding is `[INTERVIEW] · REPORTED` and capped at High. |
| Row 9 (VPC-SC config including dry-run state) **or** a statement that VPC-SC is not deployed | "We have VPC-SC" plus a dry-run-only perimeter is the most common false-positive control in this domain. Absent the config, ask the VPC-SC block and **never** record a perimeter as enforced on a verbal answer. |
| Row 26 (classification map), even as a coarse per-project tiering | Run the review but score every unclassified store as CONFIDENTIAL-until-proven-otherwise and open a `DC-` finding per store. Say so in the report's scope statement. |

**Proceed with degradation** (interview mode, `[INTERVIEW]` tags per §2.5.1) when rows 10–25 are
partial. Those rows narrow and rank chains; their absence lowers confidence, it does not invalidate
the analysis.

**When a row 1–9 artifact cannot be produced, do not stop** — switch that row to interview mode and
work its question block in §2.5.2. Say so in the scope statement in these words: *"Rows &lt;n&gt; were not
produced; the corresponding control areas are assessed `[INTERVIEW] · REPORTED`, capped at High per
§11.1.7, and the privilege graph in §6 is built only from the edge classes the available artifacts
support — the unbuilt edge classes are listed in Appendix B."*

**Do not proceed at all** only when you hold none of rows 1–9 **and** no one is available to
interview. Say that, and say which single artifact would unblock the most: the CAI `iam-policy`
export.

---

### 2.4 Scope questions asked at start

Ask these as your first output, all at once, verbatim. Do not begin Phase 2 until Q1 and Q2 are
answered. If Q3–Q7 go unanswered, record each as an open scope item in the report's scope statement.

> 1. **What is the target scope of this review?** Give the organization ID in the form
>    `organizations/NNNNNNNNNNNN`, and — if the review is narrower than the whole org — the folder
>    IDs (`folders/NNNNNNNNNNNN`) or project IDs in scope. If the answer is "the whole org", I will
>    treat every folder and project under that node as in scope.
> 2. **Is there a supplementary requirements `.md`?** Give me the file path or paste it inline. If
>    there is none, reply "baseline only" and I will run the baseline ruleset unchanged.
> 3. **Which projects hold CONFIDENTIAL data, and which hold NTK data?** If a classification map
>    exists, give me its path. If not, name the projects you know of; I will treat every unlabeled
>    data-bearing resource as unclassified and open a `DC-` finding for each.
> 4. **What evidence access do I have?** Which of these exist, and where: read-only credentials
>    against the live org, an existing Cloud Asset Inventory export (give the `gs://` URI), a
>    Terraform repo and state backend (give the paths), or interviewees only.
> 5. **May I run read-only `gcloud` / API commands against the environment myself**, or must every
>    artifact be produced by your team and handed to me?
> 6. **Which on-prem networks are connected, over what** (Dedicated Interconnect, Partner
>    Interconnect, HA VPN, Classic VPN), and **who can answer interior questions** — segmentation,
>    interior egress paths, and where cloud credentials live on interior hosts?
> 7. **Where does the IaC live and what deploys it?** Give the GHES repository URLs, the pipeline
>    names, and whether the self-hosted runners execute on GCE/GKE inside GCP or on on-prem
>    hardware. Also: are there documented exceptions, accepted risks, or a prior review I should
>    read before flagging something as a finding?

---

### 2.5 Graceful degradation — structured interview mode

When an artifact row is unavailable, do not skip its control area and do not soften the finding into
advice. Switch that area to interview mode, ask the questions below, and label the result.

#### 2.5.1 Labeling and confidence

| Label | When | Confidence value | Effect on severity |
|---|---|---|---|
| `[EVIDENCE] · CONFIRMED` | A named artifact shows the exact configuration, and you quote the field. | CONFIRMED | Rubric severity applies unchanged. |
| `[EVIDENCE] · DERIVED` | Computed by combining two or more artifacts (e.g. a chain assembled from the IAM export plus the instance list). State both sources. | DERIVED | Rubric severity applies unchanged. State the inference step so a reader can refute it. |
| `[INTERVIEW] · REPORTED` | A human stated the configuration and no artifact contradicts it. | **REPORTED — the ceiling for interview-derived findings. Never label an interview answer CONFIRMED.** | **Capped at High. Never Critical.** Remediation step 1 is always "produce artifact <row #> to confirm, then re-score." |
| `[INTERVIEW] · UNKNOWN` | The question was asked and the answer was "I don't know" / "nobody owns that". | UNKNOWN | **Capped at Medium**, and written as a *visibility* finding: the title names the unanswerable question, not a presumed misconfiguration. Remediation is the artifact request. |

Two rules that follow:

- A `[INTERVIEW] · REPORTED` finding that would otherwise be Critical is reported at High **and**
  listed in the roadmap's first tier as "confirm-then-escalate", so the cap never buries it.
- Never average confidences across a chain. A chain containing one `[INTERVIEW]` step is an
  `[INTERVIEW]` chain, tagged at the weakest step, with that step named.

#### 2.5.2 Interview question bank

Ask the questions for any area whose artifacts you lack. Answers of the form "yes, it's secure" are
not answers — re-ask naming the specific field.

**Organization Policy**
1. Which constraints are set at the **org node**, and can you name any that are overridden or reset at a folder or project below it?
2. Who holds `orgpolicy.policy.set` or `roles/orgpolicy.policyAdmin`, and at which node is each binding?
3. Is `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` enforced — i.e. does the default Compute Engine SA carry `roles/editor` in any project?
4. Are service-account key creation and key upload blocked by policy? Name the constraint you rely on and any project exempted from it.
5. Is `constraints/gcp.resourceLocations` set, and to which value groups? Which regions can a resource be created in today?

**VPC Firewall Policy**
1. Is there an **egress** deny rule, and at what scope — hierarchical (org/folder), network policy, or per-VPC legacy rules?
2. Does any rule permit egress to `0.0.0.0/0`? At what priority, and does a higher-priority deny precede it?
3. Are east-west rules keyed on secure tags or source service accounts, or on IP ranges? If tags: secure tags (IAM-gated) or legacy network tags (no IAM gate on the tag string)?
4. Is firewall rule logging on, for which rules, and where do those logs land?
5. Which subnets can originate traffic across the interconnect/VPN to on-prem, and on which ports?

**VPC Service Controls**
1. Which perimeters exist, and for each: is it **enforced** (`status` populated) or dry-run only (`spec` only)?
2. Which projects holding CONFIDENTIAL or NTK data are in **no** perimeter?
3. For each perimeter, which services are in the restricted-services list — and specifically, are `storage.googleapis.com`, `bigquery.googleapis.com`, `bigquerydatatransfer.googleapis.com`, `pubsub.googleapis.com`, `logging.googleapis.com` and `storagetransfer.googleapis.com` all there?
4. Which ingress rules admit identities from outside the perimeter, and which egress rules permit flows to other projects or perimeters? Name the identities and the projects.
5. Who can write to Access Context Manager — create/update perimeters and access levels? (This is equivalent to turning the control off.)
6. Do any Pub/Sub **push** subscriptions predate the perimeter? (A perimeter does not block push subscriptions that existed before it was created.)

**IAM (allow)**
1. Are `roles/owner`, `roles/editor`, or `roles/viewer` bound at the org or any folder? To whom?
2. Is `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` bound at **project** level anywhere? (That confers impersonation of every SA in the project.)
3. Which principals outside your domains hold any binding — `allUsers`, `allAuthenticatedUsers`, external users, or SAs from other organizations?
4. Which SAs hold data-read roles on CONFIDENTIAL stores, and which workloads run as each?
5. Are any bindings conditioned with IAM Conditions? On what attribute, and does the condition actually narrow the grant?

**IAM Deny**
1. Do any deny policies exist? At which attachment points?
2. Is `iam.serviceAccountKeys.create` denied anywhere, and for which principal set?
3. Is `iam.serviceAccounts.actAs` denied for privileged SAs outside their owning service?
4. Are `setIamPolicy` permissions denied outside a named admin group, at org or folder?
5. Are custom-role mutation permissions (`iam.roles.update`, `iam.roles.create`) denied outside the role-admin group?

**Private Service Connect**
1. How many PSC endpoints exist, and for each: does it target a Google-APIs bundle or a service attachment?
2. For Google-APIs endpoints, is the bundle `vpc-sc` or `all-apis`? (`all-apis` reaches APIs VPC-SC cannot police.)
3. For service-attachment endpoints, which organization owns the producer side?
4. Are any PSC endpoints reachable from on-prem across the link?
5. Are VPC Flow Logs enabled on the subnets holding PSC endpoints? (Without them the egress is invisible on the consumer side too.)

**Principal Access Boundary**
1. Are any PAB policies deployed, and to which principal sets?
2. Are federated (WIF) principals covered by a PAB policy, and what resource set does it permit?
3. Are cross-project service accounts covered?
4. Which resources can a compromised CI/CD principal reach today if IAM allowed it — and does a PAB stop that?
5. Has a PAB policy been tested with Policy Simulator for PAB before enforcement, or is it enforced untested?

**Workload Identity Federation**
1. Which pools and providers exist, and which external IdP issuer does each trust?
2. For each provider, what is the **`attributeCondition`** string? Does it pin a specific repository **and** ref/environment, or is it empty?
3. Which service accounts can each federated principal impersonate, and what can those SAs read?
4. Is any binding written against the pool-wide `principalSet://.../workloadIdentityPools/POOL/*` rather than a specific subject?
5. Is `constraints/iam.managed.workloadIdentityPoolProviders` set to limit which IdPs can be configured at all?

**Identity**
1. How many super-admin accounts exist, are they separate from those humans' daily accounts, and is 2SV enforced with security keys on all of them?
2. Who holds delegated admin roles — Groups Admin, Security Settings, User Management? (These are not returned by a super-admin query.)
3. Is SSO enforced for all human access, and can any account bypass it with a Google password?
4. Which groups carry IAM bindings, who can modify their membership, and is that change visible in Cloud Audit Logs (i.e. is Workspace data sharing with Google Cloud enabled)?
5. How many user-managed SA keys exist, what is the oldest one's age, and where does each live?

**Access**
1. Which Access Context Manager access levels exist, and what conditions does each carry — `ipSubnetworks` only, or also `members` / `devicePolicy`?
2. How does on-prem-originated access to Google APIs authenticate and get authorized today?
3. Is IAP used for HTTP surfaces, and who holds `roles/iap.tunnelResourceAccessor` and over which instances?
4. Is Access Approval enabled, and is Access Transparency logging retained?
5. Is there any just-in-time elevation mechanism, and does it require a second approver?

**Break-glass**
1. Is there a dedicated break-glass identity or role, and what exactly is it (user, group, or SA)?
2. In normal state, does it hold any active binding, or is the binding created only at use time?
3. What gates its use — MFA, dual control, time-boxing, a ticket reference?
4. **Does it appear in any VPC-SC ingress rule, access level `members` list, or IAM Deny exception?**
5. Does its use fire a real-time alert to somewhere the break-glass holder cannot suppress, and is there a mandatory post-use review?

**Audit logging and detection coverage**
1. For each project holding CONFIDENTIAL or NTK data, are `DATA_READ` and `ADMIN_READ` audit logs enabled, and for `allServices` or only some?
2. Does any `auditConfigs` entry carry a non-empty `exemptedMembers`? For whom?
3. Is there an org-level aggregated sink with `includeChildren` true, and does its filter include `cloudaudit.googleapis.com%2Fdata_access` and `%2Fpolicy` — not only `%2Factivity`?
4. Does the sink destination live in a project the workload principals cannot write to, and is the log bucket locked with retention set **before** locking?
5. What alerts exist today on: `SetIamPolicy` at any node, `GenerateAccessToken` / `SignJwt` / `SignBlob`, `google.iam.admin.v1.CreateServiceAccountKey`, org-policy and access-level changes, VPC-SC violations, sink deletion, and break-glass use? Name the alerting policy for each, or say "none".

**Hybrid link and the on-prem interior**
1. Which interior subnets can a cloud workload reach today, on which ports, and which cloud subnets can originate that traffic?
2. Is there interior east-west segmentation between the systems reachable from cloud and the rest of the interior — enforced by what device or policy?
3. Which interior services reachable from cloud validate a per-request credential, and which authorize because the caller is on the internal network? (Apply the TF6 test service by service.)
4. Where do cloud credentials live on interior hosts — SA key files, `gcloud` credentials in home directories, config-management secrets, artifact-store secrets, CI runner secrets?
5. What sanctioned egress paths exist from the interior (proxy, data diode, media transfer, vendor link, patch mirror), and which of them is reachable from the systems where cloud data lands?
6. Does on-prem DNS resolve `*.googleapis.com` to the restricted VIP, and does on-prem block direct routes to public Google front-end addresses?

---

## 3. Phased workflow

Execute in order. Each phase names the section of this skill it runs, the artifact it writes, and the
condition that lets you leave it. Do not start a phase until the previous phase's exit criterion is
met; record any criterion you waive, and why, in the scope statement.

1. **Scope & intake** — runs §2 and §10. Ask the seven
   scope questions; collect the artifact rows; parse and merge any supplementary requirements into
   the working ruleset **before** any assessment; record the source-of-truth precedence decision per
   artifact.
   *Artifact:* `SCOPE.md` (scope statement, artifact-received/absent table, merged ruleset,
   conflict report).
   *Exit:* the minimum viable evidence set is satisfied or explicitly waived in writing; every
   supplied requirement has a `SR-` ID and a `test`; the conflict report exists (possibly empty).

2. **Asset & identity inventory** — runs §4.2 (asset registers `TM-A1`/`TM-A2`/`TM-A3`) and §4.3
   (trust-boundary register `TM-B`). Enumerate data stores by classification tier; enumerate human,
   service-account, and federated identities; mark trust boundaries (perimeter edges, the
   cloud↔on-prem link, the internet edge, each WIF-trusted IdP, the CI/CD control plane's boundary
   into each project).
   *Artifact:* `INVENTORY.csv` + `BOUNDARIES.md`.
   *Exit:* every project in scope appears in exactly one inventory row carrying a classification
   tier and a perimeter-membership value (including the literal value `NONE`); every data-bearing
   resource without a classification has a `DC-` finding ID reserved.

3. **Threat model** — runs §4.1 and §4.4–§4.9 (the two registers built in phase 2 are its input):
   adversaries with explicit starting positions, attack paths as ordered chains, ATT&CK mapping,
   detection posture per path.
   *Artifact:* `THREATMODEL.md`.
   *Exit:* every adversary has a named starting position that maps to a concrete principal or host in
   `INVENTORY.csv`; every enumerated path has at least one step naming a real permission, rule, or
   route observed in this environment — no path is left generic.

4. **Control-by-control assessment** — work the full catalog in §5. Per
   control: observed configuration (quoted), the exfil scenario it does or does not block, the
   concrete fix.
   *Artifact:* `CONTROLS.md`.
   *Exit:* every catalog item has all three fields populated; zero items are closed with a
   generalization; every supplied `SR-` rule has a verdict of `MET`, `GAP`, or `NOT-ASSESSABLE`.

5. **Privilege-graph construction and reachability** — runs §6. Build the labeled directed graph, then compute transitive closure from every
   adversary starting position.
   *Artifact:* `PRIVGRAPH.json` + the ranked chain table.
   *Exit:* the closure is computed to fixpoint (not one hop); every path terminating at a principal
   able to read CONFIDENTIAL or NTK data is written out **as a path**, with the cheapest severing
   step marked; the residual blind spot of any native tooling used is stated.

6. **Lateral movement and traversal** — runs §7: cloud→cloud,
   cloud→on-prem, on-prem→cloud, and cross-project.
   *Artifact:* `TRAVERSAL.md` — one reachability map per adversary starting position.
   *Exit:* each direction of the link has a measured answer (not a design-document answer); every hop
   in every map names the control that should have stopped it and whether that control exists.

7. **Service isolation assessment** — runs §8, with the enforce-by-default rule.
   *Artifact:* `ISOLATION.md`.
   *Exit:* every isolation recommendation names a technical enforcement mechanism, or explicitly
   states that none exists and specifies the compensating review gate; each is assigned to one of the
   three enforcement layers (un-overridable policy / pre-merge policy-as-code / runtime detection).

8. **Org hierarchy assessment and target-state design** — runs §9.
   *Artifact:* `HIERARCHY.md` — current hierarchy, target hierarchy, and the migration delta.
   *Exit:* the target design states, for each admin role class, the node it is bound at and why; it
   states where `setIamPolicy`, `orgpolicy.policy.set`, and Access Context Manager write may be held;
   and each classification tier maps to a named folder and perimeter.

9. **Findings** — runs §11. Prioritized, each carrying resource,
   control identifier, severity from the stated rubric, the chain it enables, detection posture, and
   remediation code.
   *Artifact:* `FINDINGS.md`.
   *Exit:* every finding satisfies the three-part hard output rule; every finding traces to a numbered
   attack path and to its chain steps; no finding contains a sentence that would be true of an
   arbitrary GCP org.

10. **Remediation roadmap** — runs §11.5. Sequence the fixes, split quick wins from structural
    changes, note dependencies (e.g. a PAB rollout depends on the WIF inventory; an egress
    default-deny depends on the restricted-VIP DNS and route work).
    *Artifact:* `ROADMAP.md`.
    *Exit:* every finding banded `LOW` or above appears exactly once in the roadmap, except a finding
    whose remediation is already carried by another row — which names that row in its
    `Severs which chains` cell; **`INFO` findings never appear** (§11.1.6), and neither does an item
    that severs no chain and closes no `SR-`/`DC-` finding (§11.5); every structural item lists its
    prerequisite finding IDs; every quick win is executable with the snippet already in
    `FINDINGS.md`.

11. **Appendices** — runs §11.4.1's appendix table (A–F). Raw evidence used (with collection
    command and timestamp), the privilege graph,
    the merged requirements ruleset and conflict report, and the consolidated list of every item
    carrying "verify against current docs".
    *Artifact:* `APPENDIX/`.
    *Exit:* every assertion in `FINDINGS.md` cites an appendix evidence item or an `[INTERVIEW]` tag;
    the "verify against current docs" list is non-empty (this domain changes; an empty list means you
    stopped tracking, not that everything was verified).

---

## 4. Threat model

Build this **before** scoring any control. Every finding you later emit must cite an attack-path ID
(`AP-xx`) and an adversary ID (`A1`–`A7`) from this section; a finding that cites neither is a
configuration observation, not a security finding, and belongs in the appendix instead.

Work the five phases in order. Do not skip to the attack-path catalog: the catalog is instantiated
against the asset and boundary registers, and its steps are unusable without them.

### 4.1 Phase order

1. Build the **asset register** (data, credentials, trust) — tables `TM-A1`/`TM-A2`/`TM-A3`.
2. Build the **trust-boundary register** — table `TM-B`.
3. Instantiate the **adversary catalog** `A1`–`A7` against this environment: for each, record the
   concrete day-zero credential and network location observed here, or record `NOT PRESENT` with the
   evidence that rules it out.
4. Walk the **attack-path catalog** `AP-01`–`AP-13` step by step. Mark each step
   `REACHABLE` / `BLOCKED BY <control object>` / `N/A (<reason>)`.
5. Record **detection posture** per step, then rank each path with the function in §6.3.2 and band
   it with the rubric in §11.1.

---

### 4.2 Asset register

#### 4.2.1 Data assets — table `TM-A1`

Enumerate from the Cloud Asset Inventory export
(`gcloud asset export --content-type=resource`), not from a service list a human typed.
**`--content-type` spelling, stated once here and cross-referenced everywhere else in this skill:**
the gcloud CLI takes the lowercase-hyphenated values `resource`, `iam-policy`, `org-policy`,
`access-policy`, `os-inventory`, `relationship`; the `UPPER_SNAKE` forms (`RESOURCE`, `IAM_POLICY`, …)
are the REST enum only and are rejected by the CLI. One row per data-bearing resource: GCS bucket,
BigQuery dataset, Pub/Sub topic, Cloud SQL instance, Spanner database, Firestore database, Filestore
instance, Secret Manager secret, Artifact Registry repository, log bucket.

| Field | How to fill it |
|---|---|
| `ID` | `D-nnn`, stable for the whole review |
| `Resource` | Fully-qualified name (`//storage.googleapis.com/BUCKET`, `projects/P/datasets/D`) |
| `Project` / `Folder path` | From `gcloud projects get-ancestors PROJECT_ID` |
| `Classification (observed)` | The label/tag value actually on the resource |
| `Classification (claimed)` | What the owner says it is |
| `Read permission` | The exact permission that returns bytes: `storage.objects.get`, `bigquery.tables.getData`, `pubsub.subscriptions.consume`, `cloudsql.instances.export`, `secretmanager.versions.access` |
| `Principals with that permission` | Count + list, from `gcloud asset analyze-iam-policy --permissions=<perm> --scope=organizations/ORG_ID --expand-groups --expand-resources` |
| `Perimeter` | Perimeter name, or `NONE`; plus `enforced` or `dry-run` |
| `CMEK key` | Key resource name, or `Google-managed` |
| `DATA_READ enabled` | Yes/No from the effective `auditConfigs` at the nearest node |
| `Egress surfaces present` | e.g. BigQuery sharing listing, pre-existing Pub/Sub push subscription, signed-URL usage, Storage Transfer job, cross-region replica |

Rules that produce findings directly from this table:

- `Classification (observed)` empty on any row → finding. An unclassified data store cannot be scored,
  and it is excluded from every perimeter design that keys on classification.
- `Classification (observed)` ≠ `Classification (claimed)` → finding; treat the **higher** tier as
  true for the rest of the review.
- Tier ordering for all scoring in this skill: **`CONFIDENTIAL` outranks `NTK`** — rationale in §1,
  rule TF3. The numeric tier weights live in §6.3.2 and are the only set this skill uses.
- A row whose `Perimeter` is `NONE` or `dry-run` while `Classification` is `CONFIDENTIAL` or `NTK` →
  finding, path `AP-01`.

#### 4.2.2 Credential assets — table `TM-A2`

A credential is an asset because possessing it *is* the identity. Enumerate every row type below; a
row type you cannot evidence is recorded as `UNKNOWN`, never as absent.

| `ID` | Credential | Enumerate with | Lifetime | Identity it yields | Detectable in logs when used? |
|---|---|---|---|---|---|
| `C-key-*` | User-managed SA key | `gcloud iam service-accounts keys list --iam-account=SA --managed-by=user --created-before=...` | Until deleted | The SA, fully | Only via the call it makes; creation is `google.iam.admin.v1.CreateServiceAccountKey` (Admin Activity) |
| `C-upl-*` | Uploaded (BYO) public key on an SA | Same listing; creation event `google.iam.admin.v1.UploadServiceAccountKey` | Until deleted | The SA | Creation logged; survives reviews that watch only `CreateServiceAccountKey` |
| `C-hmac-*` | GCS HMAC key | Storage admin API | Until deleted | S3-compatible access to GCS as the SA | Creation `storage.hmacKeys.create`; **use** carries no IAM token telemetry |
| `C-oauth-*` | User OAuth refresh token | `~/.config/gcloud/credentials.db`, `application_default_credentials.json` on laptops/jump hosts | Until revoked or session policy expires | The human | Only downstream calls |
| `C-tfstate-*` | Terraform state | Read who holds `storage.objects.get` on the state bucket | Static | Often contains SA keys and secrets in plaintext | Object read only if `DATA_READ` is on |
| `C-secret-*` | Secret Manager secret | `secretmanager.versions.access` holders | Until rotated | Whatever the secret is | `DATA_READ` on `secretmanager.googleapis.com` required |
| `C-ci-*` | CI secret (GHES Actions secret, vault-injected credential) | Ask; not enumerable from GCP | Until rotated | Usually an SA key — see `A3` in §4.5 | No GCP-side record of possession |
| `C-signed-*` | GCS signed URL | Not enumerable after issue | Issuer-chosen TTL | Bearer read on one object, from anywhere | Bearer credential: VPC-SC ingress/egress rules **cannot** express `ANY_SERVICE_ACCOUNT`/`ANY_USER_ACCOUNT` for signed-URL operations |
| `C-kube-*` | `kube-env` / kubelet bootstrap credentials on GKE nodes | Reachable at `169.254.169.254/computeMetadata/v1/instance/attributes/kube-env` when the node pool is `GCE_METADATA` | Node lifetime | Cluster bootstrap | Metadata reads are not audited |

Rule: any `C-key-*`, `C-hmac-*`, or `C-ci-*` row whose storage location is an on-prem interior host or
a CI secret store is a **standing** `AP-02` start position — score it as present, not hypothetical.

#### 4.2.3 Trust assets — table `TM-A3`

The link, the IdPs, and the pipeline each *confer* identity without an IAM binding appearing on the
data resource. One row each.

| `ID` | Trust relationship | Exact binding / config string | What it confers | Scoping condition observed | Revocation action |
|---|---|---|---|---|---|
| `T-wif-*` | WIF pool + provider | `oidc.issuerUri`, `attributeCondition` (CEL, verbatim), `allowed_audiences` | Which external subjects become GCP principals | The literal CEL text — an empty condition means every token the issuer signs is accepted | Delete provider (note: a deleted pool or provider can be **undeleted for 30 days**, so deletion is suspension, not destruction — see test `WI-10`) |
| `T-bind-*` | IAM binding to a federated principal | `principal://…/subject/…`, `principalSet://…/attribute.X/Y`, `principalSet://…/POOL/*` | Roles held by external subjects | `/*` = every identity in the pool | Remove the binding |
| `T-wfif-*` | Workforce pool | `principal://iam.googleapis.com/locations/global/workforcePools/POOL/subject/…` (no project number), `--session-duration`, `--disable-programmatic-signin` | Console + gcloud for on-prem humans without Cloud Identity accounts | Session duration; 12h ceiling on an admin-capable pool is a finding | Delete provider |
| `T-cicd-*` | Pipeline → project | Repo/pipeline identifier, runner placement, the SA it assumes, the projects it can deploy to | Deploy-time `actAs` and guardrail mutation | Branch/environment protection; WIF attribute condition if any | Remove the SA's roles or the runner's credential |
| `T-link-*` | Interconnect / HA VPN | VLAN attachment or tunnel, Cloud Router, advertised prefixes, learned prefixes | Bidirectional IP reachability, and (if `199.36.153.4/30` is advertised) the restricted-VIP API path for on-prem | Custom advertisements; firewall policy on both sides | Withdraw advertisement / delete attachment |
| `T-bridge-*` | Perimeter bridge | Bridge name + member projects | Mutual access between two perimeters' projects | Bridge membership list | Delete bridge |
| `T-al-*` | Access level naming on-prem ranges | `ipSubnetworks`, `members`, `devicePolicy`, `negate` | Perimeter entry by network position | Empty `ipSubnetworks` ⇒ all IPs; empty `members` ⇒ any user; unset `devicePolicy` ⇒ all devices | Detach from perimeter |
| `T-org-*` | Cross-org IAM binding / authorized-orgs descriptor | Binding member outside the org; `AuthorizedOrgsDesc` contents | External org treated as trusted | Domain-restricted sharing state | Remove binding / descriptor |

---

### 4.3 Trust-boundary register — table `TM-B`

Enumerate every boundary below. A boundary with no enforcement object is not a boundary — record it
as `ASPIRATIONAL` and treat everything on both sides as one zone for the rest of the review.

| Field | Fill with |
|---|---|
| `ID` | `B-nn` |
| `Boundary` | One of the classes below |
| `Edge A → Edge B` | Both endpoints named concretely (perimeter name ↔ "internet"; VPC + subnet ↔ on-prem CIDR; issuer URI ↔ pool) |
| `What crosses today` | Services/ports/methods actually observed crossing, from flow logs, VPC-SC dry-run violations, and effective routes |
| `Enforcement object` | The exact object: perimeter name, firewall policy + rule priority, `attributeCondition`, deny policy ID, PAB policy ID |
| `State` | `enforced` / `dry-run` / `absent` |
| `Mutators` | Principals holding the mutate permission (see *Who can mutate it* per class below) |
| `Violation evidence` | The log query that shows an attempted crossing |

Boundary classes to enumerate, with the mutate permission you must resolve principals for:

| Class | Edge definition | Mutate permission to resolve |
|---|---|---|
| `B-vpcsc-*` | Each service perimeter's edge, per direction (ingress and egress are separate rows) | `accesscontextmanager.servicePerimeters.update`, `.replaceAll`, `.commit`, `accesscontextmanager.accessLevels.update`, `accesscontextmanager.policies.setIamPolicy` |
| `B-link` | Cloud VPC subnets ↔ on-prem CIDRs, per direction | `compute.routers.update`, `compute.firewallPolicies.update`, `compute.networks.updatePolicy` |
| `B-inet` | Any VPC/serverless workload ↔ `0.0.0.0/0` | `compute.firewallPolicies.update`, `compute.routers.nats.create` (Cloud NAT), `compute.instances.create` with external IP |
| `B-idp-*` | External IdP issuer ↔ WIF pool (one row per provider) | `iam.workloadIdentityPoolProviders.update`, `…workloadIdentityPools.setIamPolicy` |
| `B-cicd-*` | Pipeline ↔ each project it deploys to (one row per pipeline×project) | Repo write + the deploy SA's `resourcemanager.projects.setIamPolicy` / `orgpolicy.policy.set` if held |
| `B-hier` | Org/folder policy inheritance edge — the boundary a project crosses by being **moved** | `resourcemanager.projects.update` / `.move`, `orgpolicy.policy.set` |
| `B-goog` | The Google-internal boundary: your org ↔ another Google Cloud org, crossed with **no packet on any network edge** (BigQuery sharing listing, cross-region dataset copy via `cross_region_copy`, disk-snapshot share, Analytics-Hub-style subscription) | `bigquery.datasets.setIamPolicy` / `bigquery.datasets.update`, `compute.snapshots.setIamPolicy`, custom constraints on BigQuery sharing resources |

`B-goog` is the boundary reviewers omit and the one no egress firewall, NAT log, or flow log observes.
Enumerate it explicitly or the review under-reports `AP-07`.

---

### 4.4 Questions to ask verbatim

Ask these exactly as written when the artifact set does not answer them. Record answers in the
appendix; mark every finding derived only from an answer as interview-derived.

1. "Name every project that holds `CONFIDENTIAL` data and every project that holds `NTK` data. If you
   cannot name them, say so — I will derive candidates from the asset export and you will confirm or
   correct the list."
2. "Does `CONFIDENTIAL` or `NTK` data flow from Google Cloud into the on-prem interior today? For each
   flow: the source resource, the destination host or share, the mechanism, and the identity that
   performs it."
3. "List every egress path out of the on-prem interior: internet proxy, data diode, media-transfer or
   burn station, vendor and partner links, patch and package mirrors, email or file-transfer gateways.
   For each, name the interior subnets that can reach it."
4. "Which interior services authorize callers by source IP or source subnet rather than by an
   authenticated identity? Name each and the port it listens on."
5. "Which external identity providers are trusted for Workload Identity Federation, who owns each
   tenant, and which service accounts may federated identities from each provider impersonate?"
6. "Which repositories or pipelines can deploy to the `CONFIDENTIAL` projects? For each: where the
   runner executes, what credential it obtains, and who can approve or bypass the merge gate."
7. "Is there a break-glass identity? Name the principal. Is it listed in any access level `members`
   list, any perimeter ingress rule `identities` list, or exempted in any `auditConfigs`
   `exemptedMembers`?"
8. "On an on-prem host, what does `dig storage.googleapis.com` return today — an address in
   `199.36.153.4/30`, an address in `199.36.153.8/30`, or a public Google front-end address?"
9. "Who, by name, may change an organization policy, a VPC Service Controls perimeter, an access
   level, a hierarchical firewall policy, or a log sink in production? Give principals, not teams."
10. "What is the intended list of cloud subnets permitted to originate traffic across the interconnect,
    and the intended list of on-prem prefixes permitted to reach cloud? I will diff it against the
    effective routes."

---

### 4.5 Adversary catalog

Instantiate every row. `Starting position` must be filled with what the adversary actually holds on
day zero **in this environment** — a principal class and a network location — because that pair is the
seed for the reachability computation in §6.

| ID | Adversary | Day-zero credential (principal class) | Network location | What they know | First move (exact) | Seeds |
|---|---|---|---|---|---|---|
| **A1** | External attacker with a stolen human credential | OAuth refresh token or session cookie for `user:NAME@DOMAIN`, lifted from `~/.config/gcloud/credentials.db` or an OAuth-consent phish. No enrolled device, no 2SV challenge on refresh | Arbitrary public internet IP, no VPC network context | The user's email and, once authenticated, the user's groups | `gcloud auth list` → `gcloud projects list` → `gcloud asset search-all-resources --scope=organizations/ORG_ID` | Graph node = that user + every group it belongs to; network = outside all perimeters |
| **A2** | Malicious or compromised insider, legitimate low privilege | `user:NAME@DOMAIN` in `grp-*` groups, holding viewer-class roles plus whatever group nesting confers; MFA satisfied; managed device | On-prem interior LAN, inside any `ipSubnetworks` range named by an access level | The estate: project names, wiki, runbooks, where the state bucket is | `gcloud asset analyze-iam-policy --identity=user:NAME@DOMAIN --analyze-service-account-impersonation --scope=organizations/ORG_ID` | The user, its groups, and every SA the analysis returns |
| **A3** | Compromised CI/CD or other federated workload | Whatever the runner obtains: an SA key delivered as a pipeline secret, a metadata-server token if the runner is a GCE VM or GKE pod, or an STS token if a WIF provider trusts the pipeline's issuer | The runner's placement — an on-prem runner VLAN, or a subnet in the build project. Determine which; the two produce different traversal maps | Repository contents, pipeline variables, the Terraform state location, the deploy SA's identity | Dump the environment, then `gcloud auth activate-service-account --key-file=…` or read `…/service-accounts/default/token`; then `terraform state pull` | The deploy SA + every project the pipeline targets |
| **A4** | Compromised service account / leaked SA key | Offline possession of a user-managed key JSON for `SA@PROJECT.iam.gserviceaccount.com`. No MFA, no device policy, no session expiry, no revocation until the key is deleted | Any host on the internet, or an interior host — the key does not care | `client_email` and `project_id` from the key file; nothing else until it enumerates | Self-signed JWT → OAuth token → `gcloud asset search-all-resources`; `gcloud projects get-iam-policy` on the owning project | The SA node, plus every SA it can impersonate |
| **A5** | Compromised on-prem host pivoting cloudward | Root on an interior host. **Assume-breach interior:** treat lateral reach inside the interior as unconstrained unless segmentation is evidenced | Interior subnet inside the prefixes learned over the interconnect; resolves DNS through the on-prem resolver | Nothing cloud-specific at first | Harvest `~/.config/gcloud/`, `*.json` keys, config-management vault, then `dig storage.googleapis.com` to learn whether API traffic takes the restricted VIP or a public front-end | Every credential found on the host + the interior network position |
| **A6** | Compromised application workload (SSRF/RCE) | The runtime SA attached to the workload — Cloud Run revision, GCE VM, GKE pod, Dataflow worker, Composer environment. Note whether that SA is the **Compute Engine default SA** (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) | Inside the VPC subnet, or serverless egress. Metadata server reachable at `169.254.169.254` / `metadata.google.internal` | Environment variables, mounted secrets, the SA's own scopes | `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`. For SSRF that cannot set headers, the `v1` endpoint requires `Metadata-Flavor: Google`; whether any header-less legacy endpoint still answers — verify against current docs | The runtime SA + its subnet |
| **A7** | Supply-chain compromise | Code execution inside the build or the runtime: a poisoned base image from Artifact Registry, a Terraform module, or a language-package dependency. Executes as the **build** SA at build time and as the **runtime** SA thereafter. In new projects the Cloud Build default is now the Compute Engine default SA | The build worker's network, then wherever the artifact is deployed | The build environment and everything the build SA can read | Read the build worker's metadata token; write a persistence artifact (extra SA key, extra IAM binding, backdoored image tag) | The build SA + every project that consumes the artifact |

For every adversary, also record: **does this environment's control set stop the first move, and with
which object?** "No control" is an acceptable answer and is itself the finding.

---

### 4.6 Attack-path catalog

Each path is an ordered chain. `AP-01`–`AP-13` are stable IDs; findings cite them. Mark each step
`REACHABLE` / `BLOCKED BY <object>` / `N/A`. A path is `LIVE` when every step is `REACHABLE`.

Column meanings: **Enabler** = the permission string, misconfiguration, or route that makes the step
possible. **Interrupt** = the control object that should stop it, named exactly. **ATT&CK** = technique
IDs from §4.9.

#### `AP-01` — Stolen credential hits a data API from outside the perimeter

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Authenticate with the stolen refresh token | No session-length limit; no `devicePolicy` on any access level | Cloud Identity session control + 2SV reauth; `T-al-*` with `devicePolicy` set | T1078.004 |
| 2 | Enumerate the estate | `cloudasset.assets.searchAllResources` held broadly | PAB policy on the principal set; IAM Deny on `cloudasset.googleapis.com/assets.searchAllResources` | T1580, T1087.004 |
| 3 | Call the data API from a public IP | Perimeter absent, in dry-run, or the service is missing from `restrictedServices` | **Enforced** perimeter over every data-bearing API; verify membership with `gcloud access-context-manager supported-services list` rather than a hardcoded list | T1530, T1213.006 |
| 4 | Download the objects/rows | `storage.objects.get`, `bigquery.tables.getData` | Deny policy on the read permission outside an authorized principal set. (`T1567.002` applies only if the read terminates on an endpoint/Workspace surface — `T1567`'s platform list is not IaaS-scoped, so do not cite it for an in-cloud GCP read; see §4.9.) | T1537, T1530 |

**Cheapest severing control:** step 3 — perimeter enforcement. Step 4 denies are per-service and drift.

#### `AP-02` — SA key exfiltrated and used offline

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Key exists | `iam.serviceAccountKeys.create` held; `constraints/iam.managed.disableServiceAccountKeyCreation` not enforced | Enforce the managed constraint at the org node (it also covers GCS HMAC keys; the legacy `constraints/iam.disableServiceAccountKeyCreation` is documented narrower) | T1098.001 |
| 2 | Key reaches an untrusted location | Key file in CI secret store, on an interior host, or in Terraform state | Deny `iam.googleapis.com/serviceAccountKeys.create` at the folder; replace with WIF or metadata-server credentials | T1552.001 |
| 3 | Offline JWT → OAuth token | Key material signs its own assertion; **no IAM Credentials call, no `iamcredentials` log entry** | None at the token layer — this is why step 1 is the control point | T1078.004, T1550.001 |
| 4 | Read data from any IP | Perimeter absent, or an ingress rule admits `ANY_SERVICE_ACCOUNT` | Enforced perimeter; replace `ANY_SERVICE_ACCOUNT` with named identities | T1530 |

#### `AP-03` — Impersonation chain to a high-privilege SA, then egress via a public API endpoint

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Hold impersonation on some SA | `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` bound at **project** level rather than on a specific SA | Re-bind on the specific SA only; IAM Deny on `iam.googleapis.com/serviceAccounts.getAccessToken` outside a named principal set | T1548.005 |
| 2 | Mint a token | `iam.serviceAccounts.getAccessToken` → `GenerateAccessToken` | Same deny; PAB on the calling principal | T1548.005, T1550.001 |
| 3 | Chain to the next SA | The intermediate SA also holds `tokenCreator`, or `iam.serviceAccounts.implicitDelegation` via the `delegates[]` field | Follow chains to fixpoint before remediating; sever the cheapest intermediate hop | T1021.007 |
| 4 | Read the data as the terminal SA | The terminal SA's data roles | Deny the read permission for SA principals outside the owning service | T1530, T1213.006 |
| 5 | Egress to a public endpoint | Perimeter missing the destination service, or an egress rule permits it | Perimeter + egress rule scoped to named identities and services | T1537 |

> `signJwt`/`signBlob` are a parallel step 2: `roles/iam.serviceAccountTokenCreator` includes
> `iam.serviceAccounts.signJwt` and `.signBlob`, which yield credentials without `GenerateAccessToken`.
> `roles/iam.workloadIdentityUser` contains **only** `getAccessToken` and `getOpenIdToken` — do not
> treat the two roles as equivalent.

#### `AP-04` — Data staged into a bucket/dataset with public or over-broad access

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Create or select a staging resource | `storage.buckets.create`, `bigquery.datasets.create` | `constraints/gcp.restrictServiceUsage`; project-per-workload so staging cannot be co-located | T1074.002 |
| 2 | Copy data in | `storage.objects.create`, BigQuery `EXPORT DATA OPTIONS(uri='gs://…')`, `bq extract` | Perimeter must cover **both** `bigquery.googleapis.com` **and** `storage.googleapis.com`; deny `bigquery.tables.export` | T1530, T1074.002 |
| 3 | Widen access | `storage.buckets.setIamPolicy` / `storage.objects.setIamPolicy` granting `allUsers`/`allAuthenticatedUsers`; or object ACLs where uniform bucket-level access is off | `constraints/storage.publicAccessPrevention` enforced at the org node; `constraints/storage.uniformBucketLevelAccess`; `constraints/iam.managed.allowedPolicyMembers` | T1098.003 |
| 4 | Read from outside | Public object read; or a **signed URL**, which is a bearer credential no identity-based perimeter rule can express | `constraints/storage.restrictAuthTypes`; deny `iam.serviceAccounts.signBlob`; short TTLs. (`T1567.002` applies only if the read terminates on an endpoint/Workspace surface — `T1567`'s platform list is not IaaS-scoped; see §4.9.) | T1537, T1530 |

#### `AP-05` — Egress via VM external IP or an open egress rule to `0.0.0.0/0`

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Obtain compute in the data VPC | `compute.instances.create` + `iam.serviceAccounts.actAs`; or an existing workload (see `A6`) | Deny `actAs` on privileged SAs outside their owning service | T1578.002 |
| 2 | Give it an internet path | External IP (`constraints/compute.vmExternalIpAccess` / `constraints/compute.managed.vmExternalIpAccess` unset), or Cloud NAT (`constraints/compute.restrictCloudNATUsage` unset), or a Cloud Run service left at `--vpc-egress=private-ranges-only` so its public egress never traverses the VPC at all | Enforce both external-IP constraints; `constraints/run.allowedVPCEgress` pinned to `all-traffic`; default-deny egress firewall policy | — |
| 3 | Read the data | Workload SA's read permissions | Least-privilege runtime SA; never the Compute Engine default SA | T1530 |
| 4 | Push it out | Egress rule permitting `0.0.0.0/0`; assess with `gcloud compute networks get-effective-firewalls`, **not** `gcloud compute firewall-rules list`, which misses hierarchical and network-policy rules | Default-deny egress with explicit allows; firewall rules logging enabled | T1048 |

> Additional step-2 variants to test in the same table: **packet mirroring** to a collector the attacker
> controls (`roles/compute.packetMirroringAdmin` + `roles/compute.packetMirroringUser`) — a
> full-fidelity copy with no egress rule from the victim VM; and a **Cloud DNS outbound server policy
> or forwarding zone** pointed at an attacker resolver, where packets leave from Google's
> `35.199.192.0/19` range and no VM-level egress rule sees them.

#### `AP-06` — Exfil via a PSC endpoint, or across the interconnect into the soft interior

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Create or reuse a PSC endpoint | `compute.forwardingRules.create` with `--target-google-apis-bundle=all-apis`, or targeting a **service attachment in another organization** | `constraints/compute.disablePrivateServiceConnectCreationForConsumers`; `constraints/compute.restrictPrivateServiceConnectProducer`; require the `vpc-sc` bundle | — |
| 2 | Send data to it | The endpoint is a single internal IP: an egress `deny 0.0.0.0/0` with an RFC1918 allow leaves it open, and `dest_network_scope = INTERNET` does not catch it | Explicit egress deny to endpoint IPs; VPC flow logs on the client subnet (they do record PSC flows when enabled on both subnets) | T1537 |
| 3 | Alternative: cross the interconnect | Cloud subnet permitted to originate traffic across the link; interior destination reachable per effective routes | Firewall policy on the link keyed on secure tags/service accounts; withdraw unnecessary advertisements | T1021.007 |
| 4 | Land in the flat interior | Interior service that authenticates by network position | Every network-position-trusting interior service reachable from cloud is a finding in its own right | — |
| 5 | Leave via an interior egress path | Proxy, media transfer, vendor link, patch mirror reachable from where the data landed | Segmentation between the landing zone and the egress path; see §7 | T1048 |

> VPC-SC applies to Google API traffic through PSC endpoints. It has **no jurisdiction** over a PSC
> endpoint pointed at a third-party published service — state that distinction in the finding.

#### `AP-07` — BigQuery/Storage export or copy into an attacker-controlled external project

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Hold read on the source | `bigquery.tables.getData` / `storage.objects.get` | Deny outside an authorized principal set; BigQuery authorized views instead of dataset grants | T1213.006 |
| 2 | Pick a copy mechanism | Cross-region/cross-project dataset copy via BigQuery Data Transfer Service (data source `cross_region_copy`, schedulable as a recurring transfer); `bq cp`; cross-region replication; disk-snapshot share; Storage Transfer Service | Perimeter must include `bigquerydatatransfer.googleapis.com` and `storagetransfer.googleapis.com`, not only `bigquery.googleapis.com`/`storage.googleapis.com`; `constraints/gcp.resourceLocations` to block the destination region | T1537 |
| 3 | Or share instead of copy | A **BigQuery sharing listing** in a data exchange hands an entire dataset (or a Pub/Sub topic) to an external org, read in place, **no data movement to detect** | Custom org policy constraints on BigQuery sharing resources (enforceable on CREATE/UPDATE only); `constraints/iam.managed.allowedPolicyMembers` to stop external subscribers | T1537 |
| 4 | Or leave Google entirely | **BigQuery Omni** exports query results to Amazon S3 / Azure Blob — VPC-SC does not follow the data | Disable Omni connections; `constraints/gcp.restrictServiceUsage` | T1537 |

**This is the path where no packet crosses a network boundary.** Register it as `B-goog` in `TM-B`.

#### `AP-08` — Leakage through logging/monitoring sinks or exported telemetry

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Create or repoint a sink | `logging.sinks.create` / `logging.sinks.update` (`roles/logging.configWriter`, `roles/logging.admin`, plus `roles/owner`/`roles/editor`) | Deny sink-write permissions outside the logging admin group; bind logging admin at the common folder only | T1537 |
| 2 | Point it outside | Destination URIs accept a `PROJECT_ID` **outside the org**: `storage.googleapis.com/BUCKET`, `bigquery.googleapis.com/projects/P/datasets/D`, `pubsub.googleapis.com/projects/P/topics/T` | VPC-SC egress rules; check the sink's `writerIdentity` for grants in unfamiliar projects | T1537 |
| 3 | Harvest | Logs carry query text, resource names, principal identities, and sometimes payloads | `constraints/gcp.detailedAuditLoggingMode` raises the value of the logs — so it also raises the value of this path; keep the aggregated sink's destination in a project workload principals cannot write to | T1530 |
| 4 | Or chain to Pub/Sub push | A Pub/Sub destination plus a push subscription to an attacker HTTPS endpoint; Pub/Sub does not verify ownership of the push URL domain | Inside a perimeter, **new** push subscriptions are limited to a Cloud Run `run.app` URL or a Workflows execution — but **pre-existing push subscriptions survive perimeter creation**; enumerate and recreate them | T1567.004 |

#### `AP-09` — Break-glass abuse

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Obtain the break-glass credential | Standing (not deny-by-default) grant; shared vault entry; no dual control | Deny-by-default in normal state; time-boxed, MFA-gated, dual-control activation | T1078 |
| 2 | Activate | No time box, no approval record | Just-in-time elevation with an approval artifact | T1548.005 |
| 3 | Cross the perimeter | The break-glass principal is listed in an access level `members` list or a perimeter ingress rule `identities` list — i.e. **the emergency identity bypasses VPC-SC** | Remove it from access levels and ingress rules; if an emergency bypass is required, make it a separate, alerted, time-boxed perimeter change instead of a standing identity carve-out | — |
| 4 | Read and exfiltrate | Whatever the role grants | Post-use mandatory review with a named reviewer and a deadline | T1530, T1537 |

> Also check `auditConfigs.exemptedMembers` for the break-glass principal. A principal listed there
> generates **no Data Access log** — that combination makes `AP-09` undetectable by construction.
> Super admins sit above every control in this review: they can grant themselves any role at the org
> node, so super-admin count and 2SV posture are prerequisites, not optional checks.

#### `AP-10` — WIF over-trust: an external principal impersonates an SA it shouldn't

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Obtain a token from the trusted issuer | The issuer is **shared** (a multi-tenant CI platform): it signs a valid token for every tenant on the platform | Nothing — the issuer is not yours to control | T1199 |
| 2 | Pass the pool gate | `attributeCondition` empty, or present but useless (`assertion.sub != ""`), or pinning only `assertion.ref == 'refs/heads/main'` — an attacker names their branch `main` | Condition pinning immutable tenant identifiers (`assertion.repository_owner_id`, `assertion.repository_id`), not names; a **custom org policy on `resource.attributeCondition`** is the only documented way to require a non-empty condition org-wide | T1199 |
| 3 | Exchange at STS | `google.identity.sts.v1.SecurityTokenService.ExchangeToken` | `constraints/iam.workloadIdentityPoolProviders` restricts allowed issuer URIs — but **only on create/update**: a provider configured before enforcement keeps working | T1550.001 |
| 4 | Impersonate the SA | `roles/iam.workloadIdentityUser` bound to `principalSet://…/workloadIdentityPools/POOL/*` | Bind on `principalSet://…/attribute.NAME/VALUE` scoped to one repo/environment; prefer direct resource grants over impersonation — impersonation inherits everything the SA holds everywhere | T1548.005 |
| 5 | Read and exfiltrate | The SA's data roles, plus any further impersonation the SA can reach | PAB on federated principals as a hard cap independent of IAM | T1530, T1537 |

> Provider takeover variants to test in the same table: `attribute.repository_owner` mapped from the
> **name** claim rather than `repository_owner_id` (org-rename/typosquat takeover); `google.subject`
> mapped to a mutable claim such as `assertion.actor`; a custom `allowed_audiences` value that removes
> the confused-deputy protection of the default audience.
>
> **Air-gapped GHES:** OIDC-based WIF is not achievable — Google must fetch
> `https://HOSTNAME/_services/token/.well-known/jwks` and GitHub requires the `iss` claim be a publicly
> routable URL. If the environment claims WIF from an air-gapped GHES, the credential in use is
> something else (almost always an SA key delivered as a pipeline secret); find it and score it as
> `AP-02`. A static-JWKS workaround is undocumented — verify against current docs before designing
> around it.

#### `AP-11` — Multi-hop escalation (six named variants)

Each variant terminates at a principal that can read `CONFIDENTIAL` or `NTK` data. Cross-reference each to the primitive
hunt list in §6.2.

**`AP-11a` — Project-level impersonation grant → chained impersonation → data SA**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Foothold principal is in a group holding `roles/iam.serviceAccountTokenCreator` at project scope | Project-level binding silently confers impersonation of **every** SA in the project, including the default compute SA | Re-bind on specific SAs; SCC detector `PROJECT_LEVEL_SERVICE_ACCOUNT_TOKEN_CREATOR_ROLE_ADDED` for future grants | T1548.005 |
| 2 | Impersonate SA-B | `iam.serviceAccounts.getAccessToken` | IAM Deny at the folder for `iam.googleapis.com/serviceAccounts.getAccessToken` outside a named principal set | T1550.001 |
| 3 | SA-B impersonates SA-C | SA-B also holds tokenCreator, or `implicitDelegation` | Break the cheapest intermediate hop, not the last one | T1021.007 |
| 4 | SA-C reads `CONFIDENTIAL` | SA-C's data roles | PAB on SA-C's principal set | T1530 |

**`AP-11b` — `actAs` on a compute surface → metadata token**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Hold `iam.serviceAccounts.actAs` plus a create/update permission on any compute surface | `compute.instances.create`; Cloud Run/Cloud Run functions deploy; Cloud Build trigger edit; Dataflow/Dataproc/Composer/Vertex AI Workbench job create; Cloud Scheduler/Cloud Tasks with an attached SA | Deny `iam.googleapis.com/serviceAccounts.actAs` on privileged SAs outside their owning service; `constraints/iam.disableCrossProjectServiceAccountUsage` | T1578.002, T1648 |
| 2 | Or take over an existing VM | `compute.instances.setMetadata` (one VM: inject `ssh-keys` or `startup-script`) or `compute.projects.setCommonInstanceMetadata` (**every VM in the project**) | `constraints/compute.managed.requireOsLogin` — and note that instance metadata `enable-oslogin=FALSE` overrides project `TRUE` unless the constraint is enforced | T1098.004 |
| 3 | Read the token | `GET /computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google`. **VPC-SC does not apply to metadata-server traffic and no firewall rule filters it** | Nothing at the network layer — sever at step 1 or 2 | T1552.005 |
| 4 | Read data as that SA | The attached SA's roles; `cloud-platform` scope broadens what the token may do | Never attach the Compute Engine default SA; enforce `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` so it does not carry `roles/editor` | T1530 |

**`AP-11c` — Custom-role mutation (no binding ever changes)**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Principal already holds custom role `R` | Any existing binding | — | — |
| 2 | Add permissions to `R` | `iam.roles.update` (`roles/iam.roleAdmin`, `roles/iam.organizationRoleAdmin`). A principal **can add permissions it does not itself hold**; the only documented limits are the custom-role support level and the org/project scope rule | Deny `iam.googleapis.com/roles.update` and `roles.create` outside a named principal set; alert with filter `F5` | T1098.003 |
| 3 | Read data | The new permission (e.g. `bigquery.tables.getData`) | PAB caps reach regardless of the role's contents | T1530 |

> Diff-based review misses this entirely: the IAM policy is byte-identical before and after. Also watch
> `iam.roles.undelete` — restoring a previously removed over-privileged role is a persistence primitive.

**`AP-11d` — Resource-level `setIamPolicy` (project IAM never touched)**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Hold `setIamPolicy` on the data resource itself | `storage.buckets.setIamPolicy`, `storage.objects.setIamPolicy`, `bigquery.datasets.setIamPolicy` **and** `bigquery.datasets.update` (which still mutates ACLs on datasets that have not opted into fine-grained ACLs), `bigquery.tables.setIamPolicy`, `pubsub.topics.setIamPolicy`, `pubsub.subscriptions.setIamPolicy`, `cloudkms.cryptoKeys.setIamPolicy`, `secretmanager.secrets.setIamPolicy`, `artifactregistry.repositories.setIamPolicy` | Deny the v2 forms (`storage.googleapis.com/buckets.setIamPolicy`, `bigquery.googleapis.com/datasets.setIamPolicy`, `bigquery.googleapis.com/datasets.update`, …) at org/folder | T1098.003 |
| 2 | Grant self a read role on that resource | Same permission | Same | T1098.003 |
| 3 | Read | The granted role | PAB | T1530 |

> Auditing only `resourcemanager.projects.setIamPolicy` misses this whole class.

**`AP-11e` — Group-write escalation (no IAM change appears anywhere)**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Hold the ability to modify membership of a group that carries IAM roles | Group owner/manager rights; nested groups where the outer group's roles are not obvious from the inner group | Restrict group-membership management; forbid nesting for role-bearing groups | T1098.007 |
| 2 | Add self (or a controlled principal) | Membership change | SCC `SENSITIVE_ROLE_TO_GROUP_WITH_EXTERNAL_MEMBER`, `EXTERNAL_MEMBER_ADDED_TO_PRIVILEGED_GROUP` | T1098.007 |
| 3 | Read data | Inherited role | PAB on the principal, which group membership cannot widen | T1530 |

> **Detection dependency:** group-membership changes appear in Cloud Audit Logs only when Google
> Workspace data sharing with Google Cloud is enabled, and then only at the **organization** node.
> Otherwise the evidence exists solely in Workspace Admin/Groups audit. Record which case applies.

**`AP-11f` — Two-step guardrail precursor (each step looks benign alone)**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Remove the constraint | `orgpolicy.policy.set` / `orgpolicy.policies.update` on `constraints/iam.managed.disableServiceAccountKeyCreation` or `constraints/storage.publicAccessPrevention` | Bind org-policy admin at the org node only, to a group that cannot deploy workloads; alert with filter `F7` | T1685 (analyst mapping) |
| 2 | Perform the now-permitted action | `iam.serviceAccountKeys.create` on a data-tier SA; or `storage.buckets.setIamPolicy` granting `allUsers` | An IAM Deny rule is unaffected by an org-policy change — deny evaluates before allow, so it survives step 1. It can still be **deleted** with `iam.denypolicies.delete` (`roles/iam.denyAdmin`, `roles/iam.principalAccessBoundaryUser` for PAB unbind), so treat deny-admin and PAB-user as tier-0 principals | T1098.001 |
| 3 | Use the artifact | Offline key (`AP-02`) or public object (`AP-04`) | — | T1537 |

> Model this as one chain. Reviews that score each step independently rate both as low and miss the
> pair. The general rule: **any guardrail whose only enforcement is org policy can be removed by a
> single principal; guardrails that matter need an IAM Deny or PAB layer underneath.** Two worked
> instantiations — `AP-11f-1` (key-creation flip → key mint) and `AP-11f-2` (domain-restriction flip
> → external grant) — are stepped out with actor, log entry and sever in §6.2.3.

#### `AP-12` — Cross-boundary traversal (five named variants)

**`AP-12a` — Cloud workload → interconnect → flat interior → interior egress**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Compromise a workload with link access (`A6`) | The subnet is permitted to originate traffic across the link | Per-service subnets; firewall policy keyed on secure tags or service accounts, not IP ranges | T1190 |
| 2 | Reach an interior service | Effective routes permit it; the service authorizes by source IP | Every network-position-trusting interior service reachable from cloud is a finding | T1046 |
| 3 | Stage data there | Interior share/DB with no authentication | Segment the landing zone from the rest of the interior | T1074.002 |
| 4 | Egress from the interior | Proxy / media transfer / vendor link / patch mirror reachable from the landing zone | Enumerate interior egress paths and prove the landing zone cannot reach them | T1048 |

**`AP-12b` — Interior host → cached cloud credential → cloud data**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Root on an interior host (`A5`) | Assume-breach interior | — | — |
| 2 | Harvest credentials | `~/.config/gcloud/credentials.db`, `application_default_credentials.json`, SA key JSON on jump boxes, config-management vault entries, artifact-store secrets | Eliminate long-lived keys on interior hosts; where the runner can live in GCP, use the metadata server or Workload Identity Federation for GKE instead | T1552.001, T1528 |
| 3 | Call the API | Credential works from any network position | Access level with `devicePolicy` + `members`; prefer an **ingress rule** naming identities over an IP-only access level | T1078.004 |
| 4 | Read and pull back to the interior | Data roles held by the harvested principal | PAB on that principal | T1530 |

**`AP-12c` — On-prem DNS resolves `*.googleapis.com` publicly, so the perimeter never sees the request as internal**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Interior host resolves `storage.googleapis.com` | On-prem resolver returns a public Google front-end instead of `199.36.153.4/30` | On-prem DNS maps `*.googleapis.com` → `restricted.googleapis.com`; Cloud DNS inbound forwarding policy in the VPC the link terminates on | — |
| 2 | Traffic takes the public path | Cloud Router does not advertise `199.36.153.4/30` (or a **BGP-session-level** custom advertisement overrides the router-level one and drops it) | `gcloud compute routers update … --advertisement-mode custom --set-advertisement-ranges=199.36.153.4/30` at the level actually in effect; verify with `gcloud compute routers get-status` / `list-bgp-routes` | — |
| 3 | Request arrives without the perimeter's network context | Admission now depends entirely on access levels and ingress rules | Ingress rules naming identities; block the public Google front-end ranges on the interior egress path | T1078.004 |
| 4 | Read `CONFIDENTIAL` data | Data roles | Perimeter + PAB | T1530 |

> Using `private.googleapis.com` (`199.36.153.8/30`) where `restricted.googleapis.com` was intended is
> the same finding by another route: it permits every API VPC-SC does not support. Check the DNS zone
> records, not the design document. The same distinction exists for PSC-for-Google-APIs bundles:
> require `--target-google-apis-bundle=vpc-sc`, never `all-apis`.

**`AP-12d` — On-prem host reaches a PSC endpoint or private service endpoint in cloud**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Interior host routes to the endpoint's internal IP | The endpoint's subnet is advertised over the link | Do not advertise PSC endpoint subnets to on-prem unless a documented flow requires it | — |
| 2 | Call the service | Endpoint has no identity-based authorization in front of it | Identity-based auth (OIDC ID token with a specific SA as the only authorized invoker; IAP; mTLS) rather than reachability | — |
| 3 | Pull data back into the interior | Service returns data | Per-service PSC endpoints, not one shared endpoint | T1530 |

**`AP-12e` — Sanctioned cloud→interior flow becomes the exfil channel**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | A legitimate flow moves `CONFIDENTIAL` data into the interior | Storage Transfer job, database replica, log/telemetry export, application-level sync | Decide explicitly whether the flow is permitted at that classification, and record the decision | — |
| 2 | The data lands where no cloud control applies | The interior has no classification-aware control | Compensating interior control, named; if none exists, the flow is the finding | — |
| 3 | It moves laterally in the flat interior | Assume-breach interior | Segmentation between the landing zone and the rest | — |
| 4 | It leaves through an interior egress path the cloud review never modelled | Any sanctioned egress reachable from the landing zone | Enumerate every interior egress path (question 3 above) and prove non-reachability | T1048 |

#### `AP-13` — Control-plane subversion (six named variants)

The attacker modifies the guardrail rather than evading it. For each variant, record who holds the
mutate permission **today**.

**`AP-13a` — Organization policy mutation**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Change or delete the policy | `orgpolicy.policy.set`, `orgpolicy.policies.update`, `orgpolicy.policies.delete` (`roles/orgpolicy.policyAdmin`). Note `orgpolicy.policy.get`/`.set` (v1, singular) and `orgpolicy.policies.*` (v2, plural) both exist; there is **no** `orgpolicy.policies.get`, so a deny rule or custom role written against that string matches nothing | Bind org-policy admin at the org node only, separated from workload-deploy identities; IAM Deny on the mutate permissions outside that group | T1685 (analyst mapping) |
| 2 | Exploit the now-absent constraint | See `AP-11f` | Deny/PAB layer under every load-bearing constraint | — |

**`AP-13b` — VPC-SC perimeter / access-level mutation**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Widen the boundary | `accesscontextmanager.servicePerimeters.update`/`.replaceAll`/`.commit`, `accesscontextmanager.accessLevels.update`, or add an `AuthorizedOrgsDesc` widening the trusted-org list | Custom org policy constraints on Access Context Manager resources; IAM Deny on the mutate permissions; note **basic roles can dismantle perimeters** | T1578 (Defense Impairment) |
| 2 | Exfiltrate through the widened boundary | Any of `AP-01`, `AP-03`, `AP-07` | — | T1537 |

**`AP-13c` — Detection pipeline sabotage**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Blind the pipeline | `logging.sinks.delete`/`.update`, `logging.exclusions.create` (an exclusion drops logs **at ingest**, and log-based alerting policies explicitly do not operate on excluded logs), `logging.buckets.update` (shorten retention), `logging.settings.update` (repoint CMEK so stored logs become unreadable), or `setIamPolicy` adding `auditConfigs.exemptedMembers` | Aggregated org-level sink into a project workload principals cannot write to; **lock the log bucket after setting retention** (locking first pins 30 days permanently); route the sink-mutation alert outside the pipeline being mutated | T1685.002 |
| 2 | Run any other path unobserved | — | `_Required` (Admin Activity, System Event, Access Transparency) is immutable and 400 days — it survives sink deletion. Data Access and Policy Denied route to `_Default` at 30 days and do not | — |

**`AP-13d` — Firewall policy change**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Add a permissive egress rule or delete a deny | `compute.firewallPolicies.update` (hierarchical, org/folder) or network-firewall-policy update (project-scoped). These are **different objects** — collect both | Hierarchical policy at folder level with the deny rules the project cannot override; alert on firewall-policy mutation | T1686.001 |
| 2 | Egress | `AP-05` | — | T1048 |

**`AP-13e` — IaC pipeline compromise**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Land a change in the repo | Repo write, or a workflow-file edit on a branch the runner will execute | Branch protection + required review by a principal who cannot also approve; policy-as-code gate on the guardrail files | T1677 |
| 2 | The deploy identity applies it | The deploy SA holds `resourcemanager.projects.setIamPolicy` or `orgpolicy.policy.set` | **Separate the identity that deploys workloads from the identity that changes guardrails** — the deploy SA should hold neither permission | T1098.003 |
| 3 | Or read the state | `storage.objects.get` on the Terraform state bucket; state routinely contains secrets | Restrict state-bucket read to the pipeline SA; enable `DATA_READ` on that bucket | T1552.001 |
| 4 | Guardrail removed with an approved change record | — | Alert on guardrail-object mutation regardless of whether it came from the pipeline | — |

**`AP-13f` — Hierarchy move**

| # | Step | Enabler | Interrupt | ATT&CK |
|---|---|---|---|---|
| 1 | Move the project | `resourcemanager.projects.update` / project-move permission (`gcloud projects move`) | Deny project-move outside a named group; alert on it | T1666 |
| 2 | Project sheds inherited org policies and folder-level firewall policies | Inheritance is by position in the hierarchy | Attach guardrails that must not be shed at the **org** node, not at a folder | T1666 |
| 3 | Project leaves the perimeter's resource list, or lands where no perimeter applies | Perimeter membership is a project list | Alert on perimeter `resources[]` changes; reconcile perimeter membership against the asset export on a schedule | T1578 |
| 4 | Exfiltrate | Any path | — | T1537 |

> Related shedding move: creating resources in a region nobody monitors (`T1535`), countered by
> `constraints/gcp.resourceLocations`.

---

### 4.7 Detection posture

Record this for **every** path and every variant. A path with no row here is not assessed.

#### 4.7.1 Worksheet shape — table `TM-D`

| Field | Fill with |
|---|---|
| `Path/step` | e.g. `AP-11a/2` |
| `Emits` | The exact `protoPayload.methodName`, or `NONE` |
| `serviceName` | e.g. `iamcredentials.googleapis.com` |
| `Log type` | `ADMIN_ACTIVITY` / `DATA_ACCESS` / `POLICY_DENIED` / `SYSTEM_EVENT` / `NONE` |
| `On by default` | `YES` (Admin Activity, System Event, Policy Denied — cannot be disabled) / `NO` (Data Access, except BigQuery) |
| `Enabled here` | From the effective `auditConfigs` at the nearest node; record `exemptedMembers` if non-empty |
| `Retention` | `_Required` = 400 days fixed; `_Default` = 30 days unless routed to a longer-retention bucket |
| `Filter` | Filter ID from the library below, or the query you wrote |
| `Alerting` | Alert policy name + destination, or `NONE`. A log-based alerting policy has exactly one condition and does **not** operate on excluded logs |
| `Detection state` | `LOGGED+ALERTED` (3) / `LOGGED-NOT-ALERTED` (2) / `LOGGABLE-NOT-ENABLED` (1) / `UNLOGGED` (0) |

#### 4.7.2 Expected emitters per path

Pre-filled so the reviewer verifies rather than guesses. All method names below are as documented;
where a name is unverified the row says so and the filter falls back to `serviceName`.

| Path | Pivotal step | Expected `protoPayload.methodName` | Log type | Default on | Filter |
|---|---|---|---|---|---|
| `AP-01` | Data read from outside | `storage.objects.get` / `storage.objects.list`; BigQuery job methods — verify against current docs | DATA_ACCESS | **NO** (BigQuery is the documented exception) | `F14`, `F16` |
| `AP-01` | Perimeter denial | — (`VpcServiceControlAuditMetadata`) | POLICY_DENIED | YES (30-day retention) | `F12` |
| `AP-02` | Key creation | `google.iam.admin.v1.CreateServiceAccountKey`, `google.iam.admin.v1.UploadServiceAccountKey` | ADMIN_ACTIVITY | YES | `F4` |
| `AP-02` | Offline key use | **NONE at mint time** — the JWT is signed locally | — | — | Detect only at the data call (`F14`/`F16`) |
| `AP-03`, `AP-11a` | Token minting | `GenerateAccessToken`, `GenerateIdToken`, `SignJwt`, `SignBlob` — **bare method names**, `serviceName="iamcredentials.googleapis.com"` | DATA_ACCESS | **NO** | `F2` |
| `AP-04` | Public grant | `storage.setIamPermissions`; HMAC key `storage.hmacKeys.create` | ADMIN_ACTIVITY | YES | `F9` |
| `AP-05` | Firewall change | `compute.googleapis.com` firewall-policy methods — verify against current docs | ADMIN_ACTIVITY | YES | `F17` |
| `AP-06` | PSC endpoint create | Forwarding-rule create method — verify against current docs | ADMIN_ACTIVITY | YES | `F17` |
| `AP-07` | Copy/share | BigQuery Data Transfer, dataset copy, sharing listing methods — verify against current docs | DATA_ACCESS / ADMIN_ACTIVITY | mixed | `F16` |
| `AP-08` | Sink mutation | `google.logging.v2.ConfigServiceV2.CreateSink` / `UpdateSink` / `DeleteSink` / `CreateExclusion` (verify against current docs) | ADMIN_ACTIVITY | YES | `F10` |
| `AP-09` | Break-glass use | Depends on the identity; SCC ETD custom module template `Breakglass Account Used` matches a named principal | ADMIN_ACTIVITY | YES | `F1` + named-principal filter |
| `AP-10` | STS exchange | `google.identity.sts.v1.SecurityTokenService.ExchangeToken` | DATA_ACCESS | **NO** | `F3` |
| `AP-10` | Provider mutation | `google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider` / `UpdateWorkloadIdentityPoolProvider` / `SetAttestationRules` | ADMIN_ACTIVITY | YES | `F6` |
| `AP-11b` | Metadata token read | **NONE** — metadata-server reads are not audited and VPC-SC does not apply to them | — | — | Detect at step 1 (`actAs`) or at the data call |
| `AP-11b` | `actAs` at deploy | The consuming service's create/update method (Compute, Cloud Run, Cloud Build, Dataflow…) — **not** an `iamcredentials` entry | ADMIN_ACTIVITY | YES | `F17` |
| `AP-11c` | Role mutation | `google.iam.admin.v1.CreateRole` / `UpdateRole` / `UndeleteRole` | ADMIN_ACTIVITY | YES | `F5` |
| `AP-11d` | Resource-level grant | `google.iam.admin.v1.SetIAMPolicy` (**capital `IAM`**), `storage.setIamPermissions`, per-service equivalents | ADMIN_ACTIVITY | YES | `F1`, `F4`, `F9` |
| `AP-11e` | Group membership change | Present in Cloud Audit Logs **only** with Workspace data sharing enabled, and then only at the org node | ADMIN_ACTIVITY (org node) | conditional | `F19` |
| `AP-11f`, `AP-13a` | Org policy change | `google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy` / `DeletePolicy` / `DeleteCustomConstraint`; v1 path `cloudresourcemanager.v1.organizations.setOrgPolicy` | ADMIN_ACTIVITY | YES | `F7` |
| `AP-12c` | Public-path API call from on-prem | The data method itself; `protoPayload.requestMetadata.callerIp` shows the on-prem NAT public IP, and `caller_network` is absent for cross-org callers | DATA_ACCESS | **NO** | `F14`/`F16` |
| `AP-13b` | Perimeter change | `google.identity.accesscontextmanager.v1.AccessContextManager.UpdateServicePerimeter` / `CreateAccessLevel` / `UpdateAccessLevel` / `CreateAuthorizedOrgsDesc` | ADMIN_ACTIVITY | YES | `F8`, `F15` |
| `AP-13c` | Audit-config change | `setIamPolicy` carrying `auditConfigs` — no dedicated method name exists | ADMIN_ACTIVITY | YES | `F11` (partial — verify against current docs) |
| `AP-13f` | Project move | Resource Manager move method — verify against current docs | ADMIN_ACTIVITY | YES | `F18` |

Two facts that decide most of this table:

- **Every impersonation and federation event is a Data Access log and is therefore off by default.**
  The permission types split: `ADMIN_READ` covers `GenerateAccessToken` and `SignJwt`; **`DATA_READ`
  covers `GenerateIdToken`, `SignBlob` and `SignJwt`.** The `auditConfigs` entry must therefore carry
  **both** `ADMIN_READ` and `DATA_READ` for `iam.googleapis.com` — enabling it for the IAM API also
  enables it for the Service Account Credentials API, so you do **not** add an
  `iamcredentials.googleapis.com` entry; that string is the `serviceName` you *filter* on — and both
  for `sts.googleapis.com` (`ExchangeToken`). An `ADMIN_READ`-only config leaves ID-token minting and
  blob signing invisible. If the environment has not enabled them, every impersonation path scores as
  undetected.
- **These calls are long-running operations**, so one impersonation typically yields two entries
  (start and end). Do not build threshold alerts that count raw entries.

#### 4.7.3 Filter library

Paste as-is into Logs Explorer or `gcloud logging read`. Filters marked *(requires Data Access)*
return nothing until the corresponding `auditConfigs` entry exists.

`F1` — IAM policy change at project/folder/org, all API versions:
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="cloudresourcemanager.googleapis.com"
protoPayload.methodName:"setIamPolicy"
```

`F2` — impersonation / token minting *(requires Data Access **`ADMIN_READ` and `DATA_READ`** in `auditConfigs` for **`iam.googleapis.com`** — enabling it for the IAM API also enables it for the Service Account Credentials API. `ADMIN_READ` alone covers `GenerateAccessToken` and `SignJwt`; `GenerateIdToken` and `SignBlob` need `DATA_READ`, so an `ADMIN_READ`-only config silently drops ID-token minting — the primitive used to call Cloud Run / IAP / an external verifier as another SA. `serviceName` in the filter below is `iamcredentials.googleapis.com`; the `auditConfigs` entry is not.)*:
```
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.serviceName="iamcredentials.googleapis.com"
protoPayload.methodName=("GenerateAccessToken" OR "GenerateIdToken" OR "SignJwt" OR "SignBlob")
```

`F3` — federated token exchange *(requires Data Access `ADMIN_READ` on `sts.googleapis.com`)*:
```
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.serviceName="sts.googleapis.com"
protoPayload.methodName:"SecurityTokenService"
```
Pivot on `protoPayload.metadata.mapped_principal` for the pool subject and
`protoPayload.resourceName` for the provider.

`F4` — service-account and key lifecycle:
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="iam.googleapis.com"
protoPayload.methodName=("google.iam.admin.v1.CreateServiceAccountKey"
  OR "google.iam.admin.v1.UploadServiceAccountKey"
  OR "google.iam.admin.v1.CreateServiceAccount"
  OR "google.iam.admin.v1.SetIAMPolicy")
```

`F5` — custom-role definition changes (`AP-11c`):
```
protoPayload.methodName=("google.iam.admin.v1.CreateRole" OR "google.iam.admin.v1.UpdateRole"
  OR "google.iam.admin.v1.UndeleteRole" OR "google.iam.admin.v1.DeleteRole")
```

`F6` — WIF trust-boundary changes (`AP-10`):
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.methodName=("google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPool"
  OR "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider"
  OR "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider"
  OR "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPool"
  OR "google.iam.v1.WorkloadIdentityPools.SetAttestationRules"
  OR "google.iam.v1.WorkloadIdentityPools.AddAttestationRule"
  OR "google.iam.v1.WorkloadIdentityPools.RemoveAttestationRule"
  OR "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProviderKey")
```
The substring form `protoPayload.methodName:"WorkloadIdentityPools"` catches both `google.iam.v1.*`
and `google.iam.v1beta.*`; add the workforce equivalents (`google.iam.admin.v1.WorkforcePools.*`).

`F7` — org policy tampering (`AP-11f`, `AP-13a`):
```
protoPayload.methodName=("google.cloud.orgpolicy.v2.OrgPolicy.CreatePolicy"
  OR "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy"
  OR "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy"
  OR "google.cloud.orgpolicy.v2.OrgPolicy.DeleteCustomConstraint"
  OR "google.cloud.orgpolicy.v2.OrgPolicy.UpdateCustomConstraint")
```
Also cover the v1 path `cloudresourcemanager.v1.organizations.setOrgPolicy`.

`F8` — perimeter and access-level tampering (`AP-13b`):
```
protoPayload.serviceName="accesscontextmanager.googleapis.com"
protoPayload.methodName:"AccessContextManager."
NOT protoPayload.methodName:(".Get" OR ".List")
```

`F9` — bucket IAM and HMAC key creation (`AP-04`):
```
protoPayload.serviceName="storage.googleapis.com"
protoPayload.methodName=("storage.setIamPermissions" OR "storage.hmacKeys.create"
  OR "storage.buckets.update")
```

`F10` — logging-pipeline tampering (`AP-13c`) — alert loudly and route the alert **outside** this
pipeline (method names: verify against current docs):
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="logging.googleapis.com"
protoPayload.methodName=("google.logging.v2.ConfigServiceV2.UpdateSink"
  OR "google.logging.v2.ConfigServiceV2.DeleteSink"
  OR "google.logging.v2.ConfigServiceV2.CreateExclusion"
  OR "google.logging.v2.ConfigServiceV2.UpdateExclusion"
  OR "google.logging.v2.ConfigServiceV2.UpdateBucket"
  OR "google.logging.v2.ConfigServiceV2.DeleteBucket"
  OR "google.logging.v2.ConfigServiceV2.UpdateCmekSettings"
  OR "google.logging.v2.LoggingServiceV2.DeleteLog")
```

`F11` — Data Access logging being switched off (heuristic; the request field path varies by API
version — **verify against current docs** and confirm against a real log entry before relying on it):
```
protoPayload.methodName:"setIamPolicy"
protoPayload.request.policy.auditConfigs:*
```

`F12` — all VPC-SC violations (`AP-01`; Policy Denied cannot be disabled, but **can** be excluded from
the `_Default` sink — check `_Default` exclusions before trusting this):
```
log_id("cloudaudit.googleapis.com/policy") severity=ERROR resource.type="audited_resource"
protoPayload.metadata."@type"="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"
```

`F13` — dry-run-only violations (free attack-path evidence: these are the calls a perimeter *would*
have blocked):
```
log_id("cloudaudit.googleapis.com/policy") AND severity="error" AND protoPayload.metadata.dryRun="true"
```

`F14` — GCS object reads *(requires Data Access `DATA_READ` on `storage.googleapis.com`; without
`constraints/gcp.detailedAuditLoggingMode` the entries do not name the objects read)*:
```
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.serviceName="storage.googleapis.com"
protoPayload.methodName=("storage.objects.get" OR "storage.objects.list")
```

`F15` — perimeter CRUD at the **organization** node (a detection pipeline scoped to projects misses
every perimeter-tampering event):
```
logName="organizations/ORGANIZATION_ID/logs/cloudaudit.googleapis.com%2Factivity"
severity=NOTICE
protoPayload.serviceName="accesscontextmanager.googleapis.com"
protoPayload.methodName=~"google.identity.accesscontextmanager.v1.AccessContextManager.*ServicePerimeter"
```

`F16` — BigQuery data-plane activity (BigQuery is the documented exception whose Data Access logs are
on by default; exact job `methodName` values: verify against current docs):
```
logName:"cloudaudit.googleapis.com%2Fdata_access"
protoPayload.serviceName="bigquery.googleapis.com"
```

`F17` — Compute control-plane changes used by `AP-05`/`AP-06`/`AP-11b` (method names: verify against
current docs, then narrow):
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName:("firewallPolicies" OR "forwardingRules" OR "instances.insert"
  OR "instances.setMetadata" OR "projects.setCommonInstanceMetadata")
```

`F18` — resource-hierarchy move (`AP-13f`; method name: verify against current docs):
```
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="cloudresourcemanager.googleapis.com"
protoPayload.methodName:"move"
```

`F19` — group-membership change on a role-bearing group (`AP-11e`). **Requires Google Workspace data
sharing with Google Cloud**, and the entries land only at the organization node:
```
logName="organizations/ORGANIZATION_ID/logs/cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName=("admin.googleapis.com" OR "cloudidentity.googleapis.com")
```
Narrow to the specific Tier-0 group addresses before alerting, or this fires on every directory edit.

#### 4.7.4 Native-detector coverage and its gaps

Where an SCC Event Threat Detection detector already covers a step, record its name in `Alerting`
instead of writing a rule. Detectors relevant here (all **Premium** tier; SCC Enterprise is deprecated
and shuts down 2027-05-21 with orgs moving to Premium — do not recommend buying Enterprise):
`ORG_LEVEL_SERVICE_ACCOUNT_TOKEN_CREATOR_ROLE_ADDED`, `FOLDER_LEVEL_…`, `PROJECT_LEVEL_…`,
`SERVICE_ACCOUNT_KEY_CREATION`, `LEAKED_SA_KEY_USED`, `IAM_ANOMALOUS_GRANT`,
`ANOMALOUS_SA_DELEGATION_MULTISTEP_ADMIN_ACTIVITY` / `…_DATA_ACCESS`,
`SERVICE_ACCOUNT_SELF_INVESTIGATION`, `DEFENSE_EVASION_MODIFY_VPC_SERVICE_CONTROL`,
`DATA_EXFILTRATION_BIG_QUERY`, `DATA_EXFILTRATION_BIG_QUERY_EXTRACTION`,
`CLOUDSQL_EXFIL_EXPORT_TO_EXTERNAL_GCS`, `SENSITIVE_ROLE_TO_GROUP_WITH_EXTERNAL_MEMBER`.

There is **no built-in detector** for: WIF pool/provider creation or modification, an IAM binding to
`principalSet://…/*`, an `attributeCondition` being weakened or removed, `auditConfigs` being
disabled or `exemptedMembers` added, or log sink/exclusion/bucket mutation. Which of those an ETD
custom module can close, and how, is tabulated once in §5.12 (test `LG-19`) — work that table rather
than re-deriving it here.

#### 4.7.5 From detection posture to score

Feed `TM-D`'s `Detection state` into the chain-ranking function in §6.3.2 (factor **D**) and into the
band rubric in §11.1 (input **D**). Three rules bind that hand-off:

- `DET(path)` = the **maximum** detection state across the path's steps: a path is detected if any one
  step raises an alert that reaches a human or a SIEM.
- **Retention modifier, applied before scoring:** if the only step reaching `DET` ≥ 2 emits to
  `_Default` (Data Access or Policy Denied, 30 days) and no aggregated sink routes it to a
  longer-retention bucket, drop that step to `DET` = 1. A record that expires before anyone reads it
  is not detection.
- Record the arithmetic in the finding. A severity a reader cannot recompute from the inputs is not a
  rating.

---

### 4.8 Required output shape

Every attack-path finding carries: the path ID, the adversary ID, the ordered step table with each
step marked `REACHABLE` / `BLOCKED BY <control object>` / `N/A (<reason>)`, the single cheapest
severing control, the detection state per step, the score arithmetic (§6.3.2), and the ATT&CK IDs.
Emit it in the `CH-` shape defined in §11.3.1; the two worked examples are §6.3.3 (analysis form) and
§11.3.2 (report form). **Prose summaries of chains are not an acceptable substitute for the step
table.**

---

### 4.9 ATT&CK Cloud mapping

**Mapped against MITRE ATT&CK v19 (v19.0/v19.1), released 2026-04-28.** State this version in the
report; re-check before reuse.

Three v19 changes that break older mappings:

1. **The Defense Evasion tactic no longer exists in Enterprise ATT&CK.** It was split into **Stealth**
   (TA ID: verify against current docs) and **Defense Impairment (TA0112)**.
2. **T1562 and every `T1562.*` sub-technique are revoked.** Emit `T1685` (Disable or Modify Tools),
   `T1685.002` (Disable or Modify Cloud **Log**, singular — formerly `T1562.008`), and `T1686` /
   `T1686.001` (Disable or Modify Firewall, formerly `T1562.004` / `T1562.007`). Any template that
   still emits `T1562.008` is emitting a revoked ID.
3. **`T1195.002` is not a cloud technique** — its platforms are Linux, Windows and macOS only. For a
   cloud supply-chain hook cite `T1195` (SaaS matrix) or `T1677 Poisoned Pipeline Execution`
   (SaaS, Execution).

The GCP manifestations below are analyst mappings. For `T1578`, `T1666` and `T1685.002` the ATT&CK
pages themselves carry only AWS/Azure/Office examples — present the GCP framing as an analyst mapping, and
verify against current docs before quoting ATT&CK directly.

| ID | Name | Tactic | GCP manifestation here | Paths |
|---|---|---|---|---|
| `T1078` | Valid Accounts | Initial Access / Persistence / Priv Esc / Stealth | Stolen `gcloud` refresh token in `~/.config/gcloud/`, or a leaked SA key JSON | `AP-01`, `AP-02`, `AP-09`, `AP-12b` |
| `T1078.001` | Default Accounts | as parent | Compute Engine default SA `PROJECT_NUMBER-compute@developer.gserviceaccount.com` still holding project `roles/editor` | `AP-11b`, `AP-05` |
| `T1078.004` | Cloud Accounts | as parent | A Cloud Identity user or an SA principal used directly against `*.googleapis.com` | `AP-01`, `AP-02`, `AP-12b`, `AP-12c` |
| `T1199` | Trusted Relationship | Initial Access | A WIF pool trusting a shared external OIDC issuer with an empty or non-pinning `attributeCondition` | `AP-10` |
| `T1190` | Exploit Public-Facing Application | Initial Access | Internet-exposed GCE/GKE/Cloud Run reachable through a `0.0.0.0/0` ingress rule | `AP-12a`, `A6` |
| `T1195` | Supply Chain Compromise | Initial Access (**SaaS matrix**) | Poisoned dependency or base image entering the build | `AP-13e`, `A7` |
| `T1566.002` | Spearphishing Link | Initial Access (**SaaS matrix**) | OAuth consent phish minting a token with data scopes | `A1` |
| `T1651` | Cloud Administration Command | Execution | `gcloud compute ssh`, OS Config / guest-agent command execution on a VM | `AP-11b`, `AP-12a` |
| `T1648` | Serverless Execution | Execution | Cloud Run job, Cloud Run function, Eventarc trigger or Workflows execution created to run attacker code with an attached SA | `AP-11b` |
| `T1059.009` | Command and Scripting Interpreter: Cloud API | Execution | Direct REST/`gcloud`/client-library calls against `*.googleapis.com` | all |
| `T1204.003` | User Execution: Malicious Image | Execution | Malicious image pulled from Artifact Registry into GKE or Cloud Run | `A7` |
| `T1677` | Poisoned Pipeline Execution | Execution (**SaaS matrix**) | Cloud Build trigger or workflow file altered to run attacker steps as the build SA | `AP-13e` |
| `T1098` | Account Manipulation | Persistence + Priv Esc | Parent for the grant/key/SSH-key sub-techniques below | `AP-11*`, `AP-13*` |
| `T1098.001` | Additional Cloud Credentials | Persistence / Priv Esc | `gcloud iam service-accounts keys create`; uploading a public key to an SA; adding a WIF provider | `AP-02`, `AP-11f` |
| `T1098.003` | Additional Cloud Roles | Persistence / Priv Esc | `add-iam-policy-binding` granting `roles/owner` or `roles/iam.serviceAccountTokenCreator`; resource-level `setIamPolicy` | `AP-04`, `AP-11c`, `AP-11d`, `AP-13e` |
| `T1098.004` | SSH Authorized Keys | Persistence / Priv Esc | Writing project- or instance-level `ssh-keys` metadata; blocked only when OS Login is enforced | `AP-11b` |
| `T1098.005` | Device Registration | Persistence / Priv Esc | Enrolling an attacker device into Cloud Identity to satisfy an access level `devicePolicy` | `AP-01` |
| `T1098.006` | Additional Container Cluster Roles | Persistence / Priv Esc | GKE `ClusterRoleBinding` to `cluster-admin`; binding a KSA to a GSA | `AP-11b` |
| `T1098.007` | Additional Local or Domain Groups | Persistence / Priv Esc | Adding a principal to a Cloud Identity group that carries IAM grants | `AP-11e` |
| `T1136.003` | Create Account: Cloud Account | Persistence | `gcloud iam service-accounts create`; a new Cloud Identity user | `AP-13e` |
| `T1548.005` | Temporary Elevated Cloud Access | Priv Esc | Privileged Access Manager grant self-approval; SA impersonation via `roles/iam.serviceAccountTokenCreator`; `generateAccessToken` / `signJwt` | `AP-03`, `AP-09`, `AP-10`, `AP-11a` |
| `T1546` | Event Triggered Execution | Persistence / Priv Esc | Eventarc or Pub/Sub trigger wired to a function that re-grants access when the attacker's binding is removed | `AP-13e` |
| `T1525` | Implant Internal Image | Persistence | Backdoored custom GCE image or Artifact Registry base image | `A7` |
| `T1535` | Unused/Unsupported Cloud Regions | Stealth | Creating resources in a region nobody monitors; countered by `constraints/gcp.resourceLocations` | `AP-13f` |
| `T1211` | Exploitation for Stealth | Stealth | New in v19 | — |
| `T1684.001` | Social Engineering: Impersonation | Stealth (SaaS) | Formerly a standalone Impersonation technique | `A1` |
| `T1685` | Disable or Modify Tools | **Defense Impairment (TA0112)** | Disabling SCC services; deleting the function that ships findings. **Replaces T1562** | `AP-13c` |
| `T1685.002` | Disable or Modify Cloud Log | Defense Impairment | `gcloud logging sinks delete`; disabling Data Access logs in `auditConfigs`; a sink exclusion that drops the attacker's own calls; shortening a log bucket's retention. **Replaces T1562.008** | `AP-13c` |
| `T1686` / `T1686.001` | Disable or Modify (Cloud) Firewall | Defense Impairment | A permissive `allow` at priority 0, or deleting a hierarchical `deny` policy. **Replaces T1562.004 / T1562.007** | `AP-13d` |
| `T1578` | Modify Cloud Compute Infrastructure | Defense Impairment (tactic changed in v19) | Perimeter/infrastructure mutation to widen the boundary | `AP-13b` |
| `T1578.001` | Create Snapshot | Defense Impairment | `gcloud compute disks snapshot`, then share the snapshot into an attacker project | `AP-07` |
| `T1578.002` | Create Cloud Instance | Defense Impairment | Boot a VM from a snapshot of a sensitive disk, in a project without logging | `AP-05`, `AP-11b` |
| `T1578.005` | Modify Cloud Compute Configurations | Defense Impairment | Changing instance metadata or SA scopes; disabling Shielded VM | `AP-11b` |
| `T1666` | Modify Cloud Resource Hierarchy | Defense Impairment | `gcloud projects move` into a folder with weaker inherited policies or no perimeter | `AP-13f` |
| `T1556` (+ `.006`, `.007`, `.009`) | Modify Authentication Process | Persistence / Credential Access **and** Defense Impairment | Weakening 2SV enforcement; altering the SAML/OIDC SSO profile; loosening an access level | `AP-13b`, `AP-09` |
| `T1552` | Unsecured Credentials | Credential Access | Parent | `AP-02`, `AP-12b` |
| `T1552.001` | Credentials In Files | Credential Access | SA key JSON in a repo, a GCS object, Terraform state, or `/etc` on an interior host; `application_default_credentials.json` | `AP-02`, `AP-12b`, `AP-13e` |
| `T1552.005` | Cloud Instance Metadata API | Credential Access | `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` — the canonical GCP token theft, including via SSRF | `AP-11b`, `A6` |
| `T1552.007` | Container API | Credential Access | Pod reaching `169.254.169.254` on a `GCE_METADATA` node pool: node SA token plus `kube-env` kubelet credentials | `AP-11b` |
| `T1555.006` | Credentials from Cloud Secrets Management Stores | Credential Access | `gcloud secrets versions access` against Secret Manager | `AP-11d`, `AP-13e` |
| `T1528` | Steal Application Access Token | Credential Access | `gcloud auth print-access-token`, `~/.config/gcloud/credentials.db`, or a WIF-minted STS token | `AP-01`, `AP-12b` |
| `T1606.002` | Forge Web Credentials: SAML Tokens | Credential Access | Forging assertions against a Workforce Identity Federation SAML provider | `AP-10` |
| `T1040` | Network Sniffing | Credential Access | Packet Mirroring policy pointed at an attacker-controlled collector ILB | `AP-05` |
| `T1580` | Cloud Infrastructure Discovery | Discovery | `gcloud asset search-all-resources`, `gcloud compute instances list`, `gcloud storage ls` | `AP-01`, all adversaries' first move |
| `T1526` | Cloud Service Discovery | Discovery | `gcloud services list --enabled`; probing which APIs answer | `AP-01` |
| `T1087.004` | Account Discovery: Cloud Account | Discovery | `gcloud iam service-accounts list`, `gcloud organizations get-iam-policy` | `AP-03`, `AP-11a` |
| `T1069.003` | Permission Groups Discovery: Cloud Groups | Discovery | `gcloud identity groups memberships list` | `AP-11e` |
| `T1619` | Cloud Storage Object Discovery | Discovery | `gcloud storage ls -r gs://BUCKET/**` before bulk copy | `AP-01`, `AP-07` |
| `T1654` | Log Enumeration | Discovery | `gcloud logging read` to learn what is captured before impairing it | `AP-13c` |
| `T1046` | Network Service Discovery | Discovery | Scanning the VPC or the interior from a foothold | `AP-12a` |
| `T1021` | Remote Services | Lateral Movement | Parent | `AP-12*` |
| `T1021.007` | Cloud Services | Lateral Movement | Project→project pivot via SA impersonation or a cross-project IAM grant | `AP-03`, `AP-11a`, `AP-12d` |
| `T1021.008` | Direct Cloud VM Connections | Lateral Movement | `gcloud compute ssh`, IAP TCP forwarding from `35.235.240.0/20`, serial console (which supports no IP-based restriction and bypasses firewall rules) | `AP-12a` |
| `T1550` | Use Alternate Authentication Material | Lateral Movement | Parent | `AP-02`, `AP-03` |
| `T1550.001` | Application Access Token | Lateral Movement | Replaying a stolen OAuth or SA short-lived token against the API | `AP-02`, `AP-03`, `AP-10`, `AP-11a` |
| `T1550.004` | Web Session Cookie | Lateral Movement | Replaying a Google session cookie | `AP-01` |
| `T1530` | Data from Cloud Storage | Collection | Bulk read of GCS objects, BigQuery tables, or Filestore | every path that terminates at data |
| `T1213.006` | Data from Information Repositories: Databases | Collection | Reading Cloud SQL / Spanner / BigQuery / Firestore contents directly | `AP-01`, `AP-03`, `AP-07` |
| `T1119` | Automated Collection | Collection | Scheduled query, Dataflow job, or Cloud Scheduler harvesting on a cadence | `AP-07` |
| `T1074.002` | Data Staged: Remote Data Staging | Collection | Consolidating into one staging bucket or dataset before the final hop | `AP-04`, `AP-12a` |
| `T1537` | Transfer Data to Cloud Account | **Exfiltration** | The core GCP exfil technique: dataset copy to an external org, snapshot shared to an attacker project, GCS object copied out, a sharing listing subscribed by an outside org. Stays inside Google's network — no egress firewall, NAT log, or flow log sees it | `AP-04`, `AP-06`, `AP-07`, `AP-08`, `AP-13*` |
| `T1048` | Exfiltration Over Alternative Protocol | Exfiltration | DNS exfil via a Cloud DNS outbound server policy or forwarding zone (packets leave from `35.199.192.0/19`, not from the VM); non-HTTP egress from a VM; interior egress after `AP-12` | `AP-05`, `AP-06`, `AP-12a`, `AP-12e` |
| `T1567.002` | Exfiltration to Cloud Storage | Exfiltration (**SaaS matrix**) | An operator pushing an extract to third-party storage. `T1567`'s platforms do not include IaaS — lead with `T1537` for in-cloud exfil and use this for the endpoint/Workspace side | `AP-01`, `AP-04` |
| `T1567.004` | Exfiltration Over Webhook | Exfiltration (**SaaS matrix**) | Pub/Sub push subscription pointed at an attacker HTTPS endpoint; Pub/Sub does not verify domain ownership, and pre-existing push subscriptions survive perimeter creation | `AP-08` |
| `T1485.001` | Data Destruction: Lifecycle-Triggered Deletion | Impact (evidence destruction) | A 1-day GCS lifecycle rule or BigQuery table expiration set to destroy the trail | `AP-13c` |
| `T1486` | Data Encrypted for Impact | Impact | Rotating or destroying a CMEK key version to render protected data unreadable | `AP-13a` |

Tactic coverage check before emitting the report: Initial Access, Execution, Persistence, Privilege
Escalation, **Stealth**, **Defense Impairment (TA0112)**, Credential Access, Discovery, Lateral
Movement, Collection, Exfiltration. If any tactic has no technique mapped to any `LIVE` path, say so
explicitly — an empty tactic is a statement about this environment, not an omission to hide.

---

## 5. Control assessment catalog — the reviewer's checklist

Work all twelve control areas — §5.1 Organization Policy, §5.2 VPC Firewall Policy, §5.3 VPC Service
Controls, §5.4 IAM (allow), §5.5 IAM Deny, §5.6 Private Service Connect, §5.7 Principal Access
Boundary, §5.8 Workload Identity Federation, §5.9 Identity, §5.10 Access, §5.11 Break-glass,
§5.12 Audit logging and detection coverage. Each has the same four parts:

- **Observe** — the enumeration commands and the exact fields to record into the evidence appendix.
- **Findings tests** — numbered conditions. Each evaluates true/false against recorded evidence. Each carries a finding-ID stub and a default severity.
- **Exfil scenario** — the attack path this control interrupts or fails to interrupt.
- **Remediation** — exact identifiers plus a `gcloud` and a Terraform snippet.

**Rules that bind the whole catalog:**

1. **No item may be closed with a platitude.** Every item produces either a finding with a resource name in it, or the literal sentence `Assessed, no finding: <control> is <observed value> at <node>, which satisfies <test IDs>.` A control area with neither is an evidence gap, and is reported as one.
2. **Finding IDs** use the twenty-three prefixes in the §11.2.1 table — that table is the whole vocabulary, and no prefix outside it may be emitted. §5's twelve control areas emit `OP-`, `FW-`, `SC-`, `IA-`, `DN-`, `PS-`, `PB-`, `WI-`, `ID-`, `AX-`, `BG-`, `LG-`; §6 emits `IM-`; §7 emits `NW-`, `CE-`, `CD-`; §8 emits `DP-` plus the area prefixes routed in §11.2.1; §9 emits `HI-`; and `CH-`, `SR-`, `DC-`, `DRIFT-`, `VD-` are cross-cutting. Number findings sequentially within a prefix in the order you emit them; the numbers in this catalog are **test** numbers, not emitted finding numbers — record both (`IA-07 / test IA-02`).
3. **Default severity** is a starting point, adjusted by the rubric in §11.1. Apply these two adjustments here: **+1 level** if the affected resource holds CONFIDENTIAL or NTK data *and* no step in the chain produces an audit-log entry that is currently enabled; **−1 level** only if you verified a compensating control by evidence, and you name it in the finding.
4. **`AP-nn` refers to the attack-path catalog in §4.6** (`AP-01`–`AP-13` and their lettered variants). Never mint a new `AP-nn` here: if a control area exposes a path the catalog does not carry, add it to §4.6 first, then cite it.
5. **Doc host.** Every Google doc URL you cite or fetch must be `https://docs.cloud.google.com/...`. `cloud.google.com/...` 301-redirects and breaks fetchers that do not follow cross-host redirects.
6. **Unverified identifiers.** Where this catalog marks an identifier `(verify against current docs)`, do not assert it in a finding or a remediation snippet until you have confirmed it against the live documentation. Record every such item in the "verify against docs" appendix.
7. **One config fact, one finding.** Several catalog areas test the same object from different angles: access levels in §5.3 (`SC-18`, `SC-20`, `SC-21`) and §5.10 (`AX-01`, `AX-03`, `AX-04`); the private-vs-restricted VIP in §5.3 (`SC-28`) and §7.3.4 (`LM-69`); PSC bundles in §5.6 (`PS-01`, `PS-02`) and §7.3.5; perimeter bridges in §5.3 (`SC-23`) and §8.6 (`ISO-42`). Where two tests fire on the **same field of the same resource**, emit **one** finding, under the area whose *Remediation* block carries the snippet that fixes it, and cite the second test in that finding's `Misconfiguration` line as `also test <ID>`. Never emit two findings, two severities, or two roadmap rows for one edit. This does **not** apply to a supplied `SR-` rule that duplicates a baseline check — §10.1 step 6 deliberately assesses those twice, once as `SR-` and once as the baseline finding.

---

### 5.1 Organization Policy

#### OP — Observe

1. Record the organization's creation time. Organizations created **on or after 2024-05-03** have the seven-constraint security baseline enforced by default; on those orgs an *absent* baseline constraint means someone deleted it, which is a finding in its own right, not a gap.
   ```bash
   gcloud organizations describe ORG_ID --format=json    # creation-time field name: verify against current docs
   ```
2. Enumerate policies and custom constraints at every node. Run the `list` at the org, at **every** folder, and at **every** project — not a sample.
   ```bash
   gcloud org-policies list --organization=ORG_ID --format=json
   gcloud org-policies list --folder=FOLDER_ID   --format=json
   gcloud org-policies list --project=PROJECT_ID --format=json
   gcloud org-policies list-custom-constraints --organization=ORG_ID --format=json
   gcloud org-policies describe CONSTRAINT --organization=ORG_ID --format=json
   gcloud org-policies describe CONSTRAINT --effective --project=PROJECT_ID --format=json
   ```
3. Compute the **effective** policy per constraint across the hierarchy. Do not reason from the org-level policy alone — a child node silently supersedes its parent unless `inheritFromParent: true`.
   ```bash
   gcloud asset analyze-org-policies --constraint=constraints/CONSTRAINT --scope=organizations/ORG_ID --format=json
   ```
   Both `--constraint` and `--scope` are required on `analyze-org-policies`. `gcloud org-policies describe CONSTRAINT --effective` is also available and is the cheapest per-node effective read — its SYNOPSIS is `(--folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID) [--effective]`. Use `--effective --project=PROJECT_ID` on every project holding CONFIDENTIAL/NTK data, and `analyze-org-policies` when you need the whole-hierarchy picture in one call. A `describe` without `--effective` returns the policy **set at that node**, which is exactly what test OP-03 exists to catch — never verify a fix with it.
4. For every policy record: node, tier (**managed** `SERVICE.managed.NAME` vs **legacy managed** `SERVICE.NAME` vs **custom** `custom.NAME`), `spec.rules[]`, `spec.inheritFromParent`, `spec.reset`, every `spec.rules[].condition.expression`, and whether `dryRunSpec` is populated. Managed and legacy constraints of the same name are **not equivalent** — managed constraints check violations only during create/modify API requests, legacy policies could be enforced at other stages. Setting the managed twin does not retire the legacy one; Google's migration path is to run both.
5. For every conditional rule, extract the tag key/value in `resource.matchTag(...)` / `resource.matchTagId(...)` / `resource.hasTagKey(...)` and then enumerate who can write that tag value (`roles/resourcemanager.tagAdmin`, `roles/resourcemanager.tagUser` bindings on the tag key and on the target projects). **Whoever can attach the tag value can grant themselves the exception.**
6. Record every holder of `orgpolicy.policy.set`, `orgpolicy.policies.create|update|delete`, and `orgpolicy.customConstraints.*` — via `roles/orgpolicy.policyAdmin` (org-level role only), via `roles/owner` at the org node, and via any custom role. Note that `roles/resourcemanager.organizationAdmin` holds only `orgpolicy.policy.get` / `orgpolicy.policies.list` / `orgpolicy.constraints.list` — it can read org policy but not set it. There is **no** `orgpolicy.policies.get` permission; the getter is `orgpolicy.policy.get`.
7. Record which Terraform resource type manages each policy: `google_org_policy_policy` / `google_org_policy_custom_constraint` (v2, current) vs `google_organization_policy` / `google_project_organization_policy` / `google_folder_organization_policy` (v1, superseded).

#### OP — Findings tests

Constraint tiers used below refer to the **A/B/C** marker in the reference table. Tier A → default **CRITICAL**, tier B → **HIGH**, tier C → **MEDIUM**.

1. **OP-01 — baseline deletion.** Org creation time ≥ 2024-05-03 **and** any of the seven baseline constraints (`constraints/iam.managed.disableServiceAccountKeyCreation`, `constraints/iam.disableServiceAccountKeyUpload`, `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`, `constraints/iam.allowedPolicyMemberDomains`, `constraints/essentialcontacts.managed.allowedContactDomains`, `constraints/compute.managed.restrictProtocolForwardingCreationForTypes`, `constraints/storage.uniformBucketLevelAccess`) has no effective enforcement at the org node. → **CRITICAL**. Someone ran `gcloud org-policies delete` with `roles/orgpolicy.policyAdmin`.
2. **OP-02 — table conformance.** For each row of the reference table, the effective value at a project holding CONFIDENTIAL or NTK data differs from the *recommended value* column. → severity per the row's tier. Emit one finding per constraint per project set, naming the projects.
3. **OP-03 — silent override.** A folder or project node sets a policy for constraint `C` that is also set at an ancestor, and that node's `spec.inheritFromParent` is absent or `false`. → **HIGH**; **CRITICAL** if `C` is tier A or the node contains CONFIDENTIAL/NTK data. This is a finding *in its own right*, independent of whether the child value happens to be equally strict today: the inheritance link is severed, so tightening the parent later will not reach the child.
4. **OP-04 — list-merge misread.** A child node uses `inheritFromParent: true` and adds `allowedValues` expecting to widen an inherited denylist. `DENY` values always take precedence, so the widening does not happen. → **MEDIUM**, config defect; report so the team does not build on a false assumption.
5. **OP-05 — tag-conditioned escape.** A policy carries `spec.rules[].condition` referencing a tag, **and** any principal outside the guardrail-admin set holds `roles/resourcemanager.tagUser` on that tag key or can bind the tag value to a project. → **HIGH**. Also flag the mirror case: a `roles/orgpolicy.policyAdmin` binding made conditional on a resource tag (the CEL syntax for that binding is unconfirmed — verify against current docs).
6. **OP-06 — dry-run masquerade.** A constraint is set only in `dryRunSpec` with no `spec` at the same node, and is presented as enforced. → **HIGH**. Note the trap: dry-run is **not** supported for most legacy managed constraints — only custom constraints, all managed constraints, and specifically `constraints/gcp.restrictServiceUsage`, `constraints/gcp.restrictEndpointUsage`, and the TLS version/cipher constraints. `constraints/compute.vmExternalIpAccess` and `constraints/iam.allowedPolicyMemberDomains` cannot be dry-run at all; a claimed dry-run of either is a fabrication or an error.
7. **OP-07 — tier blindness.** The environment enforces `SERVICE.managed.NAME` while the review's evidence or the org's own IaC greps only for `SERVICE.NAME` (or the reverse). → **MEDIUM**, evidence defect; re-run enumeration for both spellings before asserting "not enforced". Specifically check both spellings for: service-account key creation/upload, OS Login, serial port access, `vmExternalIpAccess`, `vmCanIpForward`, guest attributes, protocol forwarding, essential contacts.
8. **OP-08 — type confusion.** A reviewer or an IaC module treats `constraints/compute.managed.vmExternalIpAccess` or `constraints/compute.managed.vmCanIpForward` as list constraints. They are **boolean**; their legacy twins are **list** taking instance URIs. → **MEDIUM**, but it invalidates any conclusion drawn from `allowedValues`.
9. **OP-09 — DRS exception sprawl.** `constraints/iam.allowedPolicyMemberDomains` (or `constraints/iam.managed.allowedPolicyMembers`) is enforced but its allow-list contains an entry that is not one of: the org's own principal set, the Workspace customer ID, or a Google service agent required by a named, documented integration (BigQuery log sinks, Cloud Storage analytics, Pub/Sub webhooks, Cloud CDN). → **HIGH**. Enforcement alone is not the finding-closing fact; *what was excepted* is.
10. **OP-10 — nonexistent constraint asserted.** Any document, IaC module, or prior report references `constraints/iam.allowedPolicyMemberSubdomains`. That constraint does not exist. Subdomain-level domain-restricted sharing requires a separate Google Workspace account per subdomain. → **MEDIUM**, and the control it was supposed to provide is absent.
11. **OP-11 — dead constraint.** Any policy still references `constraints/gcp.managed.allowedMCPServices`. Deprecated 2026-02-15 and non-functional after 2026-03-17. → **MEDIUM**; replacement is IAM deny policies.
12. **OP-12 — custom-constraint CEL defect.** A custom constraint's `condition` indexes a list or map key without a preceding `size()` or `has()` guard. Querying a non-existent index/key returns `BAD_CONDITION` and **blocks resource creation** — a self-inflicted denial of service on deploys, and a pressure source to delete the constraint. → **MEDIUM**.
13. **OP-13 — custom-constraint coverage gaps.** A design claims a custom constraint governs a Compute **Network, Subnetwork, Firewall, or Router** object. Compute custom constraints cover only `Disk`, `Image`, `Instance`, `InstanceGroup`. → **MEDIUM**; use the predefined `compute.restrict*` list constraints for network objects instead. Similarly, `DELETE` as a `methodTypes` value is unconfirmed (verify against current docs) — do not rely on a custom constraint to block deletion.
14. **OP-14 — v1 IaC.** Any `google_organization_policy`, `google_project_organization_policy`, or `google_folder_organization_policy` resource manages a constraint that also has (or needs) conditions or dry-run. The v1 resources cannot express either, and a v1 resource will fight a v2 policy on every apply. → **HIGH** when it manages a tier A/B constraint, otherwise **MEDIUM**.
15. **OP-15 — control-plane escalation feed.** Count and name every principal with `orgpolicy.policy.set` at any node, and every principal with `roles/owner` at the org node. Each becomes a **Guardrail-mutate** node in the privilege graph (see §6). → **HIGH** for any holder outside the named guardrail-admin group; **CRITICAL** if the holder is also reachable via an impersonation or group-write edge. Flag every `roles/orgpolicy.policyAdmin` binding at org scope that carries no IAM condition.
16. **OP-16 — two-step chain.** For each tier A constraint, record whether disabling it is a *precursor* step rather than an end state: turning off key creation → mint a key; turning off `constraints/storage.publicAccessPrevention` → stage data publicly; turning off `constraints/iam.allowedPolicyMemberDomains` → grant an external principal a role. Emit these as chains in §11.3, not as two unrelated findings. → severity of the terminating step.

#### OP — Constraint reference table

Tier: **A** = enforce at the org node, no exceptions without a named, ticketed, time-bounded justification. **B** = enforce at the org node, project exceptions permitted with documentation. **C** = enforce where the named condition applies.

| Constraint | Type | Recommended value | Exfil / escalation step it interrupts | Attachment node |
|---|---|---|---|---|
| **A** `constraints/iam.managed.allowedPolicyMembers` | managed, list+params | `enforce: true`; `parameters.allowedPrincipalSets: ["//cloudresourcemanager.googleapis.com/organizations/ORG_ID"]` | Granting an attacker-controlled external Google account a role on a bucket/dataset/project — the most common exfil finish. Google-recommended replacement for the legacy DRS constraint. | org |
| **A** `constraints/iam.allowedPolicyMemberDomains` | legacy, list | `allowedValues: [principalSet://iam.googleapis.com/organizations/ORG_ID]` or `is:CUSTOMER_ID` | Same as above (legacy spelling). Baseline-enforced on orgs ≥ 2024-05-03. | org |
| **A** `constraints/iam.managed.disableServiceAccountKeyCreation` | managed, boolean | `enforce: true` | Kills long-lived exportable `.json` keys **and** Cloud Storage HMAC keys — AP-02's durable credential. Baseline-enforced on orgs ≥ 2024-05-03. Legacy twin `constraints/iam.disableServiceAccountKeyCreation` is documented but one current page omits it (verify against current docs before relying on the legacy name alone). | org; folder exception for the CI folder only |
| **A** `constraints/iam.disableServiceAccountKeyUpload` | legacy, boolean | `enforce: true` | Blocks an attacker uploading their **own** public key to a victim SA — persistence with no Google-generated key to rotate. Baseline-enforced on orgs ≥ 2024-05-03. | org |
| **A** `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` | legacy, boolean | `enforce: true` | Stops Compute/App Engine default SAs receiving `roles/editor` at project creation — the "any VM = project editor" pivot behind AP-11. Baseline-enforced on orgs ≥ 2024-05-03. | org |
| **A** `constraints/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` | managed, boolean | `enforce: true` | Closes the *manual re-grant* of Editor/Owner to default SAs, which the constraint above does not cover. | org |
| **A** `constraints/storage.publicAccessPrevention` | boolean | `enforce: true` | AP-04: `allUsers`/`allAuthenticatedUsers` on a bucket. Bucket-level `enforced` is ratchet-up-only and survives org-policy removal; the org policy is the floor. | org |
| **A** `constraints/storage.uniformBucketLevelAccess` | boolean | `enforce: true` | Removes per-object ACLs, which can grant public read invisibly to any IAM-based review. Baseline-enforced on orgs ≥ 2024-05-03. | org |
| **A** `constraints/iam.workloadIdentityPoolProviders` | legacy, list | Deny-all at org root; per-project allow of the exact issuer URIs in use (`https://sts.amazonaws.com`, `https://sts.windows.net/TENANT`, the OIDC issuer URI; `KEY_UPLOAD` for SAML) | AP-10: stops standing up a pool that trusts an attacker's OIDC issuer. **Only limits create/update — a provider configured before enforcement keeps working.** | org, with project exceptions |
| **A** `constraints/gcp.restrictCmekCryptoKeyProjects` | list (Allow) | `projects/KMS_PROJECT`, or `under:folders/SEC_FOLDER` | Stops data being encrypted under a key in an attacker-controlled project — encrypt-then-take-the-key. Applies only to **newly created** resources. | org |
| **A** `constraints/gcp.restrictNonCmekServices` | list (Deny) | `bigquery.googleapis.com`, `storage.googleapis.com`, `sqladmin.googleapis.com` | Forces CMEK so key revocation is a working kill-switch on exfiltrated ciphertext. Must be set **together** with the row above; neither alone guarantees CMEK. | org |
| **B** `constraints/iam.disableCrossProjectServiceAccountUsage` | legacy, boolean | `enforce: true` | Blocks attaching a high-privilege SA from project A to an attacker-controlled workload in project B (AP-11). | org |
| **B** `constraints/iam.serviceAccountKeyExpiryHours` | legacy, list | `24h` (accepts `1h`,`8h`,`24h`,`168h`,`336h`,`720h`,`1440h`,`2160h`; ALLOW values only) | Bounds the useful life of a stolen key wherever key creation is excepted. Unset = keys never expire. | folder holding the key exception |
| **B** `constraints/iam.allowServiceAccountCredentialLifetimeExtension` | legacy, list | empty (no allow-list) | A broad allow-list here raises OAuth token lifetime from 1 h to 12 h — a 12× longer window for a stolen bearer token. | org |
| **B** `constraints/iam.serviceAccountKeyExposureResponse` | legacy, list | `DISABLE_KEY` | `WAIT_FOR_ABUSE` leaves a publicly-leaked key live. | org |
| **B** `constraints/iam.managed.disableServiceAccountApiKeyCreation` | managed, list | `enforce: true` with an empty/narrow `allowedServices` | API keys bound to an SA are bearer tokens with no IAM audit trail on use. Added 2026-06-30. | org |
| **B** `constraints/iam.workloadIdentityPoolAwsAccounts` | legacy, list | the exact 12-digit AWS account IDs in use | Narrows AWS WIF trust; unset means every AWS account on earth. | org |
| **B** `constraints/storage.restrictAuthTypes` | list | `in:ALL_HMAC_SIGNED_REQUESTS` denied | HMAC keys are S3-compatible static credentials usable from any S3 client, outside SA-key controls and outside IAM token telemetry. Existing keys stop working and cannot be reactivated. | org |
| **B** `constraints/storage.secureHttpTransport` | boolean | `enforce: true` | Denies unencrypted HTTP access to Cloud Storage. | org |
| **B** `constraints/compute.vmExternalIpAccess` | legacy, **list** | org-wide `denyAll` / `allValues: DENY`; per-instance `allowedValues: [projects/P/zones/Z/instances/I]` for named exceptions (never both `allowedValues` and `deniedValues` in one policy) | AP-05: the primary VM egress door. Forces a compromised VM to egress via a logged NAT/proxy path. Managed twin `constraints/compute.managed.vmExternalIpAccess` is **boolean** and was Preview as of 2025-09-09 (verify GA against current docs). | org |
| **B** `constraints/compute.vmCanIpForward` | legacy, **list** (instance URIs) | org-wide `denyAll` / `allValues: DENY`; per-instance `allowedValues: [projects/P/zones/Z/instances/I]` for the named router/NVA exceptions only | IP forwarding turns a VM into a router — the building block of an unlogged transit path around VPC egress controls and around any east-west rule keyed on the workload's own tag. Managed twin `constraints/compute.managed.vmCanIpForward` is **boolean**, not a list (see OP-08); enumerate both spellings before asserting "not enforced" (OP-07). | org |
| **B** `constraints/compute.restrictCloudNATUsage` | legacy, list | allow only the named egress subnets; **if neither `allowedValues` nor `deniedValues` is set, everything is allowed** | Cloud NAT is the egress path that survives `vmExternalIpAccess`. Restricting it is what actually closes internet egress for private VMs. | org |
| **B** `constraints/compute.restrictLoadBalancerCreationForTypes` | legacy, list | `deniedValues: [in:EXTERNAL]` | An external LB publishes an internal service to the internet without ever touching an external IP on a VM. | org |
| **B** `constraints/compute.disableInternetNetworkEndpointGroup` | boolean | `enforce: true` | Internet NEGs let a load balancer forward to an arbitrary external FQDN/IP — a fully Google-managed, allow-list-friendly exfil relay. | org |
| **B** `constraints/compute.disableAllIpv6` | boolean | `enforce: true` unless IPv6 is a documented requirement | IPv6 is the classic egress blind spot: firewall rules and NAT logging built for IPv4 do not cover it. Finer-grained alternatives: `constraints/compute.disableVpcExternalIpv6`, `constraints/compute.disableVpcInternalIpv6`, `constraints/compute.disableHybridCloudIpv6`. | org |
| **B** `constraints/compute.restrictProtocolForwardingCreationForTypes` | legacy list / managed list | `deniedValues: [EXTERNAL]` (legacy) or managed `parameters.deniedValues: ["EXTERNAL"]`. **Do not use `denyAll: "true"` here** — it is unqualified and denies *internal* protocol forwarding too, which the post-2024-05-03 baseline ("protocol forwarding for internal IP addresses only") deliberately permits | Protocol forwarding to an external IP is a raw-IP tunnel out of the VPC. Managed form is baseline-enforced on orgs ≥ 2024-05-03. | org |
| **B** `constraints/compute.restrictVpcPeering` | legacy, list | `under:organizations/ORG_ID` only | Peering a sensitive VPC to an attacker-controlled VPC is a full private-plane data bridge with no internet-egress logging. | org |
| **B** `constraints/compute.restrictSharedVpcHostProjects` / `constraints/compute.restrictSharedVpcSubnetworks` | legacy, list | the named host projects / the named subnets | Stops a rogue service project joining a trusted network or attaching workloads into a trusted subnet. | org / folder |
| **B** `constraints/compute.restrictDedicatedInterconnectUsage` / `constraints/compute.restrictPartnerInterconnectUsage` / `constraints/compute.restrictVpnPeerIPs` | list each | the named networks / the named peer IPs | AP-06/AP-12: hybrid links are egress paths that bypass every internet-facing control. | org |
| **B** `constraints/compute.restrictPrivateServiceConnectConsumer` / `constraints/compute.restrictPrivateServiceConnectProducer` / `constraints/compute.disablePrivateServiceConnectCreationForConsumers` | list each | Producer/consumer `restrict*` pair: `under:organizations/ORG_ID`. For `disablePrivateServiceConnectCreationForConsumers`, note the polarity: the constraint is a **denylist of endpoint types**, so to permit Google-APIs endpoints only, set `deniedValues: [SERVICE_PRODUCERS]` — do **not** write `allowedValues: [GOOGLE_APIS]`, which disables the Google-APIs endpoints and leaves the service-producer tunnel (LM-77) open. §5.6's remediation snippet shows the correct shape. Confirm the polarity against a test project with `gcloud org-policies describe constraints/compute.disablePrivateServiceConnectCreationForConsumers --effective --project=P` before org-wide rollout | AP-06: an unconstrained PSC consumer endpoint is a private egress tunnel to an attacker-run service attachment. Hierarchy value format for the `restrict*` pair (verify against current docs). | org |
| **B** `constraints/compute.requireOsLogin` | legacy, boolean | `enforce: true` | Forces IAM-governed, audited SSH and removes metadata SSH keys as an unlogged persistence and data-pull channel. Managed twin `constraints/compute.managed.requireOsLogin` also blocks disabling at project/instance level (Preview as of 2025-09-09 — verify GA). | org |
| **B** `constraints/compute.disableSerialPortAccess` | legacy, boolean | `enforce: true` | Serial console is an out-of-band shell that bypasses VPC firewalls, IAP, and IP allow-lists entirely. Managed twin is metadata-key-scoped (`serial-port-enable`). Pair with `constraints/compute.disableGlobalSerialPortAccess`. | org |
| **B** `constraints/compute.disableInstanceDataAccessApis` | boolean | `enforce: true` | Disables `GetSerialPortOutput` and `GetScreenshot` — both read data **out of a VM through the control plane**, bypassing every network control. | org |
| **B** `constraints/gcp.restrictServiceUsage` | list | allow-list mode naming only the services the project needs | Removes whole egress-capable services (Storage Transfer, BigQuery Omni, Pub/Sub, Dataform) from a sensitive project. Cannot exclude essential dependencies (IAM, Logging, Monitoring). | project (NTK), folder (CONFIDENTIAL) |
| **B** `constraints/gcp.resourceLocations` | list | `in:REGION-locations` for the approved regions | Prevents standing up a resource in a jurisdiction outside DLP/monitoring coverage as an exfil staging ground; blocks cross-region BigQuery/Cloud SQL replicas. `us-east1` is auto-prefixed to `in:us-east1-locations`; multi-regions `us`/`eu`/`asia`/`global` are literal. | org |
| **B** `constraints/gcp.restrictEndpointUsage` | list (`deniedValues`) | deny the global endpoints you do not use | Forces regional/locational endpoints, blocking a global endpoint used to move data out of a data boundary. One of the few legacy constraints that supports dry-run. | org |
| **B** `constraints/gcp.detailedAuditLoggingMode` | boolean | `enforce: true` | Without it, Cloud Storage audit logs record *that* an object was read, not *which* objects and by what query — you cannot scope an incident. Credentials, `x-goog-encryption-key`, and object data are excluded from logs; detailed logging is best-effort. | folder holding CONFIDENTIAL/NTK |
| **B** `constraints/bigquery.disableBQOmniAWS` / `constraints/bigquery.disableBQOmniAzure` | boolean each | `enforce: true` | AP-07 cross-cloud variant: BigQuery Omni queries and **exports results** to S3 / Azure Blob. | org |
| **B** `constraints/dataform.restrictGitRemotes` | list | Deny-all, or the named internal remotes | A Dataform repo can push query results and config to an arbitrary external git remote. | org |
| **B** `constraints/datastream.managed.blockPublicConnectivityMethods` | managed, boolean | `enforce: true` | Datastream is a CDC pipe; a public connection profile streams database changes to an external endpoint. | org |
| **B** `constraints/run.allowedIngress` | list | `internal` or `internal-and-cloud-load-balancing` | Stops a Cloud Run service being published as an open data-pull endpoint. Note `internal` also admits several Google-managed callers (Cloud Scheduler, Cloud Tasks, Eventarc, Pub/Sub, Workflows) — it is not a network ACL. | folder |
| **B** `constraints/run.allowedVPCEgress` | list | `all-traffic` | With `private-ranges-only`, public egress from a Cloud Run service **bypasses the VPC entirely** — no firewall policy, no Cloud NAT logging, no flow logs. | folder |
| **B** `constraints/run.managed.requireInvokerIam` | managed, boolean | `enforce: true` | Blocks unauthenticated invocation by preventing the invoker IAM check being disabled. Complements domain-restricted sharing, which blocks the `allUsers` principal. | org |
| **C** `constraints/vertexai.genAIGroundingSources` | list (`is:`) | exclude `ExternalApiSimpleSearch`, `ExternalApiElasticSearch`, `UrlContext` | These grounding sources reach third-party endpoints **with prompt content attached** — a data-egress channel inside a managed service. | folder holding CONFIDENTIAL/NTK |
| **C** `constraints/vertexai.disableGenAIGoogleSearchGrounding` | boolean | `enforce: true` on NTK projects | Grounding sends prompt content to Search. | project (NTK) |
| **C** `constraints/vertexai.allowedPartnerModelFeatures` | list (`is:`) | exclude `:web_search` features | Partner-model `web_search` is an outbound call carrying prompt content off-platform. | folder |
| **C** `constraints/compute.trustedImageProjects` | list | the named publisher projects | Blocks booting an attacker-supplied image and constrains image-based data movement. | org |
| **C** `constraints/compute.storageResourceUseRestrictions` | list | the named projects | Snapshot → share → restore elsewhere is a real cross-project exfil route. | org |
| **C** `constraints/compute.disableGuestAttributesAccess` | boolean | `enforce: true` | Guest attributes are a writable metadata channel: write data in from the VM, read it out via the Compute API from elsewhere. Casing conflict across doc pages — use `...AttributesAccess` (verify casing before enforcement). | org |
| **C** `constraints/compute.skipDefaultNetworkCreation` | boolean | `enforce: true` | The `default` VPC ships with `default-allow-ssh` and `default-allow-rdp` from `0.0.0.0/0` and auto subnets in every region. | org |
| **C** `constraints/compute.requireVpcFlowLogs` | list | a predefined policy requiring flow logs | Detection, not prevention — without flow logs there is no egress evidence at all. | org |
| **C** `constraints/compute.requireShieldedVm` | boolean | `enforce: true` | Integrity monitoring makes bootkit-level persistence detectable; also enables HTTPS metadata access. | org |
| **C** `constraints/essentialcontacts.managed.allowedContactDomains` | managed, list | the org's own domains | An attacker who adds their address becomes a recipient of Google's breach notifications — an intelligence channel and a way to intercept recovery mail. Baseline-enforced on orgs ≥ 2024-05-03. Check the legacy spelling `constraints/essentialcontacts.allowedContactDomains` too; existing contacts are not affected by either. | org |
| **C** `constraints/sql.restrictPublicIp` / `constraints/sql.restrictAuthorizedNetworks` | boolean each | `enforce: true` | Stops a database getting an internet-reachable IP or `0.0.0.0/0` in its allow-list. **Not retroactive** to existing instances — enumerate existing instances separately. Managed spellings `sql.managed.*` are inconsistent across doc pages (verify against current docs); ship the legacy names. | org |
| **C** `constraints/cloudfunctions.requireVPCConnector` | boolean | `enforce: true` if 1st-gen functions exist | **1st gen only.** Most 2026 functions are Cloud Run functions, for which this constraint does nothing — use `constraints/run.allowedVPCEgress` instead. Pin the generation with `constraints/cloudfunctions.restrictAllowedGenerations`. | folder |

Constraints marked unverified and therefore **not** to be asserted without checking: `constraints/storage.managed.publicAccessPrevention`, `constraints/storage.managed.uniformBucketLevelAccess`, `constraints/bigquery.managed.*`, any predefined `constraints/dataproc.*` (Dataproc is custom-constraints-only, on `dataproc.googleapis.com/Cluster` with `CREATE`/`UPDATE`) — verify against current docs.

#### OP — Exfil scenario

Org policy is the **precursor layer** for most chains rather than the terminal control. Concretely:

- Absent `constraints/storage.publicAccessPrevention` + `constraints/storage.uniformBucketLevelAccess` is step 3 of **AP-04**: stage the data, set an object ACL, read it from anywhere with no Google identity.
- Absent key-creation constraints is step 1 of **AP-02**: mint a `.json` key, carry it to an on-prem host or a laptop, use it offline forever.
- Absent `constraints/iam.allowedPolicyMemberDomains` / `constraints/iam.managed.allowedPolicyMembers` is the *finish* of **AP-07** and **AP-11**: grant an external principal `roles/bigquery.dataViewer` and read from their own project.
- Absent `constraints/iam.workloadIdentityPoolProviders` is step 0 of **AP-10**.
- Absent `constraints/compute.vmExternalIpAccess` + `constraints/compute.restrictCloudNATUsage` is **AP-05**.
- **AP-13** runs *through* this control: an attacker with `orgpolicy.policy.set` deletes the constraint and then executes the step it blocked. Model these as two-step chains — each step alone looks benign, and only the pair is the attack.

Org policy does **not** block a principal who already holds the permission at a node where the constraint is not attached, and it does not apply retroactively for `constraints/sql.restrictPublicIp`, `constraints/sql.restrictAuthorizedNetworks`, or the CMEK constraints. Never report an org policy as closing a path without checking existing resources.

#### OP — Remediation

Set a boolean constraint at the org node, with an explicit exception at one folder:

```bash
cat > /tmp/pap.yaml <<'EOF'
name: organizations/ORGANIZATION_ID/policies/storage.publicAccessPrevention
spec:
  rules:
  - enforce: true
EOF
gcloud org-policies set-policy /tmp/pap.yaml

# Verify effectiveness across the hierarchy, not just at the org node:
gcloud asset analyze-org-policies \
  --constraint=constraints/storage.publicAccessPrevention \
  --scope=organizations/ORGANIZATION_ID --format=json
```

Repair a silent override (OP-03) by re-linking the child to its parent instead of deleting the child policy:

```bash
cat > /tmp/child.yaml <<'EOF'
name: projects/PROJECT_ID/policies/compute.vmExternalIpAccess
spec:
  inheritFromParent: true
  rules:
  - values:
      deniedValues:
      - projects/PROJECT_ID/zones/ZONE/instances/INSTANCE_NAME
EOF
gcloud org-policies set-policy /tmp/child.yaml --update-mask=spec
```
`--update-mask` is mandatory when updating an existing policy (`spec` | `dryRunSpec` | `*`); omitting it errors and the policy does not update. To remove a dry-run spec, re-set the policy with `--update-mask=dryRunSpec` and the field removed. To return a node to the Google default, `gcloud org-policies reset CONSTRAINT --project=PROJECT_ID`.

Terraform — always `google_org_policy_policy` (v2), never `google_organization_policy` (v1, cannot express conditions or dry-run):

```hcl
resource "google_org_policy_policy" "pap" {
  name   = "organizations/${var.org_id}/policies/storage.publicAccessPrevention"
  parent = "organizations/${var.org_id}"
  spec {
    rules { enforce = "TRUE" }
  }
}

# List constraint with a tag-conditioned exception. The unconditional rule MUST come last,
# and there may be exactly one of them.
resource "google_org_policy_policy" "locations" {
  name   = "organizations/${var.org_id}/policies/gcp.resourceLocations"
  parent = "organizations/${var.org_id}"
  spec {
    rules {
      condition {
        expression  = "resource.matchTag('${var.org_id}/location', 'us-west1')"
        title       = "us-west1 exception"
      }
      values { allowed_values = ["in:us-west1-locations"] }
    }
    rules {
      values { allowed_values = ["in:us-east1-locations"] }
    }
  }
}

# Managed constraint with parameters
resource "google_org_policy_policy" "allowed_members" {
  name   = "organizations/${var.org_id}/policies/iam.managed.allowedPolicyMembers"
  parent = "organizations/${var.org_id}"
  spec {
    rules {
      enforce = "TRUE"
      parameters = jsonencode({
        allowedPrincipalSets = ["//cloudresourcemanager.googleapis.com/organizations/${var.org_id}"]
      })
    }
  }
}
```

**Custom constraint — a working CEL example.** Use custom constraints for the fields no predefined constraint covers. This one closes both Storage exfil doors in one object, including bucket IP filtering, for which no predefined constraint exists:

```yaml
name: organizations/ORGANIZATION_ID/customConstraints/custom.bucketRequirePapAndIpFilter
resourceTypes:
  - storage.googleapis.com/Bucket
methodTypes:
  - CREATE
  - UPDATE
condition: "resource.iamConfiguration.publicAccessPrevention == 'enforced' && resource.ipFilter.mode == 'Enabled'"
actionType: ALLOW
displayName: Buckets must enforce public access prevention and IP filtering
description: New or updated buckets must set publicAccessPrevention to enforced and enable bucket IP filtering.
```

```bash
gcloud org-policies set-custom-constraint /tmp/custom.bucketRequirePapAndIpFilter.yaml
gcloud org-policies list-custom-constraints --organization=ORGANIZATION_ID
```

CEL rules that matter when authoring: the condition is capped at **1000 characters**; the name is capped at **70 characters** after the `custom.` prefix and may contain only letters and numbers; most resource types allow **20 custom constraints per organization**; `ALLOW` means the operation is permitted only if the condition is true, `DENY` means it is blocked when true. Guard every list index and map key (`resource.listValue.size() >= 1 && ...`, `has(resource.mapValue.foo) && ...`) or a `BAD_CONDITION` error blocks creation. Supported forms: `==`, `>`, `<`, `.matches()`, `.startsWith()`, `.endsWith()`, `.contains()`, `.exists(v, p)`, `.all(v, p)`, `has()`.

The IAM counterpart — block a named principal from being granted an admin role, and (with `REMOVE_GRANT`, which is supported only on `iam.googleapis.com/AllowPolicy`) block an attacker stripping a protective binding on the way through:

```yaml
name: organizations/ORGANIZATION_ID/customConstraints/custom.denyProjectIamAdminGrant
resourceTypes: iam.googleapis.com/AllowPolicy
methodTypes:
  - CREATE
  - UPDATE
  - REMOVE_GRANT
condition: "resource.bindings.exists(binding, RoleNameMatches(binding.role, ['roles/resourcemanager.projectIamAdmin']) && binding.members.exists(member, MemberSubjectMatches(member, ['user:EMAIL_ADDRESS'])))"
actionType: DENY
displayName: Do not allow EMAIL_ADDRESS to be granted the Project IAM Admin role
```

```hcl
resource "google_org_policy_custom_constraint" "bucket_pap_ipfilter" {
  name           = "custom.bucketRequirePapAndIpFilter"
  parent         = "organizations/${var.org_id}"
  display_name   = "Buckets must enforce PAP and IP filtering"
  action_type    = "ALLOW"
  condition      = "resource.iamConfiguration.publicAccessPrevention == 'enforced' && resource.ipFilter.mode == 'Enabled'"
  method_types   = ["CREATE", "UPDATE"]
  resource_types = ["storage.googleapis.com/Bucket"]
}
```

**Who can change org policy — the control-plane remediation.** `roles/orgpolicy.policyAdmin` is a meta-privilege: its holder can delete `constraints/iam.allowedPolicyMemberDomains` and then grant an external principal any role. Treat it with the same scrutiny as `roles/iam.securityAdmin`. Bind it only to a named guardrail-admin group at the org node, separate from any group that deploys workloads, and back it with an IAM Deny rule on `orgpolicy.googleapis.com/policies.create`, `.update`, `.delete` and `customConstraints.*` with that group as `exceptionPrincipals` (see §5.5). Alert on `google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy` (see §5.12).

---

### 5.2 VPC Firewall Policy

#### FW — Observe

1. **Collect all four surfaces.** `gcloud compute firewall-rules list` shows only classic VPC rules and will miss every hierarchical and network-policy rule. That single mistake invalidates most firewall reviews.
   ```bash
   # Hierarchical policies — org/folder ONLY, never a project
   gcloud compute firewall-policies list --organization=ORG_ID
   gcloud compute firewall-policies list --folder=FOLDER_ID
   gcloud compute firewall-policies describe POLICY --organization=ORG_ID --format=json

   # Network firewall policies — global and regional, defined in a project, associated to a VPC
   gcloud compute network-firewall-policies list --project=PROJECT_ID --global
   gcloud compute network-firewall-policies describe POLICY --global --format=json
   gcloud compute network-firewall-policies associations list --firewall-policy=POLICY --global

   # Classic VPC firewall rules
   gcloud compute firewall-rules list --project=PROJECT_ID --format=json
   ```
2. **Compute the effective rule set**, which is the only thing that answers "what is actually enforced":
   ```bash
   gcloud compute networks get-effective-firewalls NETWORK --project=PROJECT_ID --format=json
   gcloud compute instances network-interfaces get-effective-firewalls INSTANCE \
       --network-interface=nic0 --zone=ZONE --format=json
   ```
   (Exact flag lists for these two commands: verify against current docs.)
3. **Record the enforcement order** per VPC network: the API field `networkFirewallPolicyEnforcementOrder`, value `AFTER_CLASSIC_FIREWALL` (default) or `BEFORE_CLASSIC_FIREWALL`. The full evaluation sequence, and the classic-rule pre-emption it creates, are in §7.0 — read that before scoring any rule in this area.
4. **Record per rule**: `priority` (policies 0–2,147,483,547; classic 0–65535 default 1000), `direction`, `action` (`allow` | `deny` | `goto_next` | `apply_security_profile_group`; classic rules support only allow/deny), targeting (`target_secure_tags`, `target_service_accounts`, `target_tags`, or none = all instances), every `match` field (`src_ip_ranges`, `dest_ip_ranges`, `src_fqdns`/`dest_fqdns`, `src_region_codes`/`dest_region_codes`, `src_threat_intelligences`/`dest_threat_intelligences`, `src_address_groups`/`dest_address_groups`, `src_secure_tags`, `*_network_scope`/`*_network_context`, `layer4_configs`), `enable_logging` / `log_config.metadata`, and `disabled`.
5. **Record the implied posture**: every VPC has an implied **allow egress to `0.0.0.0/0`** and an implied **deny ingress** at priority 65535. Neither can be deleted and **neither can be logged**. The implied action for ingress to load balancers is **allow**, not deny.
6. **Record how each policy was created.** Console-created policies get predefined rules at priorities 1000–1005 (RFC1918 `goto_next` egress/ingress; ingress deny `iplist-tor-exit-nodes`, `iplist-known-malicious-ips`; egress deny `iplist-known-malicious-ips`; ingress deny geolocations `CU, IR, KP, SY, XC, XD`). Policies created by gcloud, the API, or Terraform get **only** the four immutable lowest-priority `goto_next` rules at 2147483644–2147483647. Do not assume the threat-intel and geo denies exist.
7. **Record secure-tag inventory and who can bind it**: `gcloud resource-manager tags keys list --parent=organizations/ORG_ID`, values per key, bindings per instance, and the holders of `roles/resourcemanager.tagAdmin` and `roles/resourcemanager.tagUser`. Record separately every principal holding `compute.instances.setTags` (in `roles/compute.instanceAdmin.v1`).

#### FW — Findings tests

1. **FW-01 — no default-deny egress.** In the effective rule set for a NIC in a subnet hosting CONFIDENTIAL or NTK workloads, there is no EGRESS `deny` rule matching `0.0.0.0/0`, or there is one but an EGRESS `allow` to `0.0.0.0/0` sits at a numerically lower priority. → **CRITICAL**. Absent any explicit rule, the implied allow-egress applies and everything leaves.
2. **FW-02 — IPv6 hole.** An EGRESS deny exists for `0.0.0.0/0` but not for `::/0`, and `constraints/compute.disableAllIpv6` is not enforced on the project. → **HIGH**.
3. **FW-03 — enforcement-order bypass.** A default-deny egress is implemented only in a **network** firewall policy, the network's `networkFirewallPolicyEnforcementOrder` is `AFTER_CLASSIC_FIREWALL`, and at least one classic VPC rule allows the traffic. The classic allow pre-empts the policy deny. → **HIGH**; the control the team believes exists does not.
4. **FW-04 — wrong VIP in the allow-list.** The egress allow-list contains `199.36.153.8/30` (private VIP) where `199.36.153.4/30` (restricted VIP) was intended, or contains `199.36.153.0/24`, which covers both and defeats the distinction. → **HIGH**. The two /30s are distinct and must not be mixed; mixing addresses from the two VIPs causes intermittent failures because the service set differs by destination.
5. **FW-05 — incomplete restricted-VIP allow-list.** IPv6 is in use and the allow-list omits `2600:2d00:0002:1000::/56`; or Private Google Access is in use and the allow-list omits `34.126.0.0/18` / `2001:4860:8040::/42`; or Cloud DNS outbound forwarding is configured and the allow-list omits `35.199.192.0/19`. → **MEDIUM** (breakage risk that pressures the team to widen the deny).
6. **FW-06 — spurious metadata rule.** An egress allow rule exists for `169.254.169.254` or `fd20:ce::254` "so VMs keep their identity tokens", **or** a deny rule to `169.254.169.254` is presented as a metadata-theft mitigation. Traffic to and from the metadata server is always allowed and bypasses firewall rules entirely. → **MEDIUM** as a finding on the deny (it is a false control); note the allow as harmless-but-misinformed. The only real mitigations are OS-level firewalling, GKE Workload Identity's metadata interception, or a GKE NetworkPolicy on `169.254.169.254`.
7. **FW-07 — FQDN objects used as egress DLP.** Any rule uses `src_fqdns`/`dest_fqdns` to control `*.googleapis.com`, or FQDN rules are presented as the exfil-domain control. Google's own guidance: "Most Google domain names, such as `googleapis.com`, are subject to one or more of these situations. Use IP addresses or address groups instead." → **MEDIUM**, and the egress control is not present. The disqualifying properties: no wildcards and no TLDs (minimum two labels); a hard cap of **32 IPv4 + 32 IPv6** addresses per FQDN with extras silently dropped; **fail-open** if the resolver is unreachable and no cached result exists; CNAME aliases must all be enumerated; A records with TTL < 90 s are unreliable.
8. **FW-08 — legacy network tags carry no IAM gate.** Any effective rule targets or sources on `target_tags` / `source_tags`. Any principal with `compute.instances.setTags` (held by `roles/compute.instanceAdmin.v1`) can move a VM into that rule's scope with no separate authorization on the tag string. → **HIGH**; this is a privilege-escalation path, not a hygiene note. Secure tags gate binding through `roles/resourcemanager.tagUser` (the underlying atomic permissions `resourcemanager.tagValues.use` / `resourcemanager.tagValueBindings.create`: verify against current docs).
9. **FW-09 — flat VPC (lateral movement).** Apply this test literally. A VPC is **flat** if **any** of the following is true:
   - an effective INGRESS `allow` rule has **no** `target_secure_tags`, **no** `target_service_accounts`, and **no** `target_tags` (i.e. it applies to every instance in the network), **and** its `src_ip_ranges` covers an RFC1918 range spanning two or more workload subnets, **and** its `layer4_configs` is not restricted to a single port belonging to one named shared service; **or**
   - `default-allow-internal` (TCP/UDP all ports + ICMP from `10.128.0.0/9`, priority 65534) is present and enabled; **or**
   - for any ordered pair of workload subnets (A, B) carrying different data classifications, the effective rule set permits any TCP port from A to B without a rule that names a secure tag or service account on **both** ends.
   → **HIGH**, escalated to **CRITICAL** where one side of the pair holds CONFIDENTIAL or NTK data. Report it as a lateral-movement finding feeding the traversal analysis, with the specific subnet pairs listed.
10. **FW-10 — east-west keyed on IP.** Intra-VPC allow rules exist but are keyed on IP ranges rather than secure tags or service accounts, so network policy and identity do not agree and re-IPing a workload silently changes its reachability. → **MEDIUM**, escalated to **HIGH** where the ranges are `/16` or larger.
11. **FW-11 — logging off.** `enable_logging` is false (or `log_config` absent on a classic rule) on any rule that allows egress off-network, allows traffic across a classification boundary, or denies traffic you intend to alert on. → **MEDIUM**. Record explicitly that implied rules and legacy-network rules cannot be logged, so an all-implied posture has zero firewall telemetry.
12. **FW-12 — hierarchy provides no floor.** The org and folder hierarchical policies contain only `goto_next` rules (or none at all), so nothing is enforced above the project level and a project owner's network admin can undo everything. → **HIGH**.
13. **FW-13 — missing threat-intel egress denies.** No effective EGRESS deny rule references `iplist-tor-exit-nodes`, `iplist-anon-proxies`, `iplist-vpn-providers`, `iplist-crypto-miners`, or `iplist-public-clouds-aws` / `iplist-public-clouds-azure` from a network hosting CONFIDENTIAL/NTK. → **MEDIUM**. The public-cloud lists are the ones that catch "exfil to my own S3 bucket". Do not put multiple lists in one rule (Google's guidance, for debuggability); destination threat-intelligence lists cannot be combined with a non-internet destination network context.
14. **FW-14 — disabled or shadowed denies.** Any rule with `disabled: true` that would otherwise deny, or a deny whose priority number is higher than an overlapping allow. → **HIGH** if it is the only egress deny.
15. **FW-15 — internal-IP channels not covered.** The egress posture is `deny 0.0.0.0/0` plus an `allow` for RFC1918, and PSC endpoints, peered VPCs, or interconnect destinations sit inside that RFC1918 allow. → **HIGH**; the "default-deny" does not cover the private egress channels. Cross-reference §5.6.
16. **FW-16 — packet mirroring as an exfil path.** Any principal outside the network-admin group holds `roles/compute.packetMirroringAdmin` or `roles/compute.packetMirroringUser`, or a mirroring policy exists whose collector is outside the security project. → **HIGH**. Mirroring clones production traffic to a collector with **no egress firewall rule from the victim VM**.

#### FW — Exfil scenario

Firewall policy is the control for **AP-05** (egress via VM external IP or an open egress rule to `0.0.0.0/0`) and the first hop of **AP-12** (compromised cloud workload → interconnect → flat interior). It is *not* a control for **AP-01**, **AP-03**, or **AP-07** — Google API calls to `storage.googleapis.com` from inside the VPC look like ordinary allowed egress; only VPC Service Controls plus the restricted VIP constrain those. Say this explicitly in the report so nobody counts the firewall twice.

The flat-VPC finding (FW-09) is the cloud-side instance of the same soft-interior problem the on-prem network has: it converts one compromised workload into reachability across the whole environment, which is what turns a single-service compromise into **AP-11** and **AP-12**. Neither Cloud NGFW Enterprise nor Secure Web Proxy is data-loss prevention: NGFW Enterprise gives IDS/IPS, URL filtering and TLS inspection; SWP gives URL and identity-based proxy policy. Neither classifies exfiltrated content. Do not present either as an exfil control for Google-API-shaped exfil.

#### FW — Remediation

Default-deny egress with a restricted-VIP allow-list, in a **network** firewall policy, plus the enforcement-order fix that makes it actually win:

```bash
POLICY=fw-egress-baseline

gcloud compute network-firewall-policies create $POLICY --global \
    --description="Default-deny egress; restricted VIP only"

# Lowest-priority catch-all denies (IPv4 and IPv6), logged.
gcloud compute network-firewall-policies rules create 65000 \
    --firewall-policy=$POLICY --global-firewall-policy \
    --direction=EGRESS --action=deny \
    --dest-ip-ranges=0.0.0.0/0 --layer4-configs=all --enable-logging
gcloud compute network-firewall-policies rules create 65001 \
    --firewall-policy=$POLICY --global-firewall-policy \
    --direction=EGRESS --action=deny \
    --dest-ip-ranges=::/0 --layer4-configs=all --enable-logging

# Higher-priority allow for the restricted VIP only (NOT 199.36.153.8/30, NOT 199.36.153.0/24).
gcloud compute network-firewall-policies rules create 1000 \
    --firewall-policy=$POLICY --global-firewall-policy \
    --direction=EGRESS --action=allow \
    --dest-ip-ranges=199.36.153.4/30,2600:2d00:0002:1000::/56 \
    --layer4-configs=tcp:443 --enable-logging

gcloud compute network-firewall-policies associations create \
    --firewall-policy=$POLICY --global-firewall-policy \
    --network=NETWORK_NAME --name=assoc-NETWORK_NAME

# Route the restricted VIP privately (required, and NOT an internet path despite the next hop name):
gcloud compute routes create rt-restricted-vip \
    --network=NETWORK_NAME --destination-range=199.36.153.4/30 \
    --next-hop-gateway=default-internet-gateway
```

Make the policy deny beat leftover classic rules: set the VPC network's `networkFirewallPolicyEnforcementOrder` to `BEFORE_CLASSIC_FIREWALL` (API field and both enum values confirmed; the gcloud flag spelling — reported as `--policy-enforcement-order` on `gcloud compute networks update` — verify against current docs). Then delete the classic rules the policy replaces rather than leaving both.

East-west segmentation keyed on identity, not IP:

```bash
gcloud resource-manager tags keys create svc \
    --parent=organizations/ORGANIZATION_ID --purpose=GCE_FIREWALL --purpose-data=organization=auto
gcloud resource-manager tags values create payments --parent=ORGANIZATION_ID/svc
gcloud resource-manager tags values create ledger   --parent=ORGANIZATION_ID/svc

# Only tagged payments instances may reach tagged ledger instances, on one port.
gcloud compute network-firewall-policies rules create 900 \
    --firewall-policy=$POLICY --global-firewall-policy \
    --direction=INGRESS --action=allow \
    --src-secure-tags=tagValues/TAGVALUE_ID_PAYMENTS \
    --target-secure-tags=tagValues/TAGVALUE_ID_LEDGER \
    --layer4-configs=tcp:8443 --enable-logging

# Catch-all intra-VPC deny beneath it.
gcloud compute network-firewall-policies rules create 64000 \
    --firewall-policy=$POLICY --global-firewall-policy \
    --direction=INGRESS --action=deny \
    --src-ip-ranges=10.0.0.0/8 --layer4-configs=all --enable-logging
```

Terraform:

```hcl
resource "google_compute_network_firewall_policy" "egress_baseline" {
  name        = "fw-egress-baseline"
  project     = var.host_project
  description = "Default-deny egress; restricted VIP only"
}

resource "google_compute_network_firewall_policy_rule" "deny_egress_v4" {
  firewall_policy = google_compute_network_firewall_policy.egress_baseline.name
  project         = var.host_project
  direction       = "EGRESS"
  action          = "deny"
  priority        = 65000
  enable_logging  = true
  match {
    dest_ip_ranges = ["0.0.0.0/0"]
    layer4_configs { ip_protocol = "all" }
  }
}

resource "google_compute_network_firewall_policy_rule" "allow_restricted_vip" {
  firewall_policy = google_compute_network_firewall_policy.egress_baseline.name
  project         = var.host_project
  direction       = "EGRESS"
  action          = "allow"
  priority        = 1000
  enable_logging  = true
  match {
    dest_ip_ranges = ["199.36.153.4/30", "2600:2d00:0002:1000::/56"]
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443"]
    }
  }
}

resource "google_compute_network_firewall_policy_rule" "east_west_payments_to_ledger" {
  firewall_policy = google_compute_network_firewall_policy.egress_baseline.name
  project         = var.host_project
  direction       = "INGRESS"
  action          = "allow"
  priority        = 900
  enable_logging  = true
  target_secure_tags { name = "tagValues/${var.tv_ledger}" }
  match {
    src_secure_tags { name = "tagValues/${var.tv_payments}" }
    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["8443"]
    }
  }
}

resource "google_compute_network_firewall_policy_association" "assoc" {
  name              = "assoc-${var.network_name}"
  project           = var.host_project
  firewall_policy   = google_compute_network_firewall_policy.egress_baseline.name
  attachment_target = google_compute_network.vpc.id
}
```

Enable logging on the remaining classic rules you cannot yet delete: `log_config { metadata = "INCLUDE_ALL_METADATA" }` on `google_compute_firewall`. Note that `source_tags`/`target_tags` cannot be combined with `source_service_accounts`/`target_service_accounts` on the same classic rule — that constraint is often what forces a team onto tag-only targeting, and migrating to a network firewall policy with secure tags removes it.

Quota ceilings to respect when designing: 256 source/target secure tags per policy rule, 30 source / 70 target network tags per classic rule, 10 source/target service accounts per rule, 5,000 IP ranges per rule, 10 address groups per rule, 100 FQDNs per rule, 10 secure-tag values per VM network interface, 1,000 values per tag key. Address groups are the right container for large IP sets: organization-scoped groups work in hierarchical and network policies, project-scoped only in network and regional network policies, and the group's location must match the policy's.

---

### 5.3 VPC Service Controls

This is the primary GCP exfiltration control. Assess it harder than anything else in the catalog.

#### SC — Observe

1. Enumerate access policies. There is exactly **one** organization-level policy permitted, and up to **50** folder/project-scoped policies.
   ```bash
   gcloud access-context-manager policies list --organization=ORG_ID --format=json
   gcloud access-context-manager policies describe POLICY_NUMBER --format=json
   ```
   If no org-level policy exists, record it: scoped policies behave unpredictably without one.
2. Enumerate perimeters, enforced and dry-run, and every access level.
   ```bash
   gcloud access-context-manager perimeters list --policy=POLICY --format=json
   gcloud access-context-manager perimeters describe PERIMETER --policy=POLICY --format=json
   gcloud access-context-manager perimeters dry-run list --policy=POLICY --format=json
   gcloud access-context-manager levels list --policy=POLICY --format=json
   gcloud access-context-manager levels describe LEVEL --policy=POLICY --format=json
   ```
3. For each perimeter record, verbatim: `perimeterType` (`PERIMETER_TYPE_REGULAR` | `PERIMETER_TYPE_BRIDGE`), `useExplicitDryRunSpec`, and both `status.*` (the **enforced** config) and `spec.*` (the **dry-run** config) for: `resources[]`, `accessLevels[]`, `restrictedServices[]`, `vpcAccessibleServices{enableRestriction, allowedServices, allowedServicePatterns, servicePatternsEnforcementScopes}`, `ingressPolicies[]`, `egressPolicies[]`. Perimeter members are **projects (by project *number*, `projects/PROJECT_NUMBER`) and VPC networks (`//compute.googleapis.com/projects/PROJECT_ID/global/networks/NAME`) only** — folders and organizations cannot be perimeter members, so a claim that "the folder is in the perimeter" is a misunderstanding to correct.
4. For each ingress rule record `ingressFrom.identityType`, `ingressFrom.identities[]`, `ingressFrom.sources[].accessLevel|.resource|.pscEndpoint`, `ingressTo.resources[]`, `ingressTo.operations[].serviceName`, `.methodSelectors[].method|.permission`, `ingressTo.roles[]`, `title`. For each egress rule record the `egressFrom` equivalents plus **`egressFrom.sourceRestriction`**, and `egressTo.resources[]`, `egressTo.externalResources[]`, `egressTo.operations[]`, `egressTo.roles[]`. (The `pscEndpoint` sub-fields: verify against current docs.)
5. For each access level record every `basic.conditions[]` field — `ipSubnetworks[]`, `members[]`, `devicePolicy{...}`, `regions[]`, `requiredAccessLevels[]`, `negate`, `vpcNetworkSources[]` — and `combiningFunction` (`AND` default | `OR`); or, for a custom level, the full `custom.expr`.
6. Build the restricted-services completeness inputs:
   ```bash
   # (a) the machine-readable list of what VPC-SC can protect at all
   gcloud access-context-manager supported-services list --format=json
   # (b) the services actually enabled in each perimeter member project
   gcloud services list --enabled --project=PROJECT_ID --format="value(config.name)"
   # (c) which IAM roles/permissions are usable in ingress/egress rules
   gcloud access-context-manager supported-permissions list
   ```
   Never hardcode a service list — it rots. The `supported-services list` output columns include `SERVICE_SUPPORT_STAGE`, `AVAILABLE_ON_RESTRICTED_VIP`, and `KNOWN_LIMITATIONS`; record all three.
7. Record who can mutate the perimeter: every binding of `roles/accesscontextmanager.policyAdmin`, `roles/accesscontextmanager.policyEditor`, `roles/accesscontextmanager.admin`, `roles/accesscontextmanager.editor`, `roles/accesscontextmanager.gcpAccessAdmin`, **and every `roles/owner` / `roles/editor` binding at the organization node** (see test SC-24).
8. Record the IaC shape: which Terraform resources manage perimeters, whether `..._service_perimeters` (plural) or `..._access_levels` (plural) appear anywhere, and whether `lifecycle { ignore_changes = ... }` blocks are present where required.

#### SC — Findings tests

1. **SC-01 — project in no perimeter.** A project holding CONFIDENTIAL or NTK data does not appear (by project **number**) in `status.resources` of any `PERIMETER_TYPE_REGULAR` perimeter. → **CRITICAL**. A project can belong to only one regular perimeter across all policies, so this is unambiguous.
2. **SC-02 — dry-run masquerading as protection.** `useExplicitDryRunSpec: true` **and** `status` is absent, or `status.restrictedServices` is empty, while `spec` carries a rich configuration. The perimeter enforces nothing. → **CRITICAL**. Terraform tell: `use_explicit_dry_run_spec = true` with an unset or empty `status` block.
3. **SC-03 — invalid dry-run state.** `useExplicitDryRunSpec: false` with a populated `spec`. The spec is not evaluated; the implicit dry-run spec mirrors `status`. → **MEDIUM**, config defect that misleads every later reader.
4. **SC-04 — restricted-services completeness.** Run this procedure per perimeter and emit one finding per gap:
   1. `M` = the perimeter's member projects.
   2. `E` = union over `M` of enabled services (`gcloud services list --enabled`).
   3. `S` = the supported-services list.
   4. `R` = `status.restrictedServices`.
   5. **Gap class 1 (closable):** `(E ∩ S) \ R` — services that VPC-SC *can* protect but this perimeter does not restrict. → **HIGH**, **CRITICAL** when the service is data-bearing: `storage.googleapis.com`, `bigquery.googleapis.com`, `bigquerystorage.googleapis.com`, `bigquerydatatransfer.googleapis.com`, `pubsub.googleapis.com`, `spanner.googleapis.com`, `sqladmin.googleapis.com`, `firestore.googleapis.com`, `datastore.googleapis.com`, `cloudkms.googleapis.com`, `secretmanager.googleapis.com`, `dataflow.googleapis.com`, `dataproc.googleapis.com`, `composer.googleapis.com`, `aiplatform.googleapis.com`, `notebooks.googleapis.com`, `artifactregistry.googleapis.com`, `storagetransfer.googleapis.com`, `logging.googleapis.com`, `dlp.googleapis.com`.
   6. **Gap class 2 (unclosable):** `E \ S` — enabled services VPC-SC cannot protect at all. Attempting to add one to `restrictedServices` errors. → **HIGH**, remediated only by removing the service (`constraints/gcp.restrictServiceUsage`), moving it to a project outside the perimeter, and closing the network path with the restricted VIP or a PSC `vpc-sc` bundle.
5. **SC-05 — named unclosable holes present.** Any of the following is in use inside or adjacent to a perimeter. Each is a documented hole; report the ones that apply, with the specific resource:
   | Surface | What VPC-SC cannot do | Consequence |
   |---|---|---|
   | App Engine (standard and flexible) | Not supported; Google says do not include App Engine projects in perimeters | Project is both broken and unprotected; the workaround (App Engine SA in an access level) is itself a hole |
   | Cloud Billing | Not supported; billing export writes into a perimeter-protected bucket/dataset **with no access level or ingress rule** | Documented write-into-perimeter path that bypasses ingress rules |
   | Cloud Deployment Manager | Not supported; workaround puts `PROJECT_NUMBER@cloudservices.gserviceaccount.com` in an access level | A very wide service-agent grant |
   | Cloud Shell | Treated as **outside** the perimeter; allowed back in only from a device meeting the access level | Device-policy-gated bypass |
   | Google Cloud console | Always outside; console access over Private Google Access is unsupported | Forces a public-IP-range access level (see SC-18) |
   | Metadata server | Protection does not apply to traffic to or from `169.254.169.254` | Token minting and impersonation happen outside the boundary |
   | Workforce Identity Federation admin APIs | Not supported; org-level resources cannot be added to perimeters | Google's own published remedy is a very wide STS egress rule — see SC-14 |
   | IAP for TCP | Only the *usage* API is protectable; the admin API is not | Tunnel configuration is outside |
   | OS Login | SSH connections to VMs are not protected | Shell access is outside |
   | Earth Engine | Export to Google Drive not supported; legacy assets and Apps unprotected; VPC-SC only on Premium | Direct exfil channel to Drive |
   | Bare Metal Solution, Service Networking, Transfer Appliance, Google Distributed Cloud (software) for bare metal, Geocoding, Web Risk Evaluate/Submission, App Optimize | APIs cannot be protected by perimeters | Each is an unpoliced surface; remove or isolate |
   | Policy Simulator | Simulations on org and folder resources are not protected | Control-plane read outside the perimeter |
   | Dataflow Vertical Autoscaling | Requires **disabling VPC accessible services** to use inside a perimeter | Forces turning a control off |
   | Container Registry read-only mirrors | `gcr.io` mirrors available to all projects regardless of perimeters | Read path outside |
   | Client libraries / SA keys older than 2018-11-01 | Bypass token-endpoint pinning | Ancient credentials evade the perimeter |
   → **HIGH** each, or **CRITICAL** where the surface sits in a project holding CONFIDENTIAL/NTK.
6. **SC-06 — per-method exceptions.** A perimeter relies on a supported service whose relevant methods appear on the service-method-exceptions list (methods VPC-SC cannot control, which cross perimeter boundaries). → **MEDIUM–HIGH**. Cite the exceptions page rather than hardcoding entries; contents of the supported-method-restrictions page: verify against current docs.
7. **SC-07 — `ANY_IDENTITY` ingress.** Any ingress rule has `ingressFrom.identityType: ANY_IDENTITY`. This allows requests from all identities **including unauthenticated requests**. → **CRITICAL**.
8. **SC-08 — `ANY_USER_ACCOUNT` / `ANY_SERVICE_ACCOUNT` ingress.** These do not mean "any account in my org" — the attribute **does not restrict identities by organization**. `ANY_SERVICE_ACCOUNT` admits a service account from any Google Cloud organization on the internet. → **HIGH**, **CRITICAL** if paired with a wildcard source or wildcard `ingressTo`.
9. **SC-09 — wildcard source.** `ingressFrom.sources[].accessLevel: "*"` (or the egress equivalent) — the rule allows access from **any network origin**. → **HIGH** alone; **CRITICAL** in combination with test 7/8 plus `ingressTo.resources: ["*"]` and `serviceName: "*"`, which together fully negate the perimeter.
10. **SC-10 — wildcard destination inside.** `ingressTo.resources: ["*"]` — access to all resources inside the perimeter. → **HIGH**.
11. **SC-11 — wildcard operations.** `operations[].serviceName: "*"` (allows all methods **and permissions** for all services) or `methodSelectors[].method: "*"` (allows all methods **and permissions** for that service). → **HIGH**. There is no documented `*` for `methodSelectors[].permission`; a rule claiming one is malformed.
12. **SC-12 — unbounded federated identity.** `identities[]` contains any `principalSet://.../*` form (workload pool, workforce pool, agent trust domain, or SPIFFE). → **HIGH**, same class as `ANY_SERVICE_ACCOUNT`.
13. **SC-13 — service agents admitted.** `identities[]` (ingress/egress) or an access level's `members[]` contains a Google-managed **service agent** (e.g. `PROJECT_NUMBER@cloudservices.gserviceaccount.com`, `service-*@gcp-sa-*.iam.gserviceaccount.com`) rather than a customer-managed SA. Each such entry is a standing hole created to work around an unsupported service. → **HIGH**; list each with the integration it exists for, and whether that integration is still in use.
14. **SC-14 — the published-wide-rule case.** An egress rule matches Google's own documented Workforce Identity Federation workaround: `serviceName: 'sts.googleapis.com'`, `method: '*'`, `resources: ['*']`, `identityType: ANY_IDENTITY`. Recognise it as the documented remedy rather than reporting it as an unexplained wildcard — then still report it, narrowed: replace `ANY_IDENTITY` with the named workforce pool principal set and scope `resources` if the STS calls have known targets. → **HIGH**.
15. **SC-15 — egress to everywhere.** `egressTo.resources: ["*"]` authorizes access to **all resources outside the perimeter** — i.e. copy to any Google Cloud project on earth. → **CRITICAL**.
16. **SC-16 — `sourceRestriction` fail-open.** An egress rule sets `egressFrom.sources[]` but leaves `sourceRestriction` unset or `SOURCE_RESTRICTION_UNSPECIFIED`. VPC-SC then **ignores the `sources` attribute and enforces no source restriction** — the rule silently applies to every source in the perimeter. → **HIGH**. This is the single highest-yield egress-rule defect.
17. **SC-17 — external-cloud egress.** `egressTo.externalResources[]` names an `s3://`, `s3a://`, `s3n://`, or `azure://...blob.core.windows.net/...` target that is not in the documented data-flow inventory. → **HIGH**. Note the one genuine safety property: `'*'` is **not allowed** in `externalResources`, so this channel is always explicitly enumerated.
18. **SC-18 — access level allows everything.** For any `basic.conditions[]` entry: `ipSubnetworks` empty **and** `members` empty **and** `devicePolicy` unset. Each empty list means *allow all* — empty `ipSubnetworks` allows all IPs, absent `members` allows any user, unset `devicePolicy` allows all devices, and within `devicePolicy` each empty list allows all encryption statuses / OS types / management levels. A level that "looks configured" can grant everything. → **CRITICAL**. This is the highest-yield access-level check.
19. **SC-19 — negated condition.** Any condition with `negate: true`. It becomes a **NAND** over its non-empty fields: the condition is satisfied whenever *any* non-empty criterion evaluates false, which is far broader than it reads. → **HIGH**, require explicit justification.
20. **SC-20 — geolocation used where it cannot work.** A level uses `regions[]` while the intended callers are on-prem or arrive via Private Google Access. Geographic location works only for **public** source IPs; levels requiring a region **always deny requests from private IP addresses and do not support Private Google Access**. And a VPN moves the apparent location to the VPN server's public IP. → **MEDIUM** as a broken control; **HIGH** if it is the only condition and the rule is believed to be enforcing.
21. **SC-21 — shared NAT range admitted.** `ipSubnetworks` contains the public IP range of a NAT gateway shared by many workloads (typically added to make the Cloud console usable). Every workload behind that NAT inherits the access level. → **HIGH**.
22. **SC-22 — access-level dependency sprawl.** A tight-looking level lists `requiredAccessLevels` (all of which must be granted) or is one of many org-wide levels attachable to many perimeters. Note that violation logs report **all matching access levels under the organization**, including levels not attached to the violated perimeter. → **MEDIUM**; require an inventory of which perimeters each level is attached to.
23. **SC-23 — bridge over-connection.** Any perimeter with `perimeterType: PERIMETER_TYPE_BRIDGE`. A bridge is an **all-services, bidirectional** hole with no service, method, identity, or direction filter available — `restrictedServices` and `accessLevels` must both be empty on a bridge. → **HIGH** by default; **CRITICAL** if the bridge's member set spans a CONFIDENTIAL-tier perimeter and an NTK-tier perimeter. Record the one structural mitigation: bridges are **non-transitive** (A↔B and B↔C does not give A↔C), and bridges cannot span organizations or scoped policies.
24. **SC-24 — who can turn the control off.** Any principal holds `roles/owner` or `roles/editor` **at the organization node**. Both basic roles grant `accesscontextmanager.servicePerimeters.create|update|delete|replaceAll|commit` and `accesscontextmanager.policies.create|update|delete` — an org-level Owner or Editor can delete every perimeter in the organization. → **CRITICAL**. Also enumerate holders of `roles/accesscontextmanager.policyAdmin`, `roles/accesscontextmanager.policyEditor`, `roles/accesscontextmanager.admin`, `roles/accesscontextmanager.editor`, and of `accesscontextmanager.policies.setIamPolicy` (`roles/owner`, `roles/accesscontextmanager.admin`, `roles/accesscontextmanager.policyAdmin`, `roles/iam.securityAdmin`). Auditing only `roles/accesscontextmanager.*` misses the basic-role path, which is the common real case. Note the scope rule: ACM permissions granted on folders or projects **have no effect on scoped policies**; only org-level grants do.
25. **SC-25 — no un-overridable backstop on perimeter deletion.** No IAM Deny policy at the org node covers `accesscontextmanager.googleapis.com/servicePerimeters.delete`, `.update`, `.replaceAll`, `.commit` and `accesscontextmanager.googleapis.com/policies.*`. Org-policy custom constraints **cannot** cover this: ACM custom constraints support only `CREATE` and `UPDATE`, never `DELETE`. IAM Deny is therefore the only control that stops an org-level Owner/Editor. → **HIGH**.
26. **SC-26 — Shared VPC membership gap.** A perimeter contains a service project on a Shared VPC network but not the **host project** of that network. → **HIGH**; the perimeter has silent gaps and breakage. Same requirement for private services access: host and service project must be in the same perimeter.
27. **SC-27 — VPC accessible services not restricting.** `vpcAccessibleServices.enableRestriction` is false, or `allowedServices` is broader than the literal token `RESTRICTED-SERVICES` plus a short, justified list. (`"*"` is not a documented value for `allowedServices` — a config using it is malformed.) Also verify the prerequisites are actually met: the perimeter protects the same services you allow, the VPCs use the **restricted VIP**, and layer-3 firewalls are in place — without those, this feature bounds nothing. Note it does not apply to Google-API-to-Google-API communication or tenancy-unit networks. → **HIGH**.
28. **SC-28 — private VIP without service patterns.** The environment uses `private.googleapis.com` or a PSC endpoint with the `all-apis` bundle **without** `vpcAccessibleServices.allowedServicePatterns` and `servicePatternsEnforcementScopes: [GOOGLE_APIS_VIA_PRIVATE_PATH]`. Google's own wording: using `private.googleapis.com` without service patterns "can allow access to services that are not compliant with VPC Service Controls and might introduce data exfiltration risks." → **HIGH**. (Service-pattern syntax detail: verify against current docs.)
29. **SC-29 — evidence destruction path open.** The `_Default` sink (or any sink) carries an exclusion filter containing `LOG_ID("cloudaudit.googleapis.com/policy")`. Policy Denied logs cannot be disabled but they *can* be excluded from a sink — this deletes the record of every perimeter violation. → **HIGH**. Cross-reference §5.12.
30. **SC-30 — dry-run violations unread.** Dry-run or enforced violation logs exist and no one triages them. Dry-run violations are free attack-path evidence: they show exactly which principal tried to cross which boundary, without blocking anything. → **MEDIUM**, but treat the *absence of triage* as a detection finding and mine the logs yourself during the review (see §5.12 for the query).
31. **SC-31 — pre-existing Pub/Sub push subscriptions.** Push subscriptions created **before** the perimeter existed are not blocked by it. Enumerate every push subscription in perimeter member projects and check its creation time against the perimeter's. → **HIGH**; remediation is to delete and re-create them.
32. **SC-32 — IaC that silently deletes perimeters.** The repo contains `google_access_context_manager_service_perimeters` (plural) or `google_access_context_manager_access_levels` (plural), which **replace all** perimeters/levels in the policy atomically and will override anything created by the singular resources, causing a permadiff. → **HIGH**. Same reasoning applies to the REST `replaceAll` methods and the `accesscontextmanager.*.replaceAll` permissions.
33. **SC-33 — IaC oscillation / blinded drift detection.** The repo uses `google_access_context_manager_service_perimeter` alongside `..._service_perimeter_resource` / `..._ingress_policy` **without** the required `lifecycle { ignore_changes = [status[0].resources] }` (or `[status[0].ingress_policies]`, or the `spec[0].*` equivalents for dry-run resources). The two resources then fight, and **projects silently drop out of the perimeter on some applies**. → **HIGH**. Report the converse too: once `ignore_changes` is set, Terraform no longer detects out-of-band additions of projects to the perimeter, so drift detection for membership must come from Cloud Asset Inventory instead. (`ignore_changes` strings for `..._egress_policy` and the two `..._dry_run_*_policy` resources are inferred from their siblings — verify against current docs.)
34. **SC-34 — deprecated IaC resources.** The repo uses `google_access_context_manager_ingress_policy` or `google_access_context_manager_egress_policy` (no `service_perimeter_` infix). Both are deprecated in favour of `..._service_perimeter_ingress_policy` / `..._egress_policy`, and their legacy argument shapes do not resemble the real rule schema. → **MEDIUM**; a review rule matching only the short names both misses live config and matches dead config.
35. **SC-35 — quota pressure.** Ingress+egress rule attributes approaching **6,000 per perimeter config** (counted separately for enforced and dry-run), identity groups approaching **1,000**, VPC networks approaching **500** per policy, or perimeters approaching **10,000** per policy (bridges count). → **LOW–MEDIUM**; matters because hitting a limit forces someone to widen rules rather than add them.

#### SC — Exfil scenario

VPC-SC is the control that should terminate **AP-01** (stolen credential used against a data API from outside the perimeter) and **AP-07** (BigQuery/Storage export or copy into an attacker-controlled external project). It is also the only control that survives a full IAM compromise inside a project, which is why **AP-13** targets it directly: Access Context Manager write access is equivalent to turning the control off, and org-level `roles/owner`/`roles/editor` carries that write access.

What it does **not** cover, and must never be credited with: it is explicitly "not designed to enforce comprehensive controls on metadata movement"; it "doesn't block access to any third-party APIs or services on the internet"; and it is independent of IAM, never a replacement for it. Requests to and from the metadata server are outside it entirely, which is why **AP-03** (impersonation) and **AP-11** (multi-hop escalation) run underneath a perfectly configured perimeter. Cross-perimeter requests need **both** an egress rule on the source side and an ingress rule on the destination side; a request from a project in one perimeter to a protected resource in another is denied **even if an access level would normally allow it**.

For hybrid access (**AP-12** in the on-prem→cloud direction), an access level based on `ipSubnetworks` alone is a network-position-only control: anything that can route packets from the corporate LAN — a compromised laptop, a rogue VM on the same VLAN, a partner site-to-site VPN — inherits it. Google's own guidance under `NO_MATCHING_ACCESS_LEVEL` is to prefer an **ingress rule** over an access level, because the ingress rule can name identities. Note the asymmetry that forces bad designs: access-level `members[]` supports only `user:` and `serviceAccount:` and explicitly **does not support groups**, while ingress/egress `identities[]` **does** support `group:` plus workforce/workload pool and agent principals — which access levels cannot express at all.

#### SC — Remediation

Bring a perimeter to enforced with a complete restricted-services list:

```bash
gcloud access-context-manager perimeters update PERIMETER --policy=POLICY \
    --add-resources=projects/PROJECT_NUMBER \
    --add-restricted-services=storage.googleapis.com,bigquery.googleapis.com,bigquerystorage.googleapis.com,pubsub.googleapis.com,cloudkms.googleapis.com,secretmanager.googleapis.com \
    --enable-vpc-accessible-services \
    --add-vpc-allowed-services=RESTRICTED-SERVICES

# Promote a validated dry-run configuration to enforced (only a MODIFIED dry-run config can be enforced):
gcloud access-context-manager perimeters dry-run enforce PERIMETER --policy=POLICY
```

Replace a wildcard ingress rule with a scoped one. Rules are supplied as YAML files (`--ingress-policies=FILE`, `--egress-policies=FILE`):

```yaml
# ingress.yaml — named identities, named source, named service and methods, named destination.
- ingressFrom:
    identities:
      - serviceAccount:etl-reader@data-prod-01.iam.gserviceaccount.com
      - group:grp-data-analysts@example.com
    sources:
      - accessLevel: accessPolicies/POLICY/accessLevels/al_corp_managed_device
  ingressTo:
    resources:
      - projects/PROJECT_NUMBER
    operations:
      - serviceName: bigquery.googleapis.com
        methodSelectors:
          - method: google.cloud.bigquery.v2.JobService.Query
          - method: google.cloud.bigquery.v2.TableDataService.List
  title: analysts-and-etl-into-data-prod-01
```

```yaml
# egress.yaml — sourceRestriction MUST be set or `sources` is ignored entirely.
- egressFrom:
    identities:
      - serviceAccount:replicator@data-prod-01.iam.gserviceaccount.com
    sources:
      - resource: projects/PROJECT_NUMBER
    sourceRestriction: SOURCE_RESTRICTION_ENABLED
  egressTo:
    resources:
      - projects/DR_PROJECT_NUMBER
    operations:
      - serviceName: storage.googleapis.com
        methodSelectors:
          - method: google.storage.objects.create
  title: dr-replication-only
```

Narrow an access level so no empty list silently allows everything, and prefer identity over IP:

```yaml
# level.yaml
- ipSubnetworks:
    - 10.10.0.0/16
  members:
    - user:oncall-1@example.com
    - user:oncall-2@example.com
  devicePolicy:
    requireScreenlock: true
    requireCorpOwned: true
    allowedEncryptionStatuses:
      - ENCRYPTED
    allowedDeviceManagementLevels:
      - COMPLETE
  negate: false
```
```bash
gcloud access-context-manager levels update al_corp_managed_device \
    --policy=POLICY --basic-level-spec=level.yaml --combine-function=AND
```
`combiningFunction: AND` is the default and the one you want; `OR` turns a multi-condition level into a set of independent doors. Note `vpcNetworkSources` cannot be used together with `ipSubnetworks` in the same condition (its REST sub-field names: verify against current docs).

Ban perimeter bridges structurally — Google publishes this exact custom constraint and recommends replacing bridges with ingress/egress rules:

```yaml
name: organizations/ORGANIZATION_ID/customConstraints/custom.denyBridgePerimeters
resourceTypes:
  - accesscontextmanager.googleapis.com/ServicePerimeter
methodTypes:
  - CREATE
  - UPDATE
condition: "resource.perimeterType == 'PERIMETER_TYPE_BRIDGE'"
actionType: DENY
displayName: Disable perimeter bridges
description: Disables perimeter bridges; use ingress and egress rules instead.
```

Because that constraint cannot cover `DELETE`, add the IAM Deny backstop at the org node (this is what stops an org-level Owner/Editor deleting perimeters). Deny policies require the **v2 permission format**; the short allow-policy spelling `accesscontextmanager.servicePerimeters.delete` will not match:

```json
{
  "displayName": "protect-vpcsc-control-plane",
  "rules": [
    {
      "denyRule": {
        "deniedPrincipals": ["principalSet://goog/public:all"],
        "exceptionPrincipals": ["principalSet://goog/group/grp-guardrail-admins@example.com"],
        "deniedPermissions": [
          "accesscontextmanager.googleapis.com/servicePerimeters.delete",
          "accesscontextmanager.googleapis.com/servicePerimeters.update",
          "accesscontextmanager.googleapis.com/servicePerimeters.replaceAll",
          "accesscontextmanager.googleapis.com/servicePerimeters.commit",
          "accesscontextmanager.googleapis.com/accessLevels.delete",
          "accesscontextmanager.googleapis.com/accessLevels.update",
          "accesscontextmanager.googleapis.com/accessLevels.replaceAll",
          "accesscontextmanager.googleapis.com/policies.delete",
          "accesscontextmanager.googleapis.com/policies.update",
          "accesscontextmanager.googleapis.com/policies.setIamPolicy",
          "accesscontextmanager.googleapis.com/authorizedOrgsDescs.create",
          "accesscontextmanager.googleapis.com/authorizedOrgsDescs.update"
        ]
      }
    }
  ]
}
```
```bash
gcloud iam policies create protect-vpcsc-control-plane \
    --attachment-point=cloudresourcemanager.googleapis.com%2Forganizations%2FORGANIZATION_ID \
    --kind=denypolicies --policy-file=/tmp/deny-vpcsc.json
```

Terraform for the perimeter itself:

```hcl
resource "google_access_context_manager_service_perimeter" "confidential" {
  parent         = "accessPolicies/${var.policy_number}"
  name           = "accessPolicies/${var.policy_number}/servicePerimeters/confidential"
  title          = "confidential"
  perimeter_type = "PERIMETER_TYPE_REGULAR"   # Terraform uses the long enum; gcloud uses "regular"

  status {
    resources           = ["projects/${var.data_prod_01_number}"]
    access_levels       = [google_access_context_manager_access_level.corp_device.name]
    restricted_services = [
      "storage.googleapis.com",
      "bigquery.googleapis.com",
      "bigquerystorage.googleapis.com",
      "pubsub.googleapis.com",
      "cloudkms.googleapis.com",
      "secretmanager.googleapis.com",
    ]

    vpc_accessible_services {
      enable_restriction = true
      allowed_services   = ["RESTRICTED-SERVICES"]
    }

    egress_policies {
      title = "dr-replication-only"
      egress_from {
        identities         = ["serviceAccount:replicator@data-prod-01.iam.gserviceaccount.com"]
        source_restriction = "SOURCE_RESTRICTION_ENABLED"
        sources { resource = "projects/${var.data_prod_01_number}" }
      }
      egress_to {
        resources = ["projects/${var.dr_project_number}"]
        operations {
          service_name = "storage.googleapis.com"
          method_selectors { method = "google.storage.objects.create" }
        }
      }
    }
  }

  # Required only if ..._service_perimeter_resource / ..._ingress_policy resources are also used.
  # lifecycle { ignore_changes = [status[0].resources] }
}
```
If User ADCs are in use, the provider needs `billing_project` set and `user_project_override = true`, or the ACM API returns 403.

---

### 5.4 IAM (allow policies)

Every finding in this area must name the **privilege-graph edge type** it creates, using the edge vocabulary from §6: *Impersonate*, *Deploy-as (actAs)*, *Key-mint*, *Grant-self*, *Role-mutate*, *Group-write*, *Guardrail-mutate*, *Read-data*. A finding that says "over-privileged" without naming the edge is not usable by the reachability analysis and is not acceptable output.

#### IA — Observe

1. Pull allow policies at **every** node, including resource-level ones. Resource-level bindings are routinely missed and are where impersonation grants hide.
   ```bash
   gcloud organizations get-iam-policy ORG_ID --format=json
   gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json
   gcloud projects get-iam-policy PROJECT_ID --format=json
   gcloud iam service-accounts get-iam-policy SA_EMAIL --format=json      # per service account
   gcloud storage buckets describe gs://BUCKET --format="json(iam_configuration)"
   gcloud storage buckets get-iam-policy gs://BUCKET --format=json
   bq get-iam-policy --format=prettyjson PROJECT:DATASET
   gcloud pubsub topics get-iam-policy TOPIC --format=json
   gcloud pubsub subscriptions get-iam-policy SUBSCRIPTION --format=json
   gcloud kms keys get-iam-policy KEY --keyring=RING --location=LOC --format=json
   gcloud secrets get-iam-policy SECRET --format=json
   gcloud artifacts repositories get-iam-policy REPO --location=LOC --format=json
   ```
2. Sweep the whole org for bindings, then filter:
   ```bash
   gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json \
     --query='policy:"roles/iam.serviceAccountTokenCreator"'
   gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json \
     --query='policy:"allUsers" OR policy:"allAuthenticatedUsers"'
   gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json \
     --query='policy:"roles/owner" OR policy:"roles/editor"'
   gcloud asset export --organization=ORG_ID --content-type=iam-policy \
     --output-path=gs://EVIDENCE_BUCKET/iam-policy.json
   ```
   (`--content-type` spelling: see §4.2.1 — the gcloud CLI takes the lowercase-hyphenated values only.)
3. Enumerate custom roles and their contents at org and project scope, and which principals hold each:
   ```bash
   gcloud iam roles list --organization=ORG_ID --format=json
   gcloud iam roles list --project=PROJECT_ID --format=json
   gcloud iam roles describe ROLE_ID --organization=ORG_ID --format=json
   ```
4. Run the impersonation analysis, and record its limits:
   ```bash
   gcloud asset analyze-iam-policy --organization=ORG_ID \
     --analyze-service-account-impersonation --expand-groups --expand-roles \
     --output-group-edges --output-resource-edges --format=json
   ```
   This computes **one hop, backwards from a resource** — who can impersonate the service accounts that have the specified access. It does not enumerate multi-hop chains (A→B→C), `implicitDelegation` chains, or `actAs`-via-workload-attachment paths. Build the transitive closure yourself from the exported allow policies; do not present this command as closing impersonation analysis.
5. Record what native tooling cannot see, so the residual blind spot is explicit in the report. The coverage table and the verbatim residual-blind-spot list are in §6.1.6; the short form is that **Policy Analyzer is allow-policy only** (no deny, no PAB, no GKE RBAC, no Cloud Storage ACLs, no public access prevention) and **Policy Troubleshooter** answers exactly one principal × one permission × one resource — use it to *prove* a specific guardrail blocks a specific triple, never to discover unknown paths.
   ```bash
   gcloud policy-troubleshoot iam //cloudresourcemanager.googleapis.com/projects/PROJECT_ID \
     --permission=storage.objects.get --principal-email=PRINCIPAL@example.com
   ```
6. Pull role recommendations for unused grants, and record what they do **not** do:
   ```bash
   gcloud recommender recommendations list --recommender=google.iam.policy.Recommender \
     --project=PROJECT_ID --location=global --format=json   # flag spelling: verify against current docs
   ```
   Role recommendations are usage-driven least-privilege hints. They do not reason about impersonation chains, do not evaluate deny or PAB, and will not flag an unused-but-catastrophic grant as an exfil risk beyond "unused".

#### IA — Findings tests

1. **IA-01 — primitive roles at org or folder.** `roles/owner`, `roles/editor`, or `roles/viewer` bound at an organization or folder node. → **CRITICAL** for owner/editor, **HIGH** for viewer on a folder containing CONFIDENTIAL/NTK. Edges: *Grant-self* (owner/editor carry `resourcemanager.*.setIamPolicy` down the subtree), *Guardrail-mutate* (both carry the ACM perimeter mutation permissions — see SC-24), *Read-data* (viewer reads across the subtree).
2. **IA-02 — project-level impersonation.** `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountOpenIdTokenCreator`, or `roles/iam.workloadIdentityUser` bound at **project, folder, or org** scope rather than on a specific service-account resource. → **CRITICAL**. Edge: *Impersonate* to **every** SA in scope, including the default compute SA. State plainly in the finding that this **cannot** be narrowed with an IAM Condition: `iam.googleapis.com` is not among the services supporting `resource.service` conditions, so conditional TokenCreator bindings are unimplementable; the only scoping mechanism is binding the role on the individual service account, whose "lowest-level resource" is Service Account.
3. **IA-03 — impersonation role confusion.** A design treats `roles/iam.workloadIdentityUser` and `roles/iam.serviceAccountTokenCreator` as equivalent, or treats TokenCreator as granting `actAs`. They are distinct: `workloadIdentityUser` = `getAccessToken` + `getOpenIdToken` only; `serviceAccountTokenCreator` = those two plus `signBlob`, `signJwt`, `implicitDelegation`; `serviceAccountUser` = `actAs` only, and TokenCreator does **not** grant `actAs`. → **MEDIUM** as a design finding; **HIGH** if the wrong one was granted and the extra permissions are live. Note `signJwt`/`signBlob` yield credentials without calling the token API and are the most-overlooked *Impersonate* edges.
4. **IA-04 — SA-level setIamPolicy.** Any principal holds `iam.serviceAccounts.setIamPolicy` (via `roles/iam.serviceAccountAdmin`, `roles/iam.securityAdmin`, or a custom role) on a service account that reaches CONFIDENTIAL/NTK data. → **CRITICAL**. Edge: *Grant-self* → *Impersonate*. The holder self-grants TokenCreator on the target SA; no project-IAM change appears.
5. **IA-05 — key minting.** Any principal holds `iam.serviceAccountKeys.create` (via `roles/iam.serviceAccountKeyAdmin` or a custom role) and `constraints/iam.managed.disableServiceAccountKeyCreation` is not enforced on that project. → **CRITICAL**. Edge: *Key-mint*, which also produces a durable offline credential (AP-02). Add `storage.hmacKeys.create` to the same test — HMAC keys are S3-compatible static credentials outside SA-key controls.
6. **IA-06 — securityAdmin.** `roles/iam.securityAdmin` bound anywhere. It holds ~2,850 permissions including roughly 310 distinct `*.setIamPolicy` across nearly every service. → **CRITICAL**. Edge: *Grant-self* everywhere. Record its **absences** too, because they define the detection signature: it does not grant `iam.roles.create/update`, `iam.serviceAccountKeys.create`, `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.actAs`, `iam.denypolicies.create`, `iam.principalaccessboundarypolicies.create`, `orgpolicy.policies.create`, or `logging.sinks.create`. Its read-only counterpart is `roles/iam.securityReviewer`.
7. **IA-07 — custom-role mutation.** A principal holds `iam.roles.update` (via `roles/iam.roleAdmin` or `roles/iam.organizationRoleAdmin`) **and** already holds a custom role at any node. → **CRITICAL**. Edge: *Role-mutate*. A principal can add permissions to a custom role that the principal does not itself hold; the binding never changes, so diff-based review of IAM policies misses it entirely. Also flag `iam.roles.undelete` (restores a previously-removed over-privileged role — a persistence primitive) and `iam.roles.delete` (denial of control).
8. **IA-08 — resource-level setIamPolicy on data.** Any principal holds any of `storage.buckets.setIamPolicy`, `storage.objects.setIamPolicy`, `bigquery.datasets.setIamPolicy`, **`bigquery.datasets.update`**, `bigquery.tables.setIamPolicy`, `pubsub.topics.setIamPolicy`, `pubsub.subscriptions.setIamPolicy`, `cloudkms.cryptoKeys.setIamPolicy`, `secretmanager.secrets.setIamPolicy`, `artifactregistry.repositories.setIamPolicy`, or `compute.instances.setIamPolicy` on a resource holding CONFIDENTIAL/NTK. → **CRITICAL**. Edge: *Grant-self* directly to the data, **without touching project IAM at all**. Auditing only `bigquery.datasets.setIamPolicy` is insufficient — `bigquery.datasets.update` remains an ACL-mutation path on any dataset that has not opted into `enable_fine_grained_dataset_acls_option`; audit both, and record which datasets have the option on.
9. **IA-09 — public principals.** `allUsers` or `allAuthenticatedUsers` appears in any binding. → **CRITICAL** on a bucket, dataset, topic, or a Cloud Run/Cloud Functions invoker role (`roles/run.invoker`, `roles/cloudfunctions.invoker`); **HIGH** elsewhere. Edge: *Read-data* from anywhere with no Google identity (AP-04).
10. **IA-10 — external principals.** Any member whose domain is not one of the org's verified domains: `user:*@gmail.com`, users/groups from another domain, service accounts whose project is outside the organization, or a `principalSet://` from a pool in another project. → **HIGH**, **CRITICAL** on a data resource. Edges: *Read-data* or *Impersonate* across a trust boundary. Cross-check against `constraints/iam.allowedPolicyMemberDomains` — if the constraint is enforced and an external principal still holds a binding, the binding predates enforcement and is still live.
11. **IA-11 — broad data-service admin roles.** On a project holding CONFIDENTIAL/NTK, any of `roles/bigquery.admin`, `roles/bigquery.dataOwner`, `roles/bigquery.dataEditor`, `roles/storage.admin`, `roles/storage.objectAdmin`, `roles/pubsub.admin`, `roles/cloudkms.admin`, `roles/secretmanager.admin`, `roles/spanner.databaseAdmin`, `roles/cloudsql.admin`, or `roles/datastore.owner` is bound to a group, or to a principal that is not the single owning workload's service account. → **HIGH**; **CRITICAL** when bound to a group whose transitive membership exceeds the named data-tier team. Edge: *Read-data* (plus *Grant-self* where the role carries `setIamPolicy`).
12. **IA-12 — guardrail roles outside the guardrail-admin set.** Any of the following held by a principal outside the named guardrail-admin group: `roles/orgpolicy.policyAdmin`, `roles/accesscontextmanager.policyAdmin|policyEditor|admin|editor`, `roles/iam.denyAdmin`, `roles/iam.principalAccessBoundaryAdmin`, **`roles/iam.principalAccessBoundaryUser`** (holds `...bind` and `...unbind` — it can remove a PAB boundary without being a PAB admin), `roles/logging.configWriter`, `roles/logging.admin`, `roles/serviceusage.serviceUsageAdmin`, `roles/resourcemanager.projectIamAdmin` or `roles/resourcemanager.folderIamAdmin` (both carry `*.deletePolicyBinding`, so they can **delete a PAB policy binding targeting their own project**). → **CRITICAL**. Edge: *Guardrail-mutate*. Note specifically that `roles/logging.configWriter` carries `logging.sinks.create` (create a sink to an externally-owned destination and stream org logs out — AP-08) and `logging.exclusions.create` (silence the logs that would show it); `roles/serviceusage.serviceUsageAdmin` carries `serviceusage.services.enable` (turn a disabled egress API back on) and `.disable`.
13. **IA-13 — federation-trust roles.** `roles/iam.workloadIdentityPoolAdmin` (note: the role title still carries "Beta" — flag before recommending it as a deployable control), `roles/iam.workforcePoolAdmin`, or `roles/iam.oauthClientAdmin` held outside the identity-admin set. → **HIGH**. Edge: *Guardrail-mutate* into *Impersonate* — the holder adds an external IdP they control and mints principals inside the org (AP-10).
14. **IA-14 — service account over-scope.** Any service account holds a role bound at the **organization** or **folder** node. → **HIGH**, **CRITICAL** if the role is any of IA-01/06/12's roles. Edge: whatever the role confers, but now reachable by anything that can impersonate or run as that SA.
15. **IA-15 — shared and default runtime identities.** A single service account is attached to more than one workload, or the runtime identity is a Google default SA: `PROJECT_NUMBER-compute@developer.gserviceaccount.com` (Compute Engine, Cloud Run, Cloud Run functions, and — since the mid-2024 change — **Cloud Build**), `PROJECT_ID@appspot.gserviceaccount.com` (App Engine, Cloud Run functions 1st gen), or `PROJECT_NUMBER@cloudbuild.gserviceaccount.com` (the Cloud Build legacy account). → **HIGH**; **CRITICAL** if the SA also holds `roles/editor`. Edge: *Deploy-as* collapse — every workload sharing the identity shares its blast radius. The correct 2026 check is **"which SA does the build/service run as, and does that SA hold Editor"**, not "does the Cloud Build SA have the builder role"; the over-privilege moved, it did not go away.
16. **IA-16 — unenforceable conditions.** A role binding relies on an IAM Condition using `resource.service`, `resource.name`, `resource.type`, or `request.time` for a service that does not support conditional bindings. Only 29 services do; **`iam.googleapis.com` and `pubsub.googleapis.com` are not among them**, and neither are `artifactregistry`, `run`, `cloudfunctions`, `dataproc`, `aiplatform`, or `bigtable` (only `bigtableadmin`). → **HIGH** — treat the binding as unconditioned and re-score it. Available attributes where conditions *do* work: `request.time`, `request.auth.access_levels`, `request.host`, `request.path`, `resource.name|type|service`, `resource.matchTag()`/`matchTagId()`, and `destination.ip`/`destination.port` (IAP TCP tunnelling only).
17. **IA-17 — dangerous custom role contents.** Any custom role includes one or more of: `iam.serviceAccounts.getAccessToken`, `.getOpenIdToken`, `.signBlob`, `.signJwt`, `.implicitDelegation`, `.actAs`, `.setIamPolicy`, `iam.serviceAccountKeys.create`, `iam.roles.create|update`, `resourcemanager.*.setIamPolicy`, `orgpolicy.policy.set`, `accesscontextmanager.servicePerimeters.*`, `logging.sinks.*`, `logging.exclusions.*`. → **HIGH** each. Custom roles are where Tier-0 permissions hide from role-name-based review. Also record the scope rule: a project-level custom role cannot contain permissions that are only usable at org/folder level, so an org-level custom role with Tier-0 contents is the higher-risk object.
18. **IA-18 — nonexistent permission asserted.** Any custom role, deny rule, detection rule, or prior report references `iam.serviceAccounts.getIdToken`. That permission does not exist; the correct identifier is **`iam.serviceAccounts.getOpenIdToken`**, while the API *method* is `generateIdToken`. → **MEDIUM**, and whatever control it was meant to express is absent.
19. **IA-19 — unused Tier-0 grants.** A role recommendation marks a binding unused for 90 days **and** the role appears in IA-01/02/05/06/12. → **MEDIUM** on its own, but it is the cheapest remediation in the whole report: no one will notice the removal.
20. **IA-20 — blind spots not stated.** The review asserts complete coverage of effective access using Policy Analyzer output alone. → report as an **evidence gap**, naming the five exclusions (deny, PAB, GKE RBAC, GCS ACLs, GCS PAP) and how each was covered instead.

#### IA — Exfil scenario

This area supplies the *middle* of nearly every chain. **AP-03** in its canonical form: a group member holds project-level `roles/iam.serviceAccountTokenCreator` (IA-02) → `GenerateAccessToken` on a data-tier SA → `bigquery.tables.getData` on a CONFIDENTIAL dataset → `EXPORT DATA` to a bucket → out. **AP-11** substitutes IA-04, IA-07, or IA-08 for the first hop, none of which changes a project IAM policy in a way a diff-based review would catch. **AP-04** is IA-09 plus a staging step. **AP-07** is IA-10 plus a copy job.

The point to make in the report: a perfect VPC-SC perimeter around a reachable admin identity is not a control. Every finding here should carry the specific SA or group it reaches and the classification tier it terminates at, so the reachability analysis can rank it.

#### IA — Remediation

Move impersonation from the project to the specific service account — the only scoping that works, since conditions are unavailable on `iam.googleapis.com`:

```bash
# Remove the project-wide grant.
gcloud projects remove-iam-policy-binding data-prod-01 \
    --member="group:eng-all@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# Re-grant on exactly the SAs the workload needs, one binding per SA.
gcloud iam service-accounts add-iam-policy-binding etl-writer@data-prod-01.iam.gserviceaccount.com \
    --member="group:grp-ci-deploy@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# If only an OIDC ID token is needed, use the narrowest role (1 permission) instead:
gcloud iam service-accounts add-iam-policy-binding invoker@run-prod-02.iam.gserviceaccount.com \
    --member="serviceAccount:caller@run-prod-02.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountOpenIdTokenCreator"
```

```hcl
resource "google_service_account_iam_binding" "etl_writer_token_creator" {
  service_account_id = google_service_account.etl_writer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members            = ["group:grp-ci-deploy@example.com"]
}

# Where the service DOES support conditions, narrow with resource.name — e.g. Cloud Storage:
resource "google_project_iam_member" "analyst_bucket_read" {
  project = var.data_project
  role    = "roles/storage.objectViewer"
  member  = "group:grp-data-analysts@example.com"
  condition {
    title      = "only-the-curated-bucket"
    expression = "resource.type == 'storage.googleapis.com/Object' && resource.name.startsWith('projects/_/buckets/curated-confidential/')"
  }
}
```

Replace a broad predefined admin role with a custom role containing only the verbs in use (drive the contents from role recommendations, then remove every Tier-0 permission from IA-17):

```bash
gcloud iam roles create dataPipelineOperator --organization=ORG_ID \
    --title="Data Pipeline Operator" --stage=GA \
    --permissions=bigquery.jobs.create,bigquery.tables.get,bigquery.tables.getData,bigquery.datasets.get
```
```hcl
resource "google_organization_iam_custom_role" "data_pipeline_operator" {
  org_id      = var.org_id
  role_id     = "dataPipelineOperator"
  title       = "Data Pipeline Operator"
  permissions = [
    "bigquery.jobs.create",
    "bigquery.tables.get",
    "bigquery.tables.getData",
    "bigquery.datasets.get",
  ]
}
```

Every finding in this area that names a Tier-0 permission must be paired with the corresponding IAM Deny rule from §5.5 — removing a binding is reversible by anyone who can set IAM policy; the deny rule is not.

---

### 5.5 IAM Deny

Deny policies are the un-overridable backstop: **IAM always checks relevant deny policies before allow policies**, no allow policy anywhere can override a deny, and denies inherit down the hierarchy. Attach them at org or folder so a project owner cannot undo them.

#### DN — Observe

1. Enumerate deny policies at **every** attachment point. There are only three kinds of attachment point — organizations, folders, projects. Service accounts, buckets, and other resources **cannot** carry a deny policy.
   ```bash
   gcloud iam policies list --kind=denypolicies --format=json \
       --attachment-point=cloudresourcemanager.googleapis.com/organizations/ORG_ID
   gcloud iam policies list --kind=denypolicies --format=json \
       --attachment-point=cloudresourcemanager.googleapis.com/folders/FOLDER_ID
   gcloud iam policies list --kind=denypolicies --format=json \
       --attachment-point=cloudresourcemanager.googleapis.com/projects/PROJECT_ID
   gcloud iam policies get POLICY_ID --kind=denypolicies --format=json \
       --attachment-point=cloudresourcemanager.googleapis.com%2Forganizations%2FORG_ID
   ```
   The attachment point is URL-encoded on `create`/`get` (`/` → `%2F`).
2. For each policy record the full `rules[].denyRule` object: `deniedPrincipals`, `exceptionPrincipals`, `deniedPermissions`, `exceptionPermissions`, `denialCondition{title, expression}`. Note the schema: the top-level field is **`rules`** and each element wraps a singular **`denyRule`** — there is no `denyRules` field, and deny is the IAM **v2** API (`iam.googleapis.com/v2/policies`), not v3. "v3" refers to the *allow* policy schema version that enables conditional bindings, an unrelated concept.
3. Record every `exceptionPrincipals` entry and then resolve it: if it is a `principalSet://goog/group/...`, enumerate that group's transitive membership and who can modify it.
4. Record counts against the limits: **500 deny policies per resource**, and **500 deny rules total across them**.
5. Verify each `deniedPermissions` string against the deny-supported permissions list before treating the rule as effective.

#### DN — Findings tests

1. **DN-01 — no backstop at all.** No deny policy is attached at the organization node. → **HIGH**. Every removable allow-policy control in this report is one `setIamPolicy` away from being undone.
2. **DN-02 — recommended rule missing.** Any row of the recommended-rules table below has no equivalent rule at the stated attachment node. → severity per the row.
3. **DN-03 — invalid permission group.** A rule uses `iam.googleapis.com/serviceAccounts.*`. That wildcard group **does not exist** (only `serviceAccountKeys.*` does among the IAM SA families), so the policy fails to apply or silently fails to cover impersonation. → **CRITICAL**, because it produces a documented control that does nothing. The impersonation permissions must be enumerated individually. Deny policies support three group **forms** — `SERVICE_FQDN/RESOURCE.*` (every permission on a resource type), `SERVICE_FQDN/*.*` (every permission for a service), and `SERVICE_FQDN/*.VERB` (every permission for a service ending in that verb). **Support is per service, not universal**, so the form existing does not mean the service accepts it: check every group string against the deny-supported-permissions table before shipping the rule. Confirmed **present**: `iam.googleapis.com/serviceAccountKeys.*`, `iam.googleapis.com/workloadIdentityPools.*`, `iam.googleapis.com/workforcePools.*`, `iam.googleapis.com/principalaccessboundarypolicies.*`, `iam.googleapis.com/oauthClients.*`, `cloudresourcemanager.googleapis.com/projects.*`, `cloudresourcemanager.googleapis.com/folders.*`, `storage.googleapis.com/objects.*`. Confirmed **absent**: `iam.googleapis.com/serviceAccounts.*`, `iam.googleapis.com/roles.*`, `iam.googleapis.com/*.*`. Not confirmed either way, and therefore to be checked before use rather than asserted: the `accesscontextmanager.googleapis.com/{servicePerimeters,accessLevels,policies,authorizedOrgsDescs,gcpUserAccessBindings}.*` families, `logging.googleapis.com/exclusions.*`, `iam.googleapis.com/workloadIdentityPoolProviders.*`, `iam.googleapis.com/workforcePoolProviders.*`, `iam.googleapis.com/oauthClientCredentials.*` (verify against current docs) — where the check fails, enumerate the individual permissions instead, as rule #4 already does. Write the same group string in DN-03 and in the recommended-rules table below: a reviewer grepping this skill for a valid group must get one answer, not two.
4. **DN-04 — v1 permission format.** A rule names a permission in allow-policy format (`iam.roles.delete`, `resourcemanager.projects.setIamPolicy`, `accesscontextmanager.servicePerimeters.delete`) instead of the v2 `SERVICE_FQDN/RESOURCE.ACTION` format, or uses `resourcemanager.googleapis.com/...` instead of **`cloudresourcemanager.googleapis.com/...`**. → **CRITICAL**; the rule matches nothing.
5. **DN-05 — invalid service prefix.** A rule names `iamcredentials.googleapis.com/...`. No such deny permission exists and none is needed: impersonation is authorised by the `iam.googleapis.com/serviceAccounts.*` permission checked **on the service-account resource**. → **CRITICAL**; the rule is invalid.
6. **DN-06 — invalid denial condition.** A `denialCondition.expression` uses anything other than `resource.matchTag(...)` / `resource.matchTagId(...)`. Denial conditions **only recognise resource tag functions** — no `request.time`, no `resource.name`, no `resource.type`, no `request.auth.*`, no IP attributes. → **HIGH**. Any time-boxed or resource-name-scoped deny rule is unimplementable; the only scoping levers are the **attachment node**, **`exceptionPrincipals`**, and **project/folder tags**. Record the fail-closed semantics as a design consequence: if the condition evaluates true **or cannot be evaluated**, the deny applies.
7. **DN-07 — bypassable exception set.** An `exceptionPrincipals` entry is a group whose membership can be modified by anyone outside the guardrail-admin set, or by a principal who is themselves denied. → **HIGH**. Edge: *Group-write* defeats the deny with no IAM change visible in any project policy.
8. **DN-08 — attached too low.** A deny rule protecting a CONFIDENTIAL/NTK project is attached at that **project**. Whoever can administer the project can work to have it removed, and it does not cover sibling projects. → **MEDIUM–HIGH**; re-attach at the folder or org.
9. **DN-09 — deny policies are not self-protecting.** `iam.googleapis.com/denypolicies.*` is **absent** from the deny-supported list, so you generally cannot use a deny policy to protect deny policies from a `roles/iam.denyAdmin` holder. If no compensating control exists — PAB on the deny-admin principals, org-level role hygiene limiting `roles/iam.denyAdmin` to a named break-glass-gated group, and an alert on `iam.denypolicies` mutations — → **HIGH**.
10. **DN-10 — unsupported permission relied on.** A rule names `serviceusage.googleapis.com/services.enable` or `.disable` (absent from the supported list — only `services.get`, `.list`, `consumerpolicy.*`, `quotas.*` appear), or `orgpolicy.googleapis.com/policies.get` (does not exist; the getter is `orgpolicy.policy.get`, a different family). → **HIGH**, because a control is documented that does not exist. Compensating control for service enablement: `constraints/gcp.restrictServiceUsage` in allow-list mode.
11. **DN-11 — data-read deny absent on NTK.** No deny rule restricts `storage.googleapis.com/objects.get`, `objects.list`, `bigquery.googleapis.com/tables.getData`, or `tables.export` on the folder holding NTK projects. → **HIGH**.
12. **DN-12 — limit pressure.** Deny rules at a node approach 500, or policies approach 500. → **LOW–MEDIUM**; note it, because the fix people reach for is merging rules and widening exceptions.

#### DN — Recommended deny rules

All permissions below were confirmed deniable. Denied principal set `principalSet://goog/public:all` means "everyone", narrowed by `exceptionPrincipals`. Principal formats seen in official examples: `principalSet://goog/public:all`, `principalSet://goog/group/GROUP_EMAIL`, `principal://goog/subject/USER_EMAIL`.

| # | Denied permissions | Denied principals | Exception principals | Attachment node |
|---|---|---|---|---|
| 1 | `iam.googleapis.com/serviceAccountKeys.create` (or the group `iam.googleapis.com/serviceAccountKeys.*`), `storage.googleapis.com/hmacKeys.create` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-key-exception@example.com` (empty if key creation is fully banned) | **organization** |
| 2 | `cloudresourcemanager.googleapis.com/organizations.setIamPolicy`, `cloudresourcemanager.googleapis.com/folders.setIamPolicy`, `cloudresourcemanager.googleapis.com/projects.setIamPolicy` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-iam-admins@example.com` | **organization** |
| 3 | `iam.googleapis.com/serviceAccounts.setIamPolicy` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-iam-admins@example.com` | **organization** |
| 4 | `iam.googleapis.com/serviceAccounts.getAccessToken`, `iam.googleapis.com/serviceAccounts.getOpenIdToken`, `iam.googleapis.com/serviceAccounts.signBlob`, `iam.googleapis.com/serviceAccounts.signJwt`, `iam.googleapis.com/serviceAccounts.implicitDelegation` — **enumerated individually; the `serviceAccounts.*` group does not exist** | `principalSet://goog/public:all` | `principalSet://goog/group/grp-ci-deploy@example.com`, plus the named workload SAs | **folder** holding CONFIDENTIAL/NTK projects |
| 5 | `iam.googleapis.com/serviceAccounts.actAs` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-platform-deploy@example.com` | **folder** holding the privileged SAs. *Scoping limitation:* deny cannot name a specific target SA (no resource-name conditions), so isolate privileged SAs into their own project/folder and attach there, or tag the project and use `resource.matchTag` |
| 6 | `iam.googleapis.com/roles.create`, `iam.googleapis.com/roles.update`, `iam.googleapis.com/roles.delete`, `iam.googleapis.com/roles.undelete` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-iam-admins@example.com` | **organization** |
| 7 | `storage.googleapis.com/objects.get`, `storage.googleapis.com/objects.list`, `bigquery.googleapis.com/tables.getData`, `bigquery.googleapis.com/tables.export`, `bigquery.googleapis.com/datasets.setIamPolicy`, `bigquery.googleapis.com/datasets.update` | `principalSet://goog/public:all` | the NTK data-tier group **and** the specific workload service accounts, enumerated | **folder** holding NTK projects |
| 8 | `orgpolicy.googleapis.com/policies.create`, `.update`, `.delete`, `orgpolicy.googleapis.com/customConstraints.*` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-guardrail-admins@example.com` | **organization** |
| 9 | `accesscontextmanager.googleapis.com/servicePerimeters.*`, `accesscontextmanager.googleapis.com/accessLevels.*`, `accesscontextmanager.googleapis.com/policies.*`, `accesscontextmanager.googleapis.com/authorizedOrgsDescs.*` — group support for these four families is **not** on the confirmed list (verify against current docs); if the check fails, enumerate `.create`, `.update`, `.delete`, `.replaceAll`, `.commit`, `.setIamPolicy` individually as §9.6 does | `principalSet://goog/public:all` | `principalSet://goog/group/grp-guardrail-admins@example.com` | **organization** |
| 10 | `logging.googleapis.com/sinks.update`, `sinks.delete`, `logging.googleapis.com/exclusions.*` (group support unconfirmed — verify against current docs, else enumerate `exclusions.create`, `.update`, `.delete`), `logging.googleapis.com/buckets.update`, `buckets.delete` | `principalSet://goog/public:all` | `principalSet://goog/group/grp-logging-admins@example.com` | **organization** |
| 11 | `iam.googleapis.com/workloadIdentityPools.*`, `iam.googleapis.com/workforcePools.*`, `iam.googleapis.com/oauthClients.*` (all three confirmed groups); plus `iam.googleapis.com/workloadIdentityPoolProviders.*`, `iam.googleapis.com/workforcePoolProviders.*`, `iam.googleapis.com/oauthClientCredentials.*` — **group support unconfirmed, verify against current docs** before relying on these three | `principalSet://goog/public:all` | `principalSet://goog/group/grp-identity-admins@example.com` | **organization** |
| 12 | `iam.googleapis.com/principalaccessboundarypolicies.*` (includes `.bind`, `.unbind`) | `principalSet://goog/public:all` | `principalSet://goog/group/grp-guardrail-admins@example.com` | **organization** |

**Permissions IAM Deny does not support — use the compensating control instead:**

| Wanted | Reality | Compensating control |
|---|---|---|
| Deny service enablement | `serviceusage.googleapis.com/services.enable` / `.disable` are **not** in the supported list | `constraints/gcp.restrictServiceUsage` in allow-list mode at the project/folder; alert on `serviceusage` Admin Activity |
| Protect deny policies from a deny admin | `iam.googleapis.com/denypolicies.*` is **not** in the supported list | Limit `roles/iam.denyAdmin` and `roles/iam.denyReviewer` to a named break-glass-gated group. **PAB cannot be bound to a Google group** — the seven principal sets are org / folder / project / Workspace domain / workforce pool / workload pool / agent identities (§5.7), and the binding `condition` reaches only `principal.type` and `principal.subject` — so scope instead by binding PAB at the **project or folder principal set the deny admins operate from**, or by a binding `condition` on `principal.subject`. Alert on `iam.denypolicies` mutations and require dual sign-off. |
| Stop PAB bindings being removed | `*.createPolicyBinding` / `.deletePolicyBinding` / `.updatePolicyBinding` / `.searchPolicyBindings` are exceptions PAB itself cannot block | Deny rule #12 above plus role hygiene on `roles/resourcemanager.projectIamAdmin` / `folderIamAdmin` and `roles/iam.principalAccessBoundaryUser` |
| Time-box a deny (e.g. "deny outside business hours") | Denial conditions support **only** tag functions | Scope by attachment node, `exceptionPrincipals`, or a project tag toggled by an approval workflow |
| Deny impersonation of one named SA | No resource-name conditions | Isolate the SA into its own project/folder and attach the deny there; or tag the project and use `resource.matchTag` |
| Stop perimeter deletion via org policy | ACM custom constraints support only `CREATE`/`UPDATE` | Deny rule #9 (this is the only control that covers `DELETE`) |

#### DN — Exfil scenario

Deny rules are what make the rest of the report durable. Rule #4 severs **AP-03** at its impersonation hop for everyone outside the CI group, and no project-level `setIamPolicy` can re-open it. Rule #1 kills **AP-02** at the source. Rule #7 is the last line for **AP-01/AP-07** when the perimeter itself has been widened. Rules #8–#12 are the direct counter to **AP-13**: they are the only controls that constrain an org-level Owner, because deny evaluates before allow and cannot be overridden by any grant.

The failure mode to hunt for is a deny policy that *appears* to do all this and does none of it — an invalid permission group (DN-03), a v1 permission string (DN-04), or a condition that cannot be evaluated. Prove each recommended rule works before closing the finding:

```bash
gcloud policy-troubleshoot iam //cloudresourcemanager.googleapis.com/projects/PROJECT_ID \
    --permission=iam.serviceAccounts.getAccessToken \
    --principal-email=someone@example.com
```
Policy Troubleshooter evaluates allow **and** deny **and** PAB, which is exactly why it — not Policy Analyzer — is the verification tool here.

#### DN — Remediation

```json
{
  "displayName": "deny-impersonation-outside-ci",
  "rules": [
    {
      "denyRule": {
        "deniedPrincipals": ["principalSet://goog/public:all"],
        "exceptionPrincipals": ["principalSet://goog/group/grp-ci-deploy@example.com"],
        "deniedPermissions": [
          "iam.googleapis.com/serviceAccounts.getAccessToken",
          "iam.googleapis.com/serviceAccounts.getOpenIdToken",
          "iam.googleapis.com/serviceAccounts.signBlob",
          "iam.googleapis.com/serviceAccounts.signJwt",
          "iam.googleapis.com/serviceAccounts.implicitDelegation",
          "iam.googleapis.com/serviceAccounts.actAs"
        ],
        "denialCondition": {
          "title": "exempt tagged sandbox projects",
          "expression": "!resource.matchTag('ORG_ID/env', 'sandbox')"
        }
      }
    }
  ]
}
```

```bash
gcloud iam policies create deny-impersonation-outside-ci \
    --attachment-point=cloudresourcemanager.googleapis.com%2Ffolders%2FFOLDER_ID \
    --kind=denypolicies \
    --policy-file=/tmp/deny-impersonation.json

gcloud iam policies get deny-impersonation-outside-ci \
    --attachment-point=cloudresourcemanager.googleapis.com%2Ffolders%2FFOLDER_ID \
    --kind=denypolicies --format=json
```

```hcl
resource "google_iam_deny_policy" "deny_impersonation_outside_ci" {
  parent       = urlencode("cloudresourcemanager.googleapis.com/folders/${var.folder_id}")
  name         = "deny-impersonation-outside-ci"
  display_name = "Deny SA impersonation outside CI"

  rules {
    description = "Impersonation permissions must be enumerated individually; serviceAccounts.* is not a valid group."
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = ["principalSet://goog/group/grp-ci-deploy@example.com"]
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.getOpenIdToken",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt",
        "iam.googleapis.com/serviceAccounts.implicitDelegation",
        "iam.googleapis.com/serviceAccounts.actAs",
      ]
      denial_condition {
        title      = "exempt tagged sandbox projects"
        expression = "!resource.matchTag('${var.org_id}/env', 'sandbox')"
      }
    }
  }
}
```
Terraform uses snake_case (`denied_permissions`) for the camelCase API fields (`deniedPermissions`) but still takes the **v2 permission format**. Roll every deny rule out through Policy Simulator first (`roles/iam.denyAdmin` carries `policysimulator.accessPolicySimulations.*` for exactly this), because a deny that fails closed on an unevaluable condition will break production access with no allow-policy change to blame.

---

### 5.6 Private Service Connect

#### PS — Observe

1. Inventory every PSC object in every project. The five object types are **endpoints** (internal IP + forwarding rule), **backends** (a NEG behind a load balancer), **interfaces** (producer→consumer initiated), **service attachments** (the producer-side publish resource), and **PSC network endpoint groups** (targeting a service attachment or Google APIs).
   ```bash
   # Consumer endpoints, including PSC-for-Google-APIs endpoints
   gcloud compute forwarding-rules list --project=PROJECT_ID --format=json
   gcloud compute forwarding-rules describe RULE --global --format=json
   # Filter for PSC: a target that is a serviceAttachment, or a pscConnectionId, or a Google-APIs bundle
   gcloud compute forwarding-rules list --project=PROJECT_ID \
       --filter="target~serviceAttachments OR pscConnectionId:*" --format=json

   # Producer side
   gcloud compute service-attachments list --project=PROJECT_ID --format=json
   gcloud compute service-attachments describe ATTACHMENT --region=REGION --format=json

   # PSC NEGs
   gcloud compute network-endpoint-groups list --project=PROJECT_ID --format=json
   # (filter value for PSC NEG type: verify against current docs)
   ```
2. For each **PSC-for-Google-APIs** endpoint record the bundle: `--target-google-apis-bundle` is either **`all-apis`** or **`vpc-sc`**. Record the Service Directory registration and the private DNS zone it creates — records take the form `SERVICE-ENDPOINTNAME.p.googleapis.com` (for example `storage-xyz.p.googleapis.com`) in a `p.googleapis.com` zone.
3. For each **consumer endpoint targeting a service attachment**, resolve the attachment's project and organization. Record the endpoint's internal IP, its subnet, and whether that subnet is advertised over the interconnect.
4. For each **service attachment you publish**, record the connection preference (automatic vs manual accept — exact enum values: verify against current docs), the `--consumer-accept-list`, the `--consumer-reject-list`, and the connection limit.
5. Record the org policies that gate PSC: `constraints/compute.disablePrivateServiceConnectCreationForConsumers` (allowed values `GOOGLE_APIS`, `SERVICE_PRODUCERS`), `constraints/compute.restrictPrivateServiceConnectProducer`, `constraints/compute.restrictPrivateServiceConnectConsumer`.
6. Record whether VPC Flow Logs are enabled on the subnets holding PSC endpoints, on both consumer and producer sides.
7. Cross-check the effective egress firewall rules against the endpoint IPs (from §5.2).

#### PS — Findings tests

1. **PS-01 — `all-apis` bundle in use.** Any PSC-for-Google-APIs endpoint uses `--target-google-apis-bundle=all-apis`. That bundle "provides access to most Google APIs and services **regardless of VPC Service Controls support**" — the same risk profile as `private.googleapis.com`, and access to unsupported services is **allowed by default**. → **HIGH**; **CRITICAL** in a VPC serving CONFIDENTIAL/NTK projects. The `vpc-sc` bundle blocks unsupported services.
2. **PS-02 — `all-apis` without service patterns.** An `all-apis` endpoint (or `private.googleapis.com`) is in use and the perimeter does not set `vpcAccessibleServices.allowedServicePatterns` with `servicePatternsEnforcementScopes: [GOOGLE_APIS_VIA_PRIVATE_PATH]`. → **HIGH** (same finding as SC-28; report once, cross-referenced).
3. **PS-03 — cross-organization egress channel.** A consumer endpoint targets a service attachment whose project is outside your organization. → **CRITICAL**. This is a fully private, cross-org data path: it never touches the internet, never crosses a NAT gateway, and never appears in a `0.0.0.0/0` egress deny.
4. **PS-04 — default-deny does not cover PSC.** The VPC's egress posture is `deny 0.0.0.0/0` plus an `allow` for RFC1918 (or `dest_network_scope = INTERNET`), and PSC endpoint IPs fall inside the allowed internal ranges. To an egress rule a PSC endpoint looks like ordinary intra-VPC traffic. → **HIGH**. Firewall rules *do* apply to PSC resources — the control is an explicit egress deny to the endpoint IPs or subnet, plus the org policies in PS-07.
5. **PS-05 — NAT hides the destination.** The consumer's flow records show only the endpoint IP; PSC performs NAT, so there is no destination hostname or producer project in consumer-side telemetry. If VPC Flow Logs are disabled on the endpoint's subnet, there is no record at all. → **HIGH** when flow logs are off; **MEDIUM** as a standing limitation when they are on. Flows to published services are reported from **both** consumer and producer VMs only if **both** subnets have flow logs enabled, and each side's logs land in that side's project.
6. **PS-06 — VPC-SC jurisdiction misstated.** A design claims VPC Service Controls covers a PSC endpoint to a **third-party published service**. VPC-SC and PSC are compatible and perimeter protection does apply to **Google API** traffic through endpoints — but a call to a third-party service attachment is not a Google API call and VPC-SC has no jurisdiction over it. → **MEDIUM** as a design finding; the real control is the org policy plus the firewall.
7. **PS-07 — PSC org policies unset.** Any of `constraints/compute.disablePrivateServiceConnectCreationForConsumers`, `constraints/compute.restrictPrivateServiceConnectProducer`, `constraints/compute.restrictPrivateServiceConnectConsumer` is unset at the org node. → **HIGH**. Note the layered rule: "Connections are blocked if **either** an accept list **or** an organization policy denies the connection" — so the org policy is a genuine second gate, not a duplicate of the accept list.
8. **PS-08 — service attachment open to any consumer.** A published service attachment uses automatic connection acceptance with no `--consumer-accept-list`, or its accept list names projects outside your organization. → **HIGH**.
9. **PS-09 — PSC reachable from on-prem.** A PSC endpoint's IP falls within a range advertised to the on-prem network by Cloud Router (check `gcloud compute routers get-status` and the custom advertisement set), or its subnet is otherwise routable across the interconnect/VPN. → **HIGH**. This extends the endpoint — and everything behind it — into the soft interior, where any compromised host can reach it.
10. **PS-10 — Google-APIs endpoint reachable from on-prem.** The `p.googleapis.com` Service Directory zone is resolvable from on-prem and the endpoint IP is advertised. Assess whether that is the intended on-prem path to Google APIs and whether the bundle is `vpc-sc`; an `all-apis` endpoint reachable from on-prem gives interior hosts a private path to APIs VPC-SC cannot police. → **CRITICAL** in that combination. (PSC bundle DNS naming beyond the `SERVICE-ENDPOINTNAME.p.googleapis.com` form: verify against current docs.)

#### PS — Exfil scenario

PSC is the quiet variant of **AP-06**. A compromised workload with `compute.forwardingRules.create` (or an insider) stands up an endpoint pointed at an attacker-operated service attachment in another organization, then writes CONFIDENTIAL data to what looks, from every network control's point of view, like a local internal IP. No internet egress, no NAT translation record, no VPC-SC violation — because it is not a Google API call — and no destination in the consumer's flow log beyond an RFC1918 address.

The Google-APIs variant is **AP-01** with the perimeter's own network path turned against it: an `all-apis` bundle endpoint reaches every Google API that VPC Service Controls does not support, from inside a VPC that the design document describes as locked down. Combined with PS-09/PS-10 it becomes **AP-12**: an interior host reaches cloud data over a private path that neither the cloud egress controls nor the on-prem egress controls were designed to see.

#### PS — Remediation

```bash
# Google APIs via PSC: require the vpc-sc bundle.
gcloud compute addresses create psc-google-apis \
    --global --purpose=PRIVATE_SERVICE_CONNECT --addresses=10.10.0.100 --network=NETWORK_NAME
gcloud compute forwarding-rules create psc-google-apis-ep \
    --global --network=NETWORK_NAME --address=psc-google-apis \
    --target-google-apis-bundle=vpc-sc \
    --service-directory-registration=projects/PROJECT_ID/locations/REGION/namespaces/NAMESPACE

# Gate endpoint creation org-wide.
cat > /tmp/psc-consumers.yaml <<'EOF'
name: organizations/ORGANIZATION_ID/policies/compute.disablePrivateServiceConnectCreationForConsumers
spec:
  rules:
  - values:
      deniedValues:
      - SERVICE_PRODUCERS
EOF
gcloud org-policies set-policy /tmp/psc-consumers.yaml

# Constrain who may be a producer for your consumers, and who may consume your attachments.
gcloud org-policies set-policy /tmp/psc-restrict-producer.yaml   # constraints/compute.restrictPrivateServiceConnectProducer, allow under:organizations/ORG_ID
gcloud org-policies set-policy /tmp/psc-restrict-consumer.yaml   # constraints/compute.restrictPrivateServiceConnectConsumer, allow under:organizations/ORG_ID

# Producer side: manual acceptance with an explicit consumer list.
gcloud compute service-attachments update ATTACHMENT --region=REGION \
    --consumer-accept-list=CONSUMER_PROJECT_ID=10

# Flow logs on every subnet that holds a PSC endpoint.
gcloud compute networks subnets update SUBNET --region=REGION --enable-flow-logs
```

Explicit egress deny to unapproved PSC endpoint ranges, sitting **above** the RFC1918 allow (this is what closes PS-04):

```hcl
resource "google_compute_network_firewall_policy_rule" "deny_unapproved_psc" {
  firewall_policy = google_compute_network_firewall_policy.egress_baseline.name
  project         = var.host_project
  direction       = "EGRESS"
  action          = "deny"
  priority        = 800          # numerically lower than the RFC1918 allow
  enable_logging  = true
  match {
    dest_ip_ranges = [var.psc_endpoint_cidr_unapproved]
    layer4_configs { ip_protocol = "all" }
  }
}

resource "google_compute_global_forwarding_rule" "psc_google_apis" {
  name                  = "psc-google-apis-ep"
  project               = var.host_project
  target                = "vpc-sc"      # the bundle, not all-apis
  network               = google_compute_network.vpc.id
  ip_address            = google_compute_global_address.psc.id
  load_balancing_scheme = ""
}

resource "google_org_policy_policy" "psc_consumers" {
  name   = "organizations/${var.org_id}/policies/compute.disablePrivateServiceConnectCreationForConsumers"
  parent = "organizations/${var.org_id}"
  spec {
    rules {
      values { denied_values = ["SERVICE_PRODUCERS"] }
    }
  }
}
```
The hierarchy-indicator value format (`under:organizations/...`) for the two `restrictPrivateServiceConnect*` constraints, and the PSC connection-limit numbers: verify against current docs.

---

### 5.7 Principal Access Boundary

**Status, stated honestly:** principal access boundary policies are **GA** (released 2024-12-16), and the gcloud surface is on the GA track (`gcloud iam principal-access-boundary-policies`, not `gcloud beta ...`). Any write-up describing PAB as Preview is stale. The **current default enforcement version is 4**; accepted values are `1`, `2`, `3`, `4`, and `latest`. Search snippets still claiming the default is 3 are stale — read the live page.

PAB limits which **resources a principal is eligible to access**, regardless of what allow policies grant. It is not a permission filter: `effect` supports only `ALLOW`, so PAB cannot express "deny permission X everywhere" — that is IAM Deny's job. The two are complementary, and this catalog treats them as such: **Deny** removes a *permission* from a principal set everywhere; **PAB** removes every *resource outside a boundary* from a principal set.

#### PB — Observe

```bash
gcloud iam principal-access-boundary-policies list --organization=ORG_ID --location=global --format=json
gcloud iam principal-access-boundary-policies describe POLICY_ID \
    --organization=ORG_ID --location=global --format=json
gcloud iam principal-access-boundary-policies search-policy-bindings POLICY_ID \
    --organization=ORG_ID --location=global --format=json
gcloud iam policy-bindings list --organization=ORG_ID --location=global --format=json
```
(Subcommand-level flag requirements: verify against current docs.)

Record per policy: `details.enforcementVersion`, and every `details.rules[]` entry's `description`, `resources[]`, and `effect` (must be `ALLOW`). Record per binding: `target.principalSet`, `policy`, `policyKind` (`PRINCIPAL_ACCESS_BOUNDARY`), and `condition` — whose only available attributes are `principal.type` and `principal.subject`.

Principal-set formats, all with a **leading `//`** (note this differs from deny-policy attachment points, which have no leading slashes, and from deny *principals*, which use the `principalSet://goog/...` scheme — three adjacent syntaxes, and mixing them is the most common authoring error):

| Target | Format |
|---|---|
| Organization | `//cloudresourcemanager.googleapis.com/organizations/ORGANIZATION_ID` |
| Folder | `//cloudresourcemanager.googleapis.com/folders/FOLDER_ID` |
| Project | `//cloudresourcemanager.googleapis.com/projects/PROJECT_ID` |
| Workforce identity pool | `//iam.googleapis.com/locations/global/workforcePools/WORKFORCE_POOL_ID` |
| Workload identity pool | `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/WORKLOAD_POOL_ID` |
| Google Workspace domain | `//iam.googleapis.com/locations/global/workspace/CUSTOMER_ID` |
| Agent identities | `//agents.global.org-ORGANIZATION_ID.system.id.goog/attribute.container/projects/PROJECT_NUMBER` |

#### PB — Findings tests

1. **PB-01 — no boundary on federated principals.** No PAB policy is bound to any workload identity pool or workforce identity pool principal set. → **HIGH**. These are the highest-risk principals in the environment (see §5.8) and PAB is the only control that caps their reach independently of grants.
2. **PB-02 — enforcement version below 3.** Any bound PAB policy has `enforcementVersion` of `1` or `2`. Service-account impersonation only becomes PAB-blockable at **version 3**: below that, the policy provides **zero** protection against `iam.googleapis.com/serviceAccounts.getAccessToken`, `signJwt`, `signBlob`, `actAs`, or `serviceAccountKeys.create`. → **CRITICAL** when the policy is presented as impersonation containment; **HIGH** otherwise. Pinned versions never auto-upgrade — "you must update your principal access boundary policies to use the new version".
3. **PB-03 — enforcement version below 4.** `enforcementVersion` is `3`. Version 4 is what adds the IAM federation surface (`workforcePools.*`, `workforcePoolProviders.*`, `workloadIdentityPools.*`, `workloadIdentityPoolProviders.*`, `oauthClients.*`, `oauthClientCredentials.*`), the full Cloud KMS family, and the remaining BigQuery families. → **HIGH** for any policy bound to a federated principal set. Recommend `latest` or explicitly `4` unless a pin is a documented, dated decision.
4. **PB-04 — boundary is the whole organization.** A policy bound to a workload/workforce pool or a cross-project SA lists `//cloudresourcemanager.googleapis.com/organizations/ORG_ID` in `rules[].resources`. The boundary then contains everything and constrains nothing. → **HIGH**. The boundary for a workload principal should be the one or two projects it legitimately touches.
5. **PB-05 — cross-project service accounts unbounded.** A service account from project A holds bindings in project B and is not covered by a PAB policy. → **HIGH**. Pair with `constraints/iam.disableCrossProjectServiceAccountUsage` where the usage is not required at all.
6. **PB-06 — PAB assumed to protect itself.** The design relies on PAB to prevent removal of PAB bindings. It cannot: across **every** enforcement version, `*.createPolicyBinding`, `*.deletePolicyBinding`, `*.updatePolicyBinding`, and `*.searchPolicyBindings` are documented exceptions PAB does not block. → **HIGH** unless the compensating controls are present: deny rule #12 from §5.5, plus role hygiene on `roles/iam.principalAccessBoundaryUser`, `roles/iam.principalAccessBoundaryAdmin`, `roles/resourcemanager.projectIamAdmin`, and `roles/resourcemanager.folderIamAdmin` (all four can remove a binding).
7. **PB-07 — wrong Terraform resource.** The repo uses `google_iam_access_boundary_policy`, believing it is PAB. That is **Credential Access Boundary**, a different feature, and its own documentation says it is a private feature requiring GCP support contact. `google_iam_principals_access_boundary_policy_binding` **does not exist** at all. → **HIGH**; whatever boundary the team believes exists does not. The real resources are `google_iam_principal_access_boundary_policy` plus `google_iam_organizations_policy_binding` / `google_iam_folders_policy_binding` / `google_iam_projects_policy_binding`.
8. **PB-08 — limits reached.** More than 10 PAB policies bound to a single principal-set target, more than 500 resources across a policy's rules, more than 500 rules in a policy, or more than 1,000 policies in the organization. → **LOW–MEDIUM**; note it, because the workaround is always to widen a boundary.
9. **PB-09 — untested rollout.** A PAB policy is in place with no evidence of a Policy Simulator run before enforcement. → **MEDIUM**. Policy Simulator has a dedicated mode for PAB policies, and both `roles/iam.denyAdmin` and `roles/iam.principalAccessBoundaryAdmin` carry `policysimulator.*` permissions for it.

#### PB — Exfil scenario

PAB is the hard stop on the reachability paths computed in §6. Where IAM Deny severs a chain by removing a *verb*, PAB severs it by removing the *destination*: a compromised CI credential that has escalated to a data-tier service account still cannot read a project outside its boundary, because eligibility is evaluated before the allow policy is consulted at all.

Concretely, it is the containment control for **AP-10** (a federated principal that can impersonate an SA it should not — bind the workload pool to the two projects the pipeline deploys to, and the stolen token cannot reach the CONFIDENTIAL data project regardless of what IAM drift has occurred) and for **AP-11** (multi-hop escalation terminating outside the boundary). It does nothing for **AP-04** or **AP-05**, which do not depend on the attacker reaching an out-of-boundary resource.

The failure mode that makes this control imaginary is PB-02: a policy pinned to enforcement version 1 or 2 blocks Storage, BigQuery, Logging, Pub/Sub and Resource Manager but **not a single impersonation permission** — so the exact escalation the boundary was bought to contain passes straight through. Read `enforcementVersion` on every policy before crediting PAB with anything.

#### PB — Remediation

```bash
cat > /tmp/pab-ci.yaml <<'EOF'
details:
  enforcementVersion: "latest"
  rules:
  - description: CI may only touch the two deploy projects
    effect: ALLOW
    resources:
    - //cloudresourcemanager.googleapis.com/projects/app-nonprod-11
    - //cloudresourcemanager.googleapis.com/projects/app-prod-12
EOF

gcloud iam principal-access-boundary-policies create pab-ci-workloads \
    --organization=ORG_ID --location=global --policy-file=/tmp/pab-ci.yaml

gcloud iam policy-bindings create pab-bind-ci-pool \
    --organization=ORG_ID --location=global \
    --policy-kind=principal-access-boundary \
    --policy=organizations/ORG_ID/locations/global/principalAccessBoundaryPolicies/pab-ci-workloads \
    --target-principal-set=//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gh-actions
# Flag spellings on `gcloud iam policy-bindings create` (--policy-kind, --target-principal-set):
# verify against current docs. The Terraform shape below is confirmed.

# Upgrade an existing pinned policy after simulating it.
gcloud iam principal-access-boundary-policies update pab-ci-workloads \
    --organization=ORG_ID --location=global --details-enforcement-version=latest
```

```hcl
resource "google_iam_principal_access_boundary_policy" "ci_workloads" {
  organization                        = var.org_id
  location                            = "global"
  principal_access_boundary_policy_id = "pab-ci-workloads"
  display_name                        = "CI workload boundary"

  details {
    enforcement_version = "latest"     # never pin below 4 without a dated decision record
    rules {
      description = "CI may only touch the two deploy projects"
      effect      = "ALLOW"
      resources = [
        "//cloudresourcemanager.googleapis.com/projects/app-nonprod-11",
        "//cloudresourcemanager.googleapis.com/projects/app-prod-12",
      ]
    }
  }
}

resource "google_iam_organizations_policy_binding" "ci_pool" {
  organization      = var.org_id
  location          = "global"
  policy_binding_id = "pab-bind-ci-pool"
  policy            = "organizations/${var.org_id}/locations/global/principalAccessBoundaryPolicies/pab-ci-workloads"
  policy_kind       = "PRINCIPAL_ACCESS_BOUNDARY"
  target {
    principal_set = "//iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/gh-actions"
  }
}
```
Terraform's field is `enforcement_version` (snake_case) and it accepts the string `"latest"`.

---

### 5.8 Workload Identity Federation

#### WI — Observe

1. Enumerate every pool and provider, including soft-deleted ones (a deleted pool can be **undeleted** for 30 days before the deletion becomes permanent — a resurrection window that is a persistence primitive).
   ```bash
   gcloud iam workload-identity-pools list --location=global --show-deleted --format=json
   gcloud iam workload-identity-pools providers list --location=global \
       --workload-identity-pool=POOL_ID --format=json
   gcloud iam workload-identity-pools providers describe PROVIDER_ID --location=global \
       --workload-identity-pool=POOL_ID --format=json
   gcloud iam workforce-pools list --organization=ORG_ID --format=json
   gcloud iam workforce-pools providers list --workforce-pool=POOL_ID --location=global --format=json
   ```
2. Record per provider, verbatim: `oidc.issuerUri`, `oidc.allowedAudiences[]`, `oidc.jwksJson` (present or absent), `aws.accountId`, `aws.stsUri`, `saml.idpMetadataXml`, the full `attributeMapping` map, the full **`attributeCondition`** string, and `disabled`.
3. Find every IAM binding that names a principal from each pool, at every node and on every service account:
   ```bash
   gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json \
       --query='policy:"workloadIdentityPools"'
   gcloud asset search-all-iam-policies --scope=organizations/ORG_ID --format=json \
       --query='policy:"workforcePools"'
   ```
   Classify each binding's principal form: `principal://.../subject/SUBJECT` (tightest), `principalSet://.../group/GROUP_ID`, `principalSet://.../attribute.NAME/VALUE` (the correct restrictive form), or `principalSet://.../POOL_ID/*` (**all identities in the pool**).
4. For every service account a federated identity can impersonate (via `roles/iam.workloadIdentityUser` or `roles/iam.serviceAccountTokenCreator` on that SA), enumerate that SA's roles at **every** node, and then whether that SA can itself impersonate further SAs. The federated principal inherits everything the SA has, everywhere, plus every onward impersonation chain.
5. Record whether STS Data Access logging is enabled (`sts.googleapis.com`, `ADMIN_READ`) and whether workforce providers have `--detailed-audit-logging`.
6. Record the GKE pools separately: the pool is auto-named `PROJECT_ID.svc.id.goog`, and node pools must run `--workload-metadata=GKE_METADATA` for the GKE metadata server to intercept at all.

#### WI — Findings tests

1. **WI-01 — "any repo in the world" (the canonical GitHub misconfiguration).** Evaluate all three clauses:
   - the provider's `oidc.issuerUri` is `https://token.actions.githubusercontent.com` (or the trailing-slash variant), **and**
   - `attributeCondition` is empty **or** does not reference any of `assertion.repository_owner_id`, `assertion.repository_id`, `assertion.repository_owner`, `assertion.repository` (conditions such as `assertion.sub != ""` or `assertion.repository != ""` count as *not* referencing a tenant), **and**
   - at least one IAM binding names a principal from that pool.

   → **CRITICAL**. GitHub is a *shared* issuer: it signs a valid token for every repository on GitHub.com, so the pool gate reduces to "you have a GitHub account". Google states plainly that "it's insufficient to let Workload Identity Federation check a token's issuer URL to ensure that it comes from a trusted source". The same test applies with the platform's tenant claim substituted for GitLab SaaS (`assertion.namespace_id`), HCP Terraform (`assertion.terraform_organization_id`), and Azure DevOps (`assertion.oid`). Google documents conditions only for those four platforms — a Bitbucket or CircleCI condition asserted anywhere: verify against current docs.

   Note the guard and its limits: provider creation against a known shared issuer is now rejected server-side unless `attributeCondition` references a provider claim (observed error: `The attribute condition must reference one of the provider's claims`; the exact set of issuers this applies to is not documented — verify against current docs). That guard is **create/update-time only**: a provider created before it, or one whose condition references an irrelevant claim, still exists and still passes. **Read the actual condition; non-empty is not safe.**
2. **WI-02 — pool-wide binding.** Any IAM binding, at any node or on any service account, whose member is `principalSet://iam.googleapis.com/projects/PN/locations/global/workloadIdentityPools/POOL/*` or `principalSet://iam.googleapis.com/locations/global/workforcePools/POOL/*`. → **CRITICAL**. Google's own wording: "Although you can grant access to all of the identities in a workload identity pool, doing so can incur risk." Combined with WI-01 the two failures compose into full external access.
3. **WI-03 — branch pinned without a tenant.** `attributeCondition` pins only `assertion.ref == 'refs/heads/main'` (or `assertion.ref_type`, or `assertion.environment`) with no tenant claim. → **CRITICAL**; an attacker names their branch `main`.
4. **WI-04 — name claims instead of numeric IDs.** The condition or the bound `principalSet` uses `assertion.repository` / `assertion.repository_owner` (names) rather than `assertion.repository_id` / `assertion.repository_owner_id` (numeric, unique, never reused). → **HIGH**. Google's warning is explicit: "Using 'name' fields like `repository` and `repository_owner` increases the chances of cybersquatting and typosquatting attacks." An org rename frees the old name for an attacker.
5. **WI-05 — subject mapped to a mutable claim.** `google.subject` is mapped from anything reusable or user-controlled (`assertion.actor`, an email, a UPN, a display name) rather than `assertion.sub` (or `assertion.oid` for Entra ID). → **HIGH**. `google.subject` is required, capped at **127 characters**, and must map one-to-one with exactly one external identity in both directions; Google's guidance is to "limit attribute mappings to attributes that can't be modified by the user" and to use identifiers that "can't be reused over time".
6. **WI-06 — custom audience.** `oidc.allowedAudiences` is set to anything, especially a short or guessable value. The default expected `aud` is the full provider resource name (`https://iam.googleapis.com/projects/PN/locations/global/workloadIdentityPools/POOL/providers/PROVIDER`), and Google states it "helps reduce the risk of a confused deputy attack". A custom audience removes that protection: the same token can be replayed at any provider accepting it. → **HIGH**; demand a written justification. Limits: max 10 audiences, each ≤256 characters.
7. **WI-07 — the bridge lands on privilege.** A federated principal can impersonate a service account that holds `roles/owner`, `roles/editor`, any role from IA-01/06/12, or a project/folder/org-level `roles/iam.serviceAccountTokenCreator`. → **CRITICAL**. Trace and report the full chain: external principal → SA → SA's roles → data tier reached. This is the finding that makes WIF a top-tier exfil bridge rather than a hygiene item.
8. **WI-08 — no issuer allow-list.** `constraints/iam.workloadIdentityPoolProviders` is unset, so **all providers are allowed** — anyone with `iam.workloadIdentityPools.create` can stand up a pool trusting an attacker's OIDC issuer and mint GCP-usable principals from outside. → **HIGH**. Google's recommended posture is Deny All at the org root with per-project exceptions. Record the constraint's limit explicitly: it **only limits creating and updating** providers — "If an IdP was configured before you enabled the constraint, that provider can still be used." Enabling it does not retire an existing rogue provider; you must find and delete it. Same test for `constraints/iam.workloadIdentityPoolAwsAccounts` where AWS providers exist.
9. **WI-09 — no structural requirement for a real condition.** No custom org policy constraint on `iam.googleapis.com/WorkloadIdentityPoolProvider` requires a non-empty `resource.attributeCondition`. This is the only documented way to require an attribute condition org-wide, and the only control that catches the "condition present but useless" case; the list constraint cannot express it. → **MEDIUM**.
10. **WI-10 — resurrectable trust.** Any pool or provider appears in `--show-deleted` output within its 30-day undelete window. → **MEDIUM**; record who can undelete.
11. **WI-11 — GKE binding too broad.** A binding uses `principalSet://.../PROJECT_ID.svc.id.goog/namespace/NAMESPACE` (any KSA in the namespace — so namespace-create becomes credential-create) or `principalSet://.../PROJECT_ID.svc.id.goog/kubernetes.cluster/https://container.googleapis.com/v1/projects/.../clusters/CLUSTER` (the whole cluster). → **HIGH**. The correct form is `principal://.../PROJECT_ID.svc.id.goog/subject/ns/NAMESPACE/sa/KSA_NAME`. Also flag the legacy annotation form (`iam.gke.io/gcp-service-account` + `roles/iam.workloadIdentityUser` on `PROJECT_ID.svc.id.goog[NAMESPACE/KSA]`) presented as the current approach — it is still supported, but the modern path is direct `principal://` resource binding with no GSA at all.
12. **WI-12 — impersonation where direct access would do.** A federated principal is granted `roles/iam.workloadIdentityUser` on a service account when the resource roles it needs could be bound directly to the `principal://`/`principalSet://`. → **HIGH**. Direct access gives exactly the granted roles and keeps the federated principal in the data-plane audit log; impersonation inherits **everything the SA has everywhere** and launders identity — the data-plane log shows `principalEmail = <service account>`, with the real caller only in `protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail`, and **only if Data Access logs are enabled**. Revocation differs too: one resource unbind versus finding every `workloadIdentityUser` binding on every SA. (Per-product support for direct access: check the identity-federation supported-products page — the matrix does not render reliably, so verify against current docs.)
13. **WI-13 — token exchange invisible.** Data Access `ADMIN_READ` is not enabled for `sts.googleapis.com`, so `google.identity.sts.v1.SecurityTokenService.ExchangeToken` produces no log entry and there is no record of any federated token ever being minted. → **HIGH**.
14. **WI-14 — air-gapped GHES claiming OIDC federation.** The environment is an air-gapped GitHub Enterprise Server and a design claims GHES OIDC → WIF. Test it against the two stated requirements: Google must reach `https://HOSTNAME/_services/token/.well-known/openid-configuration` and `.../jwks`, and the `iss` claim must be "a publicly routable URL". An air-gapped GHES satisfies neither. → report the design as **non-functional**, not as a control. Statically pinning the GHES signing keys via `oidc.jwks_json` / `--jwk-json-path` removes the JWKS-fetch dependency, but the publicly-routable-issuer requirement still stands and Google publishes no GHES-with-static-JWKS pattern — **verify against current docs and require a working proof of concept before anyone designs around it**; it also fails silently on every GHES key rotation. Then find what the runners actually use:
   | Mechanism | Works air-gapped | Review posture |
   |---|---|---|
   | Runner on a GCE VM with an attached SA, using the metadata server | Yes, if the runner VM is in GCP | Strongest option: no key material on disk, short-lived auto-rotating tokens |
   | Runner on GKE with Workload Identity Federation for GKE | Yes, if the runner pod is in GKE | Scope with `ns/NAMESPACE/sa/KSA`, never the cluster-wide principalSet |
   | WIF with X.509 client certificates | Plausible — the one mode where Google fetches nothing from your network | Verify the certificate-based WIF setup against current docs before recommending |
   | WIF via a separate, internet-reachable corporate OIDC IdP | Yes, if such an IdP exists | Runner (or an egress proxy) must reach `sts.googleapis.com` |
   | **Service account JSON key as a GHES Actions secret** | Yes — and this is what these environments actually do | **Expected but CRITICAL.** The long-lived credential is the exfil primitive this whole review exists to catch; the compensating controls (rotation, the key-creation constraint exception, egress restriction, Data Access logging on that SA, PAB on the SA) carry the entire security burden |
   | Secret injected from an on-prem vault | Yes | Moves the trust problem on-prem; the credential is still typically an SA key |
   State the asymmetry explicitly rather than recommending WIF that cannot be deployed: **if the runner can reach Google at all (egress-only), WIF is impossible but key-based auth works** — which is exactly what pushes air-gapped shops onto long-lived keys. If the runner cannot reach `sts.googleapis.com` or `iamcredentials.googleapis.com` at all, the pipeline is not talking to GCP directly: find the relay or bastion and review **that**.
15. **WI-15 — newer trust surface unreviewed.** Attestation rules (`SetAttestationRules`, `AddAttestationRule`) or managed workload identities / pool namespaces are in use and were not enumerated. → **MEDIUM**; these are a second, less-watched path to grant trust. (Maturity and GA status: verify against current docs.)
16. **WI-16 — workforce pool hygiene.** `--session-duration` is at the 43200 s (12 h) ceiling on an admin-capable pool; or `--disable-programmatic-signin` is not set on a pool intended for human web SSO only; or `--detailed-audit-logging` is off on a privileged pool; or the attribute mapping uses a mutable claim (email, UPN, display name) instead of `assertion.oid`. → **MEDIUM–HIGH** each. Session duration must be >900 s and <43200 s; the default is 1 hour.

#### WI — Exfil scenario

**AP-10** end to end, in the shape it actually occurs: an attacker creates a repository in their own GitHub account → requests an OIDC token with `permissions: id-token: write` → the token's `iss` is the shared GitHub issuer, so it passes an empty or mis-scoped `attributeCondition` (WI-01) → the pool-wide `principalSet://.../*` binding (WI-02) lets it impersonate the CI service account → that SA holds project-level `roles/iam.serviceAccountTokenCreator` (IA-02) or `roles/editor` (WI-07) → read the CONFIDENTIAL dataset → `EXPORT DATA` to a bucket in the attacker's own project (**AP-07**). Not one step of this touches the network, so no firewall rule and no VPC-SC perimeter sees it until the final read — and the perimeter only sees that if the identity is not in an ingress rule.

The detection posture is the aggravating factor: the token exchange is a **Data Access** log (off by default, WI-13), the impersonation is a **Data Access** log (off by default), and only the final data read might be logged — also Data Access, also off by default. Score WIF findings assuming the whole chain is invisible unless you have evidence otherwise.

#### WI — Remediation

The correct restrictive provider — numeric IDs, tenant pinned, branch pinned, default audience:

```bash
gcloud iam workload-identity-pools providers create-oidc gh-actions-prov \
    --location=global --workload-identity-pool=gh-actions \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.actor=assertion.actor" \
    --attribute-condition="assertion.repository_owner_id == '1342004' && assertion.repository_id == '20300177' && assertion.ref == 'refs/heads/main' && assertion.ref_type == 'branch'"

# Bind to the ATTRIBUTE principalSet, never to the pool wildcard.
gcloud iam service-accounts add-iam-policy-binding deploy@app-prod-12.iam.gserviceaccount.com \
    --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gh-actions/attribute.repository/gh-org/gh-repo"

# Prefer direct resource access where the API supports it — no service account in the path at all:
gcloud storage buckets add-iam-policy-binding gs://ci-artifacts \
    --role=roles/storage.objectCreator \
    --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gh-actions/attribute.repository/gh-org/gh-repo"
```

```hcl
resource "google_iam_workload_identity_pool_provider" "gh_actions" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.gh.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-actions-prov"

  attribute_condition = <<EOT
    assertion.repository_owner_id == "1342004" &&
    attribute.repository == "gh-org/gh-repo" &&
    assertion.ref == "refs/heads/main" &&
    assertion.ref_type == "branch"
EOT

  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.actor"         = "assertion.actor"
    "attribute.aud"           = "assertion.aud"
    "attribute.repository"    = "assertion.repository"
    "attribute.repository_id" = "assertion.repository_id"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
    # allowed_audiences intentionally unset: keep the default provider-resource audience
  }
}
```

Gate the trust structurally, at two levels. The list constraint pins **which issuers** may be configured; the custom constraint pins **that a real condition exists** — the list constraint cannot express the second:

```bash
gcloud resource-manager org-policies allow constraints/iam.workloadIdentityPoolProviders \
    https://token.actions.githubusercontent.com --organization=ORGANIZATION_ID
```

```yaml
name: organizations/ORGANIZATION_ID/customConstraints/custom.wifRequireAttributeCondition
resourceTypes:
  - iam.googleapis.com/WorkloadIdentityPoolProvider
methodTypes:
  - CREATE
  - UPDATE
condition: "resource.attributeCondition != '' && resource.attributeCondition.contains('repository_owner_id')"
actionType: ALLOW
displayName: WIF providers must pin a tenant claim
description: Every workload identity pool provider must carry an attribute condition that pins the issuing tenant.
```

Then bind a PAB policy to the pool (see §5.7) so that even a perfect token cannot reach a project the pipeline does not deploy to, and enable Data Access `ADMIN_READ` on `sts.googleapis.com` and `iam.googleapis.com` so the exchange and the impersonation are both visible.

**Grep targets for a fast first pass:** `attribute_condition` absent from any `google_iam_workload_identity_pool_provider`; any `principalSet://` ending in `/*`; `roles/iam.workloadIdentityUser` bound to a `principalSet` that is not `attribute.`-scoped; any `allowed_audiences` set at all.

---

### 5.9 Identity

#### ID — Observe

1. **Super admins.** Cloud Identity / Workspace super admins are **above every control in this review**: they are implicitly granted permission to modify the IAM policy of the organization node, they can grant themselves any role in the organization, and consequently "you can't prevent them from being able to modify or delete audit logs." Enumerate them first.
   ```
   GET https://admin.googleapis.com/admin/directory/v1/users?domain=DOMAIN&query=isAdmin=true
   ```
   Record: count, whether each is a separate admin-only account (`alice-admin@` alongside `alice@`) or a daily-driver, 2SV method, and last sign-in. `isAdmin` is read-only, and the directory can be **up to 36 hours stale** for newly changed data — state that caveat in the finding.
2. **Delegated admins.** `isAdmin=true` returns **super** admins only. Enumerate `roleAssignments` and `roles` from the Admin SDK Directory API for delegated admin roles — User Management, Groups Admin, Security Settings, Services — several of which are escalation-relevant and none of which appear in the super-admin query. (Exact endpoint URLs: verify against current docs.)
3. **Authentication posture.** Record 2-Step Verification enforcement (Admin console → **Security > Authentication > 2-step verification**), whether security keys are required for elevated accounts, whether super-admin self-recovery is disabled, and the **Google Cloud session control** setting (Admin console → **Security > Access and data control > Google Cloud session control**; reauthentication frequency **1–24 hours**, method **password** or **security key**; requires the Security Settings admin privilege). A 16-hour default session length applies to some organizations and is not visible in the Admin console (verify against current docs).
4. **SSO.** Record the IdP, which accounts are in scope, and whether Google-side 2SV still applies to SSO users.
5. **Groups.** Enumerate every group bound to any role in the org IAM export, then resolve transitive membership:
   ```
   groups.memberships.searchTransitiveMemberships()   # direct, indirect, or both
   groups.memberships.searchTransitiveGroups()
   groups.memberships.checkTransitiveMembership()
   groups.memberships.getMembershipGraph()
   ```
   Record each membership's role (`OWNER`, `MANAGER`, `MEMBER` — every membership has at least MEMBER; OWNER can manage other OWNERs and delete the group), external members, and the group's join settings. Two gates apply: the transitive APIs require **Enterprise Standard / Enterprise Plus / Enterprise for Education / Cloud Identity Premium**, and the caller "must have permission to view the memberships of all groups that are part of the query, otherwise the request will fail" — partial visibility silently fails the whole query, so record it as an evidence gap rather than an empty result.
6. **Group-write authority.** Record who can change membership of every group bound to a Tier-0 role. This is **not an IAM permission**: "To create, view, edit, and delete groups… you need the appropriate group permissions. These permissions are managed by Google Workspace, not IAM." The Workspace-side authorities are the **Groups Admin** privilege / Groups Editor role, and group-level **OWNER**/**MANAGER** membership. Also check whether any service account has been delegated the Workspace **Group Administrator** role, which lets it call Cloud Identity `memberships.create` programmatically.
7. **Workspace data sharing.** Record whether **Google Workspace data sharing with Google Cloud** is enabled. Without it, "you can't see audit logs for Google Workspace in Google Cloud" at all.
8. **Service accounts and keys.**
   ```bash
   gcloud iam service-accounts list --project=PROJECT_ID --format=json
   gcloud iam service-accounts keys list --iam-account=SA_EMAIL --managed-by=user --format=json
   gcloud iam service-accounts keys list --iam-account=SA_EMAIL --managed-by=user \
       --created-before=2026-05-25T00:00:00Z --format=json
   ```
   `--managed-by` takes `user`, `system`, or `any` (default). **`user` is the exfil-relevant filter** — user-managed keys are the exportable, long-lived credential; `system` keys are Google-rotated and cannot be exfiltrated. Record every key's `validAfterTime`, and where the private key material lives (CI secret store, on-prem vault, a laptop, a jump box).

#### ID — Findings tests

1. **ID-01 — super-admin count and hygiene.** More super admins than the emergency minimum (a working default: 2 named break-glass accounts plus at most 2 operational), **or** any super admin account is also a person's daily-driver account rather than a separate `-admin` identity. → **CRITICAL**. Google's guidance is verbatim: "Retain only a minimal number of super-admin users and discourage everyday usage" and "Give super admins a separate account that requires a separate login."
2. **ID-02 — weak authentication on privileged accounts.** 2SV is not enforced for super admins and all elevated accounts, or it is enforced with a phishable factor rather than "a security key or other physical authentication device". → **CRITICAL**.
3. **ID-03 — self-recovery enabled.** Super-admin account self-recovery is on. It is disabled by default for new Cloud Identity/Workspace customers and Google recommends keeping it disabled. → **HIGH**.
4. **ID-04 — super admin inside the org-admin group.** A super admin is a member of the group that holds `roles/resourcemanager.organizationAdmin`. Google's guidance is to add Organization Administrator users to that group **but not the super admin user**. → **MEDIUM**; it collapses two separation-of-duty boundaries into one account.
5. **ID-05 — unmanaged human identities.** Any human principal in any IAM policy whose domain is not a verified org domain — `@gmail.com` accounts in particular. → **HIGH**; the org has no lifecycle control, no 2SV enforcement, and no offboarding over that identity.
6. **ID-06 — SSO single point of compromise.** SSO is configured such that IdP compromise yields Google account access with no independent Google-side factor for elevated accounts. → **HIGH**. Pair with the SSO-tampering detections (`TOGGLE_SSO_ENABLED`, `CHANGE_SSO_SETTINGS`, `ENFORCE_STRONG_AUTHENTICATION`, `2SV_DISABLE`), all of which read **Workspace** audit logs and therefore require data sharing to be on.
7. **ID-07 — session length.** Google Cloud session control is unset, or set at the 24-hour maximum for admin-capable principals. → **MEDIUM**. State the limit plainly in the finding so nobody counts it twice: session control applies to the Cloud console, the **gcloud CLI**, and apps requesting Google Cloud scopes — it does **not** apply to service accounts, service-account keys, or WIF/STS-derived tokens. Shortening human sessions does nothing to the service-account and federated paths that carry most of this report's risk.
8. **ID-08 — user-managed keys exist.** Any `--managed-by=user` key exists on a service account with access to CONFIDENTIAL/NTK data, or any user-managed key is older than 90 days, or `constraints/iam.serviceAccountKeyExpiryHours` is unset where key creation is excepted. → **CRITICAL** for the first clause, **HIGH** otherwise. Edge: *Key-mint* already exercised — this is AP-02's credential, in hand.
9. **ID-09 — key material outside GCP.** Any private key file is present on an on-prem host, a jump box, a developer laptop, a config-management system, or a CI secret store. → **CRITICAL**. This is the on-prem→cloud pivot in concrete form; carry it into the traversal analysis.
10. **ID-10 — human/non-human confusion.** A service account is used interactively by humans (key file shared, `gcloud auth activate-service-account` in runbooks), or a human account is used as a workload identity. → **HIGH**. Both destroy attribution: every action attributes to one identity that many people control.
11. **ID-11 — group nesting reaches a privileged group.** A group bound to any Tier-0 role has a transitive closure that includes a nested group with external members, or with join settings that allow anyone in the domain (or outside it) to join. → **CRITICAL**. An IAM binding to `group:x@example.com` is only as strong as the weakest path into that group.
12. **ID-12 — group-write is an untracked escalation.** Any principal outside the identity-admin set holds the Workspace **Groups Admin** privilege, or is an OWNER/MANAGER of a group bound to a Tier-0 role, or a service account has been delegated the Group Administrator role. → **CRITICAL**. State the detection consequence exactly:
    - **Where it leaves no trace:** the project's, folder's, and organization's IAM allow policy. Adding yourself to a group that holds `roles/bigquery.dataViewer` grants you that role with **no `SetIamPolicy` call and no change to any IAM policy** — a diff-based IAM review sees nothing.
    - **Where it does leave a trace:** the Workspace **Admin Audit** log (for console-driven changes) and the **Enterprise Groups Audit** log (for API and Groups-UI changes). These reach Cloud Logging as **Admin Activity** logs at the **organization** node, `resource.type="audited_resource"`, `serviceName` `admin.googleapis.com` or `cloudidentity.googleapis.com` — **only if Google Workspace data sharing with Google Cloud is enabled**. Two Event Threat Detection detectors cover it (`EXTERNAL_MEMBER_ADDED_TO_PRIVILEGED_GROUP` from Workspace Login Audit, `PRIVILEGED_GROUP_OPENED_TO_PUBLIC` from Workspace Admin Audit), and both require the same data sharing.
13. **ID-13 — Workspace data sharing off.** Google Workspace data sharing with Google Cloud is disabled. → **HIGH**. Every group-membership change, SSO change, and 2SV change is then invisible to Cloud Logging, SCC, and the SIEM — which makes ID-11 and ID-12 undetectable rather than merely under-monitored.
14. **ID-14 — group closure unverifiable.** The transitive membership query fails on licensing or on partial visibility. → report as an **evidence gap**, name which groups could not be resolved, and do not assert that group-based access is bounded.
15. **ID-15 — no group-based access at all.** Roles are bound to individual users rather than groups, so offboarding is manual and per-project. → **MEDIUM**. This is the one place where *more* group use is the recommendation — provided ID-11 and ID-12 are satisfied first.

#### ID — Exfil scenario

Identity is where **AP-11** starts and where **AP-13** ends. The group-write variant is the one most reviews miss and is worth writing out in the report as its own chain: a low-privilege insider holds Workspace Groups Admin (or is a MANAGER of `grp-data-readers@`) → adds themselves to that group → the group holds `roles/bigquery.dataViewer` on three CONFIDENTIAL datasets → reads → exports. **No IAM policy changed. No `SetIamPolicy` event exists.** The only evidence is a Workspace audit entry that may not be reaching Cloud Logging at all.

The super-admin case is simpler and worse: a super admin is above org policy, above IAM Deny, above VPC-SC (they can grant themselves ACM admin), and above the log sinks. Super-admin count and 2SV posture is therefore a **prerequisite finding** — report it before, not after, the technical control findings, because every other control in this document assumes those accounts are not compromised.

Service-account keys are **AP-02** in inventory form: for each key, the question the report must answer is not "does it exist" but "where is the private key file, who can read that location, and what does the SA reach".

#### ID — Remediation

```bash
# Prove which keys are the exportable kind, per service account, across the org.
for SA in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account="$SA" --managed-by=user \
      --format="table[no-heading](name,validAfterTime,validBeforeTime)"
done

# Remove a key and replace the credential with impersonation or WIF, never with another key.
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL

# Structural: ban key creation and key upload, and bound the life of any excepted key.
gcloud org-policies set-policy /tmp/no-sa-keys.yaml        # iam.managed.disableServiceAccountKeyCreation
gcloud org-policies set-policy /tmp/no-sa-key-upload.yaml  # iam.disableServiceAccountKeyUpload
gcloud org-policies set-policy /tmp/key-expiry.yaml        # iam.serviceAccountKeyExpiryHours -> 24h
```

```hcl
# Bound the blast radius of group-based access: bind roles to groups, then bound the *principals* —
# PAB targets org/folder/project, Workspace-domain, workforce-pool, workload-pool and agent principal
# sets, never a Google group (§5.7) — and deny the Tier-0 verbs for everyone outside the guardrail
# group (see §5.5).
resource "google_project_iam_member" "data_readers" {
  project = var.data_project
  role    = "roles/bigquery.dataViewer"
  member  = "group:grp-data-readers@example.com"
}
```

Group-write cannot be constrained by IAM — it is a Workspace authority. The enforceable controls are: (a) restrict the Workspace **Groups Admin** privilege to the identity-admin team and review `roleAssignments` on a schedule; (b) set every Tier-0-bound group's membership to **admin-only, no external members, no self-join**; (c) enable **Workspace data sharing with Google Cloud** so the changes reach Cloud Logging at the org node; (d) alert on `serviceName="admin.googleapis.com" OR serviceName="cloudidentity.googleapis.com"` membership events for the specific Tier-0 group addresses; (e) turn on the two ETD detectors above. Where no technical enforcement exists — nothing prevents a Groups Admin from adding a member — say so explicitly and name the compensating gate: mandatory review of group-membership deltas for Tier-0-bound groups, at a stated cadence, against a stated owner.

---

### 5.10 Access

#### AX — Observe

1. Access levels and their conditions: already enumerated in §5.3 — reuse that evidence rather than re-collecting it, and record here specifically **which access level gates on-prem-originated traffic** and what its `members` and `devicePolicy` contain.
2. Context-aware access bindings for Google Cloud console and gcloud:
   ```bash
   gcloud access-context-manager cloud-bindings list --organization=ORG_ID --format=json
   ```
   (Command group spelling for `gcpUserAccessBindings`: verify against current docs; the API resource is `accessPolicies.gcpUserAccessBindings` and the Terraform resource is `google_access_context_manager_gcp_user_access_binding`.) Record which groups are bound and to which access levels.
3. IAP: which HTTP surfaces sit behind IAP, and the full binding set for TCP forwarding — role `roles/iap.tunnelResourceAccessor`, permission `iap.tunnelInstances.accessViaIAP`, tunnel source range `35.235.240.0/20` (IPv6 `2600:2d00:1:7::/64`), idle disconnect after one hour.
4. Access Approval and Access Transparency: enabled or not, at which nodes, and where those logs go (Access Transparency lands in `_Required`, 400 days, licensing-gated).
5. Just-in-time elevation: what tool grants temporary roles, what identity it runs as, who approves, and how the grant is revoked.
6. The hybrid access path end to end: how an on-prem-originated API call authenticates, which access level or ingress rule admits it, and whether DNS sends it to the restricted VIP at all.

#### AX — Findings tests

1. **AX-01 — network position equals trust for on-prem access.** (Same field as test `SC-18` in §5.3 — per §5 rule 7, emit **one** finding: under `SC-` when the level's defect is generic, under `AX-` when the level exists specifically to admit the hybrid path. Cite the other as `also test <ID>`.) The access level admitting on-prem-originated requests contains `ipSubnetworks` of corporate RFC1918 ranges with **empty `members`** and **unset `devicePolicy`**. → **CRITICAL**. Given the assume-breach interior model, anything that can route packets from the corporate LAN inherits this: a compromised laptop, a rogue VM on the same VLAN, a partner site-to-site VPN. Ask the human, literally:
   > **"For each Google Cloud API surface reachable from the on-prem network, name the mechanism that authenticates the caller — a Google identity in an ingress rule, an access level `members` list, a device policy, or nothing but the source IP range."**
2. **AX-02 — access level used where an ingress rule belongs.** An access level exists whose intent is expressible as an ingress rule naming identities. Google's own guidance under `NO_MATCHING_ACCESS_LEVEL` is to prefer an ingress rule "because an ingress rule provides granular access control". → **HIGH** for on-prem paths, **MEDIUM** elsewhere. Note the forcing function to report alongside it: access-level `members[]` **does not support groups**, only `user:` and `serviceAccount:`, which is precisely why teams fall back to IP-only levels.
3. **AX-03 — geolocation on a private path.** (Same field as test `SC-20`; emit one finding per §5 rule 7.) An access level uses `regions[]` for traffic that arrives over the interconnect or via Private Google Access. Such levels **always deny private IPs and do not support Private Google Access**, and where they do apply they resolve to the VPN server's public IP. → **MEDIUM** as a broken control; **HIGH** if it is the only condition and is believed to be enforcing.
4. **AX-04 — device policy is nominal.** A level is described as device-gated but its `devicePolicy` sub-lists are empty (empty `allowedEncryptionStatuses`, `osConstraints`, or `allowedDeviceManagementLevels` each allow **all** values) or `requireScreenlock` is absent (defaults to false). → **HIGH**.
5. **AX-05 — no context-aware access on the console/CLI path.** No `gcpUserAccessBindings` exist for the groups holding Tier-0 roles, so console and gcloud access from an unmanaged device is unconditioned. → **HIGH**.
6. **AX-06 — IAP TCP forwarding over-scoped.** `roles/iap.tunnelResourceAccessor` bound at project, folder, or org level rather than on specific instances or tunnel destination groups. → **HIGH**; the holder can tunnel to every VM in scope, from anywhere, bypassing the need for any network position at all. Verify the corresponding ingress allow from `35.235.240.0/20` is scoped to the intended targets rather than the whole network.
7. **AX-07 — internal service trusts source IP.** Any internal HTTP or gRPC surface authorizes callers by source IP or by "it came over the interconnect" rather than an OIDC ID token with a specific service account as the authorized invoker, IAP, or mTLS with an authorization policy. → **CRITICAL**. This is the cloud-side instance of the soft-interior problem and it is a finding by the framing rule that **network position must not equal trust on either side of the link**.
8. **AX-08 — Access Approval absent.** Access Approval is not enabled for the folders holding CONFIDENTIAL/NTK projects, so Google-personnel access proceeds without an explicit customer approval step. → **MEDIUM**.
9. **AX-09 — Access Transparency not retained or not routed.** Access Transparency is unavailable (licensing) or its logs are not routed to the org sink. → **MEDIUM**.
10. **AX-10 — standing privilege where JIT belongs.** Any Tier-0 role is a standing binding rather than a time-boxed grant. → **HIGH**. State the implementation constraint that most JIT designs get wrong: `request.time` conditions work only on the 29 services that support IAM Conditions, and **`iam.googleapis.com` is not one of them** — so a time-boxed `roles/iam.serviceAccountTokenCreator` binding is unimplementable as a condition. JIT for impersonation must be an automated bind/unbind on the service-account resource, with the unbind scheduled at grant time.
11. **AX-11 — reauthentication not enforced for perimeter access.** Session controls for reauthentication are not configured on the access levels gating admin access. → **MEDIUM** (feature detail: verify against current docs; cross-reference §5.9's Google Cloud session control, which is a different setting).

#### AX — Exfil scenario

This area decides whether **AP-01** dies at the boundary or walks through it. A stolen credential used from the internet hits the perimeter and dies — unless an access level admits the caller's network position, in which case the perimeter admits the request and the credential works exactly as its owner's would. The on-prem case (**AP-12**, interior→cloud) is the same failure with a shorter walk: the attacker does not need to steal a network position, because the soft interior hands out network position to anything that gets a foothold.

IAP TCP forwarding is the mirror image and is frequently over-granted: `roles/iap.tunnelResourceAccessor` at project level converts "no external IP, private cluster, tight firewall" into "anyone in the group can open a TCP tunnel to any VM from any network", which is the entry step for the metadata-server escalation in §6.

#### AX — Remediation

```bash
# Replace an IP-only on-prem access level with an identity-scoped ingress rule.
cat > /tmp/ingress-onprem.yaml <<'EOF'
- ingressFrom:
    identities:
      - serviceAccount:onprem-etl@data-prod-01.iam.gserviceaccount.com
      - group:grp-onprem-operators@example.com
    sources:
      - accessLevel: accessPolicies/POLICY/accessLevels/al_onprem_managed
  ingressTo:
    resources:
      - projects/PROJECT_NUMBER
    operations:
      - serviceName: storage.googleapis.com
        methodSelectors:
          - method: google.storage.objects.get
  title: onprem-etl-read-only
EOF
gcloud access-context-manager perimeters update PERIMETER --policy=POLICY \
    --set-ingress-policies=/tmp/ingress-onprem.yaml
# `perimeters create` takes --ingress-policies=YAML_FILE (confirmed); the update-side flag spelling:
# verify against current docs.

# Scope IAP tunnelling to specific instances instead of the project.
gcloud compute instances remove-iam-policy-binding BASTION --zone=ZONE \
    --member="group:grp-eng@example.com" --role="roles/iap.tunnelResourceAccessor"
gcloud compute instances add-iam-policy-binding BASTION --zone=ZONE \
    --member="group:grp-oncall@example.com" --role="roles/iap.tunnelResourceAccessor"
```

```hcl
# Context-aware access on the console/gcloud path for the privileged group.
resource "google_access_context_manager_gcp_user_access_binding" "admins" {
  organization_id = var.org_id
  group_key       = var.grp_platform_admins_id
  access_levels   = [google_access_context_manager_access_level.corp_device.name]
}

# Identity-based service-to-service auth: one named invoker, never allUsers.
resource "google_cloud_run_v2_service_iam_binding" "invoker" {
  project  = var.project
  location = var.region
  name     = google_cloud_run_v2_service.svc.name
  role     = "roles/run.invoker"
  members  = ["serviceAccount:caller@${var.project}.iam.gserviceaccount.com"]
}
```
Back the last one with `constraints/run.managed.requireInvokerIam` (prevents the invoker IAM check being disabled) and domain-restricted sharing (prevents the `allUsers` principal). They cover different bypasses; recommend both.

---

### 5.11 Break-glass

#### BG — Observe

Ask for the break-glass runbook first, then verify every claim in it against configuration. If no runbook exists, that is finding BG-01 and the rest of this subsection is assessed against whatever the emergency procedure actually is in practice.

1. Identify the named break-glass principals (accounts, groups, or service accounts) and the roles they receive during an incident.
2. Record their **standing** bindings in normal state, at every node, including resource-level.
3. Record whether they appear in: any IAM Deny rule's `exceptionPrincipals`; any VPC-SC access level's `members[]`; any ingress rule's `identities[]`; any PAB binding.
4. Record the authentication requirement (2SV method, security key), where the credentials are stored, and how many people can retrieve them.
5. Record the elevation mechanism (manual `gcloud projects add-iam-policy-binding`, a ticketed workflow, a PAM tool), what identity performs the elevation, and what performs the revocation.
6. Record the alerting: which log filter fires, where the alert goes, and whether that path survives the mutation of the logging pipeline.
7. Record the last use and the last rehearsal.

#### BG — Findings tests

1. **BG-01 — no dedicated break-glass identity.** Emergency access is "a super admin logs in" or "someone uses their normal admin account". → **CRITICAL**. There is then no identity whose use is by definition anomalous, so there is nothing to alert on.
2. **BG-02 — not deny-by-default.** The break-glass principal holds standing Tier-0 bindings in normal state. → **CRITICAL**. Break-glass that is always live is just a shared admin account.
3. **BG-03 — permanently outside the guardrails.** The break-glass principal appears in `exceptionPrincipals` of the org IAM Deny rules **and** is not itself bounded by a PAB policy or a compensating time-box. → **HIGH**. The exception is necessary for the account to function during an incident, but a standing exception means the account is outside the un-overridable layer at all times, not only during one.
4. **BG-04 — it bypasses VPC Service Controls.** The decisive test. True if **any** of these hold:
   - the break-glass principal is listed in an access level's `members[]`;
   - the break-glass principal is in an ingress rule's `identities[]` whose `sources` includes `accessLevel: "*"`;
   - an ingress rule admitting the principal uses `identityType: ANY_IDENTITY`/`ANY_USER_ACCOUNT` with wildcard `ingressTo.resources` or `serviceName: "*"`;
   - the runbook instructs the operator to remove the project from the perimeter, or to add an access level, as a step.

   → **CRITICAL**. A break-glass identity that bypasses the perimeter is a standing, pre-authorized, single-credential exfil path for every project in scope — precisely **AP-09**, and it defeats the control that the rest of this report leans on hardest.
5. **BG-05 — no MFA gate or no dual control.** The account has no security-key requirement, or one person can both retrieve the credential and use it with no second party. → **HIGH** each.
6. **BG-06 — no time-box.** The elevation has no automatic expiry, or expiry relies on an IAM Condition on a service that does not support conditions. → **HIGH**. For impersonation roles specifically, `request.time` is unavailable (`iam.googleapis.com` does not support conditional bindings), so time-boxing must be an automated unbind.
7. **BG-07 — no real-time alert.** No log-based alert fires on the break-glass principal's `principalEmail` appearing in Admin Activity, or the alert routes only into a dashboard nobody watches, or it routes through the same sink an attacker would disable. → **CRITICAL**. Undetected break-glass is scored above detected break-glass by the severity rubric.
8. **BG-08 — no mandatory post-use review.** No requirement to reconcile every action taken under the break-glass identity against the incident record within a stated window, with a named owner. → **HIGH**.
9. **BG-09 — break-glass is a service account with a key.** The emergency identity is a service account whose JSON key is stored somewhere retrievable. → **CRITICAL**; it is a permanent offline credential to the highest privilege in the environment (AP-02 + AP-09 combined).
10. **BG-10 — never exercised.** No evidence of a rehearsal within the last 6 months, or the last rehearsal failed and the procedure was not fixed. → **MEDIUM**; untested break-glass reliably becomes "use the super admin instead" under pressure, which regresses to BG-01.
11. **BG-11 — over-broad elevation target.** The elevation grants `roles/owner` at the organization or a top-level folder rather than a purpose-built role at the folder containing the incident's projects. → **HIGH**.

#### BG — Exfil scenario

**AP-09** in its worst form is short: retrieve the standing credential → authenticate (no second factor) → the identity is already in an access level, so the perimeter admits it from anywhere → read CONFIDENTIAL data → export. Every other control in this report is bypassed by design, because that is what the account was built to do. The chain has one step that could be detected and, in the BG-07 case, it is not.

The subtler variant is **AP-13** wearing break-glass as a disguise: an attacker who reaches the break-glass credential does not need to modify any guardrail, because the guardrails already except this principal. That is why BG-03 and BG-04 are the two tests that matter most — an exception in IAM Deny plus a membership in an access level is a pre-built, pre-authorized bypass of both un-overridable layers.

#### Remediation — a break-glass identity that does not bypass the perimeter

Build it this way, and verify each numbered property as a separate closed finding:

1. **Dedicated human accounts, not service accounts.** Two named Cloud Identity users (`bg-1@`, `bg-2@`), security-key 2SV enforced, self-recovery disabled, **not** super admins — super admin is above every control here and its use cannot be constrained or reliably alerted.
2. **Zero standing privilege.** No role bindings in normal state, at any node. A group `grp-breakglass@` exists with the accounts as members and **no bindings**; privilege arrives only through the elevation workflow.
3. **Elevation is narrow and scripted.** The workflow grants one purpose-built custom role at the **folder** containing the incident's projects — never `roles/owner`, never at the org node. The workflow's own service account holds `resourcemanager.folders.setIamPolicy` on that folder only, and is the sole `exceptionPrincipal` for deny rule #2 **at that folder attachment point**, not at the org.
4. **The perimeter still applies.** The break-glass principals are **not** in any access level `members[]` and **not** in any wildcard ingress rule. They are admitted by one narrow ingress rule that pins identity *and* origin:

   ```yaml
   - ingressFrom:
       identities:
         - user:bg-1@example.com
         - user:bg-2@example.com
       sources:
         - accessLevel: accessPolicies/POLICY/accessLevels/al_breakglass_bastion
     ingressTo:
       resources:
         - projects/PROJECT_NUMBER
       operations:
         - serviceName: '*'
     title: breakglass-from-bastion-only
   ```
   where `al_breakglass_bastion` pins the bastion's `ipSubnetworks` **and** `devicePolicy.requireCorpOwned: true` **and** lists the two accounts in `members`. The perimeter still enforces for everyone else and for every other origin; break-glass gets an identity-scoped door, not a hole. If wildcard `serviceName` is unacceptable, enumerate the services the runbook actually needs.
5. **Dual control.** Elevation requires two distinct approvers recorded in the workflow; the credential halves (or the two accounts) are held by different people.
6. **Time-box by automated revocation.** The workflow schedules the unbind at grant time (a Cloud Scheduler job or a workflow step with a deadline). Do **not** rely on an IAM Condition for impersonation roles — `iam.googleapis.com` does not support conditions.
7. **Alert on first use, out of band.**

   ```bash
   gcloud logging read \
     'logName:"cloudaudit.googleapis.com%2Factivity"
      protoPayload.authenticationInfo.principalEmail=("bg-1@example.com" OR "bg-2@example.com")' \
     --organization=ORG_ID --freshness=1d --format=json
   ```
   Wire that filter to a log-based alerting policy **and** route a copy via Pub/Sub to a destination outside the pipeline the break-glass identity could modify. Add the Event Threat Detection custom module **`Breakglass Account Used`** (SCC Premium, GA, free to Premium customers) for the same identities — it is the cheapest detection in this whole catalog. Remember that a log-based alerting policy has exactly one condition and **does not operate on excluded logs**, so also alert on exclusion creation (see §5.12).
8. **Mandatory post-use review.** Within 24 hours of any use, reconcile every Admin Activity entry carrying that `principalEmail` against the incident record; a named owner signs off; unexplained actions escalate as an incident of their own. Record the review as evidence — an unreviewed use is a finding at the next assessment.
9. **Rehearse quarterly**, end to end, including the revocation and the alert firing.

```hcl
resource "google_folder_iam_member" "breakglass_elevation" {
  # Applied ONLY by the elevation workflow, and destroyed by the scheduled revocation.
  # Present in a break-glass Terraform workspace that is empty in normal state.
  folder = "folders/${var.incident_folder_id}"
  role   = google_organization_iam_custom_role.breakglass_operator.name
  member = "group:grp-breakglass@example.com"
}

resource "google_monitoring_alert_policy" "breakglass_used" {
  display_name = "Break-glass identity used"
  combiner     = "OR"
  conditions {
    display_name = "bg account in admin activity"
    condition_matched_log {
      filter = <<-EOT
        logName:"cloudaudit.googleapis.com%2Factivity"
        protoPayload.authenticationInfo.principalEmail=("bg-1@example.com" OR "bg-2@example.com")
      EOT
    }
  }
  notification_channels = [var.pagerduty_channel, var.siem_pubsub_channel]
}
```

---

### 5.12 Audit logging and detection coverage

Treat this as a control, not an afterthought. **Data Access logs are off by default for every service except BigQuery**, which means most of the read activity that constitutes exfiltration is invisible, and so are service-account impersonation and federated token exchange.

#### LG — Observe

1. Record which of the four log types exist and where they land:

   | Type | `logName` suffix | Default | Disableable | Bucket | Retention |
   |---|---|---|---|---|---|
   | Admin Activity | `cloudaudit.googleapis.com%2Factivity` | **on** | **no** — always written, cannot be configured, excluded, or disabled | `_Required` | **400 days**, not configurable |
   | Data Access | `cloudaudit.googleapis.com%2Fdata_access` | **off** (except BigQuery) | yes | `_Default` | **30 days** default (1–3650 configurable) |
   | System Event | `cloudaudit.googleapis.com%2Fsystem_event` | **on** | **no** | `_Required` | **400 days** |
   | Policy Denied (VPC-SC violations) | `cloudaudit.googleapis.com%2Fpolicy` | **on** | cannot be disabled, **but can be excluded from a sink** | `_Default` | **30 days** |
   | Access Transparency | `cloudaudit.googleapis.com%2Faccess_transparency` | licensing-gated | — | `_Required` | **400 days** |

   The consequence to record up front: the exfil-relevant logs (Data Access, Policy Denied) are the **short-lived, deletable** ones; `_Required` cannot be modified or deleted, so Admin Activity survives an attacker deleting sinks and Data Access does not.
2. Pull `auditConfigs` at org, every folder, and every project:
   ```bash
   gcloud organizations get-iam-policy ORG_ID --format="json(auditConfigs)"
   gcloud resource-manager folders get-iam-policy FOLDER_ID --format="json(auditConfigs)"
   gcloud projects get-iam-policy PROJECT_ID --format="json(auditConfigs)"
   ```
   Record per entry: `service` (`allServices` or a specific API), each `auditLogConfigs[].logType` (**`ADMIN_READ`**, **`DATA_READ`**, **`DATA_WRITE`** — there is no `ADMIN_WRITE` here; Admin Activity is always on and not configurable), and every `exemptedMembers[]`.
3. Enumerate sinks at **every** scope — org, each folder, each project, and the billing account. An org-level aggregated sink is invisible to `gcloud logging sinks list --project=X`, and a project-level `_Default` exclusion can silently shadow it.
   ```bash
   gcloud logging sinks list --organization=ORG_ID --format=json
   gcloud logging sinks list --folder=FOLDER_ID --format=json
   gcloud logging sinks list --project=PROJECT_ID --format=json
   gcloud logging sinks describe SINK_NAME --organization=ORG_ID --format=json
   ```
   Record per sink: `destination`, `filter`, every `exclusions[]` entry (up to 50 per sink), `disabled`, `includeChildren`, `interceptChildren`, and `writerIdentity` — a `serviceAccount:…@gcp-sa-logging.iam.gserviceaccount.com` account whose local part differs between project, folder and organization sinks (`service-PROJECT_NUMBER@…` for a project sink; the org/folder forms use the org/folder number). **Read the literal value back with `gcloud logging sinks describe SINK --organization=ORG_ID --format="value(writerIdentity)"`; never construct it** — a constructed identity is what makes the destination grant silently wrong. Resolve the destination's project and check whether it is in your organization.
4. Enumerate log buckets and their protection:
   ```bash
   gcloud logging buckets list --organization=ORG_ID --format=json
   gcloud logging buckets describe BUCKET_ID --location=LOCATION --format=json
   ```
   Record `retentionDays` and `locked`.
5. Record the alerting inventory: every `google_monitoring_alert_policy` with a `condition_matched_log` block, its filter, and its notification channels.
6. Record the SCC tier and which services are active.

#### LG — Findings tests

1. **LG-01 — Data Access logs off where exfil happens.** For each project holding CONFIDENTIAL/NTK, `auditConfigs` does not enable `ADMIN_READ` **and** `DATA_READ` for at least: `iam.googleapis.com` (enabling it for the IAM API also enables it for the **IAM Service Account Credentials API** — this is what makes impersonation visible), `sts.googleapis.com`, `storage.googleapis.com`, `cloudkms.googleapis.com`, `secretmanager.googleapis.com`, `pubsub.googleapis.com`, `spanner.googleapis.com`, `sqladmin.googleapis.com`, `firestore.googleapis.com`, `aiplatform.googleapis.com`, `dataflow.googleapis.com`. → **CRITICAL**. BigQuery is the documented exception whose Data Access logs are on by default; every other read is invisible.
2. **LG-02 — auditConfigs only at project level.** `auditConfigs` are set on projects but not at the organization node. `auditConfigs` inherit, and an org-level config is the only version a project-level `setIamPolicy` holder cannot quietly remove. → **HIGH**.
3. **LG-03 — exempted members.** Any `auditLogConfigs[].exemptedMembers` is non-empty. A listed principal generates **no Data Access log at all** — per-principal logging suppression. → **CRITICAL**.
4. **LG-04 — no org aggregated sink, or it captures nothing.** No sink exists at the organization node, or one exists with `includeChildren: false`. Without `--include-children` an org sink captures only logs written **at the org node** — effectively nothing. → **CRITICAL**.
5. **LG-05 — sink filter misses the exfil logs.** The org sink's `filter` matches only `cloudaudit.googleapis.com%2Factivity` and omits `%2Fdata_access` and `%2Fpolicy`. → **HIGH**. Those two are exactly the logs that expire in 30 days and that an attacker benefits from losing.
6. **LG-06 — destination is writable by workload principals.** The sink destination project grants any workload service account, or any group holding project-admin rights in the workload projects, write or IAM-admin access. → **CRITICAL**. The requirement is a project the workload principals cannot write to, with its own IAM and its own owners.
7. **LG-07 — destination outside the organization.** A sink's destination `PROJECT_ID` is outside your organization (log-bucket, BigQuery, Cloud Storage, Pub/Sub, or project destinations all accept an arbitrary project). Logs carry query text, resource names, principal identities and sometimes payloads. → **CRITICAL**; this is AP-08 already running. A writer identity holding a grant in an unfamiliar project is the tell.
8. **LG-08 — exclusions.** Any sink has a non-empty `exclusions[]`. Read every one. → **HIGH**. Exclusions drop logs at ingest, and log-based alerting policies explicitly **do not operate on excluded logs** — one exclusion blinds the whole detection stack silently.
9. **LG-09 — Policy Denied logs excluded.** The `_Default` sink (or any sink) carries `LOG_ID("cloudaudit.googleapis.com/policy")` in an exclusion filter. → **HIGH**; this is the documented, supported way to destroy every VPC-SC violation record. (Same finding as SC-29; report once.)
10. **LG-10 — retention at the default.** The log bucket receiving Data Access and Policy Denied logs is still at **30 days**. → **HIGH**. The 400-day figure applies **only** to `_Required`; asserting "we keep audit logs 400 days" while the exfil-relevant logs expire in 30 is a common and material error.
11. **LG-11 — bucket not locked, or locked in the wrong order.** The audit log bucket is not `--locked`, or it was locked **before** `--retention-days` was set, permanently pinning it at 30 days. → **HIGH** for unlocked, **HIGH** and irreversible for the ordering defect. Locking is irreversible; a locked bucket can only be deleted if empty, and deletion moves it to `DELETE_REQUESTED` for 7 days. Do not confuse Cloud Logging bucket locking with Cloud Storage **Bucket Lock** (`gcloud storage buckets update --lock-retention-period`), which locks a retention policy on a GCS bucket and is relevant only when the sink destination is GCS.
12. **LG-12 — no alert on pipeline mutation.** No alert exists on sink, exclusion, bucket, CMEK-settings, or log-deletion events; or the alert's notification path runs through the very pipeline being mutated. → **CRITICAL**. Route a copy out of band (Pub/Sub → external SIEM), or the alert dies with the sink.
13. **LG-13 — required alerts missing.** Any row of the required-alert table below has no corresponding alerting policy. → **HIGH** per row; **CRITICAL** for the `SetIamPolicy`, impersonation, and break-glass rows.
14. **LG-14 — alert filters use wrong method names.** Any alert filter uses `google.iam.credentials.v1.GenerateAccessToken` (matches **zero** entries — IAM Credentials logs the **bare** method name), a single `SetIamPolicy` string for Resource Manager (Resource Manager logs lowercase, versioned, resource-scoped names), or `google.iam.admin.v1.SetIamPolicy` with lowercase `Iam` (the real string is **`SetIAMPolicy`**, capital IAM, unlike every other service). → **CRITICAL** — a filter that matches nothing is a detection that does not exist.
15. **LG-15 — impersonation alerts double-count.** An alert counts IAM Credentials events without accounting for these being **long-running operations** that typically produce **two** entries (start and end) per impersonation. → **MEDIUM**, tuning defect that produces distrust in the alert.
16. **LG-16 — VPC-SC dry-run violations unread.** Dry-run violation logs exist and nobody triages them. → **MEDIUM** as a process finding, but **mine them during the review**: each one names a principal, a source, a target resource and a perimeter, which is free, ground-truth attack-path evidence. Note the service-pattern caveat: violations involving unsupported services (private VIP with service patterns) still carry `SERVICE_NOT_ALLOWED_FROM_VPC` but **may lack `methodName`, `authenticationInfo.principalEmail`, `metadata.resourceNames`, `metadata.accessLevels`, `metadata.deviceState`**, and the violation analyzer does not support them; `protoPayload.request.url` often carries the full path instead.
17. **LG-17 — GCS object-level detail absent.** `constraints/gcp.detailedAuditLoggingMode` is not enforced on projects holding CONFIDENTIAL/NTK in Cloud Storage, so audit logs record that an object was read but not **which** objects or by what query. → **HIGH**; you cannot scope an incident.
18. **LG-18 — SCC tier insufficient.** SCC is on Standard or Standard-legacy. Every detector this review depends on — Event Threat Detection, Security Health Analytics, VM Threat Detection, Sensitive Data Protection discovery, Attack Path Simulations, and both custom-module families — requires **Premium**. → **HIGH**. Do **not** recommend buying Enterprise: it is **deprecated**, shuts down **2027-05-21**, and organizations auto-move to Premium.
19. **LG-19 — detection gaps with no built-in detector.** There is no built-in ETD detector for: workload identity pool **provider** creation or modification; an IAM binding to `principalSet://.../*`; an `attributeCondition` being weakened or removed; `auditConfigs` being disabled or `exemptedMembers` added; or log sink/exclusion/bucket mutation. If none of these is covered by a log-based alerting policy or an ETD custom module, → **HIGH** each. Closure options:
    | Gap | Closable by ETD custom module? | How |
    |---|---|---|
    | WIF provider create/update | Yes | `Unexpected Cloud API Call` on `google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider` / `UpdateWorkloadIdentityPoolProvider` |
    | Log sink / exclusion mutation | Yes | `Unexpected Cloud API Call` on the filter-J method list below |
    | `auditConfigs` disabled | Partially | `Unexpected Cloud API Call` on `setIamPolicy` cannot inspect the request body and fires on every policy set — prefer the log-based alert in filter K |
    | Binding to `principalSet://.../*` | **No** | Template matches methods, not binding contents — use a log-based alerting policy or a configuration scan |
    | Weak/removed `attributeCondition` | No (detection) / Yes (prevention) | Prevent with the custom org policy on `resource.attributeCondition` from §5.8 |
    | Dangerous custom role | Yes | `Custom Role with Prohibited Permission` |
    | Break-glass identity used | Yes | `Breakglass Account Used` |
    | Specific role granted anywhere | Yes | `Unexpected Role Grant` (e.g. `roles/iam.serviceAccountTokenCreator`, `roles/iam.workloadIdentityUser`) |
    ETD custom modules are **template-only** — you cannot write arbitrary detection logic. Limits: 200 custom modules per organization, 30 findings per module per hour, 200 custom-module findings per parent resource per hour, 6 MB per module. Security Health Analytics custom modules evaluate *resource configuration* via CEL and are the right tool for the config-shaped gaps (pool-wide principalSets, missing attribute conditions, unlocked log buckets) — whether `WorkloadIdentityPoolProvider` is a supported SHA custom-module resource type: verify against current docs.
20. **LG-20 — SHA category names asserted unverified.** Any query or finding references a Security Health Analytics finding category (`LOG_NOT_EXPORTED`, `USER_MANAGED_SERVICE_ACCOUNT_KEY`, `PRIMITIVE_ROLES_USED`, `MFA_NOT_ENFORCED`, and similar) without confirmation. Only `AUDIT_LOGGING_DISABLED` and `NON_ORG_IAM_MEMBER` were confirmed. → **LOW**, but fix it: verify SHA finding category names against current docs before using them in a query.

#### Required alerts

Every row must exist as a log-based alerting policy with an out-of-band notification channel. A log-based alerting policy can have **only one condition**, so these are separate policies.

| # | Alert | Filter (§4.7.3) | Log type | Prerequisite / trap |
|---|---|---|---|---|
| A | **`SetIamPolicy` at any node** | `F1` | Admin Activity | none (always on). Substring match is required: Resource Manager emits `cloudresourcemanager.v3.projects.setIamPolicy`, `…v3.folders.setIamPolicy`, `…v3.organizations.setIamPolicy` plus v1/v1beta1/v2/v2beta1 variants |
| B | **Token generation / impersonation** | `F2` | **Data Access** | **Requires `ADMIN_READ` *and* `DATA_READ` on `iam.googleapis.com`** — `ADMIN_READ` alone misses `GenerateIdToken` and `SignBlob`. Method names are **bare** — a fully-qualified filter matches nothing |
| C | **Federated token exchange** | `F3` | **Data Access** | Requires `ADMIN_READ` on `sts.googleapis.com`. Pivot on `protoPayload.metadata.mapped_principal` for the pool subject and `protoPayload.resourceName` for the provider |
| D | **SA key creation and upload** | `F4` | Admin Activity | none. **`UploadServiceAccountKey`** is the BYO-public-key persistence path most filters miss; note `SetIAMPolicy` with capital `IAM` |
| E | **Custom-role mutation** | `F5` | Admin Activity | none. This is the only detection for the *Role-mutate* edge, which changes no binding |
| F | **WIF trust-boundary change** | `F6` | Admin Activity | none. Use the substring form to catch `google.iam.v1.*` and `google.iam.v1beta.*`, and add the workforce equivalents |
| G | **Org policy tampering** | `F7` | Admin Activity | none. The v1 path `cloudresourcemanager.v1.organizations.setOrgPolicy` is in the filter and is the one most rules omit |
| H | **Perimeter and access-level change** | `F15` (org node) and `F8` (any scope) | Admin Activity | **Perimeter and access-level CRUD lands in the ORG-level activity log, not the project log** — a detection pipeline scoped to projects misses every perimeter-tampering event. Include `CreateAuthorizedOrgsDesc` / `UpdateAuthorizedOrgsDesc`, which widen the trusted-org list and look like routine config |
| I | **VPC-SC violations, enforced** | `F12` | Policy Denied | always on, but expires in 30 days and can be excluded from a sink. Pivot fields: `protoPayload.metadata.violationReason` (`NETWORK_NOT_IN_SAME_SERVICE_PERIMETER`, `RESOURCES_NOT_IN_SAME_SERVICE_PERIMETER`, `NO_MATCHING_ACCESS_LEVEL`, `SERVICE_NOT_ALLOWED_FROM_VPC` — tolerate the singular `RESOURCE_…` spelling that appears in one doc page; other values such as `CREDENTIALS_TYPE_NOT_SUPPORTED` are unconfirmed, verify against current docs), `metadata.servicePerimeter`, `metadata.source`, `metadata.targetResource`, `metadata.targetResourcePermissions` (logs `vpcsc.permissions.unavailable` when unknown), `metadata.intermediateServices` (empty for user-initiated requests — non-empty means a confused-deputy chain), `metadata.vpcServiceControlsUniqueId` and `metadata.vpcServiceControlsTroubleshootToken` for the violation analyzer |
| J | **VPC-SC violations, dry-run** | `F13` | Policy Denied | Free attack-path evidence: dry-run logs **only the differences** in violations compared with enforced mode |
| K | **Logging-pipeline tampering** | `F10` | Admin Activity | **Notification channel must not depend on this pipeline.** `UpdateCmekSettings` can render stored logs unreadable without deleting anything |
| L | **Data Access logging switched off** | `F11` | Admin Activity | There is no dedicated method name for this. The exact request field path varies by API version — **verify against current docs and confirm against a real log entry before relying on it** |
| M | **GCS exfil setup** | `F9` | Admin Activity | `storage.hmacKeys.create` mints an S3-compatible long-lived credential; `storage.setIamPermissions` is the bucket/managed-folder IAM set |
| N | **Break-glass use** | `F1` narrowed to `protoPayload.authenticationInfo.principalEmail=("bg-1@example.com" OR "bg-2@example.com")` | Admin Activity | Plus the ETD custom module `Breakglass Account Used` |
| O | **Group membership change on a Tier-0 group** | `F19` | Admin Activity, **org node** | **Requires Google Workspace data sharing with Google Cloud.** Without it these events do not exist in Cloud Logging at all |

Useful pivots when hunting rather than alerting: `protoPayload.requestMetadata.callerIp` (the literal string **`private`** means the call originated inside Google's production network), `protoPayload.request_metadata.caller_network` (set only when the network host project is in the same organization or project as the accessed resource — cross-org callers lose network attribution), and `protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail` (the real caller behind an impersonated SA — present only when Data Access logging is on).

#### LG — Exfil scenario

Detection coverage decides the **severity** of every other finding in this report, and it is itself the target of **AP-08** and of the defense-evasion step in **AP-13**.

The concrete failure the report must state: with Data Access logs off, **AP-03** produces exactly zero log entries until the attacker touches something with an Admin Activity method. The impersonation (`GenerateAccessToken`) is `ADMIN_READ`; the BigQuery read is `DATA_READ`; the object reads are `DATA_READ`. Every one of them is off by default. An organization can be fully exfiltrated with a complete, untouched audit trail showing nothing but a handful of routine Admin Activity entries.

**AP-08** in its direct form is one API call: a principal with `roles/logging.configWriter` creates a sink to a BigQuery dataset or Pub/Sub topic in a project outside the organization, and org-wide logs — query text, resource names, principal identities — stream out continuously. The same role's `logging.exclusions.create` then silences the alerts that would have shown it, because log-based alerting policies do not operate on excluded logs.

Score every attack path in this report on the detection posture derived here: does the step produce an audit-log entry, is that log type **actually enabled** for that project, is it routed to a sink outside the workload's control, is it retained long enough to investigate, and is anything alerting on it. An undetected path is scored more severely than a detected one, and "we have audit logs" is never an answer — name the log type, the enablement state, the retention, and the alert.

#### LG — Remediation

Enable Data Access logs at the **organization** node — the only version a project-level `setIamPolicy` holder cannot quietly undo:

```bash
# Make the edit mechanical, not manual: the auditConfigs block is a TOP-LEVEL key of the
# policy document, so hand-pasting the fragment alone produces a file gcloud rejects.
gcloud organizations get-iam-policy ORG_ID --format=json > /tmp/org-policy.json
jq '.auditConfigs = [{"service":"allServices","auditLogConfigs":[
      {"logType":"ADMIN_READ"},{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}]' \
   /tmp/org-policy.json > /tmp/org-policy-new.json
gcloud organizations set-iam-policy ORG_ID /tmp/org-policy-new.json
```

The resulting fragment inside the policy document — `exemptedMembers` is omitted because empty is the
default, and any non-empty value is an audit-evasion primitive:

```json
{
  "auditConfigs": [
    {
      "service": "allServices",
      "auditLogConfigs": [
        { "logType": "ADMIN_READ" },
        { "logType": "DATA_READ" },
        { "logType": "DATA_WRITE" }
      ]
    }
  ]
}
```
`allServices` is the wildcard; a service without its own entry inherits the broader configuration. `exemptedMembers` must stay empty — any entry is an audit-evasion primitive. Google's own caveat, which the report should carry so the cost is not a surprise: "Data Access audit logs volume can be large. Enabling Data Access logs might result in your Google Cloud project being charged for the additional logs usage." Where full `allServices` coverage is refused on cost grounds, enable `ADMIN_READ` + `DATA_READ` for the services in LG-01 on the CONFIDENTIAL/NTK projects at minimum, and record the residual blind spot explicitly.

```hcl
resource "google_organization_iam_audit_config" "all_services" {
  org_id  = var.org_id
  service = "allServices"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
```
(`google_project_iam_audit_config` and `google_folder_iam_audit_config` exist with the same shape; each is **authoritative for a given service**, so a second resource for the same service will fight it.)

Org-level aggregated sink into a project workload principals cannot write to, with retention set **before** the lock:

```bash
gcloud logging sinks create org-audit-aggregated \
    logging.googleapis.com/projects/SECURITY_LOGS_PROJECT/locations/LOCATION/buckets/org-audit \
    --include-children --organization=ORG_ID \
    --log-filter='logName:"cloudaudit.googleapis.com%2Factivity" OR logName:"cloudaudit.googleapis.com%2Fdata_access" OR logName:"cloudaudit.googleapis.com%2Fsystem_event" OR logName:"cloudaudit.googleapis.com%2Fpolicy" OR logName:"cloudaudit.googleapis.com%2Faccess_transparency"'

# Grant the sink's writer identity on the destination — read it back, do not guess it.
gcloud logging sinks describe org-audit-aggregated --organization=ORG_ID --format="value(writerIdentity)"
gcloud projects add-iam-policy-binding SECURITY_LOGS_PROJECT \
    --member="serviceAccount:service-ORG_NUMBER@gcp-sa-logging.iam.gserviceaccount.com" \
    --role=roles/logging.bucketWriter
# Destination-role mapping: log bucket -> the bucket-writer role (name: verify against current docs);
# Cloud Storage -> roles/storage.objectCreator; Pub/Sub -> roles/pubsub.publisher;
# BigQuery -> roles/bigquery.dataEditor.

# Retention FIRST, then the lock. Locking a 30-day bucket pins it at 30 days permanently.
gcloud logging buckets update org-audit --location=LOCATION \
    --organization=ORG_ID --retention-days=400
gcloud logging buckets update org-audit --location=LOCATION \
    --organization=ORG_ID --locked
```

```hcl
resource "google_logging_organization_sink" "aggregated" {
  name             = "org-audit-aggregated"
  org_id           = var.org_id
  include_children = true
  destination      = "logging.googleapis.com/projects/${var.security_logs_project}/locations/${var.location}/buckets/org-audit"
  filter           = <<-EOT
    logName:"cloudaudit.googleapis.com%2Factivity" OR
    logName:"cloudaudit.googleapis.com%2Fdata_access" OR
    logName:"cloudaudit.googleapis.com%2Fsystem_event" OR
    logName:"cloudaudit.googleapis.com%2Fpolicy" OR
    logName:"cloudaudit.googleapis.com%2Faccess_transparency"
  EOT
  # exclusions intentionally absent — every exclusion is a finding until justified
}

resource "google_monitoring_alert_policy" "logging_pipeline_tampering" {
  display_name = "Logging pipeline mutated"
  combiner     = "OR"
  conditions {
    display_name = "sink/exclusion/bucket mutation"
    condition_matched_log {
      filter = <<-EOT
        logName:"cloudaudit.googleapis.com%2Factivity"
        protoPayload.serviceName="logging.googleapis.com"
        protoPayload.methodName=("google.logging.v2.ConfigServiceV2.UpdateSink" OR
          "google.logging.v2.ConfigServiceV2.DeleteSink" OR
          "google.logging.v2.ConfigServiceV2.CreateExclusion" OR
          "google.logging.v2.ConfigServiceV2.UpdateExclusion" OR
          "google.logging.v2.ConfigServiceV2.UpdateBucket" OR
          "google.logging.v2.ConfigServiceV2.DeleteBucket" OR
          "google.logging.v2.ConfigServiceV2.UpdateCmekSettings" OR
          "google.logging.v2.LoggingServiceV2.DeleteLog")
      EOT
    }
  }
  notification_channels = [var.external_siem_pubsub_channel]   # NOT a channel that depends on this pipeline
}
```
Alert policies can also be created from a file with `gcloud monitoring policies create --policy-from-file=alert.json`. Back the whole pipeline with deny rule #10 from §5.5 so `logging.sinks.update|delete` and `logging.exclusions.*` are unavailable to everyone outside the logging-admin group — a removed binding is one `setIamPolicy` from returning, a deny rule is not.

---

## 6. Privilege escalation, the privilege graph, and reachability

This is a distinct analytical phase, not a checklist. Do not stop at "principal X is
over-privileged." Compute, for every starting position in the threat model, **the set of identities
that position can become**, and every path from it to a principal that can read CONFIDENTIAL or NTK
data. Output of this phase: a labeled directed graph, a ranked chain list in the §6.3 format, and the
`TOP CUTS` list that drives the remediation roadmap.

Run it against the Cloud Asset Inventory exports collected in intake. Where an artifact is missing,
build the partial graph anyway and record the missing edge classes explicitly — an unbuilt edge class
is a blind spot, not an absence of risk.

### 6.1 Build the privilege graph

#### 6.1.1 Nodes — enumerate exactly these, in these string formats

Node identity is the IAM member string, verbatim, because that is the join key against every policy
in the evidence. Never normalise, lowercase, or strip prefixes.

| Node type | Exact identity string | How to enumerate | Why it is a node |
|---|---|---|---|
| Human | `user:alice@example.com` | `iam-policy` export, every `bindings[].members[]` with prefix `user:`; cross-check against Cloud Identity `users.list` | Starting position for adversaries A2 (insider) and A1 (stolen credential) |
| Group | `group:eng-all@example.com` | `bindings[].members[]` with prefix `group:`; expand membership via Cloud Identity `groups.memberships.searchTransitiveMemberships()` | A binding to a group is only as strong as the weakest path into the group, including nested groups |
| SA, user-managed | `serviceAccount:NAME@PROJECT_ID.iam.gserviceaccount.com` | `resource` export, `assetType == "iam.googleapis.com/ServiceAccount"` | Impersonation target and key-mint target |
| SA, default Compute Engine | `serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com` | same; match the suffix `-compute@developer.gserviceaccount.com` | Default runtime identity for GCE, **Cloud Run, Cloud Run functions (2nd gen), and Cloud Build in new projects**; carries `roles/editor` unless `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` is enforced |
| SA, default App Engine | `serviceAccount:PROJECT_ID@appspot.gserviceaccount.com` | same | Default runtime identity for Cloud Run functions (1st gen) |
| SA, Cloud Build legacy | `serviceAccount:PROJECT_NUMBER@cloudbuild.gserviceaccount.com` | same | Historically bound `roles/cloudbuild.builds.builder`; still present in pre-2024 projects |
| SA, service agent | `serviceAccount:service-PROJECT_NUMBER@gcp-sa-SERVICE.iam.gserviceaccount.com` | same; e.g. `gcp-sa-logging`, `gcp-sa-pubsub` | Log-sink writer identities hold grants in destination projects — a sink writer with a grant in an unfamiliar project is an exfil indicator |
| Federated workload identity | `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT` | `bindings[].members[]` prefix `principal://`; providers via `gcloud iam workload-identity-pools providers list` | Bridge from an external IdP into the org |
| Federated principal set (attribute) | `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTRIBUTE_NAME/ATTRIBUTE_VALUE` | same | The correct restrictive form, e.g. `attribute.repository/acme/deploy` |
| Federated principal set (whole pool) | `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/*` | same | **Every identity the IdP will ever sign.** Always a HIGH finding; treat ease-of-start as 5 |
| GKE workload (KSA), modern form | `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/NAMESPACE/sa/KSA_NAME` | same | Pod-to-cloud identity |
| GKE namespace set | `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/namespace/NAMESPACE` | same | Anyone who can create a KSA in that namespace gets the grant |
| GKE workload, legacy impersonation form | `serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]` bound `roles/iam.workloadIdentityUser` on a GSA | same | Still GA and still common; the `principal://` form is now the recommended one |
| Workforce federated human | `principal://iam.googleapis.com/locations/global/workforcePools/POOL_ID/subject/SUBJECT` | same | **No project number in the string** — org-scoped |
| Public | `allUsers`, `allAuthenticatedUsers` | grep the whole `iam-policy` export | Ease-of-start 5: no credential needed |
| Domain | `domain:example.com` | same | Grants to a domain you do not control are an external-sharing path |
| Deleted principal | `deleted:serviceAccount:...?uid=...` | same | Stale binding; flag, but it confers nothing until the uid is reused |
| Resource: data store | `//storage.googleapis.com/BUCKET`, `//bigquery.googleapis.com/projects/P/datasets/D`, `//pubsub.googleapis.com/projects/P/topics/T`, `//secretmanager.googleapis.com/projects/P/secrets/S`, `//cloudkms.googleapis.com/projects/P/locations/L/keyRings/KR/cryptoKeys/K`, `//sqladmin.googleapis.com/projects/P/instances/I` | `resource` export, filtered to the data asset types | Path terminals; each carries a classification label |
| Resource: identity-conferring | the service account resource `//iam.googleapis.com/projects/P/serviceAccounts/EMAIL`; a VM `//compute.googleapis.com/projects/P/zones/Z/instances/I` with an attached SA; a Cloud Run service; a Cloud Build trigger; a GKE node pool | `resource` export | The attachment point where `actAs` converts into a token |
| Resource: container (scope) | `organizations/ORG_ID`, `folders/FOLDER_ID`, `projects/PROJECT_NUMBER` | `ancestors[]` on every asset | Where `setIamPolicy` and `orgpolicy.policy.set` bite |

Canonicalise container nodes to the `ancestors[]` token form (`projects/123456789`), not the project
ID form, or the same project will appear as two nodes and inheritance will silently under-resolve.

#### 6.1.2 Edge catalog

Define these two shell helpers first; every "how to detect" cell below uses them against the
NDJSON asset exports.

```bash
# flatten every allow binding in the iam-policy export to one JSON object per (scope, role, member)
# scope MUST be canonicalised to the ancestors[] token form for containers, or the same
# project appears as two nodes and inheritance under-resolves (see the rule above).
flat() { jq -c '. as $a | .iamPolicy.bindings[]? |
  {scope:(if ($a.assetType|test("cloudresourcemanager.googleapis.com/(Project|Folder|Organization)"))
          then $a.ancestors[0] else $a.name end),
   type:$a.assetType, anc:$a.ancestors, role:.role,
   member:.members[], conditional:(.condition!=null)}' "$@"; }

# every custom role definition and its permission list
roles() { jq -c 'select(.assetType=="iam.googleapis.com/Role") |
  {name:.resource.data.name, perms:.resource.data.includedPermissions}' "$@"; }
```

| Edge kind | Exact permission(s) that create it | Source | Target | What the attacker gains | How to detect it in the evidence | Cheapest sever |
|---|---|---|---|---|---|---|
| **Impersonate — access token** | `iam.serviceAccounts.getAccessToken` (in `roles/iam.serviceAccountTokenCreator`, `roles/iam.workloadIdentityUser`) | any principal | SA | OAuth 2.0 bearer token for the SA | `flat iam-policy.json \| jq 'select(.role\|test("serviceAccountTokenCreator\|workloadIdentityUser"))'` | Re-bind the role **on the SA resource** instead of the project; add org IAM Deny on `iam.googleapis.com/serviceAccounts.getAccessToken` |
| **Impersonate — OIDC token** | `iam.serviceAccounts.getOpenIdToken` (also in `roles/iam.serviceAccountOpenIdTokenCreator`, the narrowest impersonation role) | any principal | SA | Audience-bound ID token: calls Cloud Run / Cloud Run functions / IAP as the SA | same query | Downgrade the binding to `roles/iam.serviceAccountOpenIdTokenCreator` on the one SA; deny `iam.googleapis.com/serviceAccounts.getOpenIdToken` elsewhere |
| **Impersonate — self-signed** | `iam.serviceAccounts.signBlob`, `iam.serviceAccounts.signJwt` (in `roles/iam.serviceAccountTokenCreator` only — **not** in `roles/iam.workloadIdentityUser`) | any principal | SA | A signature or signed JWT made with the SA's Google-managed key. The JWT is exchanged for an access token **at the OAuth token endpoint** — so no `GenerateAccessToken` call ever happens | `flat iam-policy.json \| jq 'select(.role=="roles/iam.serviceAccountTokenCreator")'` plus every custom role from `roles resource.json` containing `signJwt`/`signBlob` | Deny `iam.googleapis.com/serviceAccounts.signJwt` **and** `.signBlob` explicitly — a deny rule listing only `getAccessToken` leaves this open |
| **Impersonate — delegation chain** | `iam.serviceAccounts.implicitDelegation` | SA-A | SA-C via intermediate SA-B | A token for C without ever holding a direct grant on C; consumed through the `delegates[]` field of `GenerateAccessToken`, which has no method of its own | Search every binding of `roles/iam.serviceAccountTokenCreator`; then for each SA-B the source can reach, repeat — this edge only exists as a composition, so it must be derived, never read off a single binding | Deny `iam.googleapis.com/serviceAccounts.implicitDelegation` at the folder; it is the cheapest of the five to remove because almost nothing legitimately uses it |
| **Deploy-as (`actAs` pair rule)** | `iam.serviceAccounts.actAs` (in `roles/iam.serviceAccountUser`) **AND** a create/update permission on a surface that runs code (`compute.instances.create`, `compute.instances.setServiceAccount`, `run.services.create`, `cloudfunctions.functions.create`, `dataflow.jobs.create`, … — permission spellings other than `compute.instances.setServiceAccount` and the two metadata permissions: verify against current docs) | any principal | the attached SA | Runs attacker code as the SA and reads its token from `169.254.169.254`. **`actAs` is enforced by the consuming service, not by the IAM Credentials API** — disabling `iamcredentials.googleapis.com` does not block it, and it produces no `iamcredentials` log entry | Two queries joined: `flat iam-policy.json \| jq 'select(.role\|test("serviceAccountUser"))'` for the `actAs` half, and the same flattened output filtered to deploy roles (`roles/compute.instanceAdmin.v1`, `roles/compute.admin`, `roles/run.admin`, `roles/run.developer`, `roles/cloudfunctions.developer`, `roles/cloudbuild.builds.editor`, `roles/composer.admin`, `roles/dataflow.developer`, `roles/dataproc.editor`, `roles/notebooks.admin`, `roles/container.developer`, `roles/container.admin`) for the other half. **A principal holding only one half is not an edge** | Break the pair, not both halves: revoke the deploy permission in the project that holds the privileged SA, or bind `roles/iam.serviceAccountUser` on that one SA. Then deny `iam.googleapis.com/serviceAccounts.actAs` for every principal outside the owning deploy identity |
| **Key-mint** | `iam.serviceAccountKeys.create` (in `roles/iam.serviceAccountKeyAdmin`; also in `roles/editor`) | any principal | SA | A **long-lived private key usable entirely offline** — self-signed JWT to OAuth token, no IAM Credentials call, survives every session control, and its later use is invisible | `flat iam-policy.json \| jq 'select(.role\|test("serviceAccountKeyAdmin\|roles/editor\|roles/owner"))'`; existing keys via `gcloud iam service-accounts keys list --iam-account=SA --managed-by=user` (`user` is the exfiltratable kind; `system` keys are Google-rotated and cannot be exported) | Enforce `constraints/iam.managed.disableServiceAccountKeyCreation` at the org node (also covers Cloud Storage HMAC keys) plus the org deny group `iam.googleapis.com/serviceAccountKeys.*` — this is one of the few valid wildcard deny groups |
| **Grant-self — container** | `resourcemanager.organizations.setIamPolicy`, `resourcemanager.folders.setIamPolicy`, `resourcemanager.projects.setIamPolicy` | any principal | org / folder / project node | Any role on anything beneath that node, including impersonation of every SA under it | `flat iam-policy.json \| jq 'select(.role\|test("organizationAdmin\|folderIamAdmin\|projectIamAdmin\|securityAdmin\|roles/owner"))'` | Replace org/folder-level grants with `roles/resourcemanager.projectIamAdmin` on the single project; deny `cloudresourcemanager.googleapis.com/{organizations,folders,projects}.setIamPolicy` above that node. Note the v2 FQDN is `cloudresourcemanager.googleapis.com`, not `resourcemanager.googleapis.com` |
| **Grant-self — service account** | `iam.serviceAccounts.setIamPolicy` (in `roles/iam.serviceAccountAdmin`) | any principal | SA | Self-grant `roles/iam.serviceAccountTokenCreator` on that SA, then impersonate. Reaches the SA without ever holding an impersonation role | `flat iam-policy.json \| jq 'select(.role\|test("serviceAccountAdmin\|securityAdmin"))'` | Deny `iam.googleapis.com/serviceAccounts.setIamPolicy` at the folder; keep `roles/iam.serviceAccountAdmin` to a platform-team identity that is not a workload-deploy identity |
| **Grant-self — resource level** | `storage.buckets.setIamPolicy`, `storage.objects.setIamPolicy`, `bigquery.datasets.setIamPolicy`, **`bigquery.datasets.update`**, `bigquery.tables.setIamPolicy`, `pubsub.topics.setIamPolicy`, `pubsub.subscriptions.setIamPolicy`, `cloudkms.cryptoKeys.setIamPolicy`, `secretmanager.secrets.setIamPolicy`, `artifactregistry.repositories.setIamPolicy`, `compute.instances.setIamPolicy` | any principal | the data resource | Reads the data **without touching project IAM at all** — a review that only diffs project policies sees nothing. Also the `allUsers` staging path | `flat iam-policy.json \| jq 'select(.type\|test("Bucket\|Dataset\|Topic\|Secret\|CryptoKey"))'` — resource-level bindings live on the resource asset, not the project asset | Deny the specific v2 permissions at the folder. **Audit `bigquery.datasets.update` alongside `bigquery.datasets.setIamPolicy`**: on datasets that have not opted into `enable_fine_grained_dataset_acls_option`, `update` is still the ACL-mutation path |
| **Role-mutate** | `iam.roles.update`, `iam.roles.create`, `iam.roles.undelete` (in `roles/iam.roleAdmin`, `roles/iam.organizationRoleAdmin`) on a custom role the principal — or a group it belongs to — already holds | any principal | the scope where that role is bound | Arbitrary permissions at that scope. **A principal can add permissions to a custom role that the principal does not itself hold.** The binding never changes, only `includedPermissions`, so binding-diff review misses it entirely | Join two sets: principals holding `iam.roles.*` (`flat … \| jq 'select(.role\|test("roleAdmin"))'`) against custom-role bindings (`flat … \| jq 'select(.role\|startswith("projects/") or startswith("organizations/"))'`). Intersect on principal (after group expansion) and check the scopes overlap | Remove `roles/iam.roleAdmin` from anyone who also holds a custom role in scope; deny `iam.googleapis.com/roles.update` org-wide outside a role-governance group; alert on `google.iam.admin.v1.UpdateRole` |
| **Group-write** | **Not an IAM permission.** Workspace-side: the Groups Admin privilege, the Groups Editor role, or `OWNER`/`MANAGER` membership on the group; programmatically `cloudidentity.googleapis.com` `memberships.create` | any principal | the group node | Every role bound to that group, and to every group above it in the nesting, with **no IAM policy change of any kind** | Not in any asset export. Enumerate delegated admins via Admin SDK `roleAssignments` (`users.list?query=isAdmin=true` returns **super** admins only — Groups Admin holders are not in that result), and group `OWNER`/`MANAGER` memberships via the Cloud Identity Groups API | Move the IAM binding off the broad group onto a group whose membership is change-controlled; enable Google Workspace data sharing with Google Cloud so membership changes appear in Admin Activity logs at the org node at all |
| **Guardrail-mutate — org policy** | `orgpolicy.policy.set` (v1 family) and `orgpolicy.policies.create/update/delete` (v2 family) — both real, both in `roles/orgpolicy.policyAdmin`. There is **no** `orgpolicy.policies.get`; the getter is `orgpolicy.policy.get` | any principal | guardrail node at that scope | Turns off the constraint that was blocking the next step (see the two-step chains in §6.2.3) | `flat iam-policy.json \| jq 'select(.role\|test("orgpolicy.policyAdmin\|roles/owner"))'`; effective state per constraint via `gcloud asset analyze-org-policies --constraint=constraints/X --scope=organizations/ORG_ID` | Bind `roles/orgpolicy.policyAdmin` only at the org node, to an identity that deploys nothing; alert on `google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy` / `DeletePolicy`. Deny is available for `orgpolicy.googleapis.com/policies.create/.delete/.list/.update` |
| **Guardrail-mutate — VPC-SC / Access Context Manager** | `accesscontextmanager.servicePerimeters.update/delete/replaceAll/commit`, `accesscontextmanager.accessLevels.update/replaceAll`, `accesscontextmanager.policies.setIamPolicy` (in `roles/accesscontextmanager.policyAdmin`; `policyEditor` is identical minus `policies.setIamPolicy`) | any principal | guardrail node | Widens or deletes the perimeter that the exfil step would otherwise hit. Equivalent to turning the primary exfil control off | `flat iam-policy.json \| jq 'select(.role\|test("accesscontextmanager"))'` — note the permission family is `accesscontextmanager.policies.*`, **not** `accessPolicies.*` | Deny `accesscontextmanager.googleapis.com/servicePerimeters.*` and `accessLevels.*` outside a named perimeter-governance group; alert on `…AccessContextManager.UpdateServicePerimeter` and `UpdateAccessLevel` |
| **Guardrail-mutate — firewall** | `compute.firewallPolicies.update` (hierarchical, org/folder) and the network-firewall-policy equivalents — **these are two different object families, not a rename; collect both** | any principal | guardrail node | Adds a permissive egress rule or deletes a hierarchical deny | `gcloud compute firewall-policies list` (org/folder) and `gcloud compute network-firewall-policies list` (project); effective merge via `gcloud compute networks get-effective-firewalls` (flags: verify against current docs) | Separate the identity that edits firewall policy from the identity that deploys workloads; keep hierarchical policies at the folder |
| **Guardrail-mutate — logging** | `logging.sinks.create/update/delete`, `logging.exclusions.create`, `logging.buckets.update` (in `roles/logging.configWriter`, `roles/logging.admin`) | any principal | guardrail node | Two effects: streams org logs to an **externally owned** destination (a sink destination `PROJECT_ID` can be a project outside the org), and silences the logs that would show the exfil | `gcloud logging sinks list` at **every** scope (org, each folder, each project, billing account) — an org sink is invisible to `--project=X`. Then check each sink's writer identity `serviceAccount:service-NNN@gcp-sa-logging.iam.gserviceaccount.com` for grants in unfamiliar projects | Aggregate at the org node into a project no workload principal can write to; alert on `google.logging.v2.ConfigServiceV2.CreateSink` / `UpdateSink` / `DeleteSink` / `CreateExclusion` |
| **Guardrail-mutate — service enablement** | `serviceusage.services.enable` (in `roles/serviceusage.serviceUsageAdmin`) | any principal | guardrail node | Re-enables an API you disabled as a control (e.g. `iamcredentials.googleapis.com`), or turns on a whole exfil surface (Storage Transfer, BigQuery Data Transfer) | `flat iam-policy.json \| jq 'select(.role\|test("serviceUsageAdmin\|roles/editor\|roles/owner"))'`; current state `gcloud services list --enabled` | **`serviceusage.googleapis.com/services.enable` is NOT in the deny-supported list — do not write a deny rule for it.** Control it with role hygiene and `constraints/gcp.restrictServiceUsage` |
| **Guardrail-mutate — hierarchy move** | `gcloud projects move` (permission string: verify against current docs) | any principal | guardrail node | Moves a project to a folder with weaker inherited org policy and out of its perimeter — one command, sheds the whole inherited control set (ATT&CK T1666) | `gcloud projects get-ancestors PROJECT_ID` per project, diffed against the intended hierarchy | Deny the move permission below the org; alert on project-parent changes |
| **Guardrail-mutate — remove the backstop** | `iam.denypolicies.update/delete` (`roles/iam.denyAdmin`), `iam.principalaccessboundarypolicies.unbind` (`roles/iam.principalAccessBoundaryAdmin` **and** `roles/iam.principalAccessBoundaryUser`), `resourcemanager.{projects,folders,organizations}.deletePolicyBinding` (present in `roles/resourcemanager.projectIamAdmin` / `folderIamAdmin`) | any principal | guardrail node | Deletes the deny rule or unbinds the PAB policy that was the only thing holding the graph closed. **A `projectIamAdmin` can delete a PAB policy binding targeting their own project** — a review that watches only `setIamPolicy` misses this | `flat iam-policy.json \| jq 'select(.role\|test("denyAdmin\|principalAccessBoundary\|IamAdmin"))'` | `iam.googleapis.com/denypolicies.*` is **absent** from the deny-supported list, so you cannot deny-protect deny policies. PAB cannot block `*.deletePolicyBinding` at any enforcement version either. Control both with role hygiene at the org node and real-time alerting — say this explicitly rather than proposing a technical enforcement that does not exist |
| **Read-data** | `storage.objects.get`/`.list`; `bigquery.tables.getData`/`.export`; `pubsub.subscriptions.consume`; `secretmanager.versions.access`; `cloudkms.cryptoKeyVersions.useToDecrypt`; `cloudsql.instances.export`, `spanner.databases.read`, `datastore.entities.get` (last three: verify against current docs) | any principal | data resource | The objective. Label the edge with the resource's classification tier | `flat iam-policy.json \| jq 'select(.type\|test("Bucket\|Dataset\|Table\|Topic\|Secret\|CryptoKey"))'` **plus** every project/folder/org binding of a data role, which applies to every such resource beneath | Bind read roles on the resource, never the project; place the project in an **enforced** perimeter; enable Data Access `DATA_READ` so the read is visible at all |

Three traps that produce silently-wrong graphs:

1. **`iam.serviceAccounts.getIdToken` does not exist.** The permission is `iam.serviceAccounts.getOpenIdToken`; the API method is `generateIdToken`. Do not normalise one into the other — a deny rule or custom role written against `getIdToken` matches nothing.
2. **`iam.googleapis.com/serviceAccounts.*` is not a valid deny permission group.** Only `serviceAccountKeys.*` is. To deny impersonation you must enumerate `serviceAccounts.getAccessToken`, `.getOpenIdToken`, `.signBlob`, `.signJwt`, `.implicitDelegation`, and `.actAs` individually. A deny policy using the wildcard **fails to apply** and the graph stays open while the report claims it is closed.
3. **`roles/iam.serviceAccountTokenCreator` does not grant `actAs`, and `roles/iam.workloadIdentityUser` does not grant `signBlob`/`signJwt`/`implicitDelegation`.** They are different capabilities with different blast radii. Deriving edges from "an impersonation role is bound" rather than from the permission set produces both false positives and false negatives.

#### 6.1.3 Materialise inheritance and group closure before deriving any edge

Do these three normalisations first, or every subsequent count is wrong.

1. **Ancestor materialisation.** A binding at org, folder, or project applies to every descendant. For each asset, build `chain(asset) = [asset_id] + asset.ancestors[]`. A principal holds permission `P` on the asset if any binding granting `P` sits at any node in that chain. In particular, a project-level binding of an impersonation role confers that permission over **every service account in the project**, including the default Compute Engine SA — this is the single most common real escalation and it is invisible if you only read SA-level policies.
2. **Group closure.** Expand every `group:` member transitively, with cycle protection, and keep the group as a node so the path shows the group hop. Do not collapse groups into their members: the group hop is where remediation is cheapest, and the member count is an input to the ranking function.
3. **Custom role expansion.** Resolve every role string to a permission set. Predefined roles from the bundled table; custom roles from the `resource` export (`assetType == "iam.googleapis.com/Role"`, field `resource.data.includedPermissions`); anything left over with `gcloud iam roles describe ROLE --format=json`. **Report the unresolved role list in the appendix** — an unexpanded role is an unbuilt edge class.

#### 6.1.4 Subtract deny, then check PAB, then flag the residue

4. **Deny subtraction.** Deny evaluates before allow and no allow policy anywhere overrides it. For each candidate edge, drop it if a deny policy attached at org, folder, or project **in the target's ancestor chain** denies the v2 form of the permission for that principal, with no matching `exceptionPrincipals` or `exceptionPermissions`. Convert v1→v2 as `SERVICE.RESOURCE.VERB` → `SERVICE.googleapis.com/RESOURCE.VERB`, with `resourcemanager` → `cloudresourcemanager.googleapis.com`. Deny policies attach at **org, folder, and project only** — never on a service account, bucket, or dataset — so a "deny on this SA" recommendation is unimplementable.
5. **Conditional denies.** Denial conditions recognise **only resource tag functions** (`resource.matchTag`, `resource.matchTagId`) — no `request.time`, no `resource.name`, no IP — and they **fail closed**: if the condition evaluates true *or cannot be evaluated*, the rule applies. Since tag values are not in the asset export, keep the edge and mark it `deny-uncertain` rather than deleting a path on an assumption.
6. **PAB check (manual, version-gated).** Principal Access Boundary caps which resources a principal is eligible to touch. Read the `enforcementVersion` of **every** PAB policy: impersonation (`iam.googleapis.com/serviceAccounts.*`, `serviceAccountKeys.*`, `roles.*`) is only blocked at **version ≥ 3**, and federation/OAuth clients only at **≥ 4**. Default for new policies is 4; pinned versions never auto-upgrade. A PAB policy pinned to 1 or 2 provides **zero** protection against any impersonation edge in this graph. PAB cannot block `*.createPolicyBinding` / `*.deletePolicyBinding` / `*.updatePolicyBinding` at any version, so it cannot prevent its own removal.
7. **Conditional allow bindings.** `iam.googleapis.com` is not among the services supporting `resource.service` conditions, so **service accounts do not support conditional role bindings** — a conditional `roles/iam.serviceAccountTokenCreator` grant cannot exist and must never be recommended; the only narrowing is binding on the SA resource. Pub/Sub is likewise unsupported. For services that do support conditions, count the binding as granting and mark the edge `conditional` unless you can evaluate the expression from the evidence.

#### 6.1.5 The reachability computation

```
INPUT   V = nodes, E = labeled edges (after §6.1.3-6.1.4)
        S_a = seed principals for adversary a, for a in A1..A7
OUTPUT  for each a: the fixpoint identity set R_a, and every path to CONFIDENTIAL/NTK data
```

1. **Seed.** One seed set per adversary from the threat model, using its realistic starting position:
   A1 external attacker with a stolen credential; A2 low-privilege insider; A3 compromised CI/CD or
   federated workload; A4 compromised SA / leaked key; A5 compromised on-prem host with cached cloud
   credentials; A6 compromised application workload (SSRF/RCE); A7 supply-chain compromise. Every
   seed must be a node id that exists in the graph — a seed that does not resolve means the evidence
   is incomplete, and that is a finding, not a zero result.
2. **Closure to fixpoint.** `R := S_a`. Repeat: for every `n ∈ R`, for every out-edge `n → m` whose
   kind is not `GUARDRAIL_MUTATE`, add `m` to `R`. Stop when a **full pass adds nothing**. This
   terminates in at most `|V|` passes. Do **not** stop at one hop, and do not stop at a fixed depth:
   A can impersonate B, B can impersonate C, and the chain that matters is usually three to five
   hops long.
3. **Traversal rule for scope nodes.** A `GRANT_SELF` edge lands on a container node (project /
   folder / org). From a container node only `GRANT_IMPLIES` edges may be followed — to every SA
   beneath it and to every classified resource beneath it. This is what makes "project IAM admin" and
   "org IAM admin" expand correctly without hand-enumerating every downstream grant.
4. **Termination condition for a reported path.** A path terminates when it traverses a `READ_DATA`,
   `GRANT_SELF_RESOURCE`, or `GRANT_IMPLIES_READ` edge into a resource whose classification is
   `CONFIDENTIAL`, `NTK`, or `UNCLASSIFIED`. Unclassified stores are terminals, scored as
   CONFIDENTIAL and flagged `assumed` — an unclassified data store is a finding in its own right.
   `INTERNAL` and `PUBLIC` terminals are recorded but not ranked.
5. **Enumerate paths, not endpoints.** Report simple paths (no repeated node), bounded by
   `--max-depth 6` and `--max-paths` per seed. The intermediate hops are the product of this phase:
   the endpoint tells you what was lost, the hops tell you where remediation is cheapest.
6. **Cheapest severing control.** Count, across all reported paths, how many paths contain each edge.
   For a given path the cheapest sever is the edge on it with the highest such count, ties broken
   toward the step nearest the start. **Exclude `MEMBER_OF` edges from cut selection** — removing one
   person from a group severs nothing for the rest of the group, so it is a remediation action but
   never a control. Publish the global `TOP CUTS` list (edge, number of chains it kills) as the input
   to the remediation roadmap.
7. **Re-run after each proposed fix** and show the delta in chain count. A remediation that does not
   reduce the reported chain count did not sever anything.

#### 6.1.6 Native tooling: coverage, and the residual blind spot

| Tool | Exact surface | What it genuinely answers | What it does not cover |
|---|---|---|---|
| **Policy Analyzer for allow policies** | `gcloud asset analyze-iam-policy (--organization\|--folder\|--project) [--identity] [--full-resource-name] [--permissions] [--roles] [--analyze-service-account-impersonation] [--expand-groups] [--expand-resources] [--expand-roles] [--output-group-edges] [--output-resource-edges]` | "Which principals have what access to which resources", with group and role expansion | **Allow policies only.** Documented exclusions: IAM **deny** policies, **PAB** policies, **GKE RBAC**, **Cloud Storage ACLs**, **Cloud Storage public access prevention**. `--analyze-service-account-impersonation` is **one hop, computed backwards from a resource** — it does not close multi-hop chains (A→B→C), `implicitDelegation` chains, or `actAs`-via-workload-attachment. Anything stronger: verify against current docs. `gcloud asset analyze-iam-policy-longrunning` and its BigQuery output flag: verify against current docs |
| **Policy Troubleshooter for IAM** | `gcloud policy-troubleshoot iam [RESOURCE] --permission=PERMISSION --principal-email=EMAIL` | Evaluates **allow + deny + PAB** for one triple. Use it to *prove* a guardrail actually blocks a specific principal-permission-resource combination | A point query. It cannot enumerate and cannot discover an unknown path. (The gcloud reference page describes only allow evaluation and is stale relative to the product page; trust the product page) |
| **Role recommendations (Policy Intelligence)** — recommender ID `google.iam.policy.Recommender`; flag spelling on `gcloud recommender recommendations list`: verify against current docs | Usage-driven least-privilege suggestions over an observed 90-day window | "This role grants more than this principal used" | It is not a threat model. It does not reason about impersonation chains at all, does not evaluate deny or PAB, and will not flag an unused-but-catastrophic grant as an exfil risk beyond "unused". Never present it as chain analysis |
| **Cloud Asset Inventory** | `gcloud asset export --content-type=` (spelling: see §4.2.1); `gcloud asset search-all-resources`, `gcloud asset search-all-iam-policies` | The graph source: assets, ancestors, allow bindings, org policies, ACM policies | Deny policies (`gcloud iam policies list --kind=denypolicies`), PAB policies and bindings (`gcloud iam principal-access-boundary-policies`, `gcloud iam policy-bindings`), Workspace group membership, GKE RBAC objects, Cloud Build trigger contents, and any credential material on disk |

**Residual blind spot — state this list verbatim in the report appendix.** No GCP-native tool closes
these; they exist only because this phase builds the graph by hand:

- transitive impersonation chains of depth ≥ 2, including `implicitDelegation` delegation chains;
- `actAs` pairs (the permission and the deploy permission are in different policies and no native tool joins them);
- Workspace group nesting, and who can change group membership;
- custom-role mutation as an escalation (Policy Analyzer reads the role's current contents, not who can rewrite them);
- resource-level bindings outside the export scope, which is where impersonation and data grants hide;
- KSA→GSA mappings and GKE RBAC, which live in the cluster and not in any IAM policy;
- cached credentials on on-prem hosts and CI runners.

### 6.2 Escalation primitive hunt list

For every primitive below, state in the report whether it **exists in this environment**, via which
principal, and on which resource. "Not observed" is an acceptable answer only if the query was run;
record the query and its result.

#### 6.2.1 Direct identity assumption

| Primitive | Permission(s) / role(s) | Preconditions | Yields | Test in this environment | Sever | Logged? |
|---|---|---|---|---|---|---|
| **Project-level tokenCreator/serviceAccountUser trap** | `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` bound at the **project** node rather than on a service account | none beyond holding the binding | Impersonation of **every SA in the project**, present and future, including the default Compute Engine SA (which carries `roles/editor` unless `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` is enforced) | `flat iam-policy.json \| jq 'select(.type=="cloudresourcemanager.googleapis.com/Project" and (.role\|test("serviceAccountTokenCreator\|serviceAccountUser")))'` — every hit is a finding | Delete the project binding; re-bind on each specific SA the workload actually needs (the role's lowest grantable level is Service Account). Conditions cannot narrow it: `iam.googleapis.com` does not support IAM Conditions | `GenerateAccessToken` — **Data Access, OFF by default** |
| **Chained impersonation to fixpoint** | any composition of the five impersonation permissions | A→B and B→C bindings exist independently | C's credentials from A's starting position; each individual binding looks defensible | The §6.1.5 closure. Do not answer this with a one-hop query | Cut the highest-frequency intermediate edge from `TOP CUTS`, not the endpoint | Each hop logs separately (Data Access, off by default); nothing correlates them |
| **`signJwt` / `signBlob` self-signing** | `iam.serviceAccounts.signJwt`, `iam.serviceAccounts.signBlob` (in `roles/iam.serviceAccountTokenCreator`; **absent** from `roles/iam.workloadIdentityUser`) | binding on the target SA | A signed JWT exchanged for an access token at the OAuth token endpoint, so **`GenerateAccessToken` is never called** — every alert and deny rule keyed on `getAccessToken` alone is blind to it | Grep custom roles too: `roles resource.json \| jq 'select(.perms[]\|test("signJwt\|signBlob"))'` | Deny `iam.googleapis.com/serviceAccounts.signJwt` and `.signBlob` explicitly. Signed-URL abuse rides the same permission — denying `signBlob` is also the signed-URL control | `SignJwt` / `SignBlob` (bare method names, `serviceName="iamcredentials.googleapis.com"`) — **Data Access, OFF by default**; these are LROs, so one call yields two entries and naive alert counting double-counts |
| **`implicitDelegation`** | `iam.serviceAccounts.implicitDelegation` | a chain of ≥ 2 SAs each granting it | A token for the end of the chain with no direct grant on it; consumed through `delegates[]` on `GenerateAccessToken` | It has no API method of its own — derive it from the binding graph, then confirm with the closure | Deny `iam.googleapis.com/serviceAccounts.implicitDelegation` at the folder; near-zero legitimate use | Appears as `GenerateAccessToken` with a delegation chain — Data Access, off by default |
| **Service-account impersonation as attribution laundering** | any of the five | — | The data-plane audit entry shows `principalEmail = <service account>`. The human or workload only appears in `protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail`, **and only if Data Access logs are on** | Sample one impersonation event in the logs and confirm the delegation field is populated | Prefer direct resource access for federated principals over impersonation, so the federated subject stays in the log of the actual data operation | see above |

#### 6.2.2 Deploy-as (`actAs`) surfaces

The escalation is identical for every row: create or modify a workload that runs as a more privileged
SA, then read that SA's token from the metadata server. Confirm the pair — `actAs` **and** the
create/update permission — before recording an edge.

Metadata server facts to use when writing the step: the token is at
`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with the
header `Metadata-Flavor: Google`, and **metadata traffic bypasses VPC firewall rules** — there is no
network control for it on plain Compute Engine. The full endpoint set, the IPv6 form, the scope×IAM
interaction, and the three mitigations that do work are tabulated once in §7.1.1.

| Surface | Permission pair | Preconditions | Yields | Test | Sever | Logged? |
|---|---|---|---|---|---|---|
| **GCE instance create** | `iam.serviceAccounts.actAs` + `compute.instances.create` (spelling: verify against current docs) | target SA attachable in the project; cross-project attach possible unless `constraints/iam.disableCrossProjectServiceAccountUsage` is enforced | Root on a VM running as the SA | Join the two halves per §6.1.2; list attached SAs from the `resource` export (`compute.googleapis.com/Instance`, `resource.data.serviceAccounts[].email`) | Enforce `constraints/iam.disableCrossProjectServiceAccountUsage`; bind `roles/iam.serviceAccountUser` per SA | Instance-create call in Admin Activity; **no `iamcredentials` entry for the token read** |
| **`setMetadata` on an existing privileged VM** | `compute.instances.setMetadata` (in `roles/compute.admin`, `roles/compute.instanceAdmin.v1`) | the VM already runs as the privileged SA | SSH key or `startup-script` injection → shell → the VM's token. Google's own framing: metadata permissions are "the equivalent of providing access to the core content on an instance" | Enumerate holders of `compute.instances.setMetadata` against the VM inventory and each VM's attached SA. Also check `enable-oslogin`: setting it to `FALSE` in **instance** metadata disables OS Login **even when project metadata sets it TRUE** | Enforce `constraints/compute.managed.requireOsLogin` (blocks the per-instance opt-out) and `constraints/compute.managed.disableSerialPortAccess`; separate `roles/compute.instanceAdmin.v1` from the SA the VM runs as | Admin Activity (method name: verify against current docs) |
| **Project-wide SSH key injection** | `compute.projects.setCommonInstanceMetadata` (in `roles/compute.admin`) | — | Root on **every VM in the project**, therefore every SA attached to any of them | Holders of that permission at any scope in the project's chain | Same as above; this permission should exist on no standing human identity | Admin Activity |
| **Serial console** | `compute.instances.setMetadata` or `compute.projects.setCommonInstanceMetadata` to set `serial-port-enable=TRUE`, plus `roles/iam.serviceAccountUser` | — | Interactive console that **does not support IP-based access restrictions** — bypasses VPC firewall rules, authorized networks, and private clusters entirely; endpoint `REGION-ssh-serialport.googleapis.com:9600` | Check the metadata key on every VM and the org policy state | `constraints/compute.managed.disableSerialPortAccess` (blocks `serial-port-enable=true`) plus `constraints/compute.managed.disableSerialPortLogging` posture | Admin Activity for the metadata change |
| **Cloud Run / Cloud Run functions deploy** | `iam.serviceAccounts.actAs` + the deploy permission (`run.services.create`/`update`, `cloudfunctions.functions.create`/`update` — spellings: verify against current docs) | — | Code running as the runtime SA. **If `--service-account` was never set, Cloud Run and Cloud Run functions (2nd gen) run as the Compute Engine default SA; 1st gen runs as the App Engine default SA** | From the `resource` export, list every service and its runtime SA; flag every one still on a default SA | One dedicated SA per service; enforce `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` so defaults never carry `roles/editor` | Deploy call in Admin Activity |
| **Cloud Build triggers** | modify build config, or push to the triggering branch, + `actAs` on the build SA | trigger exists | The build's identity. **Current default (2026): builds run as the Compute Engine default service account**, not the legacy `PROJECT_NUMBER@cloudbuild.gserviceaccount.com`. The over-privilege moved, it did not go away | The right check is **"which SA does the build run as, and does that SA have Editor"** — not "does the Cloud Build SA have `roles/cloudbuild.builds.builder`". Enumerate triggers, their SA, and who can push to the triggering ref | Set a user-specified build SA per trigger; control the defaults with `constraints/cloudbuild.useBuildServiceAccount` and `constraints/cloudbuild.useComputeServiceAccount` | Build create in Admin Activity; the token read inside the build is invisible |
| **Composer / Dataflow / Dataproc / Vertex AI Workbench / Cloud Scheduler / Cloud Tasks / Deployment Manager** | `actAs` + the service's create permission | — | Attacker-controlled code with the attached SA. A Dataflow job in particular is arbitrary code with a worker SA that can read any source that SA can reach and write to any sink | List every environment/job/instance and its SA from the `resource` export; flag any running as a default SA or as an SA shared with another service | Dedicated SA per workload; keep worker VMs internal-only and enforce `constraints/compute.vmExternalIpAccess` | Create call in Admin Activity |
| **GKE pod creation** | Kubernetes RBAC `create` on `pods` in the namespace, or IAM `roles/container.developer` / `roles/container.admin` / `roles/container.clusterAdmin` | either (a) the namespace's KSA maps to a privileged GSA, or (b) the cluster/node pool has Workload Identity **off** | (a) the mapped GSA's credentials; (b) with `--workload-metadata=GCE_METADATA`, any pod curls `169.254.169.254` and reads the **node SA token** plus `kube-env` (kubelet bootstrap credentials). If the node pool runs on the Compute Engine default SA with `roles/editor`, that is project-wide compromise from one container | Per cluster: `--workload-pool` on the cluster **and** `--workload-metadata=GKE_METADATA` on **every node pool** (the GKE metadata server only intercepts on `GKE_METADATA` pools); node `--service-account`; RBAC bindings reaching `cluster-admin`; NetworkPolicy presence | Workload Identity Federation for GKE on every node pool, a custom node SA (never the Compute default), and a PodSecurity/Policy Controller rule forbidding `hostNetwork` — **`hostNetwork: true` pods bypass the GKE metadata server even with Workload Identity on**. Metadata concealment is deprecated and incompatible with Workload Identity; do not recommend it | Pod create is a Kubernetes audit event, not Cloud Audit Logs IAM; GKE evaluates **RBAC first, then IAM**, so auditing one without the other is incomplete |

Access scopes are a coarse legacy backstop, not a control, but they broaden or narrow what a stolen
metadata token can do: a request succeeds only if the **scope permits it and IAM permits it**. gcloud
aliases: `default`, `cloud-platform`, `compute-ro`, `compute-rw`, `storage-ro`, `storage-rw`,
`storage-full`, `bigquery`, `datastore`, `sql-admin`, `logging-write`, `monitoring`,
`monitoring-read`, `monitoring-write`, `userinfo-email`, `useraccounts-ro`, `useraccounts-rw`,
`taskqueue` — recognised **only by the gcloud CLI**; the API requires full scope URIs. The `default`
set expands to `devstorage.read_only`, `logging.write`, `monitoring.write`,
`service.management.readonly`, `trace.append`. Note the trap: a **Standard GKE cluster using a custom
node service account with no manual scopes gets `cloud-platform`** — so all restriction must come
from IAM on that SA, not from scopes. Current guidance is a dedicated SA plus least-privilege IAM,
**not** narrow legacy scopes; do not present scope-narrowing as the primary fix.

#### 6.2.3 Policy manipulation

| Primitive | Permission(s) | Preconditions | Yields | Test | Sever | Logged? |
|---|---|---|---|---|---|---|
| `setIamPolicy` at org / folder / project | `resourcemanager.{organizations,folders,projects}.setIamPolicy` | — | Any role on anything beneath, including impersonation of every SA and read on every dataset under it | §6.1.2 query; also check `roles/iam.securityAdmin` (≈2850 permissions, ~310 distinct `*.setIamPolicy`) and basic `roles/owner` | Deny `cloudresourcemanager.googleapis.com/{organizations,folders,projects}.setIamPolicy` above the node that legitimately needs it | `cloudresourcemanager.v3.{projects,folders,organizations}.setIamPolicy` — **Admin Activity, always on, cannot be disabled** |
| **Resource-level `setIamPolicy` — reaches data without touching project IAM** | `storage.buckets.setIamPolicy`, `bigquery.datasets.setIamPolicy`, **`bigquery.datasets.update`**, `cloudkms.cryptoKeys.setIamPolicy`, `secretmanager.secrets.setIamPolicy`, `pubsub.subscriptions.setIamPolicy`, … | binding on the resource or any ancestor | Grant self — or `allUsers` — read on the data. **The project's IAM policy never changes**, so project-policy diffing and most drift detection see nothing | Query resource-asset bindings specifically; do not infer them from project policies | Deny the specific v2 permissions at the folder; enforce `constraints/storage.publicAccessPrevention` and `constraints/iam.managed.allowedPolicyMembers` so the `allUsers` variant fails even if the permission is held | `storage.setIamPermissions` for buckets — Admin Activity. BigQuery/KMS/Secret Manager equivalents: verify method names against current docs |
| **`iam.serviceAccounts.setIamPolicy`** | as named (in `roles/iam.serviceAccountAdmin`, `roles/iam.securityAdmin`) | — | Self-grant TokenCreator on any SA, then impersonate — no impersonation role needed up front | §6.1.2 | Deny `iam.googleapis.com/serviceAccounts.setIamPolicy` | `google.iam.admin.v1.SetIAMPolicy` — note the **capital `IAM`**, unlike every other service. Admin Activity |
| **Custom-role mutation** | `iam.roles.update` (also `.create`, and `.undelete` as a persistence primitive that restores a previously-removed over-privileged role) | the principal, or a group it is in, already holds the custom role | Arbitrary permissions at the scope where the role is bound. **A principal can add permissions to a role that the principal does not hold.** Only `includedPermissions` changes | Intersect `iam.roles.*` holders with custom-role holders after group expansion | Deny `iam.googleapis.com/roles.update` and `.create` outside a role-governance group. Note `roles/iam.securityAdmin` does **not** contain `iam.roles.create/update` — this is a different detection signature from self-granting | `google.iam.admin.v1.UpdateRole` / `CreateRole` — Admin Activity, always on. Stealthy against **config-diff review**, not against the audit log: if nothing alerts on `UpdateRole`, it is undetected in practice |
| **Access-level / perimeter widening, then exfil** | `accesscontextmanager.accessLevels.update`, `…servicePerimeters.update` | ACM write at the access-policy scope | Adds the attacker's IP/device to an access level, or adds an ingress rule with `identityType: ANY_IDENTITY` and `sources[].accessLevel: "*"` — the combination that fully negates a perimeter | Diff the perimeter and access-level definitions against the intended design; collect **dry-run** config too (`gcloud access-context-manager perimeters dry-run list`) — a dry-run perimeter enforces nothing | Deny the ACM write permissions outside a perimeter-governance group; require dual control for perimeter changes | `…AccessContextManager.UpdateAccessLevel` / `UpdateServicePerimeter` — Admin Activity |

**Two-step chains where each step alone looks benign.** Model these explicitly; a reviewer looking at
either step in isolation will accept it.

*Worked chain `AP-11f-1` — key-creation constraint flip, then key mint:*

| # | Actor | Action | Exact permission / constraint | Why it looks benign alone | Log |
|---|---|---|---|---|---|
| 1 | holder of `roles/orgpolicy.policyAdmin` (or `roles/owner` at org) | Set `constraints/iam.managed.disableServiceAccountKeyCreation` to not-enforced at project `PROJECT` (or add a tag-conditioned exception rule) | `orgpolicy.policy.set` / `orgpolicy.policies.update` | Reads as a routine exception for a legacy integration | `google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy` — Admin Activity |
| 2 | any holder of `iam.serviceAccountKeys.create` on a data-reading SA | Mint a user-managed key | `iam.serviceAccountKeys.create` | Reads as normal CI onboarding | `google.iam.admin.v1.CreateServiceAccountKey` — Admin Activity |
| 3 | attacker, offline | Use the key from anywhere, indefinitely | — | — | **Nothing.** Key use is indistinguishable from legitimate use |

Sever: enforce the constraint at the **org** node (not per project), add the org deny group
`iam.googleapis.com/serviceAccountKeys.*`, and alert on step 1 and step 2 **as a correlated pair
within a time window** — either alone is normal traffic. Note the graph consequence: an enforced
key-creation constraint suppresses the key-mint edge only for principals who cannot also flip the
policy; for those who can, the edge stays and is labeled two-step.

*Worked chain `AP-11f-2` — domain-restriction flip, then external grant:*

| # | Actor | Action | Exact permission / constraint | Why it looks benign alone | Log |
|---|---|---|---|---|---|
| 1 | holder of `roles/orgpolicy.policyAdmin` | Remove or narrow `constraints/iam.managed.allowedPolicyMembers` (or the legacy `constraints/iam.allowedPolicyMemberDomains`) at a folder | `orgpolicy.policy.set` | Reads as enabling a partner integration | `…OrgPolicy.UpdatePolicy` — Admin Activity |
| 2 | holder of `bigquery.datasets.setIamPolicy` **or** `bigquery.datasets.update` on the CONFIDENTIAL dataset | Add an external principal (or `allAuthenticatedUsers`) as a reader | resource-level permission only — **the project IAM policy never changes** | Reads as a normal dataset share | BigQuery dataset ACL change (method name: verify against current docs) |
| 3 | external principal | Read in place; or subscribe to a BigQuery sharing listing, which hands over a whole dataset **with no data movement to detect** | — | — | Data Access, **off by default** |

Sever: enforce the domain constraint at the **org** node — note that for organizations created on or
after 2024-05-03 `constraints/iam.allowedPolicyMemberDomains` is enforced by default with your own domain as the
only allowed value, so if it is *unset* here somebody removed it — and deny
`bigquery.googleapis.com/datasets.setIamPolicy` **and** `datasets.update` at the folder holding
CONFIDENTIAL datasets.

Two further two-step shapes to enumerate the same way: (a) flip
`constraints/storage.publicAccessPrevention` off, then `storage.buckets.setIamPolicy` granting
`allUsers` `roles/storage.objectViewer` — public staging; (b) flip
`constraints/gcp.resourceLocations`, then create the exfil destination in a region nobody monitors
(ATT&CK T1535). And note the meta-problem for all of them: an org policy can carry a
**tag-conditioned rule**, and whoever can set that tag value can grant themselves the exception —
"the constraint is enforced" is therefore not a sufficient finding. Resolve: is there a conditional
rule, who can write the tag key/value, and is the policy re-set at a lower node without
`inheritFromParent`?

#### 6.2.4 Credential access

| Primitive | What to check | Yields | Test | Sever | Logged? |
|---|---|---|---|---|---|
| **SA keys** | existence, age, and location of every **user-managed** key | Durable offline credential; unaffected by session controls, MFA, and device policy | `gcloud iam service-accounts keys list --iam-account=SA --managed-by=user --created-before=TIMESTAMP` for every SA. `--managed-by=system` keys are Google-rotated and cannot be exfiltrated — do not report them as findings | `constraints/iam.managed.disableServiceAccountKeyCreation` at the org (covers HMAC keys too); `constraints/iam.disableServiceAccountKeyUpload` for BYO public keys; org deny group `iam.googleapis.com/serviceAccountKeys.*` | `CreateServiceAccountKey` and **`UploadServiceAccountKey`** — both Admin Activity. Use of the key is not logged as key use |
| **Key material on on-prem hosts and in CI** | jump boxes, `~/.config/gcloud/` (including `credentials.db`), `application_default_credentials.json`, config-management systems, the artifact store, self-hosted runner working directories | The soft-interior assumption means one interior foothold reaches all of them | Interview + file inventory; this is not in any cloud export | Replace every on-prem key with Workload Identity Federation or, where the interior cannot reach an IdP Google can validate, a short-lived credential broker; then delete the keys and set the org constraint so they cannot come back | Nothing on the host side |
| **Metadata server from a workload** | which workloads can reach `169.254.169.254` / `metadata.google.internal`, and via SSRF in an application that fetches URLs | The attached SA's OAuth token, its ID token, and the SA's scope list | Per VM: attached SA and scopes from the `resource` export. Per GKE cluster: `--workload-pool` set, and `--workload-metadata=GKE_METADATA` on **every** node pool. Confirm no `hostNetwork: true` workloads | Workload Identity Federation for GKE; a NetworkPolicy blocking `169.254.169.254` for pods that do not need cloud access; a dedicated low-privilege SA per workload. **There is no VPC firewall control for metadata traffic on plain Compute Engine** — say so rather than proposing a firewall rule | Nothing. The token read is local |
| **Secret Manager over-broad bindings** | who holds `secretmanager.versions.access` at project or folder scope rather than per secret | The secrets themselves, which usually include credentials to systems outside GCP | `flat iam-policy.json \| jq 'select(.role\|test("secretAccessor\|secretmanager.admin"))'` and check the scope in each hit | Bind `roles/secretmanager.secretAccessor` on the individual secret; deny `secretmanager.googleapis.com/secrets.setIamPolicy` at the folder | Data Access (`ADMIN_READ`/`DATA_READ`) — **off by default** |
| **Terraform / IaC state** | which bucket holds state, **who can read it**, whether state is encrypted with a CMEK the workload identity cannot use | State files routinely contain plaintext secrets, including generated passwords and, historically, SA keys | Identify the state bucket, then `flat iam-policy.json \| jq 'select(.scope=="//storage.googleapis.com/STATE_BUCKET")'`; also check project- and folder-level `roles/storage.admin` / `roles/viewer` holders who inherit read | Put state in the bootstrap/seed project, bind read to the pipeline SA only, enable object versioning, and treat every state-bucket reader as a tier-0 principal in the graph | Data Access on the bucket — off by default |
| **Build logs and environment variables** | build log destinations, and env vars on Cloud Run / functions / Composer holding credentials | Credentials in a place with far weaker access control than Secret Manager | Read the deploy manifests in the `resource` export and the IaC; check who can read the build log bucket | Reference secrets by Secret Manager version rather than injecting values; restrict build log access | Log reads are Data Access |
| **HMAC keys** | Cloud Storage HMAC keys | An S3-compatible long-lived credential that most reviews never look at | `storage.hmacKeys.create` holders; existing keys per project | `constraints/iam.managed.disableServiceAccountKeyCreation` covers HMAC key creation; deny `storage.googleapis.com/hmacKeys.create` | `storage.hmacKeys.create` — Admin Activity |
| **Signed URLs** | who holds `iam.serviceAccounts.signBlob` | A bearer credential embedded in a URL — whoever holds it reads the object from anywhere, with **no Google identity**. VPC-SC ingress/egress rules cannot express it: `ANY_SERVICE_ACCOUNT`/`ANY_USER_ACCOUNT` identity types do not apply to signed-URL operations | Holders of `signBlob` anywhere in the chain of a bucket holding CONFIDENTIAL data | `constraints/storage.restrictAuthTypes`, short TTLs, and denying `iam.googleapis.com/serviceAccounts.signBlob` | `SignBlob` — Data Access, off by default |

#### 6.2.5 Defense evasion accompanying escalation

Score an undetected path more severely than a detected one, and check these before concluding that
any step "would be caught".

| Primitive | Permission(s) | Effect | Test | Sever |
|---|---|---|---|---|
| Disable Data Access logs | `resourcemanager.{projects,folders,organizations}.setIamPolicy` (the `auditConfigs` block lives in the IAM policy) | Turns off exactly the logs that record impersonation and data reads | Read `auditConfigs` at org, folder, and project. Enum values are `ADMIN_READ`, `DATA_READ`, `DATA_WRITE` (there is no `ADMIN_WRITE`); wildcard service is `allServices` | Set `auditConfigs` at the **org** node so a project-level admin cannot quietly undo it; alert on `SetIamPolicy` calls whose request touches `auditConfigs` |
| **`exemptedMembers`** | same | A principal listed there generates **no Data Access log at all** while everything else looks correctly configured | Any non-empty `exemptedMembers` anywhere is a finding | Empty it; if an exemption is genuinely needed for log volume, exempt a read-only monitoring identity, never a workload identity |
| Sink deletion / modification / exclusion | `logging.sinks.delete`, `.update`, `logging.exclusions.create` | Stops export, or drops the attacker's own calls at ingest | `gcloud logging sinks list` at every scope; read every exclusion filter | Aggregated org sink into a project workload principals cannot write to; alert on `google.logging.v2.ConfigServiceV2.DeleteSink` / `UpdateSink` / `CreateExclusion` |
| Retention shortening | `logging.buckets.update` | Data Access and Policy Denied logs route to `_Default` with **30-day** default retention; `_Required` (Admin Activity, System Event, Access Transparency) is **400 days and non-configurable**. So the exfil-relevant logs are the short-lived ones, and every VPC-SC violation record expires in 30 days unless routed elsewhere | Read each log bucket's retention; confirm Policy Denied logs are routed to a long-retention bucket | Route `_Default` to a retention-locked bucket in the logging project |
| Log deletion | `logging.logs.delete` | Removes entries wholesale | Holders of `roles/logging.admin` | Keep `roles/logging.admin` off workload and deploy identities; alert on `google.logging.v2.LoggingServiceV2.DeleteLog` |
| Creating resources outside the monitored scope | project create / `gcloud projects move` | Resources in an unmonitored project or an unmonitored region (ATT&CK T1535, T1666) never appear in the review's scope at all | Reconcile the project inventory against the sink scope and the perimeter membership list; `gcloud projects get-ancestors` per project | `constraints/gcp.resourceLocations`; org-level aggregated sink with `includeChildren`; alert on project-parent changes |

**Detection posture facts that change the score of nearly every chain:** impersonation
(`GenerateAccessToken`, `GenerateIdToken`, `SignJwt`, `SignBlob`), STS token exchange
(`google.identity.sts.v1.SecurityTokenService.ExchangeToken`), and object/table reads are all **Data
Access logs, which are OFF by default** for every service except BigQuery. `SetIamPolicy`, key
creation, custom-role mutation, org-policy changes, perimeter changes, and sink changes are **Admin
Activity, always on**. Therefore the common shape "escalate quietly, then read data quietly" is
invisible end-to-end in a default configuration, while the noisy steps are the ones an attacker can
often avoid. Enabling `ADMIN_READ` + `DATA_READ` on `iam.googleapis.com`, `iamcredentials.googleapis.com`
and `sts.googleapis.com` at the org node is the single highest-value detection change this phase
produces — state the log-volume cost when recommending it.

### 6.3 Chain output format and ranking

#### 6.3.1 Emission format

Emit every discovered chain in exactly this shape. Field names are fixed so two reviewers produce
comparable output and so the JSON from the helper script maps one-to-one onto the report.

**This shape is a working-note artifact, not a report section.** The report renders chains in the
§11.3.1 shape, with the band assigned by §11.1. The two shapes carry the same steps; only this one
carries the rank score, and only §11.3.1 carries a severity band.

```
CH-nn
  rank score:       <number>  - ORDERING ONLY. The band comes from 11.1; never write a band here.
  adversary:        <A1..A7 label from the threat model>
  starting position:<exact principal string>
  terminates at:    <CONFIDENTIAL|NTK|UNCLASSIFIED(assumed CONFIDENTIAL)> in <resource full name>
  executors today:  <N concrete principals, after group expansion>
  ATT&CK:           <technique IDs in order of the steps>

  step | actor (exact principal) | action | exact permission | detectable today?
  -----+------------------------+--------+------------------+------------------
   1   | ...                    | ...    | ...              | <log type + method name, or NOT LOGGED>
   ...

  CHEAPEST SEVER (step K): <the single control change, named exactly>
  RESIDUAL after that sever: <what the adversary can still reach>
```

Rules for the table cells:

- **actor** is the verbatim IAM member string, never a description.
- **action** names the API operation, not an intention ("attach `etl-writer@` to a new e2-micro in `us-central1`", not "escalates privileges").
- **exact permission** is the v1 permission string. Where the step is an `actAs` pair, write both permissions joined by `+`.
- **detectable today** is one of: the exact `protoPayload.methodName` plus its log type and whether that log type is currently enabled in this environment; or `NOT LOGGED`. Never write "should be logged".
- **CHEAPEST SEVER** is one control change, chosen by the §6.1.5 rule, written as the exact binding to remove or the exact constraint/deny rule to add.
- **RESIDUAL** is mandatory: it is what stops a roadmap from claiming a chain is closed when the endpoint is still reachable by another route.

#### 6.3.2 Ranking function

Rank by **data tier reached × ease of starting position × number of principals who can run it**, with
a detection multiplier. **Do not rank by hop count** — a 5-hop chain that 400 people can start
outranks a 2-hop chain that one break-glass admin can start.

`SCORE = T × E × P × D`

| Factor | Value | Definition |
|---|---|---|
| **T** — tier reached | 5 | `CONFIDENTIAL` — the priority target: broad internal reach maximises attack surface |
| | 5 | `UNCLASSIFIED` — scored as CONFIDENTIAL, flagged `assumed`, and raised separately as an unclassified-store finding |
| | 4 | `NTK` — tighter perimeter, fewer principals, smaller volume |
| | 2 | `INTERNAL` |
| | 0 | `PUBLIC` — drop the chain |
| **E** — ease of the starting position | 5 | No credential required: `allUsers`/`allAuthenticatedUsers`, an unauthenticated endpoint, or a federated `principalSet://…/*` on a shared multi-tenant issuer with an empty or vacuous `attributeCondition` |
| | 4 | Any single credential from a large population: a member of an all-staff group, any pod in a cluster without Workload Identity, any host on the flat on-prem interior |
| | 3 | A specific named low-privilege human or SA credential; a CI job in one specific repo |
| | 2 | Requires an existing privileged admin credential |
| | 1 | Requires super-admin or break-glass |
| **P** — principals who can execute the first privilege-bearing step (group-expanded; `MEMBER_OF` hops are not privilege steps) | 5 | ≥ 100 |
| | 4 | 25–99 |
| | 3 | 6–24 |
| | 2 | 2–5 |
| | 1 | exactly 1 |
| **D** — detection | 1.5 | At least one step produces **no log today** (Data Access off, or the step produces no event at all) |
| | 1.25 | Every step is logged, but the chain includes a `DEPLOY_AS` step whose token read leaves no `iamcredentials` record |
| | 1.0 | Every step is logged **and an alert exists** on it today |

**This score has no bands.** It exists only to order chains against one another: §11.1.5 assigns the
band and §11.1.8 does the arithmetic. Two chains with the same rank score may legitimately carry
different bands, and a chain's rank position says nothing about its band. Ties in the *ordering* break
by: fewer hops first, then lexicographically by starting principal, then by terminal resource — so the
ordering is total and two reviewers produce the identical list.

Two hand-offs bind this function to the rest of the skill. Get them wrong and two sections of the
report disagree about the same chain:

- **Detection.** `D` here is the *ranking* multiplier and nothing else. The band a `CH-` finding
  carries in the report comes from §11.1, whose `D` is the binary `DETECTED` / `UNDETECTED` test.
  Compute both: this score orders the chains, §11.1 assigns the band. Apply the retention modifier
  in §4.7.5 before either — a step whose only record expires in 30 days counts as unlogged.
- **Ease.** `E` here and `S` in §11.1.3 are the same judgement on two scales: `S0`→`E`=5, `S1`→`E`=4
  (or 3 where the credential is one named low-privilege account rather than a population),
  `S2`→`E`=2, `S3`→`E`=1. Never rate them independently.

#### 6.3.3 Worked example

> **EXAMPLE — fictional resource names, shown only to fix the output shape. Do not carry these names
> into a real report. Chain IDs (`CH-nn`) and finding IDs shown inside this example are illustrative
> placeholders, not cross-references; real ones are assigned at review time.**

```
CH-01
  rank score:       60.0   (ordering only; this chain's band is assigned in 11.3.2 by 11.1)
  adversary:        A2 — low-privilege insider
  starting position:user:alice@example.com
  terminates at:    CONFIDENTIAL in //bigquery.googleapis.com/projects/acme-data-prod-01/datasets/customer_pii
  executors today:  2 concrete principals (group:eng-all@example.com, expanded, excluding nested group objects)
  ATT&CK:           T1078.004 -> T1548.005 -> T1213.006 -> T1537

  step | actor                                                  | action                                                                          | exact permission                                                                                                                                        | detectable today?
  -----+--------------------------------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------
   1   | user:alice@example.com                                 | is a member of eng-all@ (directly; erin@ inherits via nested eng-data@)          | none - Workspace-managed group membership, not IAM                                                                                                       | NOT LOGGED (Workspace data sharing with Google Cloud is off; membership changes appear only in Workspace audit)
   2   | group:eng-all@example.com                              | generateAccessToken on etl-writer@acme-data-prod-01.iam.gserviceaccount.com      | iam.serviceAccounts.getAccessToken, .getOpenIdToken, .signBlob, .signJwt, .implicitDelegation (roles/iam.serviceAccountTokenCreator bound at projects/123)| NOT LOGGED - GenerateAccessToken is DATA_ACCESS/ADMIN_READ, off by default on iamcredentials.googleapis.com
   3   | serviceAccount:etl-writer@acme-data-prod-01.iam.gserviceaccount.com | read and export the dataset                                        | bigquery.tables.getData, bigquery.tables.export (roles/bigquery.dataViewer bound on the dataset)                                                          | NOT LOGGED - BigQuery Data Access logs are on by default for BigQuery, but DATA_READ is exempted for this SA via auditConfigs.exemptedMembers

  CHEAPEST SEVER (step 2): delete the project-level binding of roles/iam.serviceAccountTokenCreator to
    group:eng-all@ at projects/123 and re-bind it on the two service accounts the CI job actually needs,
    ON THE SERVICE ACCOUNT RESOURCE (service accounts do not support IAM Conditions, so this is the only
    narrowing available); then add an org IAM Deny enumerating iam.googleapis.com/serviceAccounts.getAccessToken,
    .getOpenIdToken, .signBlob, .signJwt, .implicitDelegation with exceptionPrincipals
    principalSet://goog/group/grp-ci-deploy@example.com.
    This edge appears in 3 reported chains; removing it kills all 3.
  RESIDUAL after that sever: user:carol@example.com still reaches the same dataset via ROLE_MUTATE
    (iam.roles.update on projects/acme-data-prod-01/roles/customEtl, which she already holds) -> see CH-04.
```

Terraform for the sever step, for the report's remediation block:

```hcl
# 1. the binding that should never have been at project scope is deleted (removed from IaC),
#    and re-created on the specific service account:
resource "google_service_account_iam_member" "ci_impersonates_etl_writer" {
  service_account_id = google_service_account.etl_writer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "group:grp-ci-deploy@example.com"
}

# 2. the un-overridable backstop, attached at the org so a project owner cannot undo it.
#    NOTE: iam.googleapis.com/serviceAccounts.* is NOT a valid deny permission group -
#    the five permissions must be enumerated individually or the policy silently fails to cover them.
resource "google_iam_deny_policy" "no_broad_impersonation" {
  parent = urlencode("cloudresourcemanager.googleapis.com/organizations/123456789")
  name   = "deny-broad-impersonation"
  rules {
    description = "Impersonation only from the CI deploy group"
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = ["principalSet://goog/group/grp-ci-deploy@example.com"]
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.getOpenIdToken",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt",
        "iam.googleapis.com/serviceAccounts.implicitDelegation",
      ]
    }
  }
}
```

```bash
# make step 2 and step 3 visible at all - without this the chain is undetectable end to end
gcloud projects get-iam-policy ORG_OR_PROJECT --format=json > /tmp/policy.json
# add to auditConfigs, then:
#   { "service": "iam.googleapis.com",
#     "auditLogConfigs": [ {"logType":"ADMIN_READ"}, {"logType":"DATA_READ"} ] }
# and remove every entry from exemptedMembers.
gcloud projects set-iam-policy ORG_OR_PROJECT /tmp/policy.json
```

### 6.4 Escalation-primitive reference table

One row per permission: what holding it grants, and the exact severing control. Deny rules require
the **v2 format** `SERVICE_FQDN/RESOURCE.ACTION`; Resource Manager's FQDN is
`cloudresourcemanager.googleapis.com`, not `resourcemanager.googleapis.com`. Deny policies attach
only at organization, folder, and project.

| Permission (v1) | Deny form (v2) | What holding it grants | How to sever |
|---|---|---|---|
| `iam.serviceAccounts.getAccessToken` | `iam.googleapis.com/serviceAccounts.getAccessToken` | OAuth bearer token for the SA | Bind `roles/iam.serviceAccountTokenCreator` on the SA resource, never the project; org deny with `exceptionPrincipals` |
| `iam.serviceAccounts.getOpenIdToken` | `iam.googleapis.com/serviceAccounts.getOpenIdToken` | Audience-bound ID token → call Cloud Run / IAP as the SA | Use `roles/iam.serviceAccountOpenIdTokenCreator` (1 permission) instead of TokenCreator (9) |
| `iam.serviceAccounts.signBlob` | `iam.googleapis.com/serviceAccounts.signBlob` | Arbitrary signature with the SA's Google-managed key; also the signed-URL primitive | Deny explicitly; `constraints/storage.restrictAuthTypes` for the signed-URL consequence |
| `iam.serviceAccounts.signJwt` | `iam.googleapis.com/serviceAccounts.signJwt` | Self-signed JWT → access token at the OAuth endpoint, without calling `GenerateAccessToken` | Deny explicitly; alerting on `getAccessToken` alone does not cover it |
| `iam.serviceAccounts.implicitDelegation` | `iam.googleapis.com/serviceAccounts.implicitDelegation` | Token for the end of a delegation chain with no direct grant on it | Deny at the folder; almost never legitimately used |
| `iam.serviceAccounts.actAs` | `iam.googleapis.com/serviceAccounts.actAs` | Attach the SA to a workload. **Enforced by the consuming service, not IAM Credentials** — disabling `iamcredentials.googleapis.com` does not block it and it leaves no `iamcredentials` log | Bind `roles/iam.serviceAccountUser` per SA; deny outside the owning deploy identity; enforce `constraints/iam.disableCrossProjectServiceAccountUsage` |
| `iam.serviceAccountKeys.create` | `iam.googleapis.com/serviceAccountKeys.create` (or the group `serviceAccountKeys.*`) | Durable offline private key | `constraints/iam.managed.disableServiceAccountKeyCreation` at the org + deny group |
| SA key upload (BYO public key; permission string: verify against current docs) | — | Persistence: attacker-held private key with a Google-recognised public half | `constraints/iam.disableServiceAccountKeyUpload`; alert on `google.iam.admin.v1.UploadServiceAccountKey` |
| `iam.serviceAccounts.setIamPolicy` | `iam.googleapis.com/serviceAccounts.setIamPolicy` | Self-grant impersonation on any SA | Deny at the folder; keep `roles/iam.serviceAccountAdmin` off deploy identities |
| `resourcemanager.projects.setIamPolicy` | `cloudresourcemanager.googleapis.com/projects.setIamPolicy` | Any role on anything in the project | `roles/resourcemanager.projectIamAdmin` on the one project; deny above it |
| `resourcemanager.folders.setIamPolicy` | `cloudresourcemanager.googleapis.com/folders.setIamPolicy` | Any role on the whole subtree | Bind at the folder that owns the subtree only |
| `resourcemanager.organizations.setIamPolicy` | `cloudresourcemanager.googleapis.com/organizations.setIamPolicy` | Org-wide takeover; nothing above it constrains it | Break-glass only, dual-control, real-time alert |
| `resourcemanager.{projects,folders,organizations}.deletePolicyBinding` | (policy-binding family) | **Deletes a PAB policy binding targeting the node** — removes the boundary without touching allow policies | PAB cannot block this at any enforcement version. Role hygiene + alerting only; say so explicitly |
| `iam.roles.create` / `.update` / `.undelete` | `iam.googleapis.com/roles.create` / `.update` / `.undelete` | Arbitrary permissions into a role already bound to the holder; `undelete` restores a removed over-privileged role | Deny outside a role-governance group; alert on `google.iam.admin.v1.UpdateRole` |
| `iam.denypolicies.update` / `.delete` | **not deniable** — absent from the deny-supported list | Removes the deny backstop | Role hygiene on `roles/iam.denyAdmin` + alerting. Do not propose a deny rule protecting deny policies |
| `iam.principalaccessboundarypolicies.unbind` | `iam.googleapis.com/principalaccessboundarypolicies.unbind` | Removes the PAB boundary. Held by `roles/iam.principalAccessBoundaryUser` as well as the Admin role | Deny it; audit both roles |
| `storage.buckets.setIamPolicy` | `storage.googleapis.com/buckets.setIamPolicy` | Grant self or `allUsers` read on the bucket | Deny + `constraints/storage.publicAccessPrevention` + `constraints/iam.managed.allowedPolicyMembers` |
| `storage.objects.setIamPolicy` | `storage.googleapis.com/objects.setIamPolicy` | Per-object exposure below bucket-level review | `constraints/storage.uniformBucketLevelAccess` |
| `storage.objects.get` / `.list` | `storage.googleapis.com/objects.get` / `.list` | The data | Bind on the resource; enforced perimeter; `constraints/gcp.detailedAuditLoggingMode` so the log names the objects read |
| `storage.hmacKeys.create` | `storage.googleapis.com/hmacKeys.create` | S3-compatible long-lived credential | `constraints/iam.managed.disableServiceAccountKeyCreation` covers HMAC keys; deny |
| `bigquery.datasets.setIamPolicy` | `bigquery.googleapis.com/datasets.setIamPolicy` | Dataset ACL mutation (fine-grained-ACL datasets) | Deny at the folder |
| `bigquery.datasets.update` | `bigquery.googleapis.com/datasets.update` | **Also an ACL-mutation path** on datasets that have not opted into `enable_fine_grained_dataset_acls_option` — auditing only `setIamPolicy` is insufficient | Deny both |
| `bigquery.tables.getData` / `.export` | `bigquery.googleapis.com/tables.getData` / `.export` | Read or export the table (`EXPORT DATA OPTIONS(uri='gs://…')` writes straight to GCS) | Deny outside the authorised principal set; perimeter must cover **both** `bigquery.googleapis.com` and `storage.googleapis.com` |
| `pubsub.subscriptions.setIamPolicy` | `pubsub.googleapis.com/subscriptions.setIamPolicy` | Attach an external subscriber — the actual read path off a topic | Deny; note Pub/Sub does **not** support IAM Conditions |
| `secretmanager.secrets.setIamPolicy` / `secretmanager.versions.access` | `secretmanager.googleapis.com/secrets.setIamPolicy` / (versions.access: verify against current docs) | Direct credential exfil | Bind accessor per secret; deny the setIamPolicy |
| `cloudkms.cryptoKeys.setIamPolicy` | `cloudkms.googleapis.com/cryptoKeys.setIamPolicy` | Grant decrypt to an attacker principal | Separate KMS project; key IAM bound only to the owning service's SA |
| `artifactregistry.repositories.setIamPolicy` | `artifactregistry.googleapis.com/repositories.setIamPolicy` | Supply-chain: publish a backdoored image the platform will run | Deny; Binary Authorization with `--binauthz-evaluation-mode` (the older `--enable-binauthz` is deprecated) |
| `compute.instances.setMetadata` | `compute.googleapis.com/instances.setMetadata` | Root on that VM → its SA token; can also set `enable-oslogin=FALSE` per instance, overriding project-level TRUE | `constraints/compute.managed.requireOsLogin`; separate instance admin from the SA identity |
| `compute.projects.setCommonInstanceMetadata` | (verify v2 spelling against current docs) | Root on **every VM in the project** | No standing human holder; `constraints/compute.managed.blockProjectSshKeys` (Preview) |
| `compute.instances.setServiceAccount` | (verify v2 spelling against current docs) | Re-attach a more privileged SA to a VM the attacker controls | Requires `actAs` too — sever the pair |
| `compute.instances.setIamPolicy` | `compute.googleapis.com/instances.setIamPolicy` | Instance-level access grant | Deny |
| `iap.tunnelInstances.accessViaIAP` | (verify v2 spelling against current docs) | TCP tunnel to any instance in scope from `35.235.240.0/20` | Bind `roles/iap.tunnelResourceAccessor` per instance or per tag, not per project |
| `orgpolicy.policy.set` (+ `orgpolicy.policies.create/update/delete`) | `orgpolicy.googleapis.com/policies.create/.update/.delete` (**no `policies.get`** — the getter is `orgpolicy.policy.get`) | Turns off the constraint blocking the next step | `roles/orgpolicy.policyAdmin` at the org node only, on an identity that deploys nothing; deny elsewhere; alert on `…OrgPolicy.UpdatePolicy` |
| `accesscontextmanager.servicePerimeters.*` / `accessLevels.*` | `accesscontextmanager.googleapis.com/servicePerimeters.*` / `accessLevels.*` | Widening or deleting the perimeter = turning the primary exfil control off | Deny outside a perimeter-governance group; dual control |
| `accesscontextmanager.policies.setIamPolicy` | `accesscontextmanager.googleapis.com/policies.setIamPolicy` | Delegates control of every perimeter | `roles/accesscontextmanager.policyEditor` (identical minus this permission) where delegation is needed |
| `logging.sinks.create` / `.update` / `.delete` | `logging.googleapis.com/sinks.create` / `.update` / `.delete` | Stream org logs to an externally owned destination; or stop the export | Aggregated org sink into an isolated project; deny at the folder; alert on all three methods |
| `logging.exclusions.create` | `logging.googleapis.com/exclusions.create` | Drops matching entries **at ingest** — they are never written | Deny; alert on `…ConfigServiceV2.CreateExclusion` |
| `serviceusage.services.enable` | **not deniable** — absent from the deny-supported list | Re-enables a disabled API, including one you disabled as a control | `constraints/gcp.restrictServiceUsage` + role hygiene. Do not write a deny rule for it |
| `compute.firewallPolicies.update` | (verify v2 spelling against current docs) | Permissive egress rule, or deletion of a hierarchical deny | Hierarchical policies at the folder; separate firewall admin from workload deploy |
| Group membership change | **not an IAM permission** — Workspace Groups Admin privilege, Groups Editor role, or group `OWNER`/`MANAGER` | Every role bound to the group, with no IAM change | Move bindings to change-controlled groups; enable Workspace data sharing so the change is auditable in Google Cloud at all |
| Super admin | **above every control in this review** — implicitly able to modify the organization's IAM policy and to grant itself any role | Everything, including modifying or deleting audit logs | Minimal count, separate dedicated accounts (`alice-admin@`), security-key 2SV, self-recovery disabled, and an alert on every `SetIamPolicy` at the org node. Enumerate with Admin SDK `users.list?query=isAdmin=true` — this returns **super admins only**, so enumerate `roleAssignments` for delegated admins as well |

### 6.5 Graph-extraction helper

Run this after the exports are collected. It builds the graph described in §6.1, computes the closure
to fixpoint, and emits both the §6.3 path listing and a JSON graph. Standard library only.

**Write the code block below out to `privgraph.py` in the evidence directory before running it** —
the usage line inside it assumes that filename, and nothing else in this skill creates the file:

```bash
mkdir -p ./evidence && cd ./evidence
# paste the fenced python block below into privgraph.py, then:
python3 -m py_compile privgraph.py    # must exit 0 before you trust any output
```

```python
#!/usr/bin/env python3
"""privgraph.py - build the GCP privilege graph from Cloud Asset Inventory exports
and compute reachability to CONFIDENTIAL/NTK data to fixpoint.

Python 3.8+, standard library only. No third-party imports, no network calls.

--------------------------------------------------------------------------------
INPUTS - the exact commands that produce them
--------------------------------------------------------------------------------
  # 1. IAM allow policies + resources (note: gcloud takes LOWERCASE-HYPHENATED
  #    content types; IAM_POLICY / RESOURCE are the REST enum only and fail here)
  gcloud asset export --organization=ORG_ID \
      --content-type=iam-policy --output-path=gs://EVIDENCE_BUCKET/iam-policy.json
  gcloud asset export --organization=ORG_ID \
      --content-type=resource   --output-path=gs://EVIDENCE_BUCKET/resource.json
  gcloud asset export --organization=ORG_ID \
      --content-type=org-policy --output-path=gs://EVIDENCE_BUCKET/org-policy.json
  gcloud storage cp 'gs://EVIDENCE_BUCKET/*.json' ./evidence/

  # 2. IAM deny policies - one call per attachment point (org, each folder, each
  #    project). Deny policies are NOT in the asset export.
  gcloud iam policies list \
      --attachment-point=cloudresourcemanager.googleapis.com/organizations/ORG_ID \
      --kind=denypolicies --format=json > ./evidence/deny-org.json

  # 3. Group membership (Workspace-managed; not in any asset export). Produce
  #    {"group:g@d.com": ["user:a@d.com", "group:nested@d.com"], ...}
  #    from the Cloud Identity API (searchTransitiveMemberships) or
  #    `gcloud identity groups memberships list` (verify flags against current docs).

  # 4. Classification map - {"<asset full name or glob>": "CONFIDENTIAL"|"NTK"|
  #    "INTERNAL"|"PUBLIC"}. Anything unmapped is scored as UNCLASSIFIED and
  #    treated as CONFIDENTIAL-until-proven-otherwise (and is a finding itself).

  # 5. Seeds - one entry per adversary A1..A7 from the threat model:
  #    {"A3_ci_cd": {"principals": ["principalSet://...
  #      /attribute.repository/acme/deploy"], "ease": 3}, ...}

--------------------------------------------------------------------------------
RUN
--------------------------------------------------------------------------------
  python3 privgraph.py \
      --iam ./evidence/iam-policy.json \
      --resources ./evidence/resource.json \
      --org-policy ./evidence/org-policy.json \
      --deny ./evidence/deny-org.json --deny ./evidence/deny-prod.json \
      --groups ./evidence/groups.json \
      --classification ./evidence/classification.json \
      --seeds ./evidence/seeds.json \
      --roles-map ./evidence/roles.json \
      --json-out ./out/privgraph.json > ./out/paths.txt

--------------------------------------------------------------------------------
KNOWN LIMITS - state these in the report's appendix, do not silently absorb them
--------------------------------------------------------------------------------
  * Role expansion uses the bundled ROLE_PERMS table plus custom roles found in
    the resource export. Every role in the input that is absent from both is
    listed under UNEXPANDED ROLES on stderr; resolve them with
    `gcloud iam roles describe ROLE --format=json` and pass --roles-map.
  * roles/owner, roles/editor and roles/viewer are expanded from an approximate
    bundled set. Verify with `gcloud iam roles describe roles/editor`.
  * Principal Access Boundary policies are NOT modelled. PAB blocks
    iam.googleapis.com/serviceAccounts.* only at enforcementVersion >= 3; read
    the enforcementVersion of every PAB policy by hand.
  * GKE RBAC, Workspace group settings, Cloud Build trigger contents and
    on-host credential material are not in any asset export. Collect separately.
  * Conditional role bindings are counted as granting unless --drop-conditional
    is passed; each is flagged `conditional` on the edge.
"""

import argparse
import collections
import fnmatch
import json
import os
import sys
import urllib.parse

# ============================== permission vocabulary =========================

# All five yield usable credentials for the target SA. There is no
# iam.serviceAccounts.getIdToken - that identifier does not exist; the
# permission is getOpenIdToken while the API method is generateIdToken.
IMPERSONATE_PERMS = frozenset((
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.implicitDelegation",
))
ACTAS_PERM = "iam.serviceAccounts.actAs"
KEYMINT_PERM = "iam.serviceAccountKeys.create"
SA_SET_IAM_PERM = "iam.serviceAccounts.setIamPolicy"

CONTAINER_SET_IAM = {
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
}

# Resource-level policy mutation: sufficient to reach the data without ever
# touching project IAM. bigquery.datasets.update is here because it remains an
# ACL-mutation path on datasets that have not opted into fine-grained ACLs.
RESOURCE_SET_IAM = {
    "storage.buckets.setIamPolicy",
    "storage.objects.setIamPolicy",
    "bigquery.datasets.setIamPolicy",
    "bigquery.datasets.update",
    "bigquery.tables.setIamPolicy",
    "pubsub.topics.setIamPolicy",
    "pubsub.subscriptions.setIamPolicy",
    "cloudkms.cryptoKeys.setIamPolicy",
    "secretmanager.secrets.setIamPolicy",
    "artifactregistry.repositories.setIamPolicy",
    "compute.instances.setIamPolicy",
}

ROLE_MUTATE_PERMS = {"iam.roles.update", "iam.roles.create", "iam.roles.undelete"}

GUARDRAIL_PERMS = {
    "orgpolicy.policy.set": "orgpolicy",
    "orgpolicy.policies.create": "orgpolicy",
    "orgpolicy.policies.update": "orgpolicy",
    "orgpolicy.policies.delete": "orgpolicy",
    "accesscontextmanager.servicePerimeters.update": "vpcsc",
    "accesscontextmanager.servicePerimeters.delete": "vpcsc",
    "accesscontextmanager.servicePerimeters.replaceAll": "vpcsc",
    "accesscontextmanager.servicePerimeters.commit": "vpcsc",
    "accesscontextmanager.accessLevels.update": "vpcsc",
    "accesscontextmanager.accessLevels.replaceAll": "vpcsc",
    "accesscontextmanager.policies.setIamPolicy": "vpcsc",
    "logging.sinks.create": "logging",
    "logging.sinks.update": "logging",
    "logging.sinks.delete": "logging",
    "logging.exclusions.create": "logging",
    "logging.buckets.update": "logging",
    "serviceusage.services.enable": "serviceusage",
    "compute.firewallPolicies.update": "firewall",
    "iam.denypolicies.update": "deny",
    "iam.denypolicies.delete": "deny",
    "iam.principalaccessboundarypolicies.unbind": "pab",
    "resourcemanager.projects.deletePolicyBinding": "pab",
    "resourcemanager.folders.deletePolicyBinding": "pab",
    "resourcemanager.organizations.deletePolicyBinding": "pab",
}

# actAs is only an escalation when paired with a create/update permission on a
# surface that runs code. Spellings not read off a doc page in this pass are
# marked below; verify against current docs before quoting one in a finding.
DEPLOY_PERMS = {
    "compute.instances.create",                     # verify against current docs
    "compute.instances.setServiceAccount",
    "compute.instances.setMetadata",
    "compute.projects.setCommonInstanceMetadata",
    "run.services.create",                          # verify against current docs
    "run.services.update",                          # verify against current docs
    "run.jobs.create",                              # verify against current docs
    "cloudfunctions.functions.create",              # verify against current docs
    "cloudfunctions.functions.update",              # verify against current docs
    "cloudbuild.builds.create",                     # verify against current docs
    "cloudbuild.builds.update",                     # verify against current docs
    "composer.environments.create",                 # verify against current docs
    "composer.environments.update",                 # verify against current docs
    "dataflow.jobs.create",                         # verify against current docs
    "dataproc.clusters.create",                     # verify against current docs
    "notebooks.instances.create",                   # verify against current docs
    "aiplatform.notebookRuntimes.create",           # verify against current docs
    "cloudscheduler.jobs.create",                   # verify against current docs
    "cloudtasks.queues.create",                     # verify against current docs
    "deploymentmanager.deployments.create",         # verify against current docs
    "container.clusters.create",                    # verify against current docs
    "container.pods.create",                        # verify against current docs
}

# A read permission only creates an edge on the asset type it actually applies
# to: storage.objects.get on a BigQuery dataset is not a path.
READ_PERMS_BY_TYPE = {
    "storage.googleapis.com/Bucket": {"storage.objects.get", "storage.objects.list"},
    "bigquery.googleapis.com/Dataset": {"bigquery.tables.getData", "bigquery.tables.export"},
    "bigquery.googleapis.com/Table": {"bigquery.tables.getData", "bigquery.tables.export"},
    "pubsub.googleapis.com/Topic": {"pubsub.subscriptions.consume"},
    "pubsub.googleapis.com/Subscription": {"pubsub.subscriptions.consume"},
    "secretmanager.googleapis.com/Secret": {"secretmanager.versions.access"},
    "cloudkms.googleapis.com/CryptoKey": {"cloudkms.cryptoKeyVersions.useToDecrypt"},
    "sqladmin.googleapis.com/Instance": {"cloudsql.instances.export"},
    "spanner.googleapis.com/Database": {"spanner.databases.read"},
    "firestore.googleapis.com/Database": {"datastore.entities.get"},
    "file.googleapis.com/Instance": set(),
}

SET_IAM_BY_TYPE = {
    "storage.googleapis.com/Bucket": {"storage.buckets.setIamPolicy", "storage.objects.setIamPolicy"},
    "bigquery.googleapis.com/Dataset": {"bigquery.datasets.setIamPolicy", "bigquery.datasets.update",
                                        "bigquery.tables.setIamPolicy"},
    "bigquery.googleapis.com/Table": {"bigquery.tables.setIamPolicy"},
    "pubsub.googleapis.com/Topic": {"pubsub.topics.setIamPolicy"},
    "pubsub.googleapis.com/Subscription": {"pubsub.subscriptions.setIamPolicy"},
    "secretmanager.googleapis.com/Secret": {"secretmanager.secrets.setIamPolicy"},
    "cloudkms.googleapis.com/CryptoKey": {"cloudkms.cryptoKeys.setIamPolicy"},
    "sqladmin.googleapis.com/Instance": set(),
    "spanner.googleapis.com/Database": set(),
    "firestore.googleapis.com/Database": set(),
    "file.googleapis.com/Instance": set(),
}

DATA_ASSET_TYPES = set(READ_PERMS_BY_TYPE)
DATA_READ_PERMS = set()
for _s in READ_PERMS_BY_TYPE.values():
    DATA_READ_PERMS |= _s

# Org-policy constraints that suppress an edge unless the actor can also flip
# the policy. Each entry: constraint -> edge kind it suppresses.
KEY_CREATION_CONSTRAINTS = (
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.managed.disableServiceAccountKeyCreation",
)

# ============================== bundled role table ============================
# Sourced from the per-service role references. Escalation- and data-relevant
# permissions only: this table exists to derive edges, not to be a role catalog.

_TC = set(IMPERSONATE_PERMS)
_ALL_SET_IAM = CONTAINER_SET_IAM | RESOURCE_SET_IAM | {SA_SET_IAM_PERM}

ROLE_PERMS = {
    # --- impersonation ---
    "roles/iam.serviceAccountTokenCreator": set(_TC),
    "roles/iam.workloadIdentityUser": {
        "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"},
    "roles/iam.serviceAccountOpenIdTokenCreator": {"iam.serviceAccounts.getOpenIdToken"},
    "roles/iam.serviceAccountUser": {ACTAS_PERM},
    "roles/iam.serviceAccountAdmin": {SA_SET_IAM_PERM},
    "roles/iam.serviceAccountKeyAdmin": {KEYMINT_PERM},
    # --- policy mutation ---
    # securityAdmin is ~310 *.setIamPolicy permissions and nothing else. It cannot
    # mutate a dataset's metadata, only its IAM policy: do NOT fold in
    # bigquery.datasets.update, or every securityAdmin holder gets a fabricated
    # GRANT_SELF_RESOURCE edge to every BigQuery dataset in scope.
    "roles/iam.securityAdmin": (CONTAINER_SET_IAM | {SA_SET_IAM_PERM}
                                | {p for p in RESOURCE_SET_IAM if p.endswith(".setIamPolicy")}),
    "roles/resourcemanager.projectIamAdmin": {"resourcemanager.projects.setIamPolicy"},
    "roles/resourcemanager.folderIamAdmin": {"resourcemanager.folders.setIamPolicy"},
    "roles/resourcemanager.organizationAdmin": {
        "resourcemanager.organizations.setIamPolicy",
        "resourcemanager.folders.setIamPolicy",
        "resourcemanager.projects.setIamPolicy"},
    "roles/iam.roleAdmin": {"iam.roles.create", "iam.roles.update",
                            "iam.roles.delete", "iam.roles.undelete"},
    "roles/iam.organizationRoleAdmin": {"iam.roles.create", "iam.roles.update",
                                        "iam.roles.delete", "iam.roles.undelete"},
    "roles/iam.denyAdmin": {"iam.denypolicies.update", "iam.denypolicies.delete"},
    "roles/iam.principalAccessBoundaryAdmin": {"iam.principalaccessboundarypolicies.unbind"},
    "roles/iam.principalAccessBoundaryUser": {"iam.principalaccessboundarypolicies.unbind"},
    # --- guardrails ---
    "roles/orgpolicy.policyAdmin": {"orgpolicy.policy.set", "orgpolicy.policies.create",
                                    "orgpolicy.policies.update", "orgpolicy.policies.delete"},
    "roles/accesscontextmanager.policyAdmin": {
        "accesscontextmanager.servicePerimeters.update",
        "accesscontextmanager.servicePerimeters.delete",
        "accesscontextmanager.servicePerimeters.replaceAll",
        "accesscontextmanager.servicePerimeters.commit",
        "accesscontextmanager.accessLevels.update",
        "accesscontextmanager.accessLevels.replaceAll",
        "accesscontextmanager.policies.setIamPolicy"},
    "roles/accesscontextmanager.policyEditor": {
        "accesscontextmanager.servicePerimeters.update",
        "accesscontextmanager.servicePerimeters.delete",
        "accesscontextmanager.servicePerimeters.replaceAll",
        "accesscontextmanager.servicePerimeters.commit",
        "accesscontextmanager.accessLevels.update",
        "accesscontextmanager.accessLevels.replaceAll"},
    "roles/logging.configWriter": {"logging.sinks.create", "logging.sinks.update",
                                   "logging.sinks.delete", "logging.exclusions.create",
                                   "logging.buckets.update"},
    "roles/logging.admin": {"logging.sinks.create", "logging.sinks.update",
                            "logging.sinks.delete", "logging.exclusions.create",
                            "logging.buckets.update"},
    "roles/serviceusage.serviceUsageAdmin": {"serviceusage.services.enable"},
    # --- deploy surfaces ---
    "roles/compute.admin": {"compute.instances.create", "compute.instances.setMetadata",
                            "compute.projects.setCommonInstanceMetadata",
                            "compute.instances.setServiceAccount",
                            "compute.instances.setIamPolicy"},
    "roles/compute.instanceAdmin.v1": {"compute.instances.create",
                                       "compute.instances.setMetadata",
                                       "compute.instances.setServiceAccount"},
    "roles/run.admin": {"run.services.create", "run.services.update", "run.jobs.create"},
    "roles/run.developer": {"run.services.create", "run.services.update"},
    "roles/cloudfunctions.admin": {"cloudfunctions.functions.create",
                                   "cloudfunctions.functions.update"},
    "roles/cloudfunctions.developer": {"cloudfunctions.functions.create",
                                       "cloudfunctions.functions.update"},
    "roles/cloudbuild.builds.editor": {"cloudbuild.builds.create", "cloudbuild.builds.update"},
    "roles/composer.admin": {"composer.environments.create", "composer.environments.update"},
    "roles/dataflow.developer": {"dataflow.jobs.create"},
    "roles/dataproc.editor": {"dataproc.clusters.create"},
    "roles/notebooks.admin": {"notebooks.instances.create"},
    "roles/cloudscheduler.admin": {"cloudscheduler.jobs.create"},
    "roles/deploymentmanager.editor": {"deploymentmanager.deployments.create"},
    "roles/container.admin": {"container.clusters.create", "container.pods.create"},
    "roles/container.clusterAdmin": {"container.clusters.create"},
    "roles/container.developer": {"container.pods.create"},
    # --- data read ---
    "roles/storage.objectViewer": {"storage.objects.get", "storage.objects.list"},
    "roles/storage.objectUser": {"storage.objects.get", "storage.objects.list"},
    "roles/storage.legacyObjectReader": {"storage.objects.get"},
    "roles/storage.admin": {"storage.objects.get", "storage.objects.list",
                            "storage.buckets.setIamPolicy", "storage.objects.setIamPolicy"},
    "roles/bigquery.dataViewer": {"bigquery.tables.getData", "bigquery.tables.export"},
    "roles/bigquery.dataEditor": {"bigquery.tables.getData", "bigquery.tables.export"},
    "roles/bigquery.dataOwner": {"bigquery.tables.getData", "bigquery.tables.export",
                                 "bigquery.datasets.setIamPolicy", "bigquery.datasets.update",
                                 "bigquery.tables.setIamPolicy"},
    "roles/bigquery.admin": {"bigquery.tables.getData", "bigquery.tables.export",
                             "bigquery.datasets.setIamPolicy", "bigquery.datasets.update",
                             "bigquery.tables.setIamPolicy"},
    "roles/pubsub.subscriber": {"pubsub.subscriptions.consume"},
    "roles/pubsub.admin": {"pubsub.subscriptions.consume", "pubsub.topics.setIamPolicy",
                           "pubsub.subscriptions.setIamPolicy"},
    "roles/secretmanager.secretAccessor": {"secretmanager.versions.access"},
    "roles/secretmanager.admin": {"secretmanager.versions.access",
                                  "secretmanager.secrets.setIamPolicy"},
    "roles/cloudkms.cryptoKeyDecrypter": {"cloudkms.cryptoKeyVersions.useToDecrypt"},
    "roles/cloudkms.admin": {"cloudkms.cryptoKeys.setIamPolicy"},
    "roles/spanner.databaseReader": {"spanner.databases.read"},
    "roles/datastore.viewer": {"datastore.entities.get"},
    "roles/cloudsql.admin": {"cloudsql.instances.export"},
}

# Basic roles - APPROXIMATE. Verify with `gcloud iam roles describe roles/editor`.
_BASIC_VIEWER = {"storage.objects.get", "storage.objects.list",
                 "bigquery.tables.getData", "bigquery.tables.export",
                 "datastore.entities.get", "spanner.databases.read"}
_BASIC_EDITOR = _BASIC_VIEWER | {ACTAS_PERM, KEYMINT_PERM} | DEPLOY_PERMS | {
    "bigquery.datasets.update", "logging.sinks.create", "logging.sinks.update",
    "logging.sinks.delete", "logging.exclusions.create", "serviceusage.services.enable",
    "pubsub.subscriptions.consume", "cloudsql.instances.export"}
_BASIC_OWNER = _BASIC_EDITOR | _ALL_SET_IAM | ROLE_MUTATE_PERMS | {
    "orgpolicy.policy.set", "compute.firewallPolicies.update",
    "secretmanager.versions.access", "cloudkms.cryptoKeyVersions.useToDecrypt"}
ROLE_PERMS["roles/viewer"] = set(_BASIC_VIEWER)
ROLE_PERMS["roles/editor"] = set(_BASIC_EDITOR)
ROLE_PERMS["roles/owner"] = set(_BASIC_OWNER)

TRACKED_PERMS = (set(IMPERSONATE_PERMS) | {ACTAS_PERM, KEYMINT_PERM, SA_SET_IAM_PERM}
                 | CONTAINER_SET_IAM | RESOURCE_SET_IAM | ROLE_MUTATE_PERMS
                 | set(GUARDRAIL_PERMS) | DEPLOY_PERMS | DATA_READ_PERMS)

# Edge kind -> (is it recorded in an always-on Admin Activity log?, note)
EDGE_DETECTION = {
    "MEMBER_OF": (False, "Workspace-side change; in Cloud Audit Logs only if Workspace data sharing is on"),
    "IMPERSONATE": (False, "Data Access log (bare methodName GenerateAccessToken/GenerateIdToken/SignJwt/SignBlob) - OFF by default"),
    "DEPLOY_AS": (True, "create call on the consuming service is Admin Activity; NO iamcredentials entry for the token read"),
    "KEY_MINT": (True, "google.iam.admin.v1.CreateServiceAccountKey (Admin Activity); use of the key afterwards is invisible"),
    "KEY_MINT_TWO_STEP": (True, "org-policy flip + CreateServiceAccountKey, both Admin Activity, correlated by nobody"),
    "GRANT_SELF": (True, "cloudresourcemanager.v3.*.setIamPolicy / google.iam.admin.v1.SetIAMPolicy (Admin Activity)"),
    "GRANT_SELF_RESOURCE": (True, "resource-service setIamPolicy, e.g. storage.setIamPermissions (Admin Activity)"),
    "GRANT_IMPLIES": (True, "implied by the setIamPolicy above"),
    "GRANT_IMPLIES_READ": (True, "implied by the setIamPolicy above"),
    "ROLE_MUTATE": (True, "google.iam.admin.v1.UpdateRole (Admin Activity) - but NO binding changes, so config-diff review misses it"),
    "GUARDRAIL_MUTATE": (True, "service-specific Admin Activity method"),
    "READ_DATA": (False, "Data Access log (storage.objects.get / BigQuery data read) - OFF by default"),
}

TIER_SCORE = {"CONFIDENTIAL": 5, "UNCLASSIFIED": 5, "NTK": 4, "INTERNAL": 2, "PUBLIC": 0}
TERMINAL_TIERS = {"CONFIDENTIAL", "NTK", "UNCLASSIFIED"}
# The four-tier vocabulary from TF3, plus UNCLASSIFIED. A customer-supplied
# classification map routinely carries something else ("SECRET", "Restricted",
# a localised term, a trailing space). Anything outside this set must be
# normalised, not silently dropped: an unknown tier is scored as UNCLASSIFIED
# per TF4 (CONFIDENTIAL-until-proven-otherwise) and warned about on stderr.
KNOWN_TIERS = {"CONFIDENTIAL", "NTK", "INTERNAL", "PUBLIC", "UNCLASSIFIED"}
_TIER_WARNED = set()


def normalise_tier(value, nid):
    t = str(value).strip().upper()
    if t in KNOWN_TIERS:
        return t
    if t not in _TIER_WARNED:
        _TIER_WARNED.add(t)
        sys.stderr.write("# UNKNOWN CLASSIFICATION TIER %r (first seen on %s): scored as "
                         "UNCLASSIFIED per TF4, and the resource stays a terminal. "
                         "Fix the classification map.\n" % (value, nid))
    return "UNCLASSIFIED"


# ================================ input loading ===============================

def load_records(path):
    """Yield dicts from NDJSON, a JSON array, or {"assets"|"data"|"items": [...]}."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return
    if text[0] == "[":
        for rec in json.loads(text):
            yield rec
        return
    if text[0] == "{":
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            for key in ("assets", "data", "items", "policies", "results"):
                if isinstance(obj.get(key), list):
                    for rec in obj[key]:
                        yield rec
                    return
            yield obj
            return
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


def load_json_file(path, default=None):
    if not path:
        return default
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def g(rec, *names):
    """Fetch the first present key among camelCase / snake_case spellings."""
    for n in names:
        if n in rec and rec[n] is not None:
            return rec[n]
    return None


# ================================ asset model =================================

CONTAINER_TYPES = ("cloudresourcemanager.googleapis.com/Project",
                   "cloudresourcemanager.googleapis.com/Folder",
                   "cloudresourcemanager.googleapis.com/Organization")


class Graph(object):
    def __init__(self):
        self.nodes = {}                       # id -> dict(kind=..., **attrs)
        self.edges = []                       # list of dicts
        self.out = collections.defaultdict(list)
        self._index = {}                      # merge key -> edge

    def node(self, node_id, kind, **attrs):
        n = self.nodes.setdefault(node_id, {"id": node_id, "kind": kind})
        n.setdefault("kind", kind)
        n.update({k: v for k, v in attrs.items() if v is not None})
        return node_id

    def edge(self, src, dst, kind, permission, evidence, sever, **attrs):
        """Parallel edges that differ only in permission are merged: five
        impersonation permissions from one roles/iam.serviceAccountTokenCreator
        binding are one edge, not five chains."""
        key = (src, dst, kind, evidence, sever)
        e = self._index.get(key)
        if e is not None:
            perms = set(e["permission"].split(", ")) | {permission}
            e["permission"] = ", ".join(sorted(perms))
            return e
        e = {"src": src, "dst": dst, "kind": kind, "permission": permission,
             "evidence": evidence, "sever": sever}
        e.update(attrs)
        self._index[key] = e
        self.edges.append(e)
        self.out[src].append(e)
        return e


class Model(object):
    """Everything parsed out of the evidence, before edge derivation."""

    def __init__(self, args):
        self.args = args
        self.ancestors = {}          # canonical node id -> [ancestor tokens]
        self.asset_type = {}         # canonical node id -> asset type
        self.labels = {}             # canonical node id -> labels dict
        self.sa_emails = {}          # sa email -> canonical project token
        self.custom_roles = {}       # role name -> set(perms)
        self.holdings = collections.defaultdict(set)   # (member, perm) -> {scopes}
        self.perm_index = collections.defaultdict(list)  # perm -> [(member, scope, cond)]
        self.role_bindings = collections.defaultdict(list)  # role -> [(member, scope)]
        self.unexpanded = collections.Counter()
        self.deny_rules = []
        self.orgpolicy = collections.defaultdict(dict)  # scope -> constraint -> enforced?
        self.groups = {}
        self.classification = {}
        self.data_assets = {}        # node id -> tier

    # -------- canonical ids --------
    def canon(self, name, asset_type, ancestors):
        if asset_type in CONTAINER_TYPES and ancestors:
            return ancestors[0]
        if name and name.startswith("//cloudresourcemanager.googleapis.com/"):
            return name[len("//cloudresourcemanager.googleapis.com/"):]
        return name

    def chain(self, node_id):
        """The node itself plus every ancestor container token."""
        anc = self.ancestors.get(node_id, [])
        out = [node_id]
        for a in anc:
            if a != node_id:
                out.append(a)
        return out

    # -------- ingestion --------
    def ingest_asset(self, rec):
        name = g(rec, "name")
        atype = g(rec, "assetType", "asset_type") or ""
        anc = g(rec, "ancestors") or []
        if not name:
            return
        nid = self.canon(name, atype, anc)
        self.ancestors[nid] = list(anc)
        self.asset_type[nid] = atype
        res = g(rec, "resource") or {}
        data = g(res, "data") or {}
        if isinstance(data, dict):
            labels = data.get("labels")
            if isinstance(labels, dict):
                self.labels[nid] = labels
        # service accounts
        if atype == "iam.googleapis.com/ServiceAccount":
            email = None
            if isinstance(data, dict):
                email = data.get("email")
            if not email and "/serviceAccounts/" in name:
                email = name.split("/serviceAccounts/", 1)[1]
            if email:
                self.sa_emails[email] = anc[0] if anc else nid
        # custom roles
        if atype == "iam.googleapis.com/Role" and isinstance(data, dict):
            perms = data.get("includedPermissions") or data.get("included_permissions") or []
            rname = data.get("name") or name.split("/roles/")[-1]
            if rname and not rname.startswith("roles/") and "/roles/" in name:
                rname = name.split("//iam.googleapis.com/")[-1]
            self.custom_roles[rname] = set(perms)
            short = rname.split("/roles/")[-1]
            # Do NOT alias into the predefined namespace. Custom-role IDs legally
            # accept letters, digits, underscores and periods, so "editor",
            # "owner", "viewer", "storage.admin" are all valid custom-role IDs; an
            # unguarded alias makes one of them shadow the PREDEFINED role of that
            # name for every binding in the organization.
            alias = "roles/" + short
            if short and alias not in ROLE_PERMS:
                self.custom_roles.setdefault(alias, set(perms))
            elif short:
                sys.stderr.write(
                    "# custom role %s shadows predefined %s - not aliased; bindings "
                    "must cite the full custom-role name\n" % (rname, alias))
        # iam policy carried on the asset
        pol = g(rec, "iamPolicy", "iam_policy")
        if pol:
            self.ingest_policy(nid, pol)

    def ingest_policy(self, scope, policy):
        for b in policy.get("bindings", []) or []:
            role = b.get("role")
            cond = bool(b.get("condition"))
            for member in b.get("members", []) or []:
                self.role_bindings[role].append((member, scope))
                for perm in self.expand_role(role):
                    if perm in TRACKED_PERMS:
                        self.holdings[(member, perm)].add(scope)
                        self.perm_index[perm].append((member, scope, cond))

    def expand_role(self, role):
        if role.startswith("roles/") and role in ROLE_PERMS:
            return ROLE_PERMS[role]          # predefined roles always win
        if role in self.custom_roles:
            return self.custom_roles[role]
        if role in ROLE_PERMS:
            return ROLE_PERMS[role]
        if self.args.roles_map and role in self.args.roles_map:
            return set(self.args.roles_map[role])
        self.unexpanded[role] += 1
        return set()

    def ingest_org_policy(self, rec):
        name = g(rec, "name")
        atype = g(rec, "assetType", "asset_type") or ""
        anc = g(rec, "ancestors") or []
        nid = self.canon(name, atype, anc)
        for pol in g(rec, "orgPolicy", "org_policy") or []:
            constraint = pol.get("constraint")
            if not constraint:
                continue
            boolean = pol.get("booleanPolicy") or pol.get("boolean_policy") or {}
            enforced = bool(boolean.get("enforced"))
            self.orgpolicy[nid][constraint] = enforced
        # v2 shape (policySpec.rules[].enforce)
        spec = g(rec, "policySpec", "policy_spec")
        if isinstance(spec, dict):
            constraint = g(rec, "constraint") or name.split("/policies/")[-1]
            for rule in spec.get("rules", []) or []:
                if "enforce" in rule:
                    self.orgpolicy[nid]["constraints/" + constraint.split("/")[-1]] = bool(rule["enforce"])

    def constraint_enforced(self, node_id, constraints):
        for scope in self.chain(node_id):
            for c in constraints:
                if c in self.orgpolicy.get(scope, {}):
                    return self.orgpolicy[scope][c], scope
        return False, None

    def ingest_deny(self, rec):
        pname = rec.get("name", "")
        attach = None
        if "policies/" in pname:
            attach = urllib.parse.unquote(pname.split("policies/", 1)[1].split("/denypolicies")[0])
        scope = None
        if attach and "cloudresourcemanager.googleapis.com/" in attach:
            scope = attach.split("cloudresourcemanager.googleapis.com/", 1)[1]
        for rule in rec.get("rules", []) or []:
            dr = rule.get("denyRule") or rule.get("deny_rule") or {}
            self.deny_rules.append({
                "scope": scope,
                "policy": pname,
                "principals": set(dr.get("deniedPrincipals") or dr.get("denied_principals") or []),
                "exception_principals": set(dr.get("exceptionPrincipals") or dr.get("exception_principals") or []),
                "permissions": set(dr.get("deniedPermissions") or dr.get("denied_permissions") or []),
                "exception_permissions": set(dr.get("exceptionPermissions") or dr.get("exception_permissions") or []),
                "condition": dr.get("denialCondition") or dr.get("denial_condition"),
            })


# ============================== deny evaluation ===============================

def v1_to_v2(perm):
    """iam.serviceAccounts.getAccessToken -> iam.googleapis.com/serviceAccounts.getAccessToken"""
    service, _, rest = perm.partition(".")
    if not rest:
        return perm
    if service == "resourcemanager":
        service = "cloudresourcemanager"
    return "%s.googleapis.com/%s" % (service, rest)


def deny_matches_principal(rule, member, groups_of):
    pset = rule["principals"]
    if not pset:
        return False
    cands = {"principalSet://goog/public:all"}
    if member.startswith("user:"):
        cands.add("principal://goog/subject/" + member.split(":", 1)[1])
    if member.startswith("serviceAccount:"):
        cands.add("principal://goog/subject/" + member.split(":", 1)[1])
    if member.startswith("group:"):
        cands.add("principalSet://goog/group/" + member.split(":", 1)[1])
    for grp in groups_of.get(member, ()):  # inherited via group membership
        cands.add("principalSet://goog/group/" + grp.split(":", 1)[-1])
    if pset & cands:
        exc = rule["exception_principals"]
        if exc & cands:
            return False
        return True
    return False


def deny_matches_permission(rule, perm):
    v2 = v1_to_v2(perm)
    if v2 in rule["exception_permissions"]:
        return False
    for denied in rule["permissions"]:
        if denied == v2:
            return True
        if denied.endswith(".*") and v2.startswith(denied[:-1]):
            return True
    return False


def denied(model, member, perm, target_chain, groups_of):
    """Return (blocked, note). Deny attaches only at org/folder/project."""
    for rule in model.deny_rules:
        if rule["scope"] and rule["scope"] not in target_chain:
            continue
        if not deny_matches_permission(rule, perm):
            continue
        if not deny_matches_principal(rule, member, groups_of):
            continue
        if rule["condition"]:
            # Denial conditions recognise only resource tag functions and fail
            # closed. We cannot evaluate tags from the export - keep the edge and
            # flag it rather than silently deleting a path.
            return False, "deny-uncertain(%s: conditional)" % rule["policy"]
        return True, rule["policy"]
    return False, None


# ============================== group expansion ===============================

def build_group_maps(groups):
    """members_of[group] = transitive concrete members; groups_of[p] = groups p is in."""
    members_of = {}

    def expand(gid, seen):
        if gid in members_of:
            return members_of[gid]
        if gid in seen:
            return set()
        seen.add(gid)
        out = set()
        for m in groups.get(gid, []):
            out.add(m)
            if m.startswith("group:"):
                out |= expand(m, seen)
        members_of[gid] = out
        return out

    for gid in list(groups):
        expand(gid, set())
    groups_of = collections.defaultdict(set)
    for gid, members in members_of.items():
        for m in members:
            groups_of[m].add(gid)
    return members_of, groups_of


# ============================== graph construction ============================

def build_graph(model, groups, members_of, groups_of):
    G = Graph()
    args = model.args

    # ---- principal + group nodes ----
    principals = set()
    for (member, _perm) in model.holdings:
        principals.add(member)
    for gid, members in members_of.items():
        principals.add(gid)
        principals |= set(members)
    for email in model.sa_emails:
        principals.add("serviceAccount:" + email)
    for p in principals:
        G.node(p, principal_kind(p))

    # ---- membership edges (member -> group) ----
    for gid, members in members_of.items():
        for m in members:
            if m == gid:
                continue
            G.edge(m, gid, "MEMBER_OF", "(Workspace group membership - not an IAM permission)",
                   "groups file: %s" % gid,
                   "this is a per-person removal, not a control: re-bind the role held by %s to a "
                   "group whose membership is change-controlled, and enumerate who holds the "
                   "Workspace Groups Admin privilege" % gid,
                   gains="every role bound to %s, without any IAM policy changing" % gid)

    # ---- helper: subjects holding perm over a target chain ----
    def holders(perm, chain):
        out = []
        for (member, scope, cond) in model.perm_index.get(perm, ()):
            if scope in chain:
                out.append((member, scope, cond))
        return out

    def holders_multi(perms, chain):
        """(member, scope, conditional) -> the set of PERMS they hold there.
        One edge per binding, not one per permission."""
        acc = collections.defaultdict(set)
        for perm in perms:
            for key in holders(perm, chain):
                acc[key].add(perm)
        return acc

    def emit(member, dst, kind, perms, scope, cond, chain, gains, sever, label=None):
        """perms: the iterable of v1 permission strings that create this edge (a
        bare string is accepted for single-permission edges).
        label:  what to display on the edge (defaults to ', '-joined perms).
        Deny is evaluated PER PERMISSION, never on the display string: partitioning
        a joined string on its first '.' produces a token no deny rule can match,
        which silently disables deny subtraction for every multi-permission edge."""
        perm_list = [perms] if isinstance(perms, str) else sorted(perms)
        label = label or ", ".join(perm_list)
        notes, live = [], []
        for p in perm_list:
            blocked, note = denied(model, member, p, chain, groups_of)
            if note:
                notes.append(note)
            if not blocked:
                live.append(p)
        # An actAs PAIR needs BOTH halves, so denying either half kills the edge.
        # Every other kind survives while ANY one of its permissions is un-denied.
        dead = (len(live) < len(perm_list)) if kind == "DEPLOY_AS" else (not live)
        if dead and not args.keep_denied:
            return None
        attrs = {}
        if cond:
            if args.drop_conditional:
                return None
            attrs["conditional"] = True
        if notes:
            attrs["deny_note"] = "; ".join(sorted(set(notes)))
        G.node(member, principal_kind(member))
        return G.edge(member, dst, kind, label,
                      "binding at %s" % scope, sever, gains=gains, **attrs)

    # ---- impersonation, actAs, key-mint, SA setIamPolicy ----
    sa_resource = {}
    for nid, atype in model.asset_type.items():
        if atype == "iam.googleapis.com/ServiceAccount" and "/serviceAccounts/" in nid:
            sa_resource[nid.split("/serviceAccounts/", 1)[1]] = nid
    for email, proj in model.sa_emails.items():
        sa_id = "serviceAccount:" + email
        res = sa_resource.get(email)
        if res:
            chain = model.chain(res)
        elif proj:
            chain = [proj] + [a for a in model.ancestors.get(proj, []) if a != proj]
        else:
            # SA inferred from a member string only (no --resources row): its own
            # project chain is unknown, so it can only carry resource-level
            # bindings. That is the honest answer, not a guess.
            chain = []
        G.node(sa_id, principal_kind(sa_id), project=proj)

        for (member, scope, cond), perms in holders_multi(IMPERSONATE_PERMS, chain).items():
            if member == sa_id:
                continue
            sever = ("remove the binding at %s; re-bind the narrowest role "
                     "(roles/iam.serviceAccountOpenIdTokenCreator if only an OIDC ID token is "
                     "needed) ON THE SERVICE ACCOUNT RESOURCE - service accounts do not support "
                     "IAM Conditions, so resource-scoping the binding is the only narrowing "
                     "available - and add an org/folder IAM Deny enumerating %s"
                     % (scope, ", ".join(sorted(v1_to_v2(p) for p in perms))))
            emit(member, sa_id, "IMPERSONATE", perms, scope, cond, chain,
                 "credentials of %s" % email, sever)

        for (member, scope, cond) in holders(KEYMINT_PERM, chain):
            enforced, at = model.constraint_enforced(proj, KEY_CREATION_CONSTRAINTS)
            can_flip = any(s in model.holdings.get((member, "orgpolicy.policy.set"), set())
                           for s in model.chain(proj))
            if enforced and not can_flip:
                continue
            kind = "KEY_MINT_TWO_STEP" if (enforced and can_flip) else "KEY_MINT"
            sever = ("enforce constraints/iam.managed.disableServiceAccountKeyCreation at the org node "
                     "and add an org IAM Deny on iam.googleapis.com/serviceAccountKeys.create "
                     "(permission group iam.googleapis.com/serviceAccountKeys.* is valid); "
                     "revoke the binding at %s" % scope)
            emit(member, sa_id, kind, KEYMINT_PERM, scope, cond, chain,
                 "durable offline private key for %s" % email, sever)

        for (member, scope, cond) in holders(SA_SET_IAM_PERM, chain):
            if member == sa_id:
                continue
            sever = ("remove roles/iam.serviceAccountAdmin (or the custom role granting "
                     "iam.serviceAccounts.setIamPolicy) at %s; deny "
                     "iam.googleapis.com/serviceAccounts.setIamPolicy at the folder" % scope)
            emit(member, sa_id, "GRANT_SELF", SA_SET_IAM_PERM, scope, cond, chain,
                 "self-grant TokenCreator on %s, then impersonate" % email, sever)

        # actAs pair rule: actAs on the SA AND a create/update permission on a
        # surface that runs code. Cross-project attachment is possible unless
        # constraints/iam.disableCrossProjectServiceAccountUsage is enforced.
        cross_ok, _ = (model.constraint_enforced(
            proj, ("constraints/iam.disableCrossProjectServiceAccountUsage",))
            if proj else (False, None))
        for (member, scope, cond) in holders(ACTAS_PERM, chain):
            deploy_hits = []
            for dperm in DEPLOY_PERMS:
                for (m2, s2, _c2) in model.perm_index.get(dperm, ()):
                    if m2 != member:
                        continue
                    if cross_ok and s2 not in model.chain(proj):
                        continue
                    deploy_hits.append((dperm, s2))
            if not deploy_hits:
                continue
            dperm, dscope = sorted(deploy_hits)[0]
            sever = ("break the pair: revoke %s at %s, or revoke actAs at %s and re-bind "
                     "roles/iam.serviceAccountUser on this one service account only; "
                     "deny iam.googleapis.com/serviceAccounts.actAs for everyone outside the "
                     "owning deploy identity" % (dperm, dscope, scope))
            emit(member, sa_id, "DEPLOY_AS", (ACTAS_PERM, dperm), scope, cond, chain,
                 "runs code as %s; reads its token from 169.254.169.254" % email, sever,
                 label="%s + %s" % (ACTAS_PERM, dperm))

    # ---- classification of data assets ----
    for nid, atype in model.asset_type.items():
        if atype not in DATA_ASSET_TYPES:
            continue
        model.data_assets[nid] = classify(model, nid)
    for nid, tier in model.data_assets.items():
        G.node(nid, "data", asset_type=model.asset_type.get(nid), classification=tier)

    # ---- read-data edges ----
    for nid, tier in model.data_assets.items():
        chain = model.chain(nid)
        rperms = READ_PERMS_BY_TYPE.get(model.asset_type.get(nid), set())
        for (member, scope, cond), perms in holders_multi(rperms, chain).items():
            sever = ("remove the read binding at %s (%s); if the data must stay reachable to this "
                     "principal, bind the read role on the resource itself, put the project in an "
                     "ENFORCED VPC-SC perimeter, and enable Data Access DATA_READ logs so the read "
                     "is visible at all" % (scope, ", ".join(sorted(perms))))
            emit(member, nid, "READ_DATA", perms, scope, cond, chain,
                 "%s data in %s" % (tier, nid), sever)

    # ---- resource-level setIamPolicy: reach the data without touching project IAM ----
    for nid, tier in model.data_assets.items():
        chain = model.chain(nid)
        sperms = SET_IAM_BY_TYPE.get(model.asset_type.get(nid), set())
        for (member, scope, cond), perms in holders_multi(sperms, chain).items():
            sever = ("remove the binding at %s granting %s; deny %s at the folder so a "
                     "project-level admin cannot re-add it"
                     % (scope, ", ".join(sorted(perms)),
                        ", ".join(sorted(v1_to_v2(p) for p in perms))))
            emit(member, nid, "GRANT_SELF_RESOURCE", perms, scope, cond, chain,
                 "grant self (or allUsers) read on %s data without touching project IAM" % tier,
                 sever)

    # ---- container setIamPolicy -> everything beneath ----
    scope_nodes = set()
    for perm in CONTAINER_SET_IAM:
        for (member, scope, cond) in model.perm_index.get(perm, ()):
            sever = ("remove %s at %s; split it into roles/resourcemanager.projectIamAdmin on the "
                     "single project that needs it, and deny %s above that node"
                     % (perm, scope, v1_to_v2(perm)))
            G.node(scope, "scope")
            emit(member, scope, "GRANT_SELF", perm, scope, cond, model.chain(scope),
                 "any role on anything under %s" % scope, sever)
            scope_nodes.add(scope)

    # ---- role-mutate: update a custom role you (or your group) already hold ----
    for perm in ("iam.roles.update", "iam.roles.create"):
        for (member, scope, cond) in model.perm_index.get(perm, ()):
            held_scopes = set()
            for role, binds in model.role_bindings.items():
                if role not in model.custom_roles:
                    continue
                for (m2, s2) in binds:
                    if m2 == member or m2 in groups_of.get(member, ()):
                        if scope in model.chain(s2) or s2 == scope:
                            held_scopes.add((role, s2))
            for (role, s2) in sorted(held_scopes):
                sever = ("move %s to a break-glass identity only; deny iam.googleapis.com/roles.update "
                         "at the org for everyone outside the role-governance group; alert on "
                         "google.iam.admin.v1.UpdateRole for %s" % (perm, role))
                G.node(s2, "scope")
                emit(member, s2, "ROLE_MUTATE", perm, scope, cond, model.chain(s2),
                     "add any permission to %s, which is already bound to this principal at %s "
                     "- no binding changes, so binding-diff review sees nothing" % (role, s2), sever)
                scope_nodes.add(s2)

    # ---- what a scope node implies ----
    for scope in scope_nodes:
        G.node(scope, "scope")
        for email, proj in model.sa_emails.items():
            if proj and scope in ([proj] + model.ancestors.get(proj, [])):
                G.edge(scope, "serviceAccount:" + email, "GRANT_IMPLIES",
                       "(implied by setIamPolicy at %s)" % scope,
                       "SA lives under %s" % scope,
                       "same sever as the setIamPolicy edge into %s" % scope,
                       gains="bind roles/iam.serviceAccountTokenCreator to self on %s" % email)
        for nid, tier in model.data_assets.items():
            if scope in model.chain(nid):
                G.edge(scope, nid, "GRANT_IMPLIES_READ",
                       "(implied by setIamPolicy at %s)" % scope,
                       "resource lives under %s" % scope,
                       "same sever as the setIamPolicy edge into %s" % scope,
                       gains="bind a read role to self on %s data" % tier)

    # ---- guardrail-mutate (precursor edges; not data terminals) ----
    for perm, family in GUARDRAIL_PERMS.items():
        for (member, scope, cond) in model.perm_index.get(perm, ()):
            gnode = "guardrail:%s@%s" % (family, scope)
            G.node(gnode, "guardrail", family=family, scope=scope)
            sever = ("bind %s only at the folder that owns the guardrail, to an identity distinct "
                     "from any workload-deploy identity; alert on the corresponding Admin Activity "
                     "method" % perm)
            emit(member, gnode, "GUARDRAIL_MUTATE", perm, scope, cond, model.chain(scope),
                 "disable/widen the %s guardrail at %s before the next step" % (family, scope), sever)

    return G


def principal_kind(p):
    if p.startswith("user:"):
        return "human"
    if p.startswith("group:"):
        return "group"
    if p.startswith("serviceAccount:"):
        email = p.split(":", 1)[1]
        if email.endswith("-compute@developer.gserviceaccount.com"):
            return "sa_default_compute"
        if email.endswith("@appspot.gserviceaccount.com"):
            return "sa_default_appengine"
        if email.endswith("@cloudbuild.gserviceaccount.com"):
            return "sa_default_cloudbuild"
        if email.startswith("service-") and ".iam.gserviceaccount.com" in email:
            return "sa_service_agent"
        if ".svc.id.goog[" in email:
            return "ksa"
        return "sa_user_managed"
    if p.startswith("principal://") or p.startswith("principalSet://"):
        return "federated"
    if p in ("allUsers", "allAuthenticatedUsers"):
        return "public"
    if p.startswith("domain:"):
        return "domain"
    if p.startswith("deleted:"):
        return "deleted"
    return "other"


def classify(model, nid):
    explicit = model.classification
    if nid in explicit:
        return normalise_tier(explicit[nid], nid)
    for pattern, tier in explicit.items():
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatch(nid, pattern):
            return normalise_tier(tier, nid)
    for scope in model.chain(nid):
        if scope in explicit:
            return normalise_tier(explicit[scope], nid)
    label_key = model.args.classification_label
    if label_key:
        lab = model.labels.get(nid, {})
        if label_key in lab:
            return normalise_tier(lab[label_key], nid)
    return "UNCLASSIFIED"


# ============================ reachability to fixpoint ========================

TERMINAL_KINDS = {"READ_DATA", "GRANT_SELF_RESOURCE", "GRANT_IMPLIES_READ"}
TRAVERSABLE_FROM_SCOPE = {"GRANT_IMPLIES", "GRANT_IMPLIES_READ"}


def closure(G, seeds):
    """Transitive closure over identity edges. Runs to fixpoint: repeat until a
    full pass adds nothing. Returns the set of reached node ids."""
    reached = set(seeds)
    changed = True
    while changed:
        changed = False
        for node in list(reached):
            for e in G.out.get(node, ()):
                if e["kind"] == "GUARDRAIL_MUTATE":
                    continue
                if e["dst"] in reached:
                    continue
                if G.nodes.get(node, {}).get("kind") == "scope" and \
                        e["kind"] not in TRAVERSABLE_FROM_SCOPE:
                    continue
                reached.add(e["dst"])
                changed = True
    return reached


def enumerate_paths(G, seed, max_depth, max_paths, recorded_not_ranked=None):
    """Every simple path from seed that ends on a terminal edge into
    CONFIDENTIAL / NTK / UNCLASSIFIED data. INTERNAL and PUBLIC terminals are
    RECORDED into `recorded_not_ranked` rather than dropped: 6.1.5 point 4 says
    they are reported but not ranked, and a silently discarded terminus reads as
    'no path exists'."""
    results = []
    stack = [(seed, [], {seed})]
    while stack:
        node, path, visited = stack.pop()
        if len(results) >= max_paths:
            break
        if len(path) >= max_depth:
            continue
        for e in G.out.get(node, ()):
            if e["kind"] == "GUARDRAIL_MUTATE":
                continue
            if G.nodes.get(node, {}).get("kind") == "scope" and \
                    e["kind"] not in TRAVERSABLE_FROM_SCOPE:
                continue
            dst = e["dst"]
            if dst in visited:
                continue
            if e["kind"] in TERMINAL_KINDS:
                tier = G.nodes.get(dst, {}).get("classification", "UNCLASSIFIED")
                if tier in TERMINAL_TIERS:
                    results.append(path + [e])
                elif recorded_not_ranked is not None:
                    recorded_not_ranked.add((seed, dst, tier))
                continue
            stack.append((dst, path + [e], visited | {dst}))
    return results


# ================================== scoring ===================================

def principal_count_score(n):
    if n >= 100:
        return 5
    if n >= 25:
        return 4
    if n >= 6:
        return 3
    if n >= 2:
        return 2
    return 1


def detection_factor(G, path, data_access_enabled, workspace_sharing=False,
                     alerting_verified=False):
    """D per §6.3.2. Two distinctions the naive version collapses:
    (a) MEMBER_OF is cleared by Workspace data sharing, NOT by Data Access logs;
    (b) D = 1.0 means 'logged AND alerted today' - logged alone is not detected."""
    worst = 1.0
    for e in path:
        logged, _note = EDGE_DETECTION.get(e["kind"], (True, ""))
        covered = workspace_sharing if e["kind"] == "MEMBER_OF" else data_access_enabled
        if not logged and not covered:
            worst = max(worst, 1.5)
        elif e["kind"] == "DEPLOY_AS":
            worst = max(worst, 1.25)
    if worst == 1.0 and not alerting_verified:
        worst = 1.25          # §6.3.2: D=1.0 requires an alert, not just a log entry
    return worst


# There is deliberately no band() function here. The number this script computes
# ORDERS chains against one another; it does not band them. The report band comes
# from 11.1.5 (matrix) and 11.1.8 (arithmetic). Printing a band on the rank line
# is what makes a chain carry two contradicting severities.


def score_path(G, path, ease, exec_count, data_access_enabled,
               workspace_sharing=False, alerting_verified=False):
    tier = G.nodes.get(path[-1]["dst"], {}).get("classification", "UNCLASSIFIED")
    t = TIER_SCORE.get(tier, 5)
    p = principal_count_score(exec_count)
    d = detection_factor(G, path, data_access_enabled, workspace_sharing, alerting_verified)
    return round(t * ease * p * d, 2), tier, t, p, d


def executors(G, path, members_of):
    """Concrete principals who can execute the chain's first privilege-bearing
    step today. MEMBER_OF hops are not privilege steps: if the binding sits on a
    group, everyone in that group's transitive membership can run the chain."""
    for e in path:
        if e["kind"] == "MEMBER_OF":
            continue
        src = e["src"]
        if G.nodes.get(src, {}).get("kind") == "group":
            concrete = [m for m in members_of.get(src, ()) if not m.startswith("group:")]
            return max(1, len(concrete))
        return 1
    return 1


def choose_cut(path, freq):
    """Cheapest severing control = the edge shared by the most reported chains.
    MEMBER_OF is excluded: removing one person from a group severs nothing for
    the rest of the group. Ties break toward the step closest to the start."""
    candidates = [i for i, e in enumerate(path) if e["kind"] != "MEMBER_OF"] or list(range(len(path)))
    return max(candidates,
               key=lambda i: (freq[(path[i]["src"], path[i]["dst"], path[i]["kind"])], -i))


# =================================== output ===================================

def render_path(idx, path, score, tier, ease, exec_count, det, cut_edge):
    lines = []
    lines.append("CH-%02d  rank=%s (ORDERING ONLY - the band comes from 11.1)  "
                 "terminates=%s%s  start-ease=%d  executors=%d  detection-factor=%.2f"
                 % (idx, score, tier,
                    " (assumed CONFIDENTIAL per TF4)" if tier == "UNCLASSIFIED" else "",
                    ease, exec_count, det))
    lines.append("  start: %s" % path[0]["src"])
    for i, e in enumerate(path, 1):
        logged, note = EDGE_DETECTION.get(e["kind"], (True, ""))
        flags = []
        if e.get("conditional"):
            flags.append("CONDITIONAL-BINDING")
        if e.get("deny_note"):
            flags.append(e["deny_note"])
        lines.append("  %d. %s --[%s: %s]--> %s" % (i, e["src"], e["kind"], e["permission"], e["dst"]))
        lines.append("       gains:    %s" % e.get("gains", ""))
        lines.append("       evidence: %s" % e.get("evidence", ""))
        lines.append("       detect:   %s%s" % ("LOGGED (always-on) - " if logged else "NOT LOGGED BY DEFAULT - ", note))
        if flags:
            lines.append("       flags:    %s" % ", ".join(flags))
    lines.append("  CHEAPEST SEVER (step %d): %s" % (cut_edge[0] + 1, cut_edge[1]["sever"]))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iam", action="append", required=True,
                    help="Cloud Asset Inventory export, --content-type=iam-policy (repeatable)")
    ap.add_argument("--resources", action="append", default=[],
                    help="CAI export, --content-type=resource (repeatable)")
    ap.add_argument("--org-policy", action="append", default=[],
                    help="CAI export, --content-type=org-policy (repeatable)")
    ap.add_argument("--deny", action="append", default=[],
                    help="gcloud iam policies list --kind=denypolicies --format=json (repeatable)")
    ap.add_argument("--groups", help="JSON: {group_id: [member, ...]}")
    ap.add_argument("--classification", help="JSON: {asset_name_or_glob: TIER}")
    ap.add_argument("--classification-label", default="data_classification",
                    help="resource label read as a fallback classification (default: data_classification)")
    ap.add_argument("--seeds", help="JSON: {adversary: {principals: [...], ease: 1-5}}")
    ap.add_argument("--roles-map", help="JSON: {role: [permission, ...]} from gcloud iam roles describe")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--max-paths", type=int, default=200, help="per seed principal")
    ap.add_argument("--top", type=int, default=40, help="chains to print")
    ap.add_argument("--data-access-logs-enabled", action="store_true",
                    help="set only if Data Access ADMIN_READ/DATA_READ is enabled org-wide")
    ap.add_argument("--workspace-log-sharing", action="store_true",
                    help="set only if Google Workspace data sharing with Google Cloud is on "
                         "(this, not Data Access logs, is what makes MEMBER_OF visible)")
    ap.add_argument("--alerting-verified", action="store_true",
                    help="set only if an alerting policy exists on every always-on method "
                         "used by these chains; without it D floors at 1.25 per 6.3.2")
    ap.add_argument("--drop-conditional", action="store_true",
                    help="ignore conditional role bindings instead of counting them")
    ap.add_argument("--keep-denied", action="store_true",
                    help="keep edges an IAM deny policy blocks (marked), instead of removing them")
    ap.add_argument("--json-out", help="write the full graph + ranked paths here")
    args = ap.parse_args(argv)

    args.roles_map = load_json_file(args.roles_map, {}) or {}
    model = Model(args)
    model.classification = {k: v for k, v in (load_json_file(args.classification, {}) or {}).items()}
    groups = load_json_file(args.groups, {}) or {}
    members_of, groups_of = build_group_maps(groups)
    model.groups = groups

    for path in args.resources:
        for rec in load_records(path):
            model.ingest_asset(rec)
    for path in args.iam:
        for rec in load_records(path):
            model.ingest_asset(rec)
    for path in args.org_policy:
        for rec in load_records(path):
            model.ingest_org_policy(rec)
    for path in args.deny:
        for rec in load_records(path):
            model.ingest_deny(rec)

    # A project-level impersonation binding confers impersonation of EVERY service
    # account in the project. Any SA seen only as a member string must still become
    # a node, or the IMPERSONATE / DEPLOY_AS / KEY_MINT edge classes vanish silently
    # on a run with no --resources export.
    for (member, _perm) in list(model.holdings):
        if not member.startswith("serviceAccount:"):
            continue
        email = member.split(":", 1)[1]
        if email in model.sa_emails or "gserviceaccount.com" not in email:
            continue
        model.sa_emails[email] = None       # project unknown from the email alone
        sys.stderr.write("# SA %s inferred from a binding; absent from the resource "
                         "export - its own project chain is unknown\n" % email)
    if not args.resources:
        sys.stderr.write("# WARNING: no --resources export. Service accounts, custom roles "
                         "and data assets are only partially discoverable; the "
                         "impersonation/actAs/key-mint edge classes are UNDER-COUNTED. "
                         "Produce artifact row 8 (SA inventory) before quoting any score.\n")

    G = build_graph(model, groups, members_of, groups_of)

    # seeds
    if args.seeds:
        seeds = load_json_file(args.seeds)
    else:
        # One seed set per principal KIND, with the §6.3.2 ease ladder. Collapsing
        # A1-A7 into one label discards the E factor, and omitting the SA kinds
        # means A4 (leaked SA key) and A6 (workload -> metadata token) are never
        # seeded at all. This is still a stand-in for the real §4.5 positions.
        DEFAULT_EASE = {"public": 5, "federated": 5, "group": 4, "human": 3,
                        "sa_default_compute": 3, "sa_default_appengine": 3,
                        "sa_default_cloudbuild": 3, "sa_service_agent": 2,
                        "ksa": 4, "sa_user_managed": 3}
        seeds = {}
        for nid, n in G.nodes.items():
            k = n["kind"]
            if k not in DEFAULT_EASE:
                continue
            label = "auto_%s" % k
            seeds.setdefault(label, {"principals": [], "ease": DEFAULT_EASE[k]})
            seeds[label]["principals"].append(nid)
        sys.stderr.write("# NO --seeds FILE: seeding by principal kind with default ease "
                         "values. These are NOT the A1-A7 starting positions from the "
                         "threat model - supply --seeds before quoting any score.\n")

    all_paths = []
    reach_report = []
    recorded_not_ranked = set()          # (seed, resource, tier) for INTERNAL/PUBLIC termini
    for adversary, spec in sorted(seeds.items()):
        ease = int(spec.get("ease", 3))
        present = [s for s in spec.get("principals", []) if s in G.nodes]
        reached = closure(G, present)
        ids = sorted(n for n in reached
                     if G.nodes.get(n, {}).get("kind") in
                     ("human", "group", "sa_user_managed", "sa_default_compute",
                      "sa_default_appengine", "sa_default_cloudbuild", "sa_service_agent",
                      "ksa", "federated"))
        terminals = sorted(n for n in reached
                           if G.nodes.get(n, {}).get("classification") in TERMINAL_TIERS)
        reach_report.append({"adversary": adversary, "ease": ease, "seeds": present,
                             "identities_reached": ids, "data_reached": terminals})
        for seed in spec.get("principals", []):
            if seed not in G.nodes:
                print("# seed not present in the evidence: %s (%s)" % (seed, adversary),
                      file=sys.stderr)
                continue
            for path in enumerate_paths(G, seed, args.max_depth, args.max_paths,
                                        recorded_not_ranked):
                exec_count = executors(G, path, members_of)
                score, tier, t, p, d = score_path(G, path, ease, exec_count,
                                                  args.data_access_logs_enabled,
                                                  args.workspace_log_sharing,
                                                  args.alerting_verified)
                all_paths.append({"adversary": adversary, "seed": seed, "ease": ease,
                                  "path": path, "score": score, "tier": tier,
                                  "executors": exec_count, "detection_factor": d})

    # cheapest sever = the edge shared by the most reported chains, earliest first
    freq = collections.Counter()
    for rec in all_paths:
        for e in rec["path"]:
            freq[(e["src"], e["dst"], e["kind"])] += 1
    for rec in all_paths:
        rec["cut_index"] = choose_cut(rec["path"], freq)

    all_paths.sort(key=lambda r: (-r["score"], len(r["path"]),
                                  r["path"][0]["src"], r["path"][-1]["dst"]))

    print("# privgraph: %d nodes, %d edges, %d chains reaching CONFIDENTIAL/NTK/UNCLASSIFIED data"
          % (len(G.nodes), len(G.edges), len(all_paths)))
    print("# ranking = tier(%s) x start-ease(1-5) x executor-count(1-5) x detection-factor(1.0/1.25/1.5)"
          % "/".join("%s=%d" % (k, v) for k, v in sorted(TIER_SCORE.items())))
    print()
    print("# REACHABILITY TO FIXPOINT (transitive closure, unbounded depth)")
    for r in reach_report:
        print("#   %-24s seeds=%d -> %d identities, %d classified data resources"
              % (r["adversary"], len(r["seeds"]), len(r["identities_reached"]),
                 len(r["data_reached"])))
        for ident in r["identities_reached"]:
            print("#       becomes: %s" % ident)
    print()
    for i, rec in enumerate(all_paths[:args.top], 1):
        print("adversary %s / starting principal %s" % (rec["adversary"], rec["seed"]))
        print(render_path(i, rec["path"], rec["score"], rec["tier"], rec["ease"],
                          rec["executors"], rec["detection_factor"],
                          (rec["cut_index"], rec["path"][rec["cut_index"]])))
        print()

    print("# TOP CUTS - remove these edges first; each number is how many reported chains die")
    for (src, dst, kind), n in freq.most_common(15):
        print("#   %3d chains  %s --[%s]--> %s" % (n, src, kind, dst))

    if recorded_not_ranked:
        print("\n# RECORDED, NOT RANKED (INTERNAL/PUBLIC terminals) - 6.1.5 point 4")
        for seed, dst, tier in sorted(recorded_not_ranked):
            print("#   %s reaches %s (%s)" % (seed, dst, tier))

    if model.unexpanded:
        print("\n# UNEXPANDED ROLES - resolve with `gcloud iam roles describe ROLE --format=json`",
              file=sys.stderr)
        for role, n in model.unexpanded.most_common():
            print("#   %s (%d bindings)" % (role, n), file=sys.stderr)

    if args.json_out:
        out = {
            "nodes": list(G.nodes.values()),
            "edges": G.edges,
            "rank_score_note": ("rank_score orders chains; it is NOT a severity band. "
                                "Band every CH- finding with 11.1.5 / 11.1.8."),
            "paths": [{"adversary": r["adversary"], "seed": r["seed"], "rank_score": r["score"],
                       "assumed_confidential": r["tier"] == "UNCLASSIFIED",
                       "tier": r["tier"], "ease": r["ease"],
                       "executors": r["executors"], "detection_factor": r["detection_factor"],
                       "cut_index": r["cut_index"],
                       "steps": [{"src": e["src"], "dst": e["dst"], "kind": e["kind"],
                                  "permission": e["permission"], "evidence": e.get("evidence"),
                                  "gains": e.get("gains"), "sever": e.get("sever"),
                                  "conditional": bool(e.get("conditional")),
                                  "deny_note": e.get("deny_note")} for e in r["path"]]}
                      for r in all_paths],
            "reachability": reach_report,
            "recorded_not_ranked": [{"seed": s, "resource": d, "tier": t}
                                    for (s, d, t) in sorted(recorded_not_ranked)],
            "unexpanded_roles": dict(model.unexpanded),
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Feed the script's `TOP CUTS` block straight into the remediation roadmap, and re-run it after each
proposed change: a fix that does not reduce the reported chain count did not sever anything. Carry
its `UNEXPANDED ROLES` list and the §6.1.6 residual-blind-spot list into the report appendix — both
are statements about what this phase did **not** see.

---

## 7. Lateral movement and traversal

The privilege graph (see §6) covers identity
traversal. This phase covers **system and network traversal**. Run it as three separate
enumerations — cloud→cloud, cloud→on-prem, on-prem→cloud — then join the result to the privilege
graph in §7.4. Do not merge them earlier: a hop you cannot name a port and a control for is not a
hop, it is a guess.

Two rules govern every test below.

1. **Reachability is proven from effective state, never from intent.** Use
   `gcloud compute networks get-effective-firewalls` and
   `gcloud compute instances network-interfaces get-effective-firewalls`, never
   `gcloud compute firewall-rules list` — the latter shows only classic VPC rules and misses every
   hierarchical and network-firewall-policy rule.
2. **Absence of evidence is a finding, not a pass.** If the reviewer cannot obtain the on-prem
   route table, the interior service inventory, or the runner-to-repository map, record the gap as
   an interview-derived finding at the severity the worst plausible answer would earn, and mark it
   `EVIDENCE-GAP`.
3. **§7 test severities are inputs, not verdicts.** Every `LM-` test is emitted as an `NW-`, `CE-`
   or `CD-` finding (routing table in §11.2.1) and banded by §11.1.8 against that environment's
   `T`/`X`/`P`/`S`/`D`. No `LM-` row states a final severity, and a severity word appearing in one
   is a description of the usual case, never the band you ship.

### 7.0 Firewall evaluation order — read before scoring any network hop

Default enforcement order is `AFTER_CLASSIC_FIREWALL`, which evaluates in this sequence:

1. Hierarchical firewall policy on the **organization**
2. Hierarchical firewall policies on **folder ancestors**, top-level folder downward
3. Regional **system** firewall policies (Google-managed, read-only)
4. **VPC firewall rules** (classic)
5. Global network firewall policy
6. Regional network firewall policies
7. Implied action — ingress to VMs `deny`, **ingress to load balancers `allow`**, **all egress `allow`**

Consequence you must test for: **an `allow` in a classic VPC firewall rule pre-empts a `deny` in a
global or regional network firewall policy.** A default-deny built only in a network firewall policy
is silently void wherever a leftover permissive classic rule matches first. Fix is to set the VPC
network's `networkFirewallPolicyEnforcementOrder` to `BEFORE_CLASSIC_FIREWALL` (the gcloud flag is
reported as `--policy-enforcement-order` — verify against current docs).

Also assume nothing about predefined rules: what a Console-created policy ships with, and what a
gcloud/Terraform/API-created policy does not, is recorded once in §5.2 (*Observe*, item 6). Read it
before crediting a threat-intelligence or geo deny you have not seen in the effective rule set.

---

### 7.1 Cloud → cloud (east-west)

#### 7.1.1 Workload → metadata server → SA token → other services

**Enumerate.**

```bash
# every VM, its attached SA, and its scopes
gcloud compute instances list --project=P \
  --format="table(name,zone,serviceAccounts[0].email,serviceAccounts[0].scopes.list())"

# serverless runtime identities
gcloud run services list --project=P --format="table(metadata.name,spec.template.spec.serviceAccountName)"
gcloud run jobs list --project=P --format="table(metadata.name,spec.template.spec.template.spec.serviceAccountName)"
gcloud functions list --project=P --format="table(name,serviceAccountEmail)"

# GKE node pools
gcloud container node-pools list --cluster=C --location=L --format="table(name,config.serviceAccount)"

# data/ML runtimes that carry an SA
gcloud composer environments list --locations=L --format=json
gcloud dataproc clusters list --region=R --format="table(clusterName,config.gceClusterConfig.serviceAccount)"
gcloud dataflow jobs list --region=R --format=json
gcloud workbench instances list --location=L --format=json     # verify command spelling against current docs

# schedulers, queues and the legacy deployment service - each is an actAs surface (6.2.2)
gcloud scheduler jobs list --location=L \
    --format="table(name,httpTarget.oidcToken.serviceAccountEmail,httpTarget.oauthToken.serviceAccountEmail)"
gcloud tasks queues list --location=L --format=json    # then read each task's oidcToken/oauthToken SA
gcloud deployment-manager deployments list --format=json   # legacy; runs as PROJECT_NUMBER@cloudservices.gserviceaccount.com
```

**Facts that decide the finding.**

| Fact | Value |
|---|---|
| Token endpoint | `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` (also `http://metadata.google.internal/...`, IPv6 `http://[fd20:ce::254]/...`) |
| ID-token endpoint | `.../instance/service-accounts/default/identity?audience=AUDIENCE` |
| Required header | `Metadata-Flavor: Google` |
| **Network control available on plain GCE** | **None.** "Google Cloud always allows communication between a VM instance and its corresponding metadata server at `169.254.169.254`" — metadata traffic is in the always-allowed set and bypasses firewall rules entirely. A `deny` rule to `169.254.169.254` is not a mitigation and its presence in a design signals the author does not know this. |
| Only real mitigations | OS-level firewalling in the guest; GKE Workload Identity Federation for GKE (its metadata server intercepts `169.254.169.254:80`); GKE NetworkPolicy denying `169.254.169.254/32`. |
| Scope × IAM | Access scopes are the **maximum** for tokens from the metadata server; the request must be permitted by scope **and** by IAM. Scopes are a coarse legacy backstop, not the control — a custom SA with least-privilege IAM is. |

**Finding tests.**

- **LM-1** — any SA email appears as the runtime identity of **more than one deployment unit**
  (two different services, not two replicas of one service). Severity scales with the highest
  classification either unit can read: the compromise of the weaker unit yields the stronger unit's
  identity.
- **LM-2** — runtime identity is `PROJECT_NUMBER-compute@developer.gserviceaccount.com` or
  `PROJECT_ID@appspot.gserviceaccount.com`. Confirm whether that SA holds `roles/editor` by reading
  the project allow policy; check `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`
  (baseline-enforced on orgs created on/after 2024-05-03) and
  `constraints/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` (closes the manual
  re-grant the first constraint does not cover). Default SA + Editor = any RCE in that workload is a
  project takeover. ATT&CK: T1078.001, T1552.005.
- **LM-3** — a workload with **no** legitimate Google-API dependency runs with an attached SA at
  `cloud-platform` scope. Every such workload is an SSRF-to-token pivot with no compensating
  network control.
- **LM-4** — Cloud Build: the build runs as the **Compute Engine default SA** (the default for new
  projects since the May–June 2024 change) rather than a user-specified SA. The old check "does the
  Cloud Build legacy SA hold `roles/cloudbuild.builds.builder`" is now the wrong check. Controlling
  constraints: `constraints/cloudbuild.useBuildServiceAccount`,
  `constraints/cloudbuild.useComputeServiceAccount`.

**Control that should stop this hop:** a dedicated least-privilege SA per deployment unit, so the
token obtained is worth only that unit's data. Nothing at the network layer stops metadata access on
GCE — state that explicitly rather than recommending a firewall rule.

#### 7.1.2 Flat-VPC reachability from a compromised subnet

**Enumerate.**

```bash
gcloud compute networks get-effective-firewalls NETWORK --project=HOST_PROJECT --format=json
gcloud compute instances network-interfaces get-effective-firewalls INSTANCE \
  --network-interface=nic0 --zone=ZONE --project=P --format=json
gcloud compute network-firewall-policies list --project=P
gcloud compute firewall-policies list --organization=ORG_ID           # hierarchical: org/folder only
gcloud compute networks subnets list --project=P \
  --format="table(name,region,ipCidrRange,privateIpGoogleAccess,enableFlowLogs)"
```

Pick one representative instance **per subnet** and per secure-tag/SA grouping; the effective rule
set differs per NIC, so a network-level dump alone will not answer "what can this workload reach".

**Finding tests.**

- **LM-5 (flat VPC)** — for a given compromised subnet, compute the set of destination
  address/port pairs allowed by the effective rule set. If that set includes any RFC1918 supernet
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or the whole VPC CIDR on `tcp:all`/`all`, the
  VPC is flat east-west. This is a lateral-movement finding, not hygiene.
- **LM-6 (key type)** — classify every intra-VPC `allow` rule by what it is keyed on:

  | Key | Where usable | IAM gate on the key |
  |---|---|---|
  | **Secure tags** (`--src-secure-tags`, `--target-secure-tags`, value form `tagValues/281476494128717`) | hierarchical + global/regional network policies; **not** classic VPC rules | `roles/resourcemanager.tagAdmin` to create, **`roles/resourcemanager.tagUser`** to bind and to use in rules (atomic permission strings `resourcemanager.tagValues.use`, `resourcemanager.tagValueBindings.create` — verify against current docs) |
  | **Service accounts** (`--source-service-accounts`, `--target-service-accounts`) | classic rules **and** policies | requires `compute.instances.setServiceAccount` + `iam.serviceAccounts.actAs` to attach |
  | **Network tags** (`--source-tags`, `--target-tags`) | **classic VPC rules only** | **none** — any principal with `compute.instances.setTags` (in `roles/compute.instanceAdmin.v1`) can move a VM into a permissive scope |
  | **IP ranges** | everywhere | none — the key is the subnet, so any workload placed there inherits it |

  Every rule keyed on **network tags** or on **IP ranges** is a finding when it grants east-west
  reach to a workload holding or adjacent to CONFIDENTIAL/NTK data: neither key agrees with identity,
  and the network-tag key is a documented privilege-escalation path (no per-tag IAM).
  Also flag the schema constraint that hides mixed intent: `source_tags`/`target_tags` **cannot** be
  combined with `source_service_accounts`/`target_service_accounts` in one classic rule.
- **LM-7 (order bypass)** — the network has a network-firewall-policy `deny` that a classic `allow`
  pre-empts under `AFTER_CLASSIC_FIREWALL`. Prove it from the effective-firewall output: the classic
  rule appears ahead of the policy rule for the same 5-tuple.
- **LM-8 (auto-mode leftovers)** — the `default` network still exists, carrying priority-65534
  `default-allow-internal` (all TCP/UDP + ICMP from `10.128.0.0/9`), `default-allow-ssh`
  (`tcp:22` from `0.0.0.0/0`), `default-allow-rdp` (`tcp:3389` from `0.0.0.0/0`),
  `default-allow-icmp`. Remediate with `constraints/compute.skipDefaultNetworkCreation` plus
  deletion.
- **LM-9 (logging blind spot)** — implied rules cannot be logged, and VPC Flow Logs sample **egress
  before** egress rules but **ingress after** ingress rules: a blocked egress attempt is visible, a
  blocked ingress attempt is not. Record which east-west hops would leave no evidence.

**Control that should stop this hop:** a folder-level hierarchical firewall policy with a
low-priority intra-VPC `deny`, plus per-dependency `allow` rules keyed on secure tags or service
accounts, with `enable_logging = true`, and the network set to `BEFORE_CLASSIC_FIREWALL`.

#### 7.1.3 SSH / RDP / serial / IAP paths to a shell

**Enumerate.**

```bash
gcloud compute project-info describe --project=P --format="value(commonInstanceMetadata.items)"
gcloud compute instances describe INSTANCE --zone=Z --format="value(metadata.items)"
gcloud org-policies describe constraints/compute.requireOsLogin --effective --project=P
gcloud org-policies describe constraints/compute.disableSerialPortAccess --effective --project=P
gcloud asset analyze-org-policies --constraint=constraints/compute.requireOsLogin --scope=organizations/ORG_ID
# who can tunnel:
gcloud projects get-iam-policy P --format=json | jq '.bindings[] | select(.role=="roles/iap.tunnelResourceAccessor")'
```

**Finding tests.**

- **LM-10 (OS Login opt-out)** — project metadata sets `enable-oslogin=TRUE` but
  `constraints/compute.requireOsLogin` (or `constraints/compute.managed.requireOsLogin`) is not
  enforced at an ancestor. Setting `enable-oslogin=FALSE` in **instance** metadata disables OS Login
  for that VM even when project metadata says `TRUE`, so anyone with `compute.instances.setMetadata`
  opts a VM out and re-enables metadata SSH keys. ATT&CK: T1098.004.
- **LM-11 (metadata key injection)** — enumerate holders of `compute.instances.setMetadata`
  (`roles/compute.admin`, `roles/compute.instanceAdmin.v1`) and of
  **`compute.projects.setCommonInstanceMetadata`** (`roles/compute.admin`). The second writes
  project-wide `ssh-keys` and `serial-port-enable` — one grant, every VM in the project. Google's own
  framing: metadata permissions are "the equivalent of providing access to the core content on an
  instance". Every holder is an edge into every VM's attached SA.
- **LM-12 (2FA half-configured)** — `enable-oslogin-2fa` set without `enable-oslogin`, or vice
  versa. Both must be `TRUE` for OS Login 2FA to be enforced.
- **LM-13 (serial console)** — `serial-port-enable=TRUE` at project or instance level, or
  `constraints/compute.disableSerialPortAccess` / `constraints/compute.managed.disableSerialPortAccess`
  unenforced. The interactive serial console **"does not support IP-based access restrictions such
  as IP allowlists"**: it bypasses VPC firewall rules, authorized networks, private nodes and IAP.
  Endpoint is `REGION-ssh-serialport.googleapis.com:9600` via `gcloud compute connect-to-serial-port`.
  Also check `constraints/compute.disableGlobalSerialPortAccess` and
  `constraints/compute.disableInstanceDataAccessApis` (disables `GetSerialPortOutput` and
  `GetScreenshot` — both read data out of a VM through the control plane with no network path at all).
- **LM-14 (IAP tunnel scope)** — `roles/iap.tunnelResourceAccessor` bound at **project** level
  rather than on specific instances/tunnel resources. That is a shell on every VM in the project for
  every holder. Ingress source range for the tunnel is `35.235.240.0/20` (IPv6
  `2600:2d00:1:7::/64`); permission is `iap.tunnelInstances.accessViaIAP`; IAP disconnects after one
  hour of inactivity. IAP **admin** changes are audited under `iap.googleapis.com`; for
  per-connection tunnel-authorization events, verify the exact method name and log type against
  current docs — there is no documented `AuthorizeUser` method.
- **LM-15 (bastion design)** — a bastion/jump host with an attached SA, reachable from more than the
  admin source set, is two hops (shell → metadata token), not one. Bastions must run with no attached
  SA, or with an SA holding nothing.
- **LM-16** — `constraints/compute.disableSshInBrowser` unenforced leaves console SSH-in-browser as
  an access path outside the IAP audit surface.

#### 7.1.4 GKE

**Enumerate.**

```bash
gcloud container clusters describe C --location=L --format=json > cluster.json
# read: workloadIdentityConfig.workloadPool ; nodePools[].config.workloadMetadataConfig.mode ;
#       nodePools[].config.serviceAccount ; nodePools[].config.oauthScopes ;
#       networkPolicy / datapathProvider ; masterAuthorizedNetworksConfig ;
#       privateClusterConfig ; binaryAuthorization.evaluationMode
#       (control-plane endpoint field paths are newer — verify against current docs)
kubectl get networkpolicy -A
kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | {name:.metadata.name, subjects}'
kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | .metadata.name'
```

**Finding tests.**

- **LM-17 (pod → node SA)** — any node pool with `--workload-metadata=GCE_METADATA` (Workload
  Identity Federation for GKE off). Every pod on that pool can `curl` the metadata server and
  retrieve: the **node SA's OAuth token**, `.../instance/attributes/kube-env` (**kubelet bootstrap
  credentials**), and the node's instance identity token. If the node pool runs on the Compute Engine
  default SA — the default when `--service-account` is not passed — a single container RCE is
  project-wide compromise. ATT&CK: T1552.005, T1552.007.
- **LM-18 (metadata concealment)** — `--workload-metadata-from-node=SECURE` in use. Metadata
  concealment is beta and **deprecated**, is **incompatible** with Workload Identity Federation for
  GKE, and — verbatim — **"does not restrict access to the node's service account."** It is not a
  control. Removal version is not stated (verify against current docs).
- **LM-19 (hostNetwork bypass)** — Workload Identity is on but pods with `hostNetwork: true` exist.
  Those pods bypass the GKE metadata server and reach `169.254.169.254` directly. A PodSecurity
  admission or Policy Controller rule forbidding `hostNetwork`, `hostPID`, `privileged` and
  `hostPath` is **part of** the Workload Identity control, not a separate hardening item.
  PodSecurityPolicy no longer exists.
- **LM-20 (open pod network)** — **"By default, all Pods within a cluster can communicate with each
  other freely."** Any namespace with no NetworkPolicy selecting its pods is fully open. Check which
  engine is in use: GKE Dataplane V2 (Cilium-based; recommended, and the Autopilot default) or Calico
  (`--enable-network-policy`; Standard only, the legacy option — the docs do **not** call it
  deprecated, so do not claim that). The two are mutually exclusive.
- **LM-21 (FQDN policy mistaken for egress control)** — `FQDNNetworkPolicy`
  (`networking.gke.io/v1alpha1`, i.e. alpha) used as an exfil control. It caps at 50 IPs per policy,
  leaves DNS queries unrestricted, and leaks on shared/CDN IPs ("allowing one domain permits access
  to all domains on that address"). Hygiene, not a boundary.
- **LM-22 (RBAC → cluster-admin)** — GKE checks RBAC **first**, then IAM: *"To authorize an action,
  GKE checks for an RBAC policy first. If there isn't an RBAC policy, GKE checks for IAM
  permissions."* You cannot audit one without the other. Flag `roles/container.admin`,
  `roles/container.clusterAdmin` and `roles/container.developer` bound at **project or folder** —
  that is cluster-admin-equivalent on every cluster in scope, and the docs explicitly warn that
  `roles/container.developer` "presents escalation hazards" and that "the ability to create pods
  combined with node service account access creates a privilege-elevation pathway". Also flag any
  `ClusterRoleBinding` to `cluster-admin` whose subject is a workload KSA.
- **LM-23 (control-plane exposure)** — checking only `--enable-private-endpoint` and authorized
  networks is now **insufficient**. The three control-plane endpoints — DNS-based
  (`--enable-dns-access`), public IP-based (`--enable-ip-access`) and private IP-based — are
  independently switchable at any time, including after creation. A cluster can be "private" by the
  old definition and still be reachable via the DNS-based endpoint. Check all three states.
- **LM-24 (node SA scopes)** — a Standard cluster using a custom SA with no manually specified
  scopes receives `userinfo.email` and **`cloud-platform`**. All restriction must therefore come from
  IAM on the SA, not from scopes; access scopes are the documented **legacy** method and Google
  recommends not specifying your own. The minimal node-SA role set commonly cited
  (`roles/logging.logWriter`, `roles/monitoring.metricWriter`, `roles/monitoring.viewer`,
  `roles/stackdriver.resourceMetadata.writer`, `roles/artifactregistry.reader`) — verify against
  current docs.
- **LM-25 (Shared VPC image pulls)** — for Shared VPC clusters, Private Google Access must be
  enabled manually; GKE only enables it automatically for non-Shared-VPC clusters. A cluster patched
  around this with a NAT or proxy has an egress path that must be reviewed as one.

#### 7.1.5 Shared VPC

**Enumerate.** Identify the host project(s) and each attached service project; list which subnets
each service project may use; then run the effective-firewall check from an instance in each service
project.

**Finding tests.**

- **LM-26** — two service projects place workloads on the same subnet (or on subnets mutually
  reachable under the effective rule set) with no rule distinguishing them. Because firewall rules
  live in the **host** project, service-project owners cannot fix this themselves; the finding is
  owned by the network team.
- **LM-27** — `constraints/compute.restrictSharedVpcSubnetworks` unset, so any service project can
  attach workloads into a trusted subnet. Values are
  `projects/PROJECT_ID/regions/REGION/subnetworks/SUBNET_NAME` and `under:organizations/ORGANIZATION_ID`.
- **LM-28** — `constraints/compute.restrictSharedVpcHostProjects` unset, so a project can attach to
  an unapproved host network.
- **LM-29** — east-west rules in the host project keyed on IP ranges, which cannot distinguish
  service projects at all. Service-account-keyed rules do work across projects when the SA is
  attached to the instance; secure tags are the other identity-agreeing key.

#### 7.1.6 Cross-project

**Enumerate.**

```bash
gcloud asset export --organization=ORG_ID --content-type=iam-policy \
  --output-path=gs://EVIDENCE_BUCKET/iam-policies.json
# then: every binding whose member is serviceAccount:*@OTHER_PROJECT.iam.gserviceaccount.com
gcloud organizations get-iam-policy ORG_ID --format=json
gcloud compute routes list --project=P --format="table(name,destRange,nextHopPeering,nextHopGateway,nextHopVpnTunnel)"
gcloud compute networks peerings list --network=NETWORK --project=P   # verify against current docs
gcloud asset analyze-iam-policy --organization=ORG_ID --analyze-service-account-impersonation
```

**Finding tests.**

- **LM-30** — `constraints/iam.disableCrossProjectServiceAccountUsage` unenforced. This is what
  blocks attaching a high-privilege SA from project A to an attacker-controllable VM in project B.
- **LM-31** — any project IAM binding whose member is a service account from a **different project**.
  Record the pair, the role, and the classification of data reachable in the target project. These
  are the edges that make "project-per-workload" cosmetic.
- **LM-32** — any binding at the **organization** or a **folder** node granting a data-read or
  impersonation role. Org-level bindings span every project silently and never appear in a project's
  policy. Cross-check with `gcloud asset analyze-iam-policy`.
- **LM-33** — VPC peering exists to a network outside the reviewed scope, or
  `constraints/compute.restrictVpcPeering` is unset (values `under:organizations/ORG_ID`,
  `under:folders/FOLDER_ID`, `under:projects/PROJECT_ID`). Peering is a full private data bridge that
  the API-layer perimeter does not address.
- **LM-34** — snapshot/image and storage-resource sharing across projects:
  `constraints/compute.storageResourceUseRestrictions` and `constraints/compute.trustedImageProjects`
  unset. Snapshot → share → restore elsewhere is a data path with no network hop at all
  (ATT&CK T1578.001).

---

### 7.2 Cloud → on-prem (into the soft interior)

#### 7.2.1 What the link actually permits, diffed against intent

**Enumerate the ACTUAL, both directions.**

```bash
# links
gcloud compute interconnects list --project=P
gcloud compute interconnects attachments list --project=P --region=R
gcloud compute vpn-tunnels list --project=P
gcloud compute routers list --project=P

# what we advertise and what we learn, per BGP session, pre- and post-policy
gcloud compute routers get-status ROUTER_NAME --project=P --region=R      # verify flags against current docs
gcloud compute routers list-bgp-routes ROUTER_NAME --region=R --peer=PEER_NAME \
  --route-direction=ADVERTISED --address-family=IPV4
gcloud compute routers list-bgp-routes ROUTER_NAME --region=R --peer=PEER_NAME \
  --route-direction=LEARNED --address-family=IPV4 --policy-applied

# effective routes in the VPC
gcloud compute routes list --project=P --format="table(name,destRange,priority,nextHopVpnTunnel,nextHopIlb,nextHopPeering)"
```

Advertisement configuration lives at two levels and the lower one **overrides completely**:

```bash
gcloud compute routers update ROUTER --region=R \
  --advertisement-mode custom --set-advertisement-groups=all_subnets \
  --set-advertisement-ranges=199.36.153.4/30,2600:2d00:0002:1000::/56
gcloud compute routers update-bgp-peer ROUTER --peer-name=PEER \
  --advertisement-mode custom --set-advertisement-ranges=...
```

> Verbatim rule: *"if you specify any custom advertised route on a BGP session, all of the Cloud
> Router's advertised routes are ignored and overridden by the BGP session's custom advertised
> route."* This is the usual cause of "we advertised the restricted VIP but on-prem still can't
> reach it". `--advertised-groups` is not the current flag name; use
> `--set-advertisement-groups` / `--add-advertisement-ranges`. The gcloud value is lower-case
> `all_subnets` (API enum `ALL_SUBNETS`).

**Build the INTENDED table** from the network design document, the Terraform for the routers/peers,
and the firewall change record. Columns: direction | source prefix | destination prefix | protocol
and ports | business flow it serves | approver | ticket.

**Finding tests.**

- **LM-35** — **the diff is the finding.** Every ACTUAL row absent from INTENDED is a finding, one
  per row, titled with the specific prefix pair. Do not summarize as "routes are broader than
  intended".
- **LM-36** — no INTENDED table exists. Then the entire advertised set is unreviewed; raise one
  `EVIDENCE-GAP` finding and score reachability against the full advertised set.
- **LM-37** — Dedicated or Partner Interconnect carrying CONFIDENTIAL data with **no encryption**.
  Interconnect is **not encrypted by default**; HA VPN over Cloud Interconnect is the documented
  encryption story. Classic VPN in use is a separate finding (deprecated; move to HA VPN).
  Also check `constraints/compute.managed.allowedVlanAttachmentEncryption`,
  `constraints/compute.restrictDedicatedInterconnectUsage`,
  `constraints/compute.restrictPartnerInterconnectUsage`, `constraints/compute.restrictVpnPeerIPs`.
- **LM-38** — cross-region asymmetric routes back to on-prem: Google Cloud does not support them;
  a topology that implies them is a reliability **and** an evidence problem (return traffic you
  cannot account for).
- **LM-39 (which cloud subnets can originate)** — the originating set is the intersection of
  (subnets covered by advertised ranges) and (subnets whose effective egress rules permit the on-prem
  CIDRs). Compute it explicitly. Any subnet in that set that hosts a non-hybrid workload is a
  finding: it has link access it does not need.

#### 7.2.2 Assume-breach: what a compromised cloud workload reaches inside

On-prem facts cannot be enumerated with `gcloud`. Ask these questions verbatim and record the
answers as evidence:

1. *"List every on-premises CIDR reachable from any Google Cloud subnet today, and the TCP/UDP ports
   open to it. If you cannot produce this list, say so — we will treat the entire on-premises RFC1918
   space as reachable on all ports."*
2. *"For each interior service in that reachable set, what does it check on an inbound connection:
   an mTLS client certificate, a Kerberos/AD ticket, an OIDC or SAML token, a signed request, a
   static shared secret, a source-IP allowlist, or nothing?"*
3. *"Which of those services hold or can retrieve data classified CONFIDENTIAL or NTK?"*
4. *"Which interior segments are separated from each other by an enforcing device, as opposed to by
   VLAN convention?"*

**The rule, stated as the skill enforces it:** *every interior service reachable from a Google Cloud
subnet that authorizes callers on network position — source-IP allowlist, "it's on the corp LAN", a
static shared secret, or no check at all — is a finding.* Network position is cheap to obtain in a
soft interior, and a compromised cloud workload obtains it for free by riding the link.

**Test that proves it** (run with the interior team, from a cloud VM in the reachable subnet, using
an identity with **no** interior entitlement):

```bash
# L3/L4 reachability
nc -vz -w 3 INTERIOR_HOST PORT
nmap -Pn -sT -p 22,88,135,139,389,445,636,1433,1521,3268,3306,5432,5985,8080,8443,9200 INTERIOR_CIDR

# authorization test — does it answer without a credential?
curl -sS -o /dev/null -w '%{http_code}\n' http://INTERIOR_HOST:PORT/PATH
smbclient -L //INTERIOR_HOST -N
ldapsearch -x -H ldap://INTERIOR_HOST -b '' -s base
```

A `200`, a directory listing, or a successful anonymous bind from an unentitled cloud workload is
proof of network-position trust — attach the transcript to the finding.

**Finding tests.**

- **LM-40** — one finding per network-position-trusting interior service reachable from cloud,
  naming host, port, protocol, and what it holds.
- **LM-41** — interior segmentation is asserted but not enforced (VLANs without an enforcing device
  between them). Then reachability to one interior host is reachability to the segment.
- **LM-42** — no cloud-side egress restriction toward on-prem at all (effective egress permits the
  on-prem CIDRs from every subnet). The link should be reachable only from named subnets carrying
  hybrid workloads, keyed by secure tag or SA.

#### 7.2.3 CONFIDENTIAL data flowing cloud → interior (the core turtle risk)

**Enumerate every flow.** Sources: scheduled BigQuery extracts and `EXPORT DATA`, Storage Transfer
jobs, Dataflow/Composer pipelines, database replication, SFTP/SMB drops, message-bus bridges, backup
jobs, reporting extracts, and any file the interior pulls rather than cloud pushes.

Record per flow: source resource + its classification label | mechanism | schedule | destination
interior system and path | who can trigger it off-schedule | what the destination's access control is.

**Finding tests.**

- **LM-43 (unbounded landing zone)** — the interior destination is readable by a larger principal
  set than the cloud source. Quantify: count principals with read on the source resource
  (`gcloud asset analyze-iam-policy --full-resource-name=... --permissions=storage.objects.get`) and
  count members of the AD group / share ACL on the destination. Destination count > source count is
  the finding, stated with both numbers.
- **LM-44 (classification does not travel)** — the interior landing zone carries no classification
  marking, no retention limit, and no DLP/discovery coverage. The data has left the boundary where
  controls exist and entered one where they do not. State this per flow, not once.
- **LM-45 (ad-hoc trigger)** — the flow can be run off-schedule by a principal outside the data
  owner's set, i.e. it is an exfil primitive with a legitimate name.
- **LM-46 (VPC-SC does not follow)** — record explicitly, per flow, that the perimeter's jurisdiction
  ends at the API call. VPC Service Controls *"is not designed to enforce comprehensive controls on
  metadata movement"* and *"doesn't block access to any third-party APIs or services on the
  internet"*; it has no view of data at rest on-prem. A perimeter is not a mitigation for LM-43/44.

#### 7.2.4 Interior egress paths that could complete a cloud-started exfil

Even in a hermetic environment, enumerate sanctioned egress and test reachability **from the landing
zone identified in 7.2.3**, not from the interior in general.

| Interior egress path | What to record | Finding when |
|---|---|---|
| Outbound web proxy | allowlist contents, whether TLS inspection is on, who can add a destination | reachable from the landing zone and the allowlist includes any host that accepts uploads (paste sites, code hosts, object storage, webhook relays) |
| Data diode / one-way transfer | direction, the queue it drains, who submits | landing zone can submit, and submissions are not content-classified |
| Media transfer / removable-media station | which hosts may write media, approval flow | landing zone hosts may write, or the approval is self-service |
| Vendor / partner links (site-to-site VPN, MPLS) | remote endpoints, what they may reach | landing zone is inside the reachable set of any vendor link |
| Patch / mirror channels (OS repos, container registries, AV signatures) | direction, whether the mirror host is dual-homed, whether pushes are possible | mirror host is dual-homed and reachable from the landing zone |
| SMTP gateway | attachment size and type limits, DLP on outbound mail | landing zone can send mail with attachments |
| DNS resolvers with internet recursion | which resolvers recurse, from which segments | landing zone can query a recursing resolver — this is an exfil channel that no egress firewall rule inspects |

- **LM-47** — any row above evaluating to "finding" is one finding, chained explicitly to the
  LM-43/44 flow it completes. This is the chain the whole review exists to find: cloud data →
  link → interior landing zone → sanctioned interior egress.
- **LM-48** — the organization asserts "no internet egress" but cannot enumerate the paths above.
  Raise `EVIDENCE-GAP` at the severity of the worst plausible answer.

---

### 7.3 On-prem → cloud (pivot inward)

#### 7.3.1 Where cloud credentials live on the interior

**Hunt these paths** on jump boxes, build agents, admin workstations and config-management masters:

| Artifact | Path / location |
|---|---|
| Application Default Credentials | `~/.config/gcloud/application_default_credentials.json` |
| gcloud credential store | `~/.config/gcloud/credentials.db`, `~/.config/gcloud/access_tokens.db` (verify file names against current docs) |
| Explicit key file | any path named by `GOOGLE_APPLICATION_CREDENTIALS` |
| SA key JSON anywhere | files containing `"type": "service_account"` and `"private_key_id"` |
| Config management | Ansible Vault files, Puppet Hiera eyaml, Chef data bags, Salt pillars |
| CI secrets | GHES Actions secrets, runner host environment files, `.env` in job workspaces |
| Artifact store | Nexus/Artifactory credential stores used to publish to Artifact Registry |
| Vault | HashiCorp Vault GCP secrets engine roles and their bound SAs |

```bash
# interior sweep (run by the platform team; capture host + path + owner + mtime)
find / -xdev \( -name 'application_default_credentials.json' -o -name 'credentials.db' \) 2>/dev/null
grep -rlI --exclude-dir=/proc -e '"type": "service_account"' -e 'BEGIN PRIVATE KEY' / 2>/dev/null
```

**Reconcile against the cloud side** — this is the test that turns a sweep into a finding:

```bash
for SA in $(gcloud iam service-accounts list --project=P --format='value(email)'); do
  gcloud iam service-accounts keys list --iam-account="$SA" --managed-by=user \
    --format="table[no-heading](name,validAfterTime,validBeforeTime)"
done
```

- **LM-49** — any **user-managed** key (`--managed-by=user`) for which no owner can name the host and
  path that holds it. Unaccounted key material is assumed compromised. `system` keys are
  Google-rotated and are not exfiltratable; do not report them.
- **LM-50** — a key file on an interior host whose SA holds any role above the minimum its consumer
  needs, or whose SA can impersonate another SA (feed to the privilege graph).
- **LM-51** — key age exceeds the rotation policy, or `constraints/iam.serviceAccountKeyExpiryHours`
  is unset (accepted ALLOW values: `1h`, `8h`, `24h`, `168h`, `336h`, `720h`, `1440h`, `2160h`;
  unset means keys never expire).
- **LM-52** — `constraints/iam.managed.disableServiceAccountKeyCreation` not enforced (this managed
  form also covers **Cloud Storage HMAC keys**; the legacy
  `constraints/iam.disableServiceAccountKeyCreation` may be superseded — verify whether the legacy
  name is still accepted). Pair with `constraints/iam.disableServiceAccountKeyUpload`, which blocks an
  attacker uploading their **own** public key to a victim SA — a persistence path that leaves no
  Google-generated key to rotate. Also check `constraints/storage.restrictAuthTypes`
  (`in:ALL_HMAC_SIGNED_REQUESTS`) — HMAC keys are S3-compatible static credentials that bypass
  SA-key controls entirely.
- **LM-53** — ADC/refresh tokens in human home directories on shared jump boxes: any local root or
  any user with read access to that home directory inherits the human's cloud identity
  (ATT&CK T1528, T1552.001).

#### 7.3.2 Self-hosted GHES runners — the crossing point

Establish first **which credential mechanism is actually in use**, because in an air-gapped GHES
estate the usual answer is the worst one.

The seven candidate mechanisms, whether each works air-gapped, and the review posture for each are
tabulated once in §5.8 (test `WI-14`). Work that table here, per runner group, before asking anything
else — and carry its conclusion forward: **if the runner can reach Google egress-only, WIF is
impossible but key-based auth works**, which is exactly what pushes air-gapped GHES estates onto
long-lived service-account keys. If the runner cannot reach `sts.googleapis.com` /
`iamcredentials.googleapis.com` at all, the pipeline is not talking to GCP directly; find the relay or
bastion and review **that**.

**Ask verbatim.**

1. *"For each self-hosted runner: its hostname, its runner group, the full list of repositories that
   may target that group, the OS user the job runs as, and every Google credential readable by that
   user."*
2. *"Which workflow triggers can run on that runner — `push`, `pull_request` from forks,
   `workflow_dispatch`, `schedule` — and who can create them?"*

**Finding tests.**

- **LM-54 (shared runner + broad SA)** — a runner group targetable by more than one repository, on a
  host holding a credential at rest that any job can read. Then every principal who can merge or run
  a workflow in **any** of those repositories holds that SA. State the repository count and the SA's
  reachable data tier. This is a direct interior→cloud data path.
- **LM-55 (fork/PR trigger)** — a workflow on such a runner triggers on `pull_request` from forks or
  on `workflow_dispatch` open to a broad set. Then the credential is reachable by anyone who can open
  a PR.
- **LM-56 (WIF conditions)** — for every provider the runners use, dump the trust configuration and
  run tests `WI-01`, `WI-03`, `WI-04`, `WI-05` and `WI-06` from §5.8 against it:

  ```bash
  gcloud iam workload-identity-pools list --location=global --project=P --show-deleted
  gcloud iam workload-identity-pools providers list --workload-identity-pool=POOL \
    --location=global --project=P --format=json   # read attributeCondition, attributeMapping, allowedAudiences
  ```

  The runner-specific rule those tests do not carry: the condition must pin **this** repository and
  ref, not merely the platform, because a runner group is reachable by every repository allowed to
  target it. **Read the actual condition; non-empty is not safe.**
- **LM-57 (pool-wide binding)** — `roles/iam.workloadIdentityUser`, or any resource role, granted to
  `principalSet://iam.googleapis.com/projects/PN/locations/global/workloadIdentityPools/POOL/*`
  (test `WI-02`). Bind to `.../attribute.repository/ORG/REPO` instead.
- **LM-58 (name vs id claims)** — test `WI-04`: the condition or the bound `principalSet` pins
  `assertion.repository` / `assertion.repository_owner` (names, reusable after a rename) rather than
  `assertion.repository_id` / `assertion.repository_owner_id`. Also flag `google.subject` mapped to a
  mutable claim (test `WI-05`).
- **LM-59 (audience widened)** — test `WI-06`: a provider with custom `allowed_audiences` loses the
  confused-deputy protection of the default provider-resource audience.
- **LM-60 (issuer gate)** — test `WI-08`: `constraints/iam.workloadIdentityPoolProviders` unset, so
  anyone holding `iam.workloadIdentityPools.create` can stand up a pool trusting an attacker's issuer.
- **LM-61 (deleted-pool window)** — test `WI-10`: a deleted pool can be undeleted for 30 days, so
  deletion is suspension, not destruction. Record who can undelete.

Run every test above against the runners' providers specifically: a provider that is tight for one
repository is not tight for a runner group that many repositories can target.

#### 7.3.3 Federated humans from the interior IdP / AD (Workforce Identity Federation)

**Finding tests.**

- **LM-62** — `--session-duration` at the 12h ceiling (900s–43200s permitted; default 1h) on a pool
  whose principals hold admin-capable roles.
- **LM-63** — `principalSet://iam.googleapis.com/locations/global/workforcePools/POOL/*` bound to
  anything privileged: that is every federated employee.
- **LM-64** — `google.subject` mapped from a mutable claim (email, UPN, display name) rather than an
  immutable object id — a takeover vector when an interior account is renamed or recreated.
- **LM-65** — `--detailed-audit-logging` off on a privileged provider: STS audit entries then lack
  the detail needed to reconstruct a disputed sign-in.
- **LM-66** — a design that gates federated humans with an Access Context Manager access level
  cannot work: workforce and workload pool principals, agent identities and service agents can be
  named in VPC-SC ingress/egress `identities[]` but **not** in an access level, whose `members[]`
  accepts only `user:` and `serviceAccount:` (no groups either). The full statement of the asymmetry
  and why it forces IP-only levels is in §5.3 (*Exfil scenario*). Use ingress rules.

#### 7.3.4 On-prem access to Google APIs — does it traverse VPC-SC or bypass it

This is the single highest-value test in the on-prem→cloud direction. If an interior host resolves
and reaches the **public** Google front ends, its API calls do not arrive with the network context of
your perimeter, and the perimeter's assumption that "on-prem arrives over the restricted VIP" is void.

**The required configuration, in full.**

| # | Element | Exact value |
|---|---|---|
| 1 | On-prem DNS maps `*.googleapis.com` → `restricted.googleapis.com` | A → `199.36.153.4`, `199.36.153.5`, `199.36.153.6`, `199.36.153.7`; AAAA → `2600:2d00:0002:1000::` |
| 2 | Delivery of that mapping | either a Cloud DNS **private zone** `googleapis.com` (`*.googleapis.com` CNAME → `restricted.googleapis.com.` plus the A/AAAA records) reached through a Cloud DNS **inbound server policy** whose forwarder entry point is **in the same region as the tunnel**, or on-prem BIND **response policy zones** redirecting to the restricted VIP |
| 3 | Cloud Router **custom advertisement** over every tunnel/attachment | `199.36.153.4/30` and `2600:2d00:0002:1000::/56` |
| 4 | On-prem routes for the VIP range | pointed at the VPN tunnel / VLAN attachment |
| 5 | The same treatment for the sibling domains | `*.gcr.io`, `*.gstatic.com`, `*.pkg.dev`, `pki.goog`, `*.run.app`, `*.gke.goog` (A record for `DOMAIN` → the VIP IPs, CNAME `*.DOMAIN` → `DOMAIN`), plus any Cloud Storage custom domain |
| 6 | Interior block of the public path | firewall/proxy deny from interior segments to Google's public front ends on TCP/443 |

Both DNS and BGP are required. *"There are public DNS records for `private.googleapis.com` or
`restricted.googleapis.com`. However, you can't use the public records to access Google APIs"*, and
the VIP ranges are *"not announced to the internet"* — so DNS without BGP blackholes, and BGP without
DNS leaves clients on the public path.

**Test commands that prove which path a host takes** (run **on the interior host**):

```bash
dig +short storage.googleapis.com                 # must return 199.36.153.4-.7
dig +short @CORP_RESOLVER bigquery.googleapis.com # test each resolver the host may use
dig +short us-docker.pkg.dev                      # sibling domains are the usual gap
getent hosts storage.googleapis.com

ip route get 199.36.153.4                         # must egress via the interconnect/VPN interface
curl -s -o /dev/null -w 'connected_to=%{remote_ip}\n' https://storage.googleapis.com/
traceroute -T -p 443 199.36.153.4
```

`connected_to` is the definitive evidence: anything other than `199.36.153.4`–`.7` means the request
left on the public path. Cross-check from the cloud side that the range is actually advertised:

```bash
gcloud compute routers list-bgp-routes ROUTER --region=R --peer=PEER \
  --route-direction=ADVERTISED --address-family=IPV4 | grep 199.36.153.4/30
```

**Finding tests.**

- **LM-67** — any interior resolver returns a non-`199.36.153.4/30` address for `*.googleapis.com`
  while a perimeter protects CONFIDENTIAL or NTK projects. On-prem-originated API calls bypass the
  perimeter entirely. Score with §11.1: this is `X = EGRESS-OUT` whenever a reachable credential can
  read CONFIDENTIAL/NTK, which bands **CRITICAL** at `S1` (assume-breach interior) — see the worked
  chain `CH-03` in §11.3.2, which bands exactly this condition against exactly this evidence.
- **LM-68** — `199.36.153.4/30` absent from `--route-direction=ADVERTISED` on any session that
  carries API traffic; or a **per-session** custom advertisement that omits it while the router-level
  advertisement includes it (the session-level override wipes the router-level set).
- **LM-69** — `private.googleapis.com` (`199.36.153.8/30`) used where `restricted` was intended.
  `private` *"can allow access to services that are not compliant with VPC Service Controls and might
  introduce data exfiltration risks"*; `restricted` *"denies access to Google APIs and services that
  are not supported by VPC Service Controls"*. If the private VIP is genuinely required, it must be
  paired with `vpcAccessibleServices.allowedServicePatterns` and
  `servicePatternsEnforcementScopes: [GOOGLE_APIS_VIA_PRIVATE_PATH]`; without that pairing it is a
  HIGH exfil finding per Google's own wording. (Service-pattern syntax — verify against current docs;
  the `#service-patterns` doc anchor does not currently resolve, so do not cite it.)
- **LM-70** — both VIP ranges in use in the same network or DNS view. Verbatim: *"Do not mix
  addresses from the `private.googleapis.com` and `restricted.googleapis.com` VIPs."* Note also that
  a firewall or route written for `199.36.153.0/24` covers **both** /30s and defeats the separation.
- **LM-71** — `*.pkg.dev` / `*.gcr.io` (or the other sibling domains) not overridden: Artifact
  Registry and Container Registry pulls stay on the public path even when `googleapis.com` is pinned.
- **LM-72** — the VIPs support **only HTTP-based protocols over TCP** (HTTP, HTTPS, HTTP/2); any
  design relying on other protocols over them is broken and will have been "fixed" by a bypass —
  find it.
- **LM-73 (access levels gating on-prem)** — dump every access level attached to the perimeters and
  run tests `SC-18` (an empty `ipSubnetworks`, `members` or `devicePolicy` each mean *allow all*),
  `SC-19` (`negate: true` is a NAND), `SC-20` (`regions` always denies private IPs and does not support
  Private Google Access) and `SC-21` (a shared NAT range admits every workload behind it) against each:

  ```bash
  gcloud access-context-manager levels list --policy=POLICY --format=json
  gcloud access-context-manager perimeters list --policy=POLICY --format=json
  gcloud access-context-manager perimeters dry-run list --policy=POLICY
  ```

  The on-prem-specific consequence, which those tests do not state: an access level admitting the
  corporate range is a **network-position-only** control, and in a soft interior network position is
  what every foothold already has. Google's guidance under `NO_MATCHING_ACCESS_LEVEL` is to *"[create]
  an ingress rule instead of an access level because an ingress rule provides granular access
  control."*
- **LM-74 (perimeter negation via ingress rule)** — run tests `SC-07`, `SC-08`, `SC-09`, `SC-10`,
  `SC-11` and `SC-16` against every rule that admits an on-prem caller. The loud combination is
  `sources[].accessLevel: "*"` + `identityType: ANY_IDENTITY` + `ingressTo.resources: ["*"]` +
  `operations[].serviceName: "*"`, which negates the perimeter outright; the quiet one is
  `egressFrom.sources` set while `sourceRestriction` is unset, which makes the rule apply to every
  source in the perimeter.

#### 7.3.5 Interior reach to PSC endpoints and private service endpoints

**Enumerate.**

```bash
gcloud compute forwarding-rules list --project=P \
  --filter="target~serviceAttachments OR pscConnectionId:*" --format=json
gcloud compute service-attachments list --project=P --format=json   # command spelling: verify against current docs
gcloud org-policies describe constraints/compute.disablePrivateServiceConnectCreationForConsumers --effective --project=P
gcloud org-policies describe constraints/compute.restrictPrivateServiceConnectProducer --effective --project=P
```

**Finding tests.**

- **LM-75** — a PSC endpoint IP falls inside a subnet range advertised to on-prem. Then interior
  hosts reach it, and the attack surface of that published service extends into the soft interior.
- **LM-76** — any PSC-for-Google-APIs endpoint created with `--target-google-apis-bundle=all-apis`.
  That bundle *"provides access to most Google APIs and services regardless of VPC Service Controls
  support"* — the same risk profile as the private VIP. Require `vpc-sc`, which *"restricts access to
  APIs and services that are supported by VPC Service Controls."* (The DNS names created by each
  bundle, e.g. `p.googleapis.com` / `SERVICE-ENDPOINT.p.googleapis.com` — verify against current
  docs; the two sources disagree.)
- **LM-77** — any endpoint whose service attachment lives **outside your organization**. A PSC
  endpoint is a single internal IP in your own VPC: to an egress rule it looks like ordinary
  intra-VPC traffic, so an egress `deny 0.0.0.0/0` with an RFC1918 allow leaves it wide open, and
  `dest_network_scope = INTERNET` does not catch it either. NAT hides the destination — the consumer
  flow record shows only the endpoint IP, with no producer project or hostname.
- **LM-78** — the jurisdiction distinction, stated per endpoint: VPC-SC applies to PSC traffic to
  **Google APIs**; a PSC endpoint to a **third-party published service** is not a Google API call and
  the perimeter has no jurisdiction over it.
- **LM-79** — flow logs not enabled on the consumer subnet. PSC traffic *is* logged from both sides
  *"as long as both VMs are in subnets that have VPC Flow Logs enabled"* — "unmonitored" is a default,
  not a law. Enable `--enable-flow-logs` on consumer subnets; you still will not see the far side.
- **LM-80** — controls not in place: egress deny to the endpoint IPs (firewall rules **do** apply to
  PSC resources), plus `constraints/compute.disablePrivateServiceConnectCreationForConsumers`
  (allowed values `GOOGLE_APIS`, `SERVICE_PRODUCERS`) and
  `constraints/compute.restrictPrivateServiceConnectProducer`. Layered rule: *"Connections are
  blocked if either an accept list or an organization policy denies the connection."*

---

### 7.4 Output artifact: the traversal map, and joining it to the privilege graph

Produce **one table per adversary starting position** defined in §4.5: `A1` external attacker with a
stolen credential; `A2` malicious low-privilege insider; `A3` compromised CI/CD or federated
workload; `A4` compromised SA / leaked key; `A5` compromised on-prem host; `A6` compromised
application workload (SSRF/RCE); `A7` supply-chain compromise.

Exact columns, in this order:

| Source position | Hop | Mechanism | Reachable target | Port / protocol / API | Control that should stop it | Control exists? | Evidence |
|---|---|---|---|---|---|---|---|

Rules for filling it:

- **Hop** is an integer starting at 1; one row per hop, never a merged row.
- **Mechanism** names the exact primitive: `metadata token read`, `setMetadata SSH key injection`,
  `IAP tunnel`, `pod → node SA token`, `BGP-advertised route + effective egress allow`,
  `restricted-VIP bypass via public DNS`, `PSC endpoint to external service attachment`.
- **Control exists?** takes exactly one of `yes` / `no` / `dry-run only` / `present but bypassable
  (reason)`. "Partially" is not an allowed value.
- **Evidence** is a command name plus the artifact filename, or a transcript line — never a claim.
- A row whose control is `no` and whose target holds CONFIDENTIAL or NTK data is a finding in its own
  right, independent of whether a full chain was assembled.

**Joining to the privilege graph.** Alternate between the two graphs until a fixpoint or six hops,
whichever comes first, using these two join rules:

1. **Network hop → identity node.** Any traversal hop that terminates in code execution on a
   workload (shell, pod, function, notebook, build step) adds the workload's runtime SA — and every
   SA reachable from it in the privilege graph — to the adversary's identity set.
2. **Identity hop → network position.** Any privilege-graph edge that yields
   `iam.serviceAccounts.actAs` plus a create/update permission on a compute surface, or
   `compute.instances.setMetadata`, or pod-create in a cluster, adds that workload's **subnet and
   secure-tag/SA position** to the adversary's network set — including its link access, its PSC
   reach, and its metadata server.

Emit end-to-end chains only for paths that terminate at a principal or host able to read
CONFIDENTIAL or NTK data. Rank chains by **(data tier reached × ease of the starting position ×
number of principals who can execute it)** — not by hop count — and, for each, name the **single
cheapest severing control** and whether every step is currently visible in logs. An undetected chain
scores above a detected one of equal reach.

**EXAMPLE — required output shape only; names are fictional.**

| Source position | Hop | Mechanism | Reachable target | Port / protocol / API | Control that should stop it | Control exists? | Evidence |
|---|---|---|---|---|---|---|---|
| RCE in `svc-web` (Cloud Run, `example-prod-01`) | 1 | metadata ID/access token read | runtime SA `svc-web@example-prod-01` | `metadata.google.internal:80` | dedicated least-privilege SA per service | present but bypassable (SA shared with `svc-batch`) | `run-services.json`, `iam-policies.json` |
| " | 2 | `roles/bigquery.dataViewer` held by that SA | dataset `example-prod-01:sales_conf` (CONFIDENTIAL) | `bigquery.googleapis.com` | perimeter + authorized views | dry-run only | `perimeters-dryrun.json` |
| " | 3 | `EXPORT DATA` to a bucket outside the perimeter | `gs://example-staging-eu` | `storage.googleapis.com` | egress rule / restricted services list | no — `storage.googleapis.com` absent from `restrictedServices` | `perimeter-sp-prod.json` |
| " | 4 | scheduled SFTP drop of that bucket to interior | `fileshare-01.corp.example` `:22` | `tcp/22` over VLAN attachment | egress rule to on-prem keyed on secure tag | no — egress permits `10.0.0.0/8` from all subnets | `effective-fw-nic0.json` |

---

## 8. Service isolation — enforce by default

**Governing rule, applied to every recommendation in this section:** name the technical enforcement
mechanism. Where no enforcement mechanism exists, say so in those words and specify the compensating
review gate that replaces it. **"Recommended" with neither an enforcement mechanism nor a named gate
is not acceptable output** — delete the sentence or supply one.

Definition used throughout: a **service** is one deployment unit with one owner, one runtime
identity, one set of data resources, and one declared set of dependencies on other services. Two
components that share any of those four are one service for isolation purposes; call that out rather
than pretending they are isolated.

### 8.1 Identity isolation

| Requirement | Enforcement | Finding test |
|---|---|---|
| Exactly one dedicated SA per service | **None exists** — no org policy counts SA attachments. **Compensating gate:** (a) IaC policy-as-code rule that every compute resource's service-account field must reference an SA declared in the same module and referenced exactly once; (b) a scheduled detector over Cloud Asset Inventory grouping runtime resources by SA email and alerting on count > 1. | ISO-1: any SA email attached to more than one deployment unit |
| No default SA as a runtime identity | `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` (stops the auto-grant of `roles/editor`; baseline-enforced on orgs created on/after 2024-05-03) + `constraints/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` (blocks the manual re-grant of Editor/Owner to the Compute and App Engine default SAs). Neither prevents *use* of the default SA — that gap is real; **compensating gate:** IaC rule rejecting any resource whose service account matches `*-compute@developer.gserviceaccount.com` or `*@appspot.gserviceaccount.com`. | ISO-2: any Cloud Run / functions / GCE / Cloud Build / node pool running as a default SA |
| No exportable key material | `constraints/iam.managed.disableServiceAccountKeyCreation` (also covers Cloud Storage HMAC keys), `constraints/iam.disableServiceAccountKeyUpload`, `constraints/iam.serviceAccountKeyExpiryHours`, `constraints/storage.restrictAuthTypes` | ISO-3: any user-managed key on a service SA; ISO-4: an exception granted at a lower node without `inheritFromParent: true` |
| Service A's principal cannot impersonate service B's SA | IAM Deny at the folder, plus binding impersonation roles **only on the specific target SA** | ISO-5: `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` bound at **project** level — that confers impersonation of every SA in the project, including the default compute SA |

The deny rule that enforces cross-service `actAs` and impersonation isolation is the one in §5.5
(*Remediation*): attach it at the folder holding the privileged service accounts, with the owning
deploy group as `exceptionPrincipals`. Three authoring facts decide whether it works at all —
`iam.googleapis.com/serviceAccounts.*` is **not** a valid permission group, so the six permissions
must be enumerated individually (test `DN-03`); denial conditions recognize **only** resource-tag
functions and fail closed (test `DN-06`); and attachment points are organizations, folders and
projects only, never a service account. Whether a **service account** supports the tag binding a
`resource.matchTag` condition would need — verify against current docs; if it does not, scope by
attachment point instead, which means isolating privileged SAs into their own project or folder.

### 8.2 Resource and project isolation

| Requirement | Enforcement | Finding test |
|---|---|---|
| Project-per-workload as the isolation unit | **None exists** — nothing forces one workload per project. **Compensating gate:** project-factory IaC module that creates exactly one workload's resources plus its SA, and a detector flagging any project containing runtime SAs with disjoint data grants. | ISO-6: a project hosting two services whose data grants do not overlap |
| No cross-project SA attachment | `constraints/iam.disableCrossProjectServiceAccountUsage` | ISO-7: constraint unenforced, or enforced with an undocumented exception |
| No unapproved network joins | `constraints/compute.restrictSharedVpcHostProjects`, `constraints/compute.restrictSharedVpcSubnetworks`, `constraints/compute.restrictVpcPeering` | ISO-8: any unset, or a project attached to a host project outside the allow-list |
| Remove unused egress-capable services per project | `constraints/gcp.restrictServiceUsage` (note the documented exclusion of essential dependencies — IAM, Logging, Monitoring) | ISO-9: `storagetransfer.googleapis.com`, `bigquerydatatransfer.googleapis.com`, `dataform.googleapis.com`, `datastream.googleapis.com` enabled in a project with no such workload |
| Pin data residency | `constraints/gcp.resourceLocations` (value groups take the `in:` prefix, e.g. `in:us-locations`) | ISO-10: unset on a CONFIDENTIAL/NTK project (ATT&CK T1535) |

Remember the inheritance trap when testing all of the above: *"A resource that has an organization
policy set by default supersedes any policy set by its parent resources."* A child node silently
wins unless it sets `inheritFromParent: true`. Always resolve the effective policy:

```bash
gcloud asset analyze-org-policies --constraint=constraints/CONSTRAINT --scope=organizations/ORG_ID
```

### 8.3 Network isolation

| Requirement | Enforcement | Finding test |
|---|---|---|
| Default-deny east-west | Hierarchical firewall policy at the folder with a low-priority intra-VPC `deny`, associated to prod/nonprod folders; **plus** the VPC network set to `BEFORE_CLASSIC_FIREWALL`, or leftover classic `allow` rules pre-empt it | ISO-11: no folder-level deny; ISO-12: enforcement order left at the default |
| Rules keyed on identity, not location | Rules use `--src-secure-tags` / `--target-secure-tags` or `--source-service-accounts` / `--target-service-accounts`. Secure tag binding is IAM-gated by `roles/resourcemanager.tagUser`, which can be granted *"without needing to be granted the Compute Security Admin role"* | ISO-13: any east-west `allow` keyed on network tags (no IAM gate on the tag string — `compute.instances.setTags` is enough to enter a permissive scope) or on IP ranges |
| Per-service subnets, explicit allow per dependency pair | One `allow` rule per declared dependency, both endpoints keyed by secure tag, `enable_logging = true` | ISO-14: an `allow` rule with no named dependency in the service catalog |
| Default-deny egress with a minimal allow-list | `deny` egress rule plus the exact allow-list below | ISO-15: no egress deny (the implied rule is **allow to `0.0.0.0/0` at priority 65535** and cannot be logged) |

Minimum egress allow-list for a default-deny VPC — each entry verified, with the one that is
**not** needed called out because its presence signals a misunderstanding:

| Destination | Needed for |
|---|---|
| `169.254.169.254`, `fd20:ce::254` | **NOT NEEDED** — metadata and internal DNS traffic is firewall-exempt. Do not add it; and never present a `deny` to it as a metadata-theft mitigation, because firewall rules cannot block it. |
| `199.36.153.4/30` + `2600:2d00:0002:1000::/56` | `restricted.googleapis.com` |
| `34.126.0.0/18` + `2001:4860:8040::/42` | additional Private Google Access ranges — commonly missing from older allow-lists |
| `35.199.192.0/19` | Cloud DNS **outbound** forwarding source range, only if an outbound server policy or forwarding zone is in use |
| `199.36.153.8/30` + `2600:2d00:0002:2000::/56` | `private.googleapis.com` — only if deliberately chosen, and then only with service patterns (see §7.3.4) |

Health-check and proxy ranges are **ingress**, not egress: `35.191.0.0/16` (GFE probes),
`130.211.0.0/22` (GFE proxy source for ALB/proxy NLB), `136.124.104.0/22` + `136.124.108.0/22`
(global external passthrough NLB), `209.85.152.0/22` + `209.85.204.0/22` (regional external
passthrough NLB), the Envoy proxy-only subnet for managed regional LBs, and `35.235.240.0/20` for
IAP TCP forwarding. The old advice "allow `35.191.0.0/16` and `130.211.0.0/22` and you're done" is
now incomplete.

```hcl
resource "google_compute_network_firewall_policy_rule" "deny_internet_egress" {
  firewall_policy = google_compute_network_firewall_policy.prod.name
  action          = "deny"
  direction       = "EGRESS"
  priority        = 65000
  enable_logging  = true
  match {
    # dest_network_scope is cleaner than 0.0.0.0/0 because it does not blackhole
    # on-prem or peered destinations. Terraform marks *_network_scope Beta and exposes a
    # GA-track *_network_context with the same values — verify against current docs.
    dest_network_scope = "INTERNET"
    layer4_configs { ip_protocol = "all" }   # verify "all" is accepted in this field
  }
}
```

Do **not** use FQDN objects for `*.googleapis.com` or as an exfil control: no wildcards, a hard cap
of 32 IPv4 + 32 IPv6 addresses per FQDN, and the rule **fails open** when the resolver is
unreachable ("the FQDN objects within the rule are ignored"). Google's own text: *"Most Google
domain names, such as `googleapis.com`, are subject to one or more of these situations. Use IP
addresses or address groups instead."* Threat-intelligence lists are the useful egress-deny set:
`iplist-tor-exit-nodes`, `iplist-anon-proxies`, `iplist-vpn-providers`, `iplist-crypto-miners`, and
`iplist-public-clouds-aws` / `-azure` for "exfil to my own S3 bucket" (Standard tier; do not put
multiple lists in one rule).

**GKE isolation.**

| Requirement | Enforcement | Finding test |
|---|---|---|
| Namespace per service | **None at the GCP layer.** **Compensating gate:** Policy Controller / admission constraint requiring every workload to carry an owning-service label and live in that service's namespace | ISO-16: two services in one namespace |
| Default-deny NetworkPolicy per namespace | NetworkPolicy with Dataplane V2 (recommended; the Autopilot default) or Calico (`--enable-network-policy`, Standard only) | ISO-17: a namespace with no policy selecting its pods — pod-to-pod is open by default |
| Workload Identity per KSA→GSA | `--workload-pool=PROJECT_ID.svc.id.goog` on the cluster **and** `--workload-metadata=GKE_METADATA` on every node pool | ISO-18: any node pool at `GCE_METADATA`; ISO-19: any `hostNetwork: true` pod (bypasses the GKE metadata server) |
| Separate node pools by sensitivity | Distinct node pools with distinct node SAs, plus secure-tag-based firewall policy enforcement for GKE | ISO-20: CONFIDENTIAL and INTERNAL workloads schedulable onto the same pool |
| Binary Authorization | `--binauthz-evaluation-mode=project-singleton-policy-enforce` (`--enable-binauthz` is deprecated; GA values are `disabled` and `project-singleton-policy-enforce`; policy `evaluationMode` strings and the dry-run flag — verify against current docs) | ISO-21: mode `disabled` |
| No cluster-admin for workloads | RBAC review; note GKE checks **RBAC first, then IAM**, so both must be read | ISO-22: `roles/container.admin` / `clusterAdmin` / `developer` at project or folder; ISO-23: a `ClusterRoleBinding` to `cluster-admin` with a workload KSA subject |

Bind workload identities with the modern direct form; the annotation form is legacy but still GA:

```bash
gcloud projects add-iam-policy-binding projects/PROJECT_ID \
  --role=roles/storage.objectViewer --condition=None \
  --member=principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/NAMESPACE/sa/KSA_NAME
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-all, namespace: svc-a }
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
```

Never bind to `.../workloadIdentityPools/PROJECT_ID.svc.id.goog/namespace/NAMESPACE` or to the
whole-cluster principalSet when a single KSA is meant.

### 8.4 Service-to-service authentication

| Requirement | Enforcement | Finding test |
|---|---|---|
| Cloud Run / functions invoked only by a named SA | `roles/run.invoker` (or `roles/cloudfunctions.invoker` for 1st gen) bound to exactly one caller SA; `constraints/run.managed.requireInvokerIam` blocks disabling the invoker check; `constraints/iam.allowedPolicyMemberDomains` / `constraints/iam.managed.allowedPolicyMembers` block external principals | ISO-24: `allUsers` or `allAuthenticatedUsers` on an invoker role; ISO-25: invoker bound to a group rather than the calling service's SA |
| Callers present an OIDC ID token | Caller fetches `.../instance/service-accounts/default/identity?audience=SERVICE_URL`; receiver validates | ISO-26: a service accepting requests with no token |
| Ingress restricted | `--ingress=internal` pinned by `constraints/run.allowedIngress`. **State the caveat:** `internal` is broader than "my VPC" — it admits internal ALBs, resources allowed by any VPC-SC perimeter containing the service, VPC networks in the same project, the Shared VPC network the revision egresses to, and Cloud Scheduler / Cloud Tasks / Eventarc / Pub/Sub / Workflows in the same project or perimeter. It is not a network ACL. | ISO-27: `--ingress=all` on a service handling CONFIDENTIAL data |
| Egress subject to VPC controls | `--vpc-egress=all-traffic` pinned by `constraints/run.allowedVPCEgress`. With `private-ranges-only`, **public internet egress bypasses the VPC entirely** — NGFW policy, Cloud NAT logging and flow logs never see it. | ISO-28: `private-ranges-only` on any service that can read classified data |
| HTTP surfaces behind IAP | IAP with `roles/iap.tunnelResourceAccessor` scoped per resource for TCP | ISO-29: tunnel role at project scope |
| mTLS with mesh authorization policies | **No GCP org-policy enforcement exists** for mesh authorization policy content. **Compensating gate:** policy-as-code check that every mesh workload has an `AuthorizationPolicy` with a non-empty principals selector, plus a CI test that an unauthenticated call from another namespace is refused. | ISO-30: a mesh service with a permissive or absent authorization policy |
| **No source-IP-only authorization** | **No platform enforcement exists.** **Compensating gate:** a mandatory design-review question, answered per internal service, recorded in the service catalog. | ISO-31: the cloud-side turtle problem — any internal service that authorizes on source IP or subnet alone. Test: from a workload in the same subnet but with a different SA and no application credential, call the service; a `200` proves IP-only authorization. |

### 8.5 Data-plane isolation

| Requirement | Enforcement | Finding test |
|---|---|---|
| Separate bucket / dataset / topic per service **and** per classification tier | **No org policy enforces the split.** **Compensating gate:** IaC naming-and-label contract (`service`, `classification` labels mandatory) plus a detector flagging any data resource with no `classification` label — an unclassified data store is a finding in its own right | ISO-32: one bucket/dataset holding two tiers; ISO-33: any data-bearing resource with no classification label |
| No shared data-lake bucket spanning tiers | Permitted only where object-level controls actually enforce the split. With `constraints/storage.uniformBucketLevelAccess` enforced (baseline on post-2024 orgs) per-object ACLs no longer exist, so the only IAM-auditable object-level controls are IAM Conditions on object-name prefixes and managed folders (semantics — verify against current docs) | ISO-34: a multi-tier bucket whose only separation is prefix convention |
| CMEK key per service or per classification, key IAM bound only to that service's SA | `constraints/gcp.restrictNonCmekServices` (Deny list of services that must not use Google-managed keys) **and** `constraints/gcp.restrictCmekCryptoKeyProjects` (Allow list of key projects: `projects/PROJECT_ID`, `under:folders/FOLDER_ID`, `under:organizations/ORGANIZATION_ID`). Both must be set together; both apply **only to newly created resources**; and the second *"by itself does not necessarily guarantee the use of customer-managed encryption keys from allowed projects… because other methods of encryption might be available."* | ISO-35: either constraint unset; ISO-36: one key serving multiple services; ISO-37: key IAM granting `cloudkms.cryptoKeyVersions.useToDecrypt` beyond the owning service's SA |
| BigQuery fine-grained access instead of broad dataset grants | Authorized views; column-level policy tags (read role `roles/datacatalog.categoryFineGrainedReader`, taxonomy toggle "enforce access control"); row access policies (row-level syntax — verify against current docs). Product is now **Knowledge Catalog** (formerly Dataplex Universal Catalog); identifiers stay `datacatalog.*` / `dataplex.*`. Data Catalog **search/metadata** APIs shut down 2026-06-01; policy tags and taxonomies are not deprecated. | ISO-38: `roles/bigquery.dataViewer` at dataset or project scope where a view or policy tag would do; ISO-39: an authorized view granting into a dataset in another project or org |

CMEK caveat to state in every recommendation that uses it: **CMEK is a revocation and blast-radius
control, not an exfil-prevention control.** A principal authorized to read plaintext through
BigQuery or GCS gets plaintext. What CMEK buys is a cryptographic boundary that survives an IAM
mistake on the data resource itself, and a kill switch on copies taken at the storage layer.

Also enumerate the data-plane paths that leave the boundary without a network hop, and confirm the
perimeter covers **every** service involved, not just the obvious one: BigQuery `EXPORT DATA` and
`bq extract` (needs `bigquery.googleapis.com` **and** `storage.googleapis.com` in
`restrictedServices`), cross-region/cross-project dataset copy (`cross_region_copy` via BigQuery Data
Transfer Service — pure in-network movement no egress firewall sees), BigQuery sharing listings
(hands a dataset to another organization with no data movement to detect), BigQuery Omni export to
S3/Blob, Storage Transfer Service, Pub/Sub push subscriptions (and note: *"VPC Service Controls
policy only applies to new Cloud Pub/Sub push subscriptions"* — pre-existing push channels survive
perimeter creation and must be enumerated and recreated), Cloud Storage **signed URLs** (a bearer
credential that identity-based perimeter rules cannot express; mitigate with
`constraints/storage.restrictAuthTypes`, short TTLs, and denying
`iam.googleapis.com/serviceAccounts.signBlob`), and log sinks whose destination project is outside
the org.

### 8.6 Boundary isolation

| Requirement | Enforcement | Finding test |
|---|---|---|
| Perimeters drawn on classification boundaries | `ServicePerimeter.status` populated and enforced. Perimeter members are **projects (`projects/PROJECT_NUMBER`) and VPC networks only — folders and organizations cannot be members**, so folder-aligned design requires per-project membership automation | ISO-40: a CONFIDENTIAL/NTK project in no perimeter (test `SC-01`); ISO-41: a perimeter carrying only `spec` with an empty or absent `status`, which enforces nothing (test `SC-02`; the Terraform tell is `use_explicit_dry_run_spec = true`) |
| Bridges only where a documented flow exists | Scoped ingress/egress rules, which the docs state *"can replace and simplify use cases that previously required one or more perimeter bridges"*; the custom org constraint that bans `PERIMETER_TYPE_BRIDGE` outright is in §5.3 (*Remediation*) | ISO-42: **every** `PERIMETER_TYPE_BRIDGE` is a finding — an all-services, bidirectional hole with no service, method, identity or direction filter available (test `SC-23`) |
| Restricted-services completeness | Enumerate machine-readably: `gcloud access-context-manager supported-services list` (columns include `AVAILABLE_ON_RESTRICTED_VIP` and `KNOWN_LIMITATIONS`). Never hardcode a service list — it rots | ISO-43: any data-bearing API enabled in a member project and absent from `restrictedServices`; the two gap classes and the remediation for each are test `SC-04` |
| PAB per service principal | `google_iam_principal_access_boundary_policy` + `google_iam_organizations_policy_binding` (or `_folders_` / `_projects_`), `enforcement_version = "latest"` | ISO-44: any PAB policy pinned below version 3, which blocks no impersonation permission at all; the version ladder is tests `PB-02` and `PB-03` |

PAB gap to state rather than gloss: `*.createPolicyBinding`, `*.deletePolicyBinding`,
`*.updatePolicyBinding` and `*.searchPolicyBindings` are documented exceptions at every enforcement
version, so **PAB cannot prevent someone from removing PAB bindings** (test `PB-06`). Symmetrically,
`iam.googleapis.com/denypolicies.*` is absent from the deny-supported list, so deny cannot protect
deny (test `DN-09`). The one partial technical control that does exist is §5.5 deny rule #12
(`iam.googleapis.com/principalaccessboundarypolicies.*`, which covers `.bind`/`.unbind`) plus role
hygiene on `roles/iam.principalAccessBoundaryUser`, `roles/resourcemanager.projectIamAdmin` and
`roles/resourcemanager.folderIamAdmin` — all three carry `*.deletePolicyBinding`. Beyond that the
gaps close only with org-node role hygiene plus real-time alerting on `iam.denypolicies` and
policy-binding mutations. **Do not propose a technical enforcement that does not exist** — in
particular, PAB is not the answer for either gap, and it cannot be bound to a Google group (§5.7).

```hcl
resource "google_iam_principal_access_boundary_policy" "svc_a" {
  organization                        = "ORGANIZATION_ID"
  location                            = "global"
  principal_access_boundary_policy_id = "pab-svc-a"
  details {
    enforcement_version = "latest"
    rules {
      description = "svc-a principals may only reach svc-a's own project"
      effect      = "ALLOW"
      resources   = ["//cloudresourcemanager.googleapis.com/projects/prj-svc-a-prod"]
    }
  }
}
```

(The PAB / deny self-protection gap and its compensating controls are stated once, above this
Terraform block — tests `PB-06` and `DN-09`. Do not restate it per requirement row.)

### 8.7 Enforcement plumbing — every control, all three layers

Layer 1 = org policy / IAM Deny (un-overridable). Layer 2 = policy-as-code in the IaC pipeline
(pre-merge gate). Layer 3 = SCC / custom detectors / VPC-SC dry-run (runtime detection).
Every row is filled or says `none — compensating gate: X`.

| # | Isolation control | L1 — org policy / IAM Deny | L2 — IaC pre-merge gate | L3 — runtime detection |
|---|---|---|---|---|
| 1 | One SA per service | none — compensating gate: L2 rule below | plan check: each compute resource's SA is declared in the same module and referenced once | CAI query grouping runtime resources by SA; alert on count > 1 |
| 2 | No default SA as runtime identity | `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`, `constraints/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` (neither blocks *use*) | reject SA matching `*-compute@developer.gserviceaccount.com` / `*@appspot.gserviceaccount.com` | detector on any new resource with a default SA; SCC finding on default SA holding Editor |
| 3 | No SA keys | `constraints/iam.managed.disableServiceAccountKeyCreation`, `constraints/iam.disableServiceAccountKeyUpload`, `constraints/iam.serviceAccountKeyExpiryHours`, `constraints/storage.restrictAuthTypes` | reject `google_service_account_key` resources | alert on `CreateServiceAccountKey`; weekly `keys list --managed-by=user` diff |
| 4 | No cross-service impersonation | IAM Deny on the five impersonation permissions + `actAs`, at folder | reject project-level `tokenCreator` / `serviceAccountUser` bindings | alert on `GenerateAccessToken` / `SignJwt` where caller ∉ owning service; `analyze-iam-policy --analyze-service-account-impersonation` on a schedule |
| 5 | Project-per-workload | none — compensating gate: project-factory module + L3 detector | project factory creates one workload's resources only | detector: project containing runtime SAs with disjoint data grants |
| 6 | No cross-project SA attachment | `constraints/iam.disableCrossProjectServiceAccountUsage` | reject SA references outside the module's project | alert on `SetServiceAccount` with a foreign SA |
| 7 | Default-deny east-west | hierarchical firewall policy at folder + `BEFORE_CLASSIC_FIREWALL` | reject any `allow` rule without a declared dependency pair | firewall rules logging on the deny rule; alert on new permissive rules (T1686.001) |
| 8 | Rules keyed on tags/SA, not IP | none — compensating gate: L2 rule; `roles/resourcemanager.tagUser` gates who may bind tags | reject `source_tags` / `target_tags` and RFC1918-supernet sources | detector over `get-effective-firewalls` output classifying rule keys |
| 9 | Per-service subnets | `constraints/compute.restrictSharedVpcSubnetworks` | subnet-per-service naming contract | detector: instance in a subnet not owned by its service label |
| 10 | Default-deny egress + restricted VIP only | egress deny rule; `constraints/compute.restrictCloudNATUsage`; `constraints/compute.vmExternalIpAccess`; `constraints/compute.disableInternetNetworkEndpointGroup`; `constraints/compute.restrictLoadBalancerCreationForTypes` (`deniedValues: [in:EXTERNAL]`) | reject external IPs, internet NEGs, and non-restricted-VIP DNS records | VPC Flow Logs + Cloud NAT logging; alert on new external IP or NAT gateway |
| 11 | GKE namespace per service + default-deny NetworkPolicy | none — compensating gate: Policy Controller constraint | reject manifests without a namespace and a default-deny policy | Policy Controller audit; detector for namespaces with no NetworkPolicy |
| 12 | GKE Workload Identity per KSA→GSA | `constraints/iam.disableWorkloadIdentityClusterCreation` where WI must not be used; otherwise none for requiring it — compensating gate: L2 | reject clusters without `workload_pool` and node pools without `GKE_METADATA` | detector over cluster configs for `GCE_METADATA` node pools |
| 13 | No privileged / hostNetwork / hostPath pods | none — compensating gate: PodSecurity admission or Policy Controller | reject manifests setting `hostNetwork`, `hostPID`, `privileged`, `hostPath` | admission audit mode; alert on violating pods |
| 14 | No cluster-admin for workloads | IAM Deny on `container.googleapis.com` admin permissions outside the platform group (confirm deniability — verify against current docs) | reject `ClusterRoleBinding` to `cluster-admin` with a KSA subject | periodic `clusterrolebinding` dump diffed against an allow-list |
| 15 | Binary Authorization | none — compensating gate: L2 + L3 | reject clusters with `evaluation_mode = disabled` | Binary Authorization dry-run/audit log review |
| 16 | Invoker = one SA, never `allUsers` | `constraints/run.managed.requireInvokerIam`, `constraints/iam.allowedPolicyMemberDomains` / `constraints/iam.managed.allowedPolicyMembers` | reject `allUsers` / `allAuthenticatedUsers` in any IAM member list | SCC public-resource findings; alert on `SetIamPolicy` adding `allUsers` |
| 17 | Cloud Run ingress `internal`, egress `all-traffic` | `constraints/run.allowedIngress`, `constraints/run.allowedVPCEgress` | reject `ingress = all` and `vpc_egress = private-ranges-only` | detector over service configs |
| 18 | No source-IP-only authorization | none — no platform enforcement exists — compensating gate: mandatory design-review question recorded per service in the catalog | reject LB/backend configs whose only auth is an IP allowlist | periodic unauthenticated-call test from a peer subnet (ISO-31 test) |
| 19 | Bucket/dataset/topic per service and tier | `constraints/storage.publicAccessPrevention`, `constraints/storage.uniformBucketLevelAccess` (tier separation itself: none) | mandatory `service` + `classification` labels; reject multi-tier resources | detector for unlabeled or multi-tier data stores; Sensitive Data Protection discovery profiles |
| 20 | CMEK key per service/tier | `constraints/gcp.restrictNonCmekServices` + `constraints/gcp.restrictCmekCryptoKeyProjects` (new resources only) | reject data resources without `kms_key_name`; reject a key shared by two services | detector: key IAM members ≠ {owning service SA}; alert on `cryptoKeys.setIamPolicy` |
| 21 | BigQuery authorized views / policy tags | IAM Deny on `bigquery.googleapis.com/tables.getData` outside the authorized set | reject dataset-level `dataViewer` grants; require policy tags on classified columns | Data Access logs on BigQuery; alert on `jobs.create` reading tagged columns by an unlisted principal |
| 22 | Perimeter on classification boundary | `ServicePerimeter.status` enforced; custom constraint on ACM resources | reject a project label change that moves classification without a perimeter change | VPC-SC **dry-run** violations as free attack-path evidence; alert on `servicePerimeters.*` writes |
| 23 | No perimeter bridges | custom org constraint banning `PERIMETER_TYPE_BRIDGE` (resource type/field — verify against current docs) | reject `perimeter_type = "PERIMETER_TYPE_BRIDGE"` | alert on bridge creation in the ACM audit log |
| 24 | PAB per service principal | PAB policy + binding at `enforcement_version = "latest"`; IAM Deny on `iam.googleapis.com/principalaccessboundarypolicies.*` outside the security group | require a PAB binding for every new workload/federated principal set | `gcloud iam principal-access-boundary-policies list` diff; alert on unbind |
| 25 | Every data resource carries a classification label | none — compensating gate: L2 + L3 | reject data resources without `classification ∈ {PUBLIC, INTERNAL, CONFIDENTIAL, NTK}` | CAI query for unlabeled data resources; each one is a finding |

---

## 9. Organization hierarchy — assessment and target design

### 9.1 Assess the current hierarchy

**Enumerate.**

```bash
gcloud organizations list
gcloud asset search-all-resources --scope=organizations/ORG_ID \
  --asset-types=cloudresourcemanager.googleapis.com/Folder,cloudresourcemanager.googleapis.com/Project \
  --format="table(name,displayName,parentFullResourceName)"
gcloud projects get-ancestors PROJECT_ID                 # per project, to get the full path
gcloud org-policies list --organization=ORG_ID --format=json
gcloud org-policies list --folder=FOLDER_ID --format=json
gcloud org-policies list --project=PROJECT_ID --format=json
gcloud asset analyze-org-policies --constraint=constraints/CONSTRAINT --scope=organizations/ORG_ID
gcloud iam policies list --attachment-point=cloudresourcemanager.googleapis.com/folders/FOLDER_ID \
  --kind=denypolicies --format=json
gcloud logging sinks list --organization=ORG_ID          # then repeat per folder and per project
gcloud access-context-manager perimeters list --policy=POLICY --format=json
```

Build one row per project: `project | ancestry path | classification of data held | perimeter
membership | org policies set at this node (and inheritFromParent) | deny policies in ancestry | PAB
bindings | Shared VPC role (host/service/none)`.

**Finding tests.**

- **HI-01** — any project parented directly to the organization node. It cannot receive
  folder-scoped hierarchical firewall policies, folder-level IAM, or folder-level deny policies.
- **HI-02** — a project holding CONFIDENTIAL or NTK data sharing a folder with dev, sandbox or
  experimentation projects. A folder-level policy must then be the loosest of the two populations,
  which is the whole reason to separate them.
- **HI-03** — a constraint set at a lower node **without** `inheritFromParent: true`, voiding the
  ancestor policy there. Resolve every exfil-relevant constraint with
  `gcloud asset analyze-org-policies`, never by reading the org-level policy alone. Note the merge
  rule for list constraints: `DENY` values always take precedence; and **managed constraints do not
  merge at all** — an inherited managed constraint is not combined with a child's.
- **HI-04** — a **tag-conditioned** org policy rule (`resource.matchTag(...)`) whose tag value can
  be attached by anyone outside the guardrail group. Whoever can set the tag grants themselves the
  exception. Enumerate `roles/resourcemanager.tagUser` and `roles/resourcemanager.tagAdmin` holders
  alongside every conditional policy. "The constraint is enforced" is not a sufficient finding.
- **HI-05** — on an org created on or after 2024-05-03, **absence** of any of the seven baseline
  constraints enumerated in test `OP-01` means someone deliberately deleted it, not that it was
  never set. High-signal finding: pull the `google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy` event
  (filter `F7`) and name the principal.
- **HI-06** — `resourcemanager.projects.setIamPolicy`, `resourcemanager.folders.setIamPolicy`
  or `resourcemanager.organizations.setIamPolicy` held at org or at a folder containing prod by any principal that also
  holds a deploy role. Guardrail-change and workload-deploy must be disjoint principal sets.
- **HI-07** — `roles/orgpolicy.policyAdmin` (an organization-level-only role) held by a deploy
  identity, or held without an IAM condition at org scope. It is a meta-privilege: its holder can
  delete `constraints/iam.allowedPolicyMemberDomains` and then grant an external principal any role.
- **HI-08** — holders of `resourcemanager.projects.move` / `projects.create` outside the platform
  group. `gcloud projects move` sheds inherited org policies **and** perimeter membership in one
  command (ATT&CK T1666 — the GCP framing is an analyst mapping, present it as such).
- **HI-09** — the aggregated log sink destination project, or the SCC project, sits in a folder
  where workload principals hold any write role. Also verify the sink writer identity
  (`serviceAccount:service-ORG_NUMBER@gcp-sa-logging.iam.gserviceaccount.com` form) has a grant on
  the destination, and that no project-level `_Default` sink exclusion shadows it — an org sink does
  not appear in `gcloud logging sinks list --project=X`, so run the command at every scope.
- **HI-10** — the Shared VPC host project sits inside a workload folder rather than a network
  folder, so folder-level network admin grants leak to workload owners.
- **HI-11** — a project in a data folder that is **not** a member of that folder's perimeter.
  Perimeter membership is per project (`projects/PROJECT_NUMBER`) and cannot be expressed on a
  folder, so folder-aligned designs need automation; every drift is a hole.
- **HI-12** — billing account admin or `billing.resourceAssociations.create` held broadly:
  detaching billing or re-parenting under a different billing account is a hierarchy-escape and a
  destruction path.

### 9.2 Target hierarchy

```
organizations/ORG_ID
│
├── fldr-bootstrap                       # IaC seed only; no workloads, no data
│   └── prj-bootstrap-tfstate            # Terraform state bucket, seed deploy SAs
│
├── fldr-common                          # shared function; no business workloads
│   ├── fldr-common-security
│   │   ├── prj-audit-logs               # destination of the org aggregated sink
│   │   ├── prj-scc                      # Security Command Center, custom detectors
│   │   └── prj-kms-central              # org/classification-scoped CMEK keyrings
│   ├── fldr-common-network
│   │   ├── prj-shared-vpc-host-prod     # Shared VPC host: prod service projects attach here
│   │   ├── prj-shared-vpc-host-nonprod
│   │   └── prj-hybrid-edge              # Interconnect/VPN attachments, Cloud Routers, Cloud DNS
│   └── fldr-common-tooling
│       ├── prj-artifact-registry
│       └── prj-ci-runners               # GCE/GKE-hosted CI runners (see §7.3.2)
│
├── fldr-prod
│   ├── fldr-prod-bu-a
│   │   ├── prj-bu-a-svc1-prod           # INTERNAL
│   │   └── prj-bu-a-svc2-prod           # CONFIDENTIAL
│   ├── fldr-prod-bu-b
│   │   └── prj-bu-b-svc3-prod           # CONFIDENTIAL
│   └── fldr-prod-ntk                    # NTK data domain — strict perimeter, no bridges
│       └── prj-ntk-domain1-prod         # NTK
│
├── fldr-nonprod                         # mirrors fldr-prod shape; synthetic data only
├── fldr-dev
└── fldr-sandbox                         # time-boxed, restrictive egress, no real data
```

Design rules that make this hierarchy load-bearing rather than cosmetic:

1. **Networking lives in separate projects fronted by a Shared VPC host in `fldr-common-network`;
   workload projects are service projects.** This separates network administration from workload
   ownership and puts the hybrid link and every egress control in one place with one owner. Pin it
   with `constraints/compute.restrictSharedVpcHostProjects` (allow-list = exactly the two host
   projects) and `constraints/compute.restrictSharedVpcSubnetworks` (per service project).
   Interconnect/VPN creation is confined to `prj-hybrid-edge` via
   `constraints/compute.restrictDedicatedInterconnectUsage`,
   `constraints/compute.restrictPartnerInterconnectUsage` and `constraints/compute.restrictVpnPeerIPs`.
2. **Security and logging projects sit in `fldr-common-security`, in a scope workload principals
   cannot write to.** Enforce with an IAM Deny at the org node denying
   `logging.googleapis.com/sinks.*`, `logging.googleapis.com/buckets.*`,
   `logging.googleapis.com/exclusions.*` and `cloudresourcemanager.googleapis.com/projects.setIamPolicy`
   with `exceptionPrincipals` = the security group, and by granting no workload principal any role in
   `fldr-common-security`.
3. **`fldr-sandbox` is the only folder where experimentation is permitted, and it holds no real
   data.** Attach `constraints/compute.vmExternalIpAccess` (`allValues: DENY`),
   `constraints/compute.restrictCloudNATUsage` (deny-all), a minimal
   `constraints/gcp.restrictServiceUsage` allow-list, and an IAM Deny on data-read permissions.

### 9.3 Policy attachment strategy

| Node | Attach | Why here |
|---|---|---|
| Organization | The seven baseline constraints (verify present, not deleted); `constraints/iam.managed.allowedPolicyMembers` or `constraints/iam.allowedPolicyMemberDomains`; `constraints/iam.managed.disableServiceAccountKeyCreation`; `constraints/iam.disableServiceAccountKeyUpload`; `constraints/iam.disableCrossProjectServiceAccountUsage`; `constraints/iam.workloadIdentityPoolProviders` set to deny-all with per-project exceptions; `constraints/gcp.restrictCmekCryptoKeyProjects`; IAM Deny policies for the escalation permission set; PAB bindings for every workforce/workload pool | These must be un-overridable and must apply to projects that do not exist yet. Deny evaluates before allow and inherits down. |
| `fldr-common` | Hierarchical firewall policy: allow the restricted-VIP egress set, deny everything else outbound; org-wide address groups | The network folder owns the egress definition once, for everyone. |
| `fldr-prod` | Hierarchical firewall policy (stricter east-west deny); `constraints/compute.vmExternalIpAccess` deny-all; `constraints/compute.restrictCloudNATUsage` allow-list; `constraints/compute.requireOsLogin` / `constraints/compute.managed.requireOsLogin`; `constraints/compute.disableSerialPortAccess`; `constraints/compute.requireShieldedVm`; `constraints/compute.restrictLoadBalancerCreationForTypes` with `deniedValues: [in:EXTERNAL]` | Prod-only tightening that dev cannot inherit-break, applied by inheritance to every future prod project. |
| `fldr-prod-ntk` | `constraints/gcp.restrictServiceUsage` allow-list; `constraints/gcp.resourceLocations`; `constraints/gcp.restrictNonCmekServices`; `constraints/gcp.detailedAuditLoggingMode`; `constraints/bigquery.disableBQOmniAWS` / `disableBQOmniAzure`; `constraints/dataform.restrictGitRemotes` deny-all | NTK is the smallest population, so the strictest set costs least here and would break prod if applied globally. |
| `fldr-sandbox` | External IP deny-all; Cloud NAT deny-all; minimal service allow-list; IAM Deny on data-read permissions | Contains experimentation without a perimeter, because there is no real data to perimeter. |
| Perimeters (ACM, **not** a hierarchy node) | `sp-confidential` — controlled-egress perimeter over every CONFIDENTIAL project, with named egress rules per documented flow. `sp-ntk` — strict, **no bridges**, ingress rules only for the named admin group and the named pipeline SA. Both enforced (`status`), with dry-run used only for change rehearsal. | Perimeters cannot attach to folders; membership is per project. Automate membership from the project's classification label and treat drift (HI-11) as a finding. |

Org-level access policy count is **1**; folder/project-scoped policies are capped at **50**. Perimeters
per policy cap at 10,000 (bridges count), protected resources at 40,000, and ingress+egress rule
attributes at **6,000 per perimeter config, counted separately for enforced and dry-run**. Design
inside those numbers before proposing a per-service perimeter.

### 9.4 Hierarchy as an escalation boundary

Bind each admin role class at exactly one node, and state the prohibition explicitly. The separation
that matters most: **the identity that deploys workloads and the identity that changes guardrails
must be disjoint principal sets**, enforced by an IAM Deny at the org node that denies the
guardrail-mutation permissions to `principalSet://goog/public:all` with `exceptionPrincipals` set to
the guardrail group.

| Admin role class | Exact roles / permissions | Bound at | Why there | Explicitly must NOT be held |
|---|---|---|---|---|
| Org-policy admin | `roles/orgpolicy.policyAdmin`; `orgpolicy.policy.set`, `orgpolicy.policies.create/update/delete`, `orgpolicy.customConstraints.*` | **Organization node only** (the role does not appear at project scope) | Constraints must be settable above every workload folder; the role is a meta-privilege that can delete domain-restricted sharing and then grant an external principal any role | by any deploy SA, any workload owner, or the same humans who hold ACM write |
| Perimeter / ACM admin | `accesscontextmanager.googleapis.com/servicePerimeters.*`, `accessLevels.*`, `policies.setIamPolicy` | **Organization node**, to a group whose membership is **disjoint** from the org-policy admin group | ACM write is equivalent to turning VPC-SC off; splitting it from org-policy admin means no single principal can dismantle both guardrail layers | by deploy identities; by anyone holding `roles/orgpolicy.policyAdmin` |
| Org IAM admin | `resourcemanager.organizations.setIamPolicy` | **Organization node**, break-glass only, zero standing holders | One grant here reaches every project | as a standing grant to any human or SA |
| Folder IAM admin | `resourcemanager.folders.setIamPolicy` | **Each top-level folder**, to that folder's owning platform group | Confines a compromised platform group to one environment | across folders; at the org node |
| Project IAM admin | `resourcemanager.projects.setIamPolicy` | **The project**, to the platform group | Resource-level `setIamPolicy` on a bucket/dataset/KMS key already reaches data without touching project IAM — keep the project grant as narrow as the resource ones | by the project's own runtime SA (that is a self-grant loop) |
| Deny-policy admin | `iam.googleapis.com/denypolicies.*` (create/update/delete) | **Organization node**, security group | Deny is the un-overridable layer; it must sit above every folder | by deploy identities. Note deny cannot protect deny — use PAB v3+ and role hygiene |
| PAB admin | `iam.googleapis.com/principalaccessboundarypolicies.*`, `iam.*.createPolicyBinding` / `deletePolicyBinding` | **Organization node**, security group | PAB itself cannot block its own binding verbs, so this must be protected by IAM Deny and role hygiene | by deploy identities |
| Network / firewall admin | `roles/compute.networkAdmin`, `roles/compute.securityAdmin`, `compute.firewallPolicies.update` | **`fldr-common-network`** for the host projects; hierarchical-policy write at the **organization/folder** to the network-security group only | Keeps firewall change out of workload folders and puts the hybrid link under one owner | by workload owners or service-project deployers |
| Tag admin / tag user | `roles/resourcemanager.tagAdmin` (create), `roles/resourcemanager.tagUser` (bind, and use in firewall rules) | tagAdmin at the **organization** to the security group; tagUser **per folder, on specific tag values** | Tags drive both org-policy conditions and firewall targeting: whoever binds a tag can grant themselves a policy exception or move a VM into a permissive firewall scope | tagAdmin by anyone outside security; tagUser on the tag values that gate org-policy exceptions |
| Billing / parent change | billing account admin; `resourcemanager.projects.create`, `projects.move`; `billing.resourceAssociations.create` | **Organization node**, billing group | `projects.move` sheds inherited policy and perimeter membership in one call | by deploy identities. Enforce with an IAM Deny on the group `cloudresourcemanager.googleapis.com/projects.*` with `exceptionPermissions` limited to what deploys genuinely need |
| Workload deploy identity | per-project deploy SA; `iam.serviceAccounts.actAs` **bound on that project's runtime SAs only**; service-specific create/update permissions | **The project it deploys to** | Confines a compromised pipeline to one project's blast radius | `setIamPolicy` at folder or org; `orgpolicy.policy.set`; ACM write; firewall policy write; `projects.move` / `projects.create` |
| Break-glass | a dedicated emergency identity (see §5.11) | no standing binding anywhere | Deny-by-default in normal state; time-boxed, dual-control, alerting on use | as a standing grant; and verify whether it bypasses VPC-SC — if it does, that is a prime exfil vector, not a convenience |

Detection that makes this table enforceable rather than aspirational: alert on `SetIamPolicy` at any
node, on every `orgpolicy.googleapis.com` and `accesscontextmanager.googleapis.com` write, on SA-key
creation, on token-generation/impersonation calls, and on VPC-SC violations including dry-run ones.

### 9.5 Classification → hierarchy mapping

| Tier | Lives in | Perimeter | Egress posture | Mandatory controls | Who may hold read |
|---|---|---|---|---|---|
| `PUBLIC` | any folder; separate projects from other tiers | may sit outside a perimeter | standard default-deny egress | classification label; `constraints/storage.publicAccessPrevention` still enforced unless a documented public-serving exception exists | anyone in-org |
| `INTERNAL` | `fldr-prod-<bu>` / `fldr-nonprod` | inside `sp-confidential` only if colocated with CONFIDENTIAL; otherwise its own or none | default-deny egress + restricted VIP | classification label; UBLA; Data Access logs on the data services | in-org groups, no external principals (`constraints/iam.managed.allowedPolicyMembers`) |
| `CONFIDENTIAL` | dedicated projects under `fldr-prod-<bu>` | **`sp-confidential`, enforced**, controlled egress: named egress rules per documented flow, no `resources: ["*"]`, no `serviceName: "*"` | default-deny egress; restricted VIP only; no external IPs; Cloud NAT allow-listed | CMEK per service or tier with key IAM = owning SA only; Data Access logs on every data service; PAB on every service principal; authorized views / policy tags instead of dataset-wide grants | the owning service's SA plus one named human group; no project-level `dataViewer` |
| `NTK` | dedicated projects under **`fldr-prod-ntk`** | **`sp-ntk`, enforced, minimally bridged — no bridges at all in the target design**; ingress rules naming the specific admin group and pipeline SA | as CONFIDENTIAL, plus `constraints/gcp.restrictServiceUsage` allow-list and `constraints/gcp.resourceLocations` | everything for CONFIDENTIAL, plus separate KMS project or keyring, `constraints/gcp.detailedAuditLoggingMode`, separate GKE node pools, and folder-level IAM that no other folder's admins hold | a named, enumerable principal list — if the list cannot be enumerated, the data is not NTK |

Separation of duties is enforced through **folder-level IAM**: the group that administers
`fldr-prod-ntk` holds no role in `fldr-prod-bu-a`, and vice versa; neither holds anything in
`fldr-common-security`.

### 9.6 Terraform sketch — folder and policy skeleton

```hcl
# ---------- folders ----------
resource "google_folder" "common" {
  display_name = "common"
  parent       = "organizations/${var.org_id}"
}

resource "google_folder" "prod" {
  display_name = "prod"
  parent       = "organizations/${var.org_id}"
}

resource "google_folder" "ntk" {
  display_name = "prod-ntk"
  parent       = google_folder.prod.name
}

# ---------- baseline guardrails at the org root ----------
resource "google_org_policy_policy" "no_sa_keys" {
  name   = "organizations/${var.org_id}/policies/iam.managed.disableServiceAccountKeyCreation"
  parent = "organizations/${var.org_id}"
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "no_cross_project_sa" {
  name   = "organizations/${var.org_id}/policies/iam.disableCrossProjectServiceAccountUsage"
  parent = "organizations/${var.org_id}"
  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# ---------- prod-only tightening, inherited by every future prod project ----------
resource "google_org_policy_policy" "prod_no_external_ip" {
  name   = "folders/${google_folder.prod.folder_id}/policies/compute.vmExternalIpAccess"
  parent = google_folder.prod.name
  spec {
    inherit_from_parent = true
    rules { deny_all = "TRUE" }
  }
}

# ---------- NTK: service allow-list + CMEK key projects ----------
resource "google_org_policy_policy" "ntk_services" {
  name   = "folders/${google_folder.ntk.folder_id}/policies/gcp.restrictServiceUsage"
  parent = google_folder.ntk.name
  spec {
    inherit_from_parent = true
    rules {
      values { allowed_values = ["bigquery.googleapis.com", "storage.googleapis.com", "cloudkms.googleapis.com"] }
    }
  }
}

# ---------- hierarchical firewall policy attached at the prod folder ----------
resource "google_compute_firewall_policy" "prod" {
  parent      = google_folder.prod.name
  short_name  = "fp-prod"
  description = "prod east-west default-deny; allows are per declared dependency"
}

resource "google_compute_firewall_policy_rule" "prod_deny_east_west" {
  firewall_policy = google_compute_firewall_policy.prod.id
  action          = "deny"
  direction       = "INGRESS"
  priority        = 65000
  enable_logging  = true
  match {
    src_ip_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    layer4_configs { ip_protocol = "all" }  # verify this block name on the hierarchical-policy
                                            # rule resource against current docs
  }
}

resource "google_compute_firewall_policy_association" "prod" {
  firewall_policy = google_compute_firewall_policy.prod.id
  attachment_target = google_folder.prod.name
  name            = "assoc-fp-prod"
}

# ---------- guardrail/deploy separation, un-overridable ----------
resource "google_iam_deny_policy" "guardrail_mutation" {
  parent = urlencode("cloudresourcemanager.googleapis.com/organizations/${var.org_id}")
  name   = "deny-guardrail-mutation-outside-security"
  rules {
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = ["principalSet://goog/group/grp-gcp-guardrails@example.com"]
      denied_permissions = [
        "orgpolicy.googleapis.com/policies.create",
        "orgpolicy.googleapis.com/policies.update",
        "orgpolicy.googleapis.com/policies.delete",
        "orgpolicy.googleapis.com/customConstraints.create",
        "orgpolicy.googleapis.com/customConstraints.update",
        "orgpolicy.googleapis.com/customConstraints.delete",
        "accesscontextmanager.googleapis.com/servicePerimeters.create",
        "accesscontextmanager.googleapis.com/servicePerimeters.update",
        "accesscontextmanager.googleapis.com/servicePerimeters.delete",
        "accesscontextmanager.googleapis.com/servicePerimeters.replaceAll",
        "accesscontextmanager.googleapis.com/servicePerimeters.commit",
        "accesscontextmanager.googleapis.com/accessLevels.create",
        "accesscontextmanager.googleapis.com/accessLevels.update",
        "accesscontextmanager.googleapis.com/accessLevels.delete",
        "accesscontextmanager.googleapis.com/accessLevels.replaceAll",
        "accesscontextmanager.googleapis.com/policies.create",
        "accesscontextmanager.googleapis.com/policies.update",
        "accesscontextmanager.googleapis.com/policies.delete",
        "accesscontextmanager.googleapis.com/policies.setIamPolicy",
        "accesscontextmanager.googleapis.com/authorizedOrgsDescs.create",
        "accesscontextmanager.googleapis.com/authorizedOrgsDescs.update",
        "accesscontextmanager.googleapis.com/authorizedOrgsDescs.delete",
        "logging.googleapis.com/sinks.delete",
        "logging.googleapis.com/sinks.update"
      ]
    }
  }
}
```

This block is the org-node instance of §5.5 rules #8–#10, and every line of it is load-bearing.
`servicePerimeters.replaceAll` wipes **every** perimeter in the access policy in one call;
`.commit` promotes an attacker-authored dry-run spec to enforced; `policies.delete` deletes the access
policy outright, taking every perimeter with it; `customConstraints.delete` removes the constraint that
alert filter `F7` fires on. Omitting any of the four leaves a live bypass of the whole VPC-SC control
plane. If you trim this list, re-run test `SC-25` against the result before calling the gap closed.

Use `google_org_policy_policy` and `google_org_policy_custom_constraint` (Org Policy **v2**), never
`google_organization_policy` / `google_project_organization_policy` — the v1 resources cannot express
conditions or dry-run, and a v1 resource managing a constraint that also has a v2 conditional policy
will fight it on every apply. Minimum provider versions — verify against current docs.

---

## 10. Extensibility — the supplementary requirements file

The reviewer accepts an optional `.md` of additional or overriding requirements: org-specific policy,
a compliance framework, custom constraints, named data domains. **Absent a file, run the baseline
ruleset unchanged** and record in `SCOPE.md`: `Supplementary requirements: none supplied; baseline
ruleset unchanged.` Do not invent requirements to fill the gap.

Reserved ID prefixes, from the single scheme in §11.2.1: **`SR-`** for a supplied requirement, for
any gap finding against it, and — suffixed `(conflict)` — for a baseline/supplied disagreement;
**`DC-`** for unclassified data-bearing resources; **`DRIFT-`** for IaC-vs-live divergence.

### 10.1 Merge algorithm

Run this **before** Phase 2. Merging after assessment invalidates the assessment.

1. **Read the whole file.** If none was supplied, set `RULESET = baseline` and skip to Phase 2.
2. **Atomize.** Every heading, bullet, or table row that states a testable obligation becomes one
   rule record: `id` (`SR-001`, `SR-002`, … in document order), `source` (file name + heading path
   + line), `statement` (**verbatim** text), `scope` (org / folder / project / resource selector; if
   the text names none, scope = the whole review scope), `test` (the observable that decides it),
   `severity_floor` (if the document states one), `authority` = `supplied`.
3. **Handle untestable statements.** If you cannot write `test` as an observable check against an
   intake artifact, do not drop the rule and do not guess. Record it with
   `test = UNTESTABLE-AS-WRITTEN` and emit this literal question:
   > "Requirement `SR-nnn` states: *"<verbatim statement>"*. What observable configuration would you
   > accept as proof this is met — which resource, which field, and which value?"
4. **Classify each supplied rule against the baseline.** Find the baseline rules covering the same
   control target (same constraint name, same permission string, same resource class, same
   perimeter/boundary):
   - **ADDITIVE** — no baseline rule addresses that target. Append to `RULESET`.
   - **STRICTER** — the supplied rule permits a strict subset of what the baseline permits. The
     supplied rule becomes the assessed rule; keep the baseline rule as a note in the merged ruleset.
   - **LOOSER** — the supplied rule permits something the baseline forbids. → **CONFLICT**.
   - **CONTRADICTORY** — the supplied rule requires something the baseline forbids, or forbids
     something the baseline requires. → **CONFLICT**.
5. **Never resolve a conflict silently and never weaken a baseline check.** On CONFLICT, keep **both**
   rules in `RULESET`, assess the environment against **both**, write the gap finding against the
   supplied rule (it is authoritative), and additionally emit an `SR-nnn (conflict)` entry carrying
   the baseline deviation and its exfil consequence.
6. **Assess in Phase 4 against the merged ruleset.** Every supplied rule appears in the coverage
   table with a verdict — `MET`, `GAP`, or `NOT-ASSESSABLE` — even where it duplicates a baseline
   check. A supplied rule with no verdict is a defect in the review.
7. **Emit gaps as findings with the `SR-` prefix**, never under a baseline ID. Each carries the
   verbatim requirement text, the observed value, and a remediation snippet in the same three-part
   form as every other finding.
8. **Publish** the merged ruleset and the full conflict report as appendices, with the requirements
   file's own name and a content hash so a later reviewer can tell which version was merged.

### 10.2 Conflict report shape

```
SR-nnn (conflict)
  Supplied rule:   SR-nnn — "<verbatim statement from the requirements file>"
                   source: <file>.md § "<heading path>" (line N)
  Baseline rule:   <skill section> — "<baseline requirement, quoted>"
  Conflict type:   ADDITIVE | STRICTER | LOOSER | CONTRADICTORY
  Disagreement:    <one sentence: what the supplied rule permits or requires that the baseline does not>
  Exfil delta:     <which attack path is no longer interrupted, at which step, and what control remains>
  Assessed under:  BOTH — finding <SR-id> against the supplied rule; finding <baseline-id> retained
                   and marked "in conflict with SR-nnn"
  Decision needed: "<literal question put to the human owner>"
```

### 10.3 Worked example

> **EXAMPLE — illustrative shape only. `acme-*` names below are fictional and appear solely to show
> the required output form.**

```
SR-021 (conflict)
  Supplied rule:   SR-021 — "Analytics teams may export query results to the shared analytics
                   landing bucket in the acme-analytics-shared project without a change ticket."
                   source: acme-security-requirements.md § "Data Platform" → "Analytics workflows" (line 148)
  Baseline rule:   §5.3 (VPC Service Controls) — "every project holding
                   CONFIDENTIAL data sits inside an enforced perimeter whose egress rules name the
                   specific identity and project for each permitted flow"
  Conflict type:   LOOSER
  Disagreement:    SR-021 permits an unrestricted-identity egress flow from the CONFIDENTIAL
                   perimeter to projects/acme-analytics-shared; the baseline permits that flow only
                   for a named identity set under an egress rule.
  Exfil delta:     `AP-07` (BigQuery/Storage export or copy into an attacker-controlled
                   external project) is no longer interrupted at step 3. The residual control is the bucket's own IAM policy, which
                   any principal holding storage.buckets.setIamPolicy on it can rewrite; no perimeter
                   check remains on the egress itself.
  Assessed under:  BOTH — finding SR-021-a written against the supplied rule (verdict GAP: the
                   landing bucket is in no perimeter at all, so even SR-021's own boundary is
                   absent); finding `SC-04` retained and marked "in conflict with SR-021".
  Decision needed: "SR-021 permits ticket-free export from CONFIDENTIAL projects into
                   acme-analytics-shared. Do you want that flow expressed as a VPC-SC egress rule
                   naming the analytics service accounts and projects/acme-analytics-shared — which
                   preserves the exemption while keeping the perimeter check — or should SR-021
                   stand as written, accepting that any principal able to read the source data can
                   move it out of the perimeter without a perimeter-level control?"
```

---

## 11. Output specification, severity rubric, report template, and the anti-fluff gate

This section governs what you emit. Do not start writing the report until you can fill every required
field of every finding. Do not emit the report until the anti-fluff gate (11.6) passes with zero
outstanding items.

---

### 11.1 Severity rubric

Restate this rubric **verbatim** in Section 0 of every report — the table, the five inputs, the
detection rule, and the ordering rule. Do not paraphrase or abbreviate it, and do not invent a band
that is not in it.

#### 11.1.1 The five scoring inputs

Score every finding and every chain on exactly these five variables. Record all five in the finding's
`Severity` line.

| Input | Symbol | Values | How you determine it |
|---|---|---|---|
| Classification tier reachable at the end of the path | **T** | `NTK`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`, `NONE` (credential or control-plane only) | Highest tier the terminal principal can read. Unclassified store → score as `CONFIDENTIAL` and raise a `DC-` finding (11.2.1). |
| Terminus of the path | **X** | `EGRESS-OUT`, `EGRESS-BOUNDARY`, `READ-ONLY`, `CONTROL-PLANE` | See 11.1.2. |
| Number of principals who can execute it today | **P** | integer, or `UNBOUNDED` | Enumerate. Expand groups to their transitive closure (`groups.memberships.searchTransitiveMemberships()`). `allUsers`, `allAuthenticatedUsers`, `identityType: ANY_IDENTITY`/`ANY_USER_ACCOUNT`/`ANY_SERVICE_ACCOUNT`, and any `principalSet://…/*` are `UNBOUNDED`. |
| Ease of the starting position | **S** | `S0`, `S1`, `S2`, `S3` | See 11.1.3. |
| Detection posture of the pivotal step | **D** | `DETECTED`, `UNDETECTED` | See 11.1.4. Binary — there is no partial credit. |

#### 11.1.2 Terminus values (X)

| Value | Means | Examples |
|---|---|---|
| `EGRESS-OUT` | Data leaves every boundary the org controls | Copy to a project outside the org (`T1537`), BigQuery dataset copy via `bigquerydatatransfer.googleapis.com` data source `cross_region_copy`, `EXPORT DATA OPTIONS(uri='gs://…')` to an outside bucket, BigQuery Omni export to `s3://`/`azure://`, Pub/Sub push subscription to an attacker HTTPS endpoint, signed URL, log sink to an outside project, VM external IP or Cloud NAT to the internet, data landing in the on-prem interior beyond the authorized landing zone |
| `EGRESS-BOUNDARY` | Data crosses an unauthorized internal boundary but stays where org controls still exist | Cross-perimeter copy inside the org, perimeter bridge traversal, CONFIDENTIAL data into a project with no perimeter, cloud → authorized on-prem landing zone with no downstream constraint |
| `READ-ONLY` | Path reaches read access; no egress channel demonstrated from that position | Principal can `bigquery.tables.getData` but every egress-capable service is restricted and no outbound rule matches |
| `CONTROL-PLANE` | Path only mutates a guardrail; data access is a later step not yet demonstrated | `orgpolicy.policy.set`, `accesscontextmanager.googleapis.com/servicePerimeters.update`, `iam.roles.update`, `logging.sinks.delete` |

A path is not `READ-ONLY` because you did not look for the egress step. Before scoring `READ-ONLY`,
state which egress channels you enumerated and which control blocks each.

#### 11.1.3 Starting-position ladder (S)

| Value | Starting position | Test |
|---|---|---|
| `S0` | No pre-existing access, or access any internet party holds | Unauthenticated caller; any Google account; any GitHub/GitLab tenant against an unconditioned WIF provider; a public bucket or `allUsers` binding |
| `S1` | One low-privilege but legitimate credential, or one compromised application workload | Any member of a broad group; a compromised app with SSRF reaching `169.254.169.254`; a compromised on-prem interior host (assume-breach interior — treat interior foothold as `S1`, never `S2`) |
| `S2` | A specific named privileged identity must be compromised first | A named CI service account, a platform-team human account, a specific SA key file on a specific host |
| `S3` | Super-admin, or two independent compromises that do not share a cause | Cloud Identity super admin; break-glass plus a second unrelated credential |

#### 11.1.4 Detection rule (D)

A path is `DETECTED` only when **all three** hold for the pivotal step (the step whose removal
severs the path):

1. The log type that would record it is **enabled in this environment** — verified by reading the
   `auditConfigs` block or the sink config, not assumed. Most impersonation and read activity is
   `DATA_ACCESS`, which is off by default (BigQuery is the documented exception).
2. An alerting policy fires on it, and you can name the policy and its notification channel.
3. The alert's log route and notification channel are outside the blast radius of the path — the
   principals in the path cannot delete the sink, add an exclusion, shorten retention, or silence the
   channel.

Anything else is `UNDETECTED`.

> **Undetected scores one band higher.** Compute the base band from `T`, `X`, `S`, `P`, then if
> `D = UNDETECTED`, raise the result exactly one band. The raise cannot exceed `CRITICAL` and never
> applies to `INFO`. Show the arithmetic in the finding.

#### 11.1.5 Base band matrix

| T | X | S0 / S1 | S2 | S3 |
|---|---|---|---|---|
| `CONFIDENTIAL` or `NTK` | `EGRESS-OUT` | **CRITICAL** | **HIGH** | **MEDIUM** |
| `CONFIDENTIAL` or `NTK` | `EGRESS-BOUNDARY` | **HIGH** | **HIGH** | **MEDIUM** |
| `CONFIDENTIAL` or `NTK` | `READ-ONLY` | **HIGH** | **MEDIUM** | **MEDIUM** |
| `INTERNAL` | `EGRESS-OUT` | **HIGH** | **MEDIUM** | **LOW** |
| `INTERNAL` | `EGRESS-BOUNDARY` or `READ-ONLY` | **MEDIUM** | **LOW** | **LOW** |
| `NONE` | `CONTROL-PLANE` | **HIGH** | **MEDIUM** | **LOW** |
| `PUBLIC` | any | **LOW** | **LOW** | **INFO** |

#### 11.1.6 Band definitions (what each band asserts)

| Band | Assertion the band makes |
|---|---|
| **CRITICAL** | CONFIDENTIAL or NTK data can leave every org-controlled boundary today, from a starting position an adversary can obtain without first compromising a named privileged identity — or an unbounded principal set can execute it. Fix inside the current change window. |
| **HIGH** | Same data tier, but one named privileged compromise is required first; or the data is reachable with no demonstrated egress channel; or a guardrail protecting that data can be mutated by principals outside the guardrail-owner set. Fix inside the current quarter, sequenced per 11.5. |
| **MEDIUM** | The path exists only from a hard starting position, or reaches only INTERNAL data, or the control is present but detective/dry-run where this review requires enforcement, or an isolation boundary is collapsed with no currently reachable path across it. |
| **LOW** | Lengthens a chain by one cheap hop, or degrades forensics, with no live path to INTERNAL-or-higher data. |
| **INFO** | Observed configuration recorded for traceability, accepted documented exceptions, and unresolved "(verify against current docs)" items. No defect asserted. `INFO` never takes the detection modifier and never appears in the roadmap. |

#### 11.1.7 Evidence cap on severity

| Evidence class | Maximum band |
|---|---|
| `[EVIDENCE]` | `CRITICAL` |
| `[INTERVIEW]`, confidence `HIGH` | `HIGH` |
| `[INTERVIEW]`, confidence `MEDIUM` | `HIGH` |
| `[INTERVIEW]`, confidence `LOW` | `MEDIUM` |

No `[INTERVIEW]` finding is ever `CRITICAL`. If an interview points at a `CRITICAL`, name the one
artifact that would settle it and ask for that artifact by name in Appendix F.

#### 11.1.8 Decision procedure (run in this order; two reviewers must land in the same band)

1. Name the terminal resource and read its classification label/tag. Record `T`. If unlabeled, set
   `T = CONFIDENTIAL`, mark the assumption in the finding, and raise the matching `DC-` finding.
2. Name the egress mechanism the terminal principal can invoke and the control that blocks it.
   Record `X`.
3. Enumerate the principals who hold every permission in the path today. Record `P` as an integer or
   `UNBOUNDED`; list them (or the principal set) in the finding scope.
4. Rate `S` against the ladder in 11.1.3 using the adversary starting positions defined in the threat
   model, not a hypothetical.
5. Read the base band from 11.1.5.
6. If `P = UNBOUNDED` or `P > 50` and the base band is below `CRITICAL`, raise one band.
7. Evaluate `D` against all three conditions in 11.1.4. If `UNDETECTED`, raise one band (cap
   `CRITICAL`).
8. Apply the evidence cap in 11.1.7.
9. Write the arithmetic into the `Severity` line.

**Ordering rule for equal bands** (so report order is reproducible): CONFIDENTIAL-tier findings rank
above NTK-tier findings in the same band, because CONFIDENTIAL's broad internal reach maximizes
attack surface; then higher `P` first; then lower `S` first; then lower ID first.

#### 11.1.9 Worked scoring example

> Finding: `roles/iam.serviceAccountTokenCreator` bound at project scope to a CI group, conferring
> impersonation of `etl-writer@…` which holds `roles/bigquery.dataViewer` on three CONFIDENTIAL
> datasets, from which `EXPORT DATA` can write to a bucket in an outside project.
>
> 1. `T = CONFIDENTIAL` — the three datasets carry `data_classification: confidential`.
> 2. `X = EGRESS-OUT` — `bigquery.jobs.create` + `EXPORT DATA OPTIONS(uri='gs://…')`; the perimeter
>    restricts `bigquery.googleapis.com` but not `storage.googleapis.com`, so the GCS write leaves.
> 3. `P = 6` — the group's transitive closure is 6 accounts, enumerated.
> 4. `S = S2` — the path starts from one of those 6 named CI-operator accounts.
> 5. Base band from the matrix (`CONFIDENTIAL` × `EGRESS-OUT` × `S2`) = **HIGH**.
> 6. `P = 6`, not `UNBOUNDED` and not `> 50` → no raise.
> 7. `D = UNDETECTED` — the pivotal step logs as `protoPayload.methodName="GenerateAccessToken"`,
>    `serviceName="iamcredentials.googleapis.com"`, which is a Data Access `ADMIN_READ` log; the org
>    `auditConfigs` has no `ADMIN_READ` entry for `iam.googleapis.com`, so nothing is written →
>    raise one band → **CRITICAL**.
> 8. `[EVIDENCE]` (org IAM policy export + `auditConfigs`) → cap `CRITICAL`, no reduction.
>
> `Severity: CRITICAL (T=CONFIDENTIAL, X=EGRESS-OUT, P=6, S=S2, D=UNDETECTED; base HIGH +1 undetected)`

---

### 11.2 Finding format

#### 11.2.1 ID scheme

`PREFIX-NN`, two digits, zero-padded, assigned in discovery order within each prefix. IDs are stable:
never renumber across report revisions; a withdrawn finding keeps its ID and is marked `WITHDRAWN`
with the reason. Two width exceptions, both deliberate: **`SR-` uses three digits** (`SR-001`), because
a supplied requirements file routinely carries more than 99 rules; and the **test-ID namespace below
(`LM-`, `ISO-`) is not zero-padded**, because those IDs are read out of this skill and never sorted in
Appendix E. Every *finding* prefix, `HI-` included, is two digits and zero-padded — Appendix E sorts
lexicographically, so `HI-01` files between `HI-12` and `HI-02`.

| Prefix | Area |
|---|---|
| `OP-` | Organization policy — constraints, inheritance, lower-node overrides, custom constraints, tag-conditioned exceptions |
| `FW-` | VPC firewall — hierarchical/network/legacy rules, egress posture, east-west segmentation, firewall logging |
| `SC-` | VPC Service Controls and Access Context Manager — perimeters, restricted services, ingress/egress rules, access levels, bridges, dry-run |
| `IA-` | IAM allow policies — over-provisioning, toxic combinations, resource-level bindings, external principals |
| `DN-` | IAM Deny — missing or mis-scoped deny policies |
| `PB-` | Principal Access Boundary — missing bindings, enforcement version too low |
| `IM-` | Impersonation and escalation primitives — privilege-graph edges (`actAs`, token minting, key mint, `setIamPolicy`, role mutation, group write, guardrail mutation) |
| `WI-` | Workload / Workforce Identity Federation — pools, providers, attribute mappings and conditions |
| `ID-` | Identity posture — Cloud Identity/Workspace, super admins, SSO/MFA, groups and nesting, SA and key lifecycle |
| `AX-` | Access — access levels, IAP context-aware access, Access Approval, Access Transparency, JIT elevation |
| `BG-` | Break-glass |
| `LG-` | Audit logging and detection coverage — Data Access logs, sinks, retention, alerting |
| `NW-` | Hybrid networking — interconnect/VPN, BGP and effective routes, DNS, Private Google Access and the restricted VIP |
| `PS-` | Private Service Connect — endpoints, published services, NEGs |
| `CE-` | Compute / GKE / serverless deployment surface — attached SAs, scopes, metadata, OS Login, node SAs, RBAC, invoker bindings |
| `CD-` | CI/CD and IaC control plane — pipelines, self-hosted runners, deploy identities, Terraform state |
| `DP-` | Data-plane isolation — per-service buckets/datasets/topics, CMEK/KMS key IAM, authorized views, policy tags |
| `HI-` | Resource hierarchy — current hierarchy defects and target-state gaps |
| `CH-` | Attack-chain findings (11.3) — one per end-to-end chain |
| `SR-` | **Supplementary-requirement gap** — the environment fails a requirement from the supplied `.md`, or a supplied requirement conflicts with a baseline recommendation |
| `DC-` | **Unclassified or mis-classified data store** — a data-bearing resource with no classification label/tag, or one whose label contradicts its contents |
| `VD-` | Appendix-only: an item this review could not verify against current documentation |
| `DRIFT-` | IaC-declared state vs live state divergence (§2.1) |
| `LM-` | **Test ID, not a finding** — a traversal check in §7 |
| `ISO-` | **Test ID, not a finding** — a service-isolation check in §8 |

`CH-` findings cite the threat-model path they instantiate as `AP-nn`. `AP-nn` IDs are assigned in
§4.6; never mint a new `AP-nn` inside the findings section.

Two ID namespaces exist and must not be collapsed. **Finding IDs** are the prefixes above: emitted in
the report, numbered in discovery order, stable across revisions. **Test IDs** are the numbered checks
inside this skill — §5's catalog tests share the finding prefix (`SC-04`, `IA-02`, `LG-13`), while
§7's traversal tests (`LM-nn`) and §8's isolation tests (`ISO-nn`) carry their own. A failed `LM-` or
`ISO-` test is emitted under the area prefix given by the routing table below, citing the test ID in
its `Misconfiguration` line. Every finding therefore reads `<finding ID> (test <test ID>)`.
**Write a test reference as `test SC-04`, never bare:** a bare `SC-04` anywhere in a report is a
finding ID, and the two namespaces reuse the same numbers.

**Test-ID → finding-prefix routing.** This is the whole mapping; do not choose a prefix by feel. Where
a subsection routes to two prefixes, the second applies only in the stated case.

| Test IDs from | Emit under | Second prefix, when |
|---|---|---|
| §7.0, §7.1.2 (flat VPC), §7.1.5 (Shared VPC), §7.1.6 (cross-project) | `NW-` | `FW-` when the defect is a specific firewall rule or its priority |
| §7.1.1 (metadata → SA token), §7.1.3 (SSH/serial/IAP), §7.1.4 (GKE) | `CE-` | `IM-` when the finding's subject is the token/impersonation edge rather than the compute surface |
| §7.2.1–§7.2.4 (cloud → on-prem) | `NW-` | `DP-` when the finding is about where CONFIDENTIAL data lands, not about reachability |
| §7.3.1 (credentials on interior hosts) | `CD-` | `ID-` when the credential is a user-managed SA key (lifecycle, not pipeline) |
| §7.3.2 (self-hosted GHES runners) | `CD-` | `WI-` when the defect is the WIF provider's `attributeCondition` |
| §7.3.3 (federated humans from the interior IdP) | `WI-` | — |
| §7.3.4 (restricted VIP / DNS), §7.3.5 (interior reach to PSC) | `NW-` | `PS-` when the object is a PSC endpoint or service attachment |
| §8.1 (identity isolation) | `IM-` | `ID-` for SA-key and default-SA lifecycle |
| §8.2 (resource/project isolation) | `HI-` | `OP-` when the missing enforcement is an org-policy constraint |
| §8.3 (network isolation) | `FW-` | `NW-` for GKE NetworkPolicy and inter-subnet reachability |
| §8.4 (service-to-service auth) | `CE-` | — |
| §8.5 (data-plane isolation) | `DP-` | — |
| §8.6 (boundary isolation) | `SC-` | `PB-` for the PAB-per-service-principal row |
| §8.7 (enforcement plumbing) | the prefix of the control the row governs | `LG-` when the missing layer is runtime detection |

#### 11.2.2 Fully-qualified name forms (use these, not display names)

| Object | Form |
|---|---|
| Project | `projects/PROJECT_ID` — add `projects/PROJECT_NUMBER` wherever the API takes a number (VPC-SC perimeter membership, WIF principal sets) |
| Folder / org node | `folders/FOLDER_ID`, `organizations/ORG_ID` |
| Bucket | `gs://BUCKET` and `//storage.googleapis.com/BUCKET` |
| BigQuery | `PROJECT_ID:DATASET` / `PROJECT_ID.DATASET.TABLE` |
| Service account | full email `NAME@PROJECT_ID.iam.gserviceaccount.com` (default SAs: `PROJECT_NUMBER-compute@developer.gserviceaccount.com`) |
| Perimeter / access level | `accessPolicies/POLICY_ID/servicePerimeters/NAME`, `accessPolicies/POLICY_ID/accessLevels/NAME` |
| Principal | IAM form (`user:`, `group:`, `serviceAccount:`, `principal://`, `principalSet://`) |
| KMS key | `projects/P/locations/L/keyRings/R/cryptoKeys/K` |
| Constraint | `constraints/SERVICE.NAME` (state legacy vs `SERVICE.managed.NAME` explicitly) |

#### 11.2.3 The template

Every finding uses exactly these fields, in this order. No field is omitted; a field with nothing to
say says why.

````markdown
#### <ID> — <title: names the resource and the defect, no verbs like "review" or "harden">

- **Severity**: <BAND> (T=…, X=…, P=…, S=…, D=…; base <BAND> <±modifier>)
- **Scope**: <fully-qualified resource(s), one per line; and the principal(s) if the finding is about access>
- **Evidence**: [EVIDENCE] <artifact or command that produced it> · collected <YYYY-MM-DD HH:MMZ>
  — or — [INTERVIEW] <role/person, date> · confidence <HIGH|MEDIUM|LOW> · <the one artifact that would settle it>
- **Misconfiguration**: `<exact identifier>` — observed `<value>`, required `<value>`. <One sentence on the mechanism, no adjectives.>
- **Attack chain enabled**: AP-nn (<path name>) → chain CH-nn, steps <n–m>. ATT&CK: <IDs + names>.
- **Detection posture**:
  - Log method: `<protoPayload.methodName>` (`serviceName="<…>"`)
  - Log type: <ADMIN_ACTIVITY | DATA_ACCESS ADMIN_READ/DATA_READ/DATA_WRITE | POLICY_DENIED | NONE>
  - Enabled here: <yes/no> — verified via <where you read it>
  - Alerting: <policy name + channel, or "none">
  - Retention: <bucket, days, locked?>
  - Verdict: <DETECTED | UNDETECTED>
- **Remediation**: <exact constraint / role / permission / rule field and the value to set>
  ```bash
  # gcloud
  ```
  ```hcl
  # Terraform
  ```
- **Blast radius**: <what stops working, who notices, how to enumerate the affected callers BEFORE applying>
- **Rollback**: <exact command that reverts, time to revert, whether the revert is itself detectable>
- **Verify fix**: <one command whose output proves the finding is closed>
````

Rules that bind the template:

1. If the remediation has no technical enforcement mechanism, say so in `Remediation` and name the
   compensating review gate (who reviews what, on what trigger, with what query) — per the
   enforce-by-default rule in §8. "Recommended" with neither is not an
   acceptable output.
2. `Blast radius` must name the enumeration step that precedes the change, not a warning. "May break
   automation" is fluff; "run alert filter `B` (§5.12) for 14 days and enumerate the
   callers of `GenerateAccessToken` on this SA" is a blast-radius statement.
3. Any identifier you could not confirm against current documentation carries the literal marker
   `(verify against current docs)` at its point of use **and** an entry in Appendix D.
4. When you cannot resolve `T`, `P`, or `D` from evidence, ask the literal question (11.4.4) rather
   than guessing, and mark the finding `[INTERVIEW]` until answered.

#### 11.2.4 Worked example — organization-policy finding

> **EXAMPLE — shape and specificity only. Resource names are illustrative. Chain IDs (`CH-nn`) and
> finding IDs shown here are illustrative placeholders, not cross-references; real ones are assigned
> at review time.**

````markdown
#### OP-02 — `constraints/storage.publicAccessPrevention` unset at the org node and unenforced on two CONFIDENTIAL projects

- **Severity**: CRITICAL (T=CONFIDENTIAL, X=EGRESS-OUT, P=UNBOUNDED, S=S0, D=UNDETECTED; base CRITICAL, capped)
- **Scope**:
  - `organizations/123456789012` (no policy for this constraint at any node)
  - `projects/data-prod-01` — buckets `gs://data-prod-01-landing`, `gs://data-prod-01-curated` (label `data_classification: confidential`)
  - `projects/analytics-prod-03` — bucket `gs://analytics-prod-03-exports` (label `data_classification: confidential`)
  - Principals: `allUsers` is not currently bound, but any of the 23 principals holding
    `storage.buckets.setIamPolicy` on these buckets can bind it in one call
- **Evidence**: [EVIDENCE] `gcloud org-policies list --organization=123456789012 --format=json` (constraint absent);
  `gcloud asset export --organization=123456789012 --content-type=iam-policy --output-path=gs://…` for the bucket bindings
  · collected 2026-08-25 09:14Z
- **Misconfiguration**: `constraints/storage.publicAccessPrevention` (legacy managed, Boolean) — observed **no policy at
  org, folder, or project**, so the Google default (not enforced) applies; required `spec.rules[0].enforce: true` at
  `organizations/123456789012`. Note this constraint is **not** part of the seven baseline constraints auto-enforced on
  organizations created on or after 2024-05-03 (that set includes `constraints/storage.uniformBucketLevelAccess`, not
  this one), so its absence here is the default state, not evidence of deletion.
- **Attack chain enabled**: AP-04 (data staged into a bucket with public or over-broad access) → chain CH-04, steps 3–4.
  ATT&CK: T1098.003 (Additional Cloud Roles — the `allUsers` grant), T1530 (Data from Cloud Storage),
  T1537 (Transfer Data to Cloud Account). T1567.002 is **not** cited: its platform list is not IaaS-scoped.
- **Detection posture**:
  - Log method: `storage.setIamPermissions` (`serviceName="storage.googleapis.com"`) for the grant;
    `storage.objects.get` / `storage.objects.list` for the read
  - Log type: the grant is ADMIN_ACTIVITY (always on); the reads are DATA_ACCESS `DATA_READ`
  - Enabled here: grant yes; reads **no** — org IAM policy has no `auditConfigs` entry for
    `storage.googleapis.com` or `allServices`. `constraints/gcp.detailedAuditLoggingMode` is also unset, so even if
    enabled the entries would not name which objects were read
  - Alerting: none on `storage.setIamPermissions`
  - Retention: n/a for the reads (not written)
  - Verdict: UNDETECTED — the exfiltration itself produces no log
- **Remediation**: set `constraints/storage.publicAccessPrevention` to enforced at `organizations/123456789012`.
  This blocks `AP-04` at the staging step. There is **no dry-run for this constraint** — dry-run mode is limited to
  custom constraints, managed constraints, and a small set of legacy ones (`constraints/gcp.restrictServiceUsage`,
  `constraints/gcp.restrictEndpointUsage`, TLS constraints) — so run the pre-scan in *Blast radius* instead of a dry-run.
  ```bash
  cat > /tmp/pap.yaml <<'EOF'
  name: organizations/123456789012/policies/storage.publicAccessPrevention
  spec:
    rules:
    - enforce: true
  EOF
  gcloud org-policies set-policy /tmp/pap.yaml
  gcloud org-policies describe constraints/storage.publicAccessPrevention \
      --effective --project=data-prod-01 --format=json
  ```
  ```hcl
  resource "google_org_policy_policy" "public_access_prevention" {
    name   = "organizations/123456789012/policies/storage.publicAccessPrevention"
    parent = "organizations/123456789012"
    spec {
      rules { enforce = "TRUE" }
    }
  }
  ```
- **Blast radius**: any bucket currently serving public objects stops serving them. Enumerate before applying:
  `gcloud asset search-all-iam-policies --scope=organizations/123456789012 --query='policy:allUsers OR policy:allAuthenticatedUsers'`.
  A bucket whose own `iamConfiguration.publicAccessPrevention` is already `enforced` is unaffected — that bucket-level
  setting is ratchet-up-only and survives removal of the org policy. Buckets deliberately serving public content must be
  moved to a project excluded by a tag-conditioned rule, and the tag-write permission (`roles/resourcemanager.tagUser` on that
  tag value) must be held only by `grp-platform-net@example.com`, or the exception becomes the bypass.
- **Rollback**: `gcloud org-policies delete constraints/storage.publicAccessPrevention --organization=123456789012`
  (requires `roles/orgpolicy.policyAdmin`). The deletion is logged as
  `google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy` in org-level ADMIN_ACTIVITY — alert on it (alert filter `G`, §5.12).
- **Verify fix**: `gcloud org-policies describe constraints/storage.publicAccessPrevention --effective --project=data-prod-01 --format="value(spec.rules[0].enforce)"` returns `True` (`--effective`, and at the **project** node — the org-node read would report "fixed" while a project override still disables it), and creating a public binding on
  `gs://data-prod-01-landing` fails.
````

#### 11.2.5 Worked example — impersonation-chain finding

> **EXAMPLE — shape and specificity only. Resource names are illustrative.**

````markdown
#### IM-01 — `roles/iam.serviceAccountTokenCreator` bound to `group:eng-all@example.com` at project scope on `projects/data-prod-01`

- **Severity**: CRITICAL (T=CONFIDENTIAL, X=EGRESS-OUT, P=212, S=S1, D=UNDETECTED; base CRITICAL, capped)
- **Scope**:
  - Binding: `projects/data-prod-01` allow policy, role `roles/iam.serviceAccountTokenCreator`,
    member `group:eng-all@example.com` (212 accounts in the transitive closure)
  - Confers impersonation of **all 14** service accounts in the project, including
    `etl-writer@data-prod-01.iam.gserviceaccount.com` (`roles/bigquery.dataViewer` on
    `data-prod-01:cust_txn`, `data-prod-01:cust_pii`, `data-prod-01:billing_hist`, all labeled
    `data_classification: confidential`)
- **Evidence**: [EVIDENCE] `gcloud projects get-iam-policy data-prod-01 --format=json`;
  `gcloud asset analyze-iam-policy --project=data-prod-01 --analyze-service-account-impersonation`
  · collected 2026-08-25 09:22Z
- **Misconfiguration**: the role is bound at **project** scope. Observed: one project-level binding.
  Required: bindings on the specific service-account resources the callers need, and nothing at project scope.
  A project-scope binding of this role grants, on every SA in the project, the five permissions the role carries —
  `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.getOpenIdToken`, `iam.serviceAccounts.signBlob`,
  `iam.serviceAccounts.signJwt`, `iam.serviceAccounts.implicitDelegation`. It does **not** grant
  `iam.serviceAccounts.actAs` (that is `roles/iam.serviceAccountUser`). `signBlob`/`signJwt` yield usable credentials
  without calling the token API, so a control that watches only `GenerateAccessToken` misses two of the five.
  Narrowing this binding with an IAM Condition is **not possible**: `iam.googleapis.com` is not among the services that
  support conditional role bindings on resource attributes, so the only scoping mechanism is binding on the SA resource.
- **Attack chain enabled**: AP-11 (multi-hop escalation) and AP-03 (impersonation → read → egress) → chain CH-01,
  steps 2–5. ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1548.005 (Temporary Elevated Cloud Access),
  T1213.006 (Data from Information Repositories: Databases), T1537 (Transfer Data to Cloud Account).
- **Detection posture**:
  - Log method: `GenerateAccessToken` / `GenerateIdToken` / `SignJwt` / `SignBlob` — **bare method names**, with
    `serviceName="iamcredentials.googleapis.com"` (a filter on `google.iam.credentials.v1.GenerateAccessToken`
    matches zero entries)
  - Log type: DATA_ACCESS (`ADMIN_READ` for `GenerateAccessToken`/`SignJwt`; `DATA_READ` for `GenerateIdToken`/
    `SignBlob`/`SignJwt`)
  - Enabled here: **no** — `organizations/123456789012` IAM policy carries no `auditConfigs` entry for
    `iam.googleapis.com` or `allServices`; nothing records any of the 14 SAs being impersonated
  - Alerting: none. (When enabled, note these are long-running operations that emit two entries per call — dedupe on
    `operation.id` before thresholding.)
  - Retention: n/a (not written). Once enabled, Data Access lands in `_Default` at 30 days unless routed.
  - Verdict: UNDETECTED
- **Remediation**: three changes, applied in this order.
  1. Enable Data Access `ADMIN_READ` + `DATA_READ` for `iam.googleapis.com` at `organizations/123456789012` and run
     for 14 days to enumerate the real callers (this also covers the Service Account Credentials API).
  2. Remove the project-level binding; re-bind `roles/iam.serviceAccountTokenCreator` **on each specific SA** the
     enumerated callers need — here `etl-writer@` and `bq-scheduler@` for `group:grp-ci-deploy@example.com` only.
  3. Add an IAM Deny policy at the parent folder so the binding cannot be re-added at project level.
  ```bash
  # 2 — resource-scoped re-bind (the only available narrowing mechanism)
  gcloud projects remove-iam-policy-binding data-prod-01 \
      --member='group:eng-all@example.com' --role='roles/iam.serviceAccountTokenCreator'
  gcloud iam service-accounts add-iam-policy-binding \
      etl-writer@data-prod-01.iam.gserviceaccount.com \
      --member='group:grp-ci-deploy@example.com' --role='roles/iam.serviceAccountTokenCreator'

  # 3 — folder-level deny. Permissions MUST be enumerated: iam.googleapis.com/serviceAccounts.* is
  #     NOT a valid deny permission group, and a rule using it fails to apply.
  cat > /tmp/deny-impersonation.json <<'EOF'
  {
    "displayName": "deny-impersonation-outside-ci",
    "rules": [{
      "denyRule": {
        "deniedPrincipals": ["principalSet://goog/public:all"],
        "exceptionPrincipals": ["principalSet://goog/group/grp-ci-deploy@example.com"],
        "deniedPermissions": [
          "iam.googleapis.com/serviceAccounts.getAccessToken",
          "iam.googleapis.com/serviceAccounts.getOpenIdToken",
          "iam.googleapis.com/serviceAccounts.signBlob",
          "iam.googleapis.com/serviceAccounts.signJwt",
          "iam.googleapis.com/serviceAccounts.implicitDelegation"
        ]
      }
    }]
  }
  EOF
  gcloud iam policies create deny-impersonation-outside-ci \
      --attachment-point=cloudresourcemanager.googleapis.com%2Ffolders%2F987654321098 \
      --kind=denypolicies --policy-file=/tmp/deny-impersonation.json
  ```
  ```hcl
  resource "google_iam_deny_policy" "deny_impersonation_outside_ci" {
    name         = "deny-impersonation-outside-ci"
    parent       = urlencode("cloudresourcemanager.googleapis.com/folders/987654321098")
    display_name = "Deny SA impersonation outside grp-ci-deploy"
    rules {
      deny_rule {
        denied_principals    = ["principalSet://goog/public:all"]
        exception_principals = ["principalSet://goog/group/grp-ci-deploy@example.com"]
        denied_permissions = [
          "iam.googleapis.com/serviceAccounts.getAccessToken",
          "iam.googleapis.com/serviceAccounts.getOpenIdToken",
          "iam.googleapis.com/serviceAccounts.signBlob",
          "iam.googleapis.com/serviceAccounts.signJwt",
          "iam.googleapis.com/serviceAccounts.implicitDelegation",
        ]
      }
    }
  }
  ```
  A Principal Access Boundary policy on the same principal set is complementary but does **not** substitute:
  PAB blocks `iam.googleapis.com/serviceAccounts.*` only from `enforcementVersion` 3 and higher, and pinned versions
  do not auto-upgrade — read `details.enforcementVersion` on every existing PAB policy before counting it as this
  control.
- **Blast radius**: every job that impersonates any of the 14 SAs from an `eng-all@` member account breaks at step 2.
  The deny in step 3 is absolute — deny evaluates before allow and no allow policy anywhere overrides it — so the
  exception principal set must be correct before it lands. Do not attempt to time-box or resource-scope the deny:
  denial conditions recognize only resource tag functions, and they fail closed (a condition that cannot be evaluated
  applies the denial).
- **Rollback**: `gcloud iam policies delete deny-impersonation-outside-ci --attachment-point=… --kind=denypolicies`,
  then re-add the project-level binding. Both actions are ADMIN_ACTIVITY-logged.
- **Verify fix**: `gcloud policy-troubleshoot iam //iam.googleapis.com/projects/data-prod-01/serviceAccounts/etl-writer@data-prod-01.iam.gserviceaccount.com --permission=iam.serviceAccounts.getAccessToken --principal-email=<an eng-all member>` returns denied, and
  `gcloud projects get-iam-policy data-prod-01` shows no project-level `roles/iam.serviceAccountTokenCreator`.
````

---

### 11.3 Attack-chain findings section format

Chains get their own subsection of the findings section. Present each chain as an **ordered step
table**, never as prose. One table per chain. Rank chains by
(data tier reached × ease of starting position × number of principals who can run it) — not by hop
count — and number them in that order.

#### 11.3.1 Required shape

```markdown
#### CH-nn — <chain name> — <BAND>

- **Instantiates**: AP-nn (<threat-model path name>)
- **Adversary / starting position**: <adversary from the threat model> at <S value + concrete position>
- **Terminus**: <T tier> · <X value> · <the exact egress mechanism>
- **Principals who can execute it today**: <N, enumerated or named principal set>
- **Severity inputs**: T=… X=… P=… S=… D=… (base <BAND> <±modifier>)

| # | Step | Actor → target | Exact permission / route / misconfiguration | Control that should have interrupted it | Present? | Log method (serviceName) | Log type | Enabled? | Alerting? |
|---|------|----------------|---------------------------------------------|------------------------------------------|----------|--------------------------|----------|----------|-----------|

**Cheapest severing control**: step <n> — <exact change, exact identifier>. Carried by finding <ID>.
**Why this step is cheapest**: <fewest principals affected / one policy object / no workload change / no data migration>.
**Second-cheapest sever**: step <m> — <change> (<why it costs more>).
**Steps that remain undetected after the sever**: <list, or "none">.
```

Mark the sever row by appending ` ⟵ SEVER` to the step number cell, so the table is readable without
the prose line.

#### 11.3.2 Worked example

> **EXAMPLE — shape and specificity only. Resource names are illustrative. Chain IDs (`CH-nn`) and
> finding IDs shown here are illustrative placeholders, not cross-references; real ones are assigned
> at review time.**

```markdown
#### CH-03 — On-prem interior foothold → cached SA key → public API path → CONFIDENTIAL BigQuery read → export to outside project — CRITICAL

- **Instantiates**: AP-12 (cross-boundary traversal, interior → cloud)
- **Adversary / starting position**: compromised on-prem interior host `jump-01.corp.example` (assume-breach interior) — S1
- **Terminus**: CONFIDENTIAL · EGRESS-OUT · `EXPORT DATA OPTIONS(uri='gs://<outside-project-bucket>/*.csv')`
- **Principals who can execute it today**: any principal with shell on `jump-01` — 41 accounts per the config-management inventory
- **Severity inputs**: T=CONFIDENTIAL X=EGRESS-OUT P=41 S=S1 D=UNDETECTED (base CRITICAL, capped)

| # | Step | Actor → target | Exact permission / route / misconfiguration | Control that should have interrupted it | Present? | Log method (serviceName) | Log type | Enabled? | Alerting? |
|---|------|----------------|---------------------------------------------|------------------------------------------|----------|--------------------------|----------|----------|-----------|
| 1 | Foothold on interior host | attacker → `jump-01.corp.example` | none (assume-breach interior; no east-west segmentation between `10.40.0.0/16` and `10.20.0.0/16`) | interior segmentation | No | n/a (on-prem EDR only) | n/a | — | — |
| 2 | Harvest cloud credential | attacker → `/home/deploy/.config/gcloud/application_default_credentials.json` (key for `tf-deploy@shared-svc-01.iam.gserviceaccount.com`) | file read; key is user-managed and 612 days old | `constraints/iam.disableServiceAccountKeyCreation` (and `constraints/iam.managed.disableServiceAccountKeyCreation`, which also covers Cloud Storage HMAC keys) | No — unset at every node | key *creation* logs as `google.iam.admin.v1.CreateServiceAccountKey`; key **use** produces no event of its own | ADMIN_ACTIVITY (creation only) | yes (creation) | no |
| 3 ⟵ SEVER | Reach the API without perimeter context | `jump-01` → `bigquery.googleapis.com` | on-prem resolver `10.20.0.53` returns a public Google front-end address for `*.googleapis.com`; Cloud Router `cr-hub-use4` does not advertise `199.36.153.4/30`, so no restricted-VIP path exists; access level `al-corp-egress` admits the corporate egress range `203.0.113.0/24` | on-prem DNS pinned to `restricted.googleapis.com` (`199.36.153.4/30`, IPv6 `2600:2d00:0002:1000::/56`) + Cloud Router custom advertisement of that range + an access level that does not admit a broad NAT range | No | none — the request is allowed, so no Policy Denied entry is written | — | — | — |
| 4 | Read CONFIDENTIAL data | `tf-deploy@` → `data-prod-01:cust_pii` | `bigquery.jobs.create` + `bigquery.tables.getData` (SA holds `roles/bigquery.dataViewer` via a folder binding) | perimeter `prod_data` with `bigquery.googleapis.com` in `status.restrictedServices` and no access level admitting `203.0.113.0/24` | Partial — service is restricted, but `al-corp-egress` admits the range | `google.cloud.bigquery.v2.JobService.InsertJob` (`bigquery.googleapis.com`) | DATA_ACCESS — BigQuery is the documented exception where Data Access logs are on by default | yes | no |
| 5 | Egress | `tf-deploy@` → `gs://<outside-project>/…` | `EXPORT DATA OPTIONS(uri='gs://…', format='CSV')`; perimeter restricts `bigquery.googleapis.com` but `storage.googleapis.com` is absent from `status.restrictedServices` | `storage.googleapis.com` in `restrictedServices`, plus an egress rule that names the identity and target instead of `egressTo.resources: ["*"]` | No | `storage.objects.create` (`storage.googleapis.com`) | DATA_ACCESS `DATA_WRITE` | no | no |

**Cheapest severing control**: step 3 — pin `*.googleapis.com` to `restricted.googleapis.com` on the on-prem resolver, advertise `199.36.153.4/30` and `2600:2d00:0002:1000::/56` from `cr-hub-use4`, and remove `203.0.113.0/24` from `accessPolicies/POLICY_ID/accessLevels/al-corp-egress`. Carried by finding `NW-01`.
**Why this step is cheapest**: one DNS zone, one Cloud Router advertisement, one access-level edit — no workload, IAM, or data change — and it converts **every** on-prem-originated API call in the estate into a perimeter-evaluated call, which also severs CH-05 and CH-07 at their equivalent steps. Order matters: advertise the range **before** removing the access level, or on-prem API traffic black-holes (the VIP range has no public route). Note that a custom advertisement on a BGP session overrides router-level advertisements entirely — check both.
**Second-cheapest sever**: step 5 — add `storage.googleapis.com` to `status.restrictedServices` (costs more because every legitimate cross-perimeter write must first be enumerated from dry-run violations and expressed as a scoped egress rule).
**Steps that remain undetected after the sever**: steps 1 and 2 — key *use* is never logged as an event; only enabling Data Access `ADMIN_READ` on `iam.googleapis.com` plus removing the key closes that gap (`ID-04`).
```

---

### 11.4 Report structure and emission

#### 11.4.1 Ordered outline

The deliverable is one document, in this order. Section numbers 1–11 map to the phased workflow.

| § | Section | Must contain |
|---|---|---|
| 0 | Header | Target environment (org ID, folder scope, project list); review window; evidence-collection timestamps; who was interviewed; **the severity rubric from 11.1, verbatim**; the finding-count table by band; the evidence-vs-interview split (`n` findings `[EVIDENCE]`, `n` `[INTERVIEW]`); the top 5 chains by rank with their cheapest severs |
| 1 | Scope & intake | Artifacts requested vs received, with gaps named; the classification map as received; whether a supplementary requirements `.md` was supplied, and the merged ruleset delta |
| 2 | Asset & identity inventory | Data stores by classification tier; human / service-account / federated identity inventory; trust boundaries enumerated (perimeter edges, the cloud↔on-prem link, the internet edge, each IdP trusted via WIF, the CI/CD boundary into each project) |
| 3 | Threat model | Assets, trust boundaries, adversaries with starting positions, and the `AP-nn` attack-path tree with ATT&CK mappings and per-path detection posture |
| 4 | Control-by-control assessment | Every control-catalog item: observed config, the exfil scenario tied to it, the concrete fix. Items with no defect are recorded as `INFO`, not omitted |
| 5 | Privilege graph & reachability | Node/edge counts, the escalation primitives found and by which principal, and the reachability closure per adversary starting position |
| 6 | Lateral movement & traversal | Traversal map per starting position: cloud→cloud, cloud→on-prem, on-prem→cloud, cross-project — reachable systems, the control that should have stopped each hop, whether it exists |
| 7 | Service isolation assessment | Per isolation dimension: the enforcement mechanism named, or the explicit statement that none exists plus the compensating review gate; which of the three layers (org policy / IAM Deny, policy-as-code, runtime detection) holds each control |
| 8 | Hierarchy assessment & target state | Current hierarchy defects (`HI-`), the proposed target hierarchy, where each admin role class binds and why, and the classification→perimeter mapping |
| 9 | Findings | **9.1 Discrete findings** — ordered by band, then by the 11.1.8 ordering rule, grouped by prefix within band. **9.2 Attack-chain findings** — `CH-nn` step tables per 11.3, in rank order |
| 10 | Remediation roadmap | Per 11.5: quick wins, structural changes, sequencing rules applied |
| 11 | Appendices | A–F below |

Appendices:

| App. | Contents |
|---|---|
| **A — Raw evidence used** | One row per artifact: what it is, the exact command or export that produced it, collection timestamp, who collected it, and the finding IDs that cite it. Anything you were told but not shown is listed here as `[INTERVIEW]` with the artifact that would replace it |
| **B — Privilege graph** | Node table (principal / resource, type, tier held); edge table (source → target, the permission that creates the edge, scope of the binding); the reachability closure per adversary starting position; the `TOP CUTS` list; the `UNEXPANDED ROLES` list from the §6.5 helper; and the residual-blind-spot list from §6.1.6, copied verbatim |
| **C — Merged supplementary requirements** | The supplied requirements as parsed, each mapped to `satisfied` (with the citing finding or evidence), `SR-nnn gap`, or `SR-nnn conflict` with the baseline recommendation it contradicts and both positions stated. Nothing silently dropped. If no file was supplied, say so in one line |
| **D — "Verify against current docs" list** | Every `VD-nn`: the identifier or claim, where it appears in the report, why it could not be verified, and what would settle it |
| **E — Findings index** | ID → title → band → report section, sorted by ID |
| **F — Open questions for the customer** | The literal questions still unanswered, each tagged with the finding whose severity or scope depends on the answer |

#### 11.4.2 How to emit it

1. Write the full report to a Markdown file at an absolute path:
   `gcp-security-review-<ORG_ID_or_scope>-<YYYY-MM-DD>.md`. This file is the source of truth; do not
   truncate it to fit whatever surface you report through, and do not split it across files.
2. Run the anti-fluff gate (11.6) against that file. Revise and re-run until it passes.
3. Ask the literal publication question in 11.4.4, then:
   - **If your environment can publish an HTML page and the answer is yes**: author a self-contained
     HTML page from the Markdown — every stylesheet and script inline, no external scripts,
     stylesheets, fonts, or images — laid out for reading rather than dumped as raw Markdown: a
     contents list, the finding-count table by band, and one anchored section per finding. Give it a
     short noun-phrase `<title>` naming the engagement. Publish it to a destination that is private by
     default, confirm it is private before you hand over the link, and report the URL. Do not brand
     the page as the customer organization or any real company; do not attempt to distribute it by any
     other route if publishing is refused.
   - **If no publishing mechanism is available, or the answer is no**: leave the Markdown file in place,
     print its absolute path, and print inline: the finding-count table by band, and the ID + title +
     one-line severity arithmetic for every `CRITICAL` and `HIGH` finding, plus the top 3 chains with
     their cheapest severing controls. The reader must get the headline without opening the file.
4. Never emit a partial report as a status update. Emit once, complete.

#### 11.4.3 Interview-mode degradation in the output

When raw config was unavailable for an area, the report still contains that area's section. Mark
every finding in it `[INTERVIEW]` with a confidence value, apply the evidence cap in 11.1.7, and put
the missing artifact in Appendix A and the unanswered question in Appendix F. Never quietly omit an
uncollected area — an absent section reads as "no problem here".

#### 11.4.4 Literal questions

Ask these verbatim when the corresponding input cannot be resolved from evidence.

- Unknown classification: **"Which classification tier applies to `<fully-qualified resource>` —
  PUBLIC, INTERNAL, CONFIDENTIAL, or NTK? If you cannot answer today, I will score it as CONFIDENTIAL
  and raise it as an unclassified-data-store finding."**
- Unresolvable principal count: **"How many accounts are in the transitive closure of
  `group:<GROUP_EMAIL>`, including nested groups, and who can add a member to that group or to any
  group nested inside it?"**
- Unverifiable detection: **"Is there an alerting policy that fires on
  `<protoPayload.methodName>`, what notification channel does it deliver to, and can the principals
  named in this finding modify that sink, exclusion, or channel?"**
- Unverifiable enforcement: **"Is perimeter `<accessPolicies/…/servicePerimeters/NAME>` enforced or
  dry-run today — that is, does `status` carry the restricted services and resources, or only
  `spec`?"**
- Before publishing: **"This report names live projects, service accounts, datasets, and network
  ranges. Do you want it published as a private web page with a link, or kept as a local Markdown
  file only?"**
- Target environment, when not supplied at invocation: **"What is the organization ID or folder
  scope for this review, and which projects are in scope?"**

---

### 11.5 Remediation roadmap

Two tables, in this order. Every row references the finding IDs it closes. Nothing enters the roadmap
without an owner: an item whose owner is unknown is an Appendix F question, not a roadmap row.

**Quick wins** — deployable inside one change window, no workload change, no data migration,
reversible in minutes:

| Item | Severs which chains | Effort | Dependencies | Blast radius | Owner |
|---|---|---|---|---|---|

**Structural changes** — hierarchy, perimeter geometry, identity model, network path:

| Item | Severs which chains | Effort | Dependencies | Blast radius | Owner |
|---|---|---|---|---|---|

Cell rules:

- **Item**: `<FINDING-ID> — <imperative change naming the exact identifier and target value>`. Not a
  theme.
- **Severs which chains**: `CH-nn` at step `n`, comma-separated. An item that severs no chain and
  closes no `SR-`/`DC-` finding does not belong in the roadmap.
- **Effort**: hours or days, plus the unit of work (`1 policy object`, `3 Terraform modules`,
  `14-day dry-run window`). Never "low/medium/high".
- **Dependencies**: finding IDs or roadmap row numbers that must land first, or `none`.
- **Blast radius**: what stops working and how many principals/workloads are affected, with the
  enumeration command that produces the number.
- **Owner**: a named team or role that owns the change surface. Never "the platform team should".

#### 11.5.1 Sequencing rules (these bind the dependency column)

1. **Visibility before restriction.** Enable Data Access `ADMIN_READ` + `DATA_READ` at the org node
   for `iam.googleapis.com`, `iamcredentials.googleapis.com`, `sts.googleapis.com`,
   `storage.googleapis.com` (and any other service whose reads matter) and run **≥14 days** before
   removing any IAM binding or applying any IAM Deny. You cannot enumerate the legitimate callers of
   an impersonation grant you are about to delete when the calls are not logged.
2. **Route and retain before you lock.** Create the org-level aggregated sink with
   `--include-children` into a project the workload principals cannot write to, confirm the filter
   actually includes `cloudaudit.googleapis.com%2Fdata_access` and `%2Fpolicy` (not only `activity`),
   set `--retention-days` **first**, then `--locked`. Locking a bucket still at the 30-day default
   pins 30 days permanently and is irreversible.
3. **Dry-run before enforce, where dry-run exists.** For perimeters: populate `spec` with
   `useExplicitDryRunSpec: true`, harvest
   `log_id("cloudaudit.googleapis.com/policy") AND severity="error" AND protoPayload.metadata.dryRun="true"`
   for at least one full business cycle including month-end batch, then
   `gcloud access-context-manager perimeters dry-run enforce`. For org policy, dry-run is available
   only for custom constraints, managed constraints, and a small legacy set — for every other legacy
   constraint substitute an asset-inventory pre-scan and say so in the row.
4. **Enumerate before deny.** Run the impersonation and allow-policy analysis and fix the
   `exceptionPrincipals` list before any IAM Deny policy lands. Deny evaluates before allow, cannot
   be overridden by any allow policy, and denial conditions fail closed.
5. **Classify before you draw perimeters.** Every `DC-` finding closes before the target perimeter
   geometry is applied; perimeters are drawn on classification boundaries and a mislabeled project
   lands in the wrong one.
6. **Pin the restricted VIP before narrowing hybrid access levels.** DNS pinning plus the Cloud
   Router advertisement of `199.36.153.4/30` (and the IPv6 range) must be live before broad
   IP-based access levels are removed; the reverse order black-holes on-prem API traffic because the
   VIP range has no public route.
7. **Raise PAB enforcement version before counting PAB as a sever.** A PAB policy at
   `enforcementVersion` below 3 does not cover service-account impersonation; below 4 it does not
   cover workload/workforce federation or OAuth clients. Pinned versions never auto-upgrade.
8. **Prove break-glass against the new control before enforcing it.** Test the emergency identity
   against each deny policy and perimeter in dry-run; an untested break-glass path plus a new
   absolute deny is an outage waiting for an incident.
9. **Hierarchy moves last.** `gcloud projects move` changes inherited org policy and perimeter
   membership; move projects only after the destination folder's policies exist, and alert on the
   move itself.

---

### 11.6 Anti-fluff enforcement gate

Run this over the finished report **before** emitting it. This is a hard gate, not a style
preference.

#### 11.6.1 The one-line test

> **If the sentence would be true of any GCP organization, it is fluff — cut it or make it specific.**

Second test, applied to every remediation sentence: **could the reader execute this sentence without
asking you a question?** If not, it is not a remediation.

#### 11.6.2 Banned phrases

Never emit these. The grep in 11.6.4 must return zero hits outside backticked identifiers and
block-quoted verbatim documentation.

`ensure` · `ensure that` · `follow least privilege` · `enforce least privilege` ·
`principle of least privilege` · `restrict service account permissions` · `excessive permissions` ·
`overly permissive` · `as appropriate` · `where appropriate` · `review carefully` ·
`carefully review` · `should be reviewed` · `regularly review` · `periodically` · `as needed` ·
`if necessary` · `sensitive data should be protected` · `consider` · `consider whether` ·
`may want to` · `it is recommended` · `best practice` · `best practices` · `industry standard` ·
`harden` · `lock down` · `tighten` · `defense in depth` · `robust` · `adequate` ·
`properly configured` · `misconfigured` (without naming the field and its value) ·
`unauthorized access` (as a standalone risk statement) · `could potentially` · `attackers may` ·
`poses a risk` · `increases the attack surface` · `monitor for suspicious activity` ·
`implement monitoring` · `significant risk` · `critical importance`

Replacement rule for the four that reviewers reach for most:

| Instead of | Write |
|---|---|
| "regularly review X" | the query, the cadence, the owner, and the trigger: "`grp-secops@` runs alert filter `J` (§5.12) weekly; any `DeleteSink` outside change window CR-### is an incident" |
| "least privilege" | the exact role to remove, the exact role or custom role to bind, and the resource to bind it on |
| "monitor for suspicious activity" | the `protoPayload.methodName`, the log type, whether it is enabled, the alert policy name, and the notification channel |
| "misconfigured" | the field, the observed value, and the required value |

#### 11.6.3 BAD / GOOD contrast pairs

> **EXAMPLE — shape and specificity only. Resource names, chain IDs (`CH-nn`) and finding IDs inside
> the GOOD strings are illustrative placeholders, not cross-references; real ones are assigned at
> review time.**

- **BAD**: "Sensitive buckets should not be publicly accessible."
  **GOOD**: "`constraints/storage.publicAccessPrevention` is unset at the org node and unenforced on
  projects `data-prod-01` and `analytics-prod-03`, which hold CONFIDENTIAL data. Set it to `enforced`
  at the org node; this blocks `AP-04` (public-staging exfil). Terraform:
  `google_org_policy_policy` …"

- **BAD**: "Service accounts have excessive permissions."
  **GOOD**: "`roles/iam.serviceAccountTokenCreator` is bound to group `eng-all@` at project
  `data-prod-01`, conferring impersonation of all 14 SAs in the project including
  `etl-writer@data-prod-01` (`roles/bigquery.dataViewer` on 3 CONFIDENTIAL datasets). Chain: group
  member → generateAccessToken on etl-writer → BigQuery read → export. Sever at step 2: remove the
  project-level binding, re-bind tokenCreator on the two specific SAs the CI job needs, and add an
  IAM Deny at the folder for `iam.serviceAccounts.getAccessToken` outside `grp-ci-deploy@`."

- **BAD**: "VPC Service Controls should be enabled to prevent data exfiltration."
  **GOOD**: "`accessPolicies/POLICY_ID/servicePerimeters/prod_data` has `useExplicitDryRunSpec: true`
  with a populated `spec` and an empty `status.restrictedServices`, so it enforces nothing, while
  `projects/512…` (`data-prod-01`) and `projects/733…` (`analytics-prod-03`) — both CONFIDENTIAL —
  are inside it. `status.ingressPolicies[2]` additionally sets `ingressFrom.identityType:
  ANY_IDENTITY` with `sources[].accessLevel: "*"` and `ingressTo.resources: ["*"]`, which admits
  unauthenticated callers to every resource in the perimeter once it is enforced as written. Add
  `bigquery.googleapis.com`, `storage.googleapis.com` and `bigquerydatatransfer.googleapis.com` to
  `status.restrictedServices`, delete ingress rule #2, then run
  `gcloud access-context-manager perimeters dry-run enforce prod_data --policy=POLICY_ID` once 14
  days of `protoPayload.metadata.dryRun="true"` violations show no unexplained denials. Severs CH-02
  at step 4."

- **BAD**: "Ensure on-premises hosts access Google APIs privately."
  **GOOD**: "On-prem resolver `10.20.0.53` answers `bigquery.googleapis.com` with a public Google
  front-end address (`dig +short bigquery.googleapis.com @10.20.0.53` returns `142.250.x.x`, not
  `199.36.153.4`–`.7`), and `gcloud compute routers get-status cr-hub-use4 --region=us-east4` shows
  `199.36.153.4/30` is not advertised across the interconnect. Every on-prem-originated API call
  therefore reaches the public endpoint and is not evaluated as perimeter-internal, so `prod_data` is
  bypassed from the entire interior. Fix: (1) create a private zone with
  `*.googleapis.com. CNAME restricted.googleapis.com.` plus A records `199.36.153.4 .5 .6 .7` and
  AAAA `2600:2d00:0002:1000::`, and forward `googleapis.com` from the on-prem resolver to an inbound
  forwarder entry point in `us-east4`; (2)
  `gcloud compute routers update cr-hub-use4 --region=us-east4 --advertisement-mode=custom --set-advertisement-groups=all_subnets --set-advertisement-ranges=199.36.153.4/30,2600:2d00:0002:1000::/56`
  — and check the BGP sessions, because a session-level custom advertisement overrides the router's
  entirely; (3) drop `203.0.113.0/24` from `accessPolicies/POLICY_ID/accessLevels/al-corp-egress`.
  Verify: `dig` from an interior host returns only `199.36.153.4`–`.7`. Severs CH-03 at step 3."

#### 11.6.4 Self-audit checklist

The seventeen checks are the *Skill self-check* at the end of this file — `0a`–`0c` plus 1–14. Run
all seventeen over the finished report file, record the result of each in your working notes (not in
the report), and do not emit until every one passes.

#### 11.6.5 Unimplementable-remediation blocklist (check 14)

Never recommend these; each is a documented dead end. If your draft contains one, replace it with the
right-hand column.

| Do not emit | Emit instead |
|---|---|
| An IAM Condition narrowing a `roles/iam.serviceAccountTokenCreator` binding by `resource.name` or `request.time` | Bind the role **on the specific service-account resource** — `iam.googleapis.com` does not support conditional role bindings on resource attributes |
| `iam.googleapis.com/serviceAccounts.*` as a deny permission group | Enumerate the permissions individually: `getAccessToken`, `getOpenIdToken`, `signBlob`, `signJwt`, `implicitDelegation` (+ `actAs` to block attachment) |
| A deny rule on `serviceusage.googleapis.com/services.enable` | Role hygiene on `roles/serviceusage.serviceUsageAdmin` plus alerting on the enablement event |
| A time-boxed or resource-name-scoped denial condition | Scope the deny with the attachment point, `exceptionPrincipals`, or resource **tag** functions — denial conditions recognize nothing else and fail closed |
| A dry-run rollout of a legacy managed org-policy constraint (other than `constraints/gcp.restrictServiceUsage`, `constraints/gcp.restrictEndpointUsage`, TLS constraints) | An asset-inventory pre-scan, or migration to the `*.managed.*` twin, which supports dry-run |
| An org-policy custom constraint that blocks perimeter **deletion** | IAM Deny on `accesscontextmanager.googleapis.com/servicePerimeters.delete` — custom constraint `methodTypes` covers `CREATE`/`UPDATE` only |
| A VPC firewall rule that blocks the metadata server at `169.254.169.254` | GKE Workload Identity, OS-level controls, or removing the SA from the workload — metadata traffic bypasses VPC firewall rules |
| `iam.serviceAccounts.getIdToken` | `iam.serviceAccounts.getOpenIdToken` (the **method** is `generateIdToken`; do not normalize one to the other) |
| `constraints/iam.allowedPolicyMemberSubdomains` | `constraints/iam.managed.allowedPolicyMembers`, an `iam.googleapis.com/AllowPolicy` custom constraint, or `constraints/iam.allowedPolicyMemberDomains` |
| `google_iam_principals_access_boundary_policy_binding` | `google_iam_organizations_policy_binding` / `google_iam_folders_policy_binding` / `google_iam_projects_policy_binding` (and note `google_iam_access_boundary_policy` is a different, private-preview feature) |
| ATT&CK `T1562.008` (or any `T1562.*`) | `T1685.002 Disable or Modify Cloud Log` (optionally annotated "formerly T1562.008") |
| "Buy SCC Enterprise tier" | Premium — Enterprise is deprecated with a 2027-05-21 shutdown and orgs move to Premium automatically |
| WIF via OIDC from an air-gapped GitHub Enterprise Server | Name the actual options — runner on a GCE VM or GKE with an attached identity, X.509-certificate-based WIF, or an internet-reachable corporate IdP — and treat any surviving SA key as the credential the compensating controls must carry `(verify against current docs)` before designing around static JWKS |
| A filter on `protoPayload.methodName="google.iam.credentials.v1.GenerateAccessToken"` | The bare method names `GenerateAccessToken` / `GenerateIdToken` / `SignJwt` / `SignBlob` with `serviceName="iamcredentials.googleapis.com"` |
| A single-string filter on `SetIamPolicy` | The versioned, resource-scoped strings — `cloudresourcemanager.v3.projects.setIamPolicy`, `…folders.setIamPolicy`, `…organizations.setIamPolicy`, and `google.iam.admin.v1.SetIAMPolicy` (capital `IAM`) |
| A PAB policy binding whose target is a Google group (`group:…`) | Bind at the org / folder / project, Workspace-domain, or workforce/workload-pool principal set, or condition the binding on `principal.subject` — `group:` is not a PAB principal set, so "mitigated: PAB bound to `grp-x@`" certifies a control that cannot be created |

#### 11.6.6 Failing the gate

A report that fails any of the 17 checks (`0a`–`0c` and 1–14) is **revised and re-checked before emission**. Do not ship a
report with a caveat that says a check failed — the caveat is the failure. If a check cannot be
satisfied because the environment did not supply the evidence, that is not a gate failure: convert
the affected item to an `[INTERVIEW]` finding with the capped severity, put the missing artifact in
Appendix A and the literal question in Appendix F, and re-run the gate.

---

## Verify against current docs

**Identifiers verified against official documentation as of 2026-08-25** — `docs.cloud.google.com`,
MITRE ATT&CK v19.0/v19.1 (released 2026-04-28), and the GitHub Enterprise Server docs at versions
3.15, 3.17 and 3.21. Every identifier in this skill that is **not** listed below was read off a
rendered official page on that date. Everything listed below was **not** confirmed and carries the
literal marker `verify against current docs` at its point of use in the body. The two sets are
**not** 1:1 by count — one row routinely covers two or three identifiers that each carry their own
marker, and the marker sometimes reads `(verify against current docs)`, sometimes
`— verify against current docs`. Derive the counts, never assert them:

```bash
grep -c -o 'verify against current docs' SKILL_FILE     # markers, body + appendix
grep -o '^| `VD-[0-9]\+`' SKILL_FILE | sort -u | wc -l  # Appendix D rows
```

The binding relation is by **identifier**, not by count: every marked identifier must be named in some
row below, and every row's identifier must appear at least once in the body. A marker you cannot match
to a row means the identifier is unverified and un-tracked — open a new `VD-` row for it rather than
dropping the marker (self-check 13).

**How to use this section.** Before you assert any row below in a finding, a remediation snippet, a
detection filter, or a design, fetch the current page and confirm it. If it confirms, drop the marker
in that finding. If it does not, or you cannot fetch it, keep the marker, emit the item as a `VD-nn`
row in Appendix D per §11.4.1, and **do not build a remediation on it** — pick a control from the
verified set instead. An empty Appendix D means you stopped tracking, not that everything was
verified.

Two standing staleness warnings that outrank any individual row:

- **Search snippets for this domain are stale.** Snippets still report Principal Access Boundary's
  default enforcement version as 3 (the live page says **4**) and still describe PAB as Preview (it
  went GA 2024-12-16). Read the page, never the snippet.
- **Google's own prose naming is currently inconsistent** across pages for the Data Catalog →
  Dataplex Universal Catalog → Knowledge Catalog renames, and for Cloud Functions vs Cloud Run
  functions. Pin every claim to an **API or IAM identifier**, which the renames did not change, not to
  a product name.

### Organization policy and custom constraints

| ID | Item | What would settle it |
|---|---|---|
| `VD-01` | `constraints/sql.managed.restrictPublicIp`, `constraints/sql.managed.restrictAuthorizedNetworks` — likely nonexistent; every Cloud SQL page uses the un-prefixed names. Ship the legacy names | Cloud SQL org-policy constraints page |
| `VD-02` | `constraints/storage.managed.publicAccessPrevention`, `constraints/storage.managed.uniformBucketLevelAccess` — no evidence they exist | Org-policy constraints index |
| `VD-03` | `constraints/bigquery.managed.*` — no evidence; BigQuery uses the Omni booleans plus custom constraints | Org-policy constraints index |
| `VD-04` | Any predefined `constraints/dataproc.*` — Dataproc appears to be custom-constraints-only, on `dataproc.googleapis.com/Cluster` with `CREATE`/`UPDATE` | Dataproc custom-constraints page |
| `VD-05` | `DELETE` as a valid `methodTypes` value on a custom constraint. Do **not** rely on a custom constraint to block deletion (this is why perimeter deletion needs IAM Deny — §5.3, test `SC-25`) | Custom-constraints reference |
| `VD-06` | Individual `orgpolicy.customConstraints.*` permission strings | `roles/orgpolicy.policyAdmin` role reference |
| `VD-07` | The IAM-Condition CEL syntax for tag-scoping a `roles/orgpolicy.policyAdmin` binding (test `OP-05`, mirror case) | IAM Conditions attribute reference |
| `VD-08` | Minimum Terraform provider versions for `google_org_policy_policy` and `google_org_policy_custom_constraint` | Provider changelog |
| `VD-09` | Deprecation text for `google_project_organization_policy` specifically | Provider registry page |
| `VD-11` | `gcloud asset analyze-org-policy-governed-assets` and `…-governed-containers` flag sets | gcloud reference |
| `VD-12` | Casing of `constraints/compute.disableGuestAttributesAccess` — doc pages conflict | Compute org-policy page |
| `VD-13` | Hierarchy-indicator value format (`under:organizations/…`) for `constraints/compute.restrictPrivateServiceConnectProducer` / `…Consumer` | PSC org-policy page |
| `VD-14` | `constraints/gcp.restrictTLSVersion` constraint type | Org-policy constraints index |
| `VD-15` | Whether the legacy `constraints/iam.disableServiceAccountKeyCreation` still resolves, now that `constraints/iam.managed.disableServiceAccountKeyCreation` exists — one current page omits the legacy name | IAM org-policy constraints page |
| `VD-16` | Organization `creationTime` field name on `gcloud organizations describe` (needed for the 2024-05-03 baseline test, `OP-01`) | Resource Manager API reference |

### IAM, deny policies, PAB and policy tooling

| ID | Item | What would settle it |
|---|---|---|
| `VD-17` | `gcloud asset analyze-iam-policy-longrunning` and its `--output-bigquery-table` flag (confirmed only that the flag is absent from the non-longrunning command) | gcloud reference |
| `VD-18` | `gcloud asset analyze-move` and `gcloud asset analyze-org-policies` full flag sets | gcloud reference |
| `VD-19` | Exact flag spelling for `gcloud recommender recommendations list --recommender=google.iam.policy.Recommender` (the recommender ID is verified) | gcloud reference |
| `VD-20` | Whether uniform bucket-level access disables object ACLs entirely (asserted from general knowledge, not a fetched page) | Cloud Storage UBLA page |
| `VD-21` | PAB enforcement version 4's release date (v3 is dated 2025-05-05; default = 4 is verified) | IAM release notes |
| `VD-22` | Whether IAM Deny supports attachment below project level in any preview. Only organizations, folders and projects are documented | IAM Deny overview |
| `VD-23` | PAB subcommand-level flags on `gcloud iam principal-access-boundary-policies` and `gcloud iam policy-bindings` (`--organization`, `--location`, `--policy-kind`, `--target-principal-set`). The Terraform shape in §5.7 is confirmed | gcloud reference |
| `VD-24` | `cloudasset.assets.searchAllIamPolicies` permission string | Cloud Asset Inventory permissions reference |
| `VD-25` | `resourcemanager.organizations.getIamPolicy` permission string | Resource Manager permissions reference |
| `VD-26` | `gcloud iam service-accounts list` flag set | gcloud reference |
| `VD-27` | Service-account **key upload** permission string (the constraint `constraints/iam.disableServiceAccountKeyUpload` and the method `google.iam.admin.v1.UploadServiceAccountKey` are verified) | IAM permissions reference |
| `VD-28` | v2 deny-permission spellings for `compute.projects.setCommonInstanceMetadata`, `compute.instances.setServiceAccount`, `compute.firewallPolicies.update`, `iap.tunnelInstances.accessViaIAP` | IAM Deny supported-permissions list |
| `VD-29` | Project-move permission string behind `gcloud projects move` | Resource Manager permissions reference |
| `VD-30` | `secretmanager.versions.access` in v2 deny form | IAM Deny supported-permissions list |
| `VD-31` | Read-permission strings `cloudsql.instances.export`, `spanner.databases.read`, `datastore.entities.get` | Per-service IAM permissions references |
| `VD-32` | Deploy-permission spellings marked in the §6.5 helper's `DEPLOY_PERMS` set (everything except `compute.instances.setServiceAccount` and the two metadata permissions) | Per-service IAM permissions references |
| `VD-33` | Whether `roles/owner`, `roles/editor` and `roles/viewer` expand as the §6.5 helper's approximate bundled sets assume | `gcloud iam roles describe roles/editor` |
| `VD-34` | Whether `container.googleapis.com` cluster-admin permissions are deniable (isolation layer L1, row 14 in §8.7) | IAM Deny supported-permissions list |
| `VD-35` | Whether a **service account** supports the resource-tag binding a `resource.matchTag` denial condition would need (§8.1). If not, scope by attachment point | Resource Manager tags supported-resources page |

### VPC Service Controls and Access Context Manager

| ID | Item | What would settle it |
|---|---|---|
| `VD-36` | `PrivateServiceConnectEndpoint` sub-field names inside `ingressFrom.sources[].pscEndpoint` | VPC-SC ingress/egress rule reference |
| `VD-37` | Contents of the supported-method-restrictions page (URL confirmed, table not enumerated) — the per-method exception class, test `SC-06` | That page |
| `VD-38` | "Perimeter bridges cannot have VPC accessible services" as a direct quote (inferred, not quoted) | Perimeter-bridge page |
| `VD-39` | Accepted string formats for an access policy's `scopes` field (`folders/…`, `projects/…`) | ACM API reference |
| `VD-40` | `VpcNetworkSource` REST sub-field names (and its mutual exclusion with `ipSubnetworks` in one condition) | Access level API reference |
| `VD-41` | GA/Preview status of custom (CEL) access levels overall, and of the `api.mcp.is_mcp` / `api.mcp.tool.is_read_only` CEL attributes | Custom access levels page |
| `VD-42` | `violationReason` values beyond the four documented — `CREDENTIALS_TYPE_NOT_SUPPORTED` and friends (alert row `I`, §5.12) | VPC-SC troubleshooting page |
| `VD-43` | VPC-SC **service patterns** syntax for `vpcAccessibleServices.allowedServicePatterns` and `servicePatternsEnforcementScopes` (tests `SC-28`, `PS-02`, `LM-69`). The `#service-patterns` doc anchor does not currently resolve — do not cite it | VPC accessible services page |
| `VD-44` | PSC-for-Google-APIs bundle DNS names (`p.googleapis.com`, `SERVICE-ENDPOINT.p.googleapis.com`) — two sources disagree | PSC for Google APIs page |
| `VD-45` | Cloud **Monitoring** VPC-SC support status | Supported-services list |
| `VD-46` | Terraform `ignore_changes` strings for `google_access_context_manager_service_perimeter_egress_policy` and the two `..._dry_run_*_policy` resources (pattern inferred from three verbatim siblings) | Provider registry pages |
| `VD-47` | Flag spelling on the update side of `gcloud access-context-manager perimeters` for ingress/egress policy files (`perimeters create --ingress-policies=YAML_FILE` is confirmed) | gcloud reference |
| `VD-48` | Command-group spelling for `gcpUserAccessBindings` (`gcloud access-context-manager cloud-bindings`). The API resource `accessPolicies.gcpUserAccessBindings` and the Terraform resource are confirmed | gcloud reference |
| `VD-49` | Session controls for reauthentication on an access level (test `AX-11`) | ACM session-controls page |

### Workload / Workforce Identity Federation, identity, logging, SCC

| ID | Item | What would settle it |
|---|---|---|
| `VD-50` | The exact set of issuers for which Google rejects provider creation without a claim-referencing `attributeCondition`. The error string `The attribute condition must reference one of the provider's claims` was observed in a community thread, not on a Google page; the guard is **create/update-time only** either way | WIF deployment-pipelines page |
| `VD-51` | Attribute-condition claim names for platforms beyond GitHub, GitLab SaaS, HCP Terraform and Azure DevOps (a Bitbucket or CircleCI condition asserted anywhere) | WIF provider docs |
| `VD-52` | Whether a GHES-with-static-JWKS pattern (`oidc.jwks_json` / `--jwk-json-path`) works at all: the publicly-routable-issuer requirement still stands and Google publishes no such pattern. **Require a working proof of concept before designing around it**, and note it fails silently on every GHES key rotation | WIF X.509/OIDC pages plus a live test |
| `VD-53` | Certificate-based WIF (X.509 client certificates) setup — the one federation mode needing no inbound reachability, and therefore the one air-gapped candidate worth testing | WIF X.509 page |
| `VD-54` | GHES enterprise issuer customization (`/enterprises/{enterprise}/actions/oidc/customization/issuer`, `include_enterprise_slug`) — surfaced in snippets, **absent** from the GHES pages; it appears to be a GitHub Enterprise **Cloud** feature. Read the docs for the **exact GHES version deployed**; OIDC behaviour changed across 3.6 → 3.21 | GHES docs at the deployed version |
| `VD-55` | Maturity / GA status of WIF attestation rules (`SetAttestationRules`, `AddAttestationRule`) and managed workload identities / pool namespaces (test `WI-15`) | IAM managed-workload-identity pages |
| `VD-56` | Workforce-pool console sign-in URL form | Workforce federation page |
| `VD-57` | Admin SDK `roleAssignments` / `roles` endpoint URLs for enumerating **delegated** admins (`users.list?query=isAdmin=true` returns super admins only — verified) | Admin SDK Directory reference |
| `VD-58` | The 16-hour default Google Cloud session length said to apply to a subset of organizations from June 2026 and "not visible in the Admin console" | Workspace session-control page |
| `VD-59` | Advanced Protection Program enrolment policy name for super admins | Workspace security page |
| `VD-60` | Max group-nesting depth and OAuth scopes for `groups.memberships.searchTransitiveMemberships()` | Cloud Identity Groups API reference |
| `VD-61` | The `auditConfigs` request field path used by alert filter `L` / `F11` — it varies by API version. **Confirm against a real log entry before relying on it** | A live Admin Activity entry |
| `VD-62` | Cloud Logging audit method names `google.logging.v2.ConfigServiceV2.UpdateSink` / `DeleteSink` / `CreateExclusion` / `UpdateBucket` / `DeleteBucket` / `UpdateCmekSettings` / `LoggingServiceV2.DeleteLog` (filter `F10`, alert `K`) | Cloud Logging audit-logging page |
| `VD-63` | `--custom-writer-identity` on `gcloud logging sinks create` | gcloud reference |
| `VD-64` | The destination role name for a log-bucket sink (Cloud Storage → `roles/storage.objectCreator`, Pub/Sub → `roles/pubsub.publisher`, BigQuery → `roles/bigquery.dataEditor` are confirmed) | Log-routing page |
| `VD-65` | `google_logging_project_bucket_config` field names for `locked` and `retention_days` | Provider registry page |
| `VD-66` | Whether `WorkloadIdentityPoolProvider` is a supported Security Health Analytics custom-module resource type, and the SHA custom-module CEL contract (test `LG-19`) | SHA custom-modules page |
| `VD-67` | SHA finding-category names other than `AUDIT_LOGGING_DISABLED` and `NON_ORG_IAM_MEMBER` — `LOG_NOT_EXPORTED`, `USER_MANAGED_SERVICE_ACCOUNT_KEY`, `PRIMITIVE_ROLES_USED`, `MFA_NOT_ENFORCED` and similar are unconfirmed (test `LG-20`) | SHA findings reference |
| `VD-68` | ETD detector names beyond those listed in §4.7.4 — the detector index page renders as navigation only | ETD detector index |
| `VD-69` | BigQuery job `methodName` values for filter `F16`, and the copy/share method names for `AP-07` | BigQuery audit-logging page |
| `VD-70` | Compute control-plane and Resource Manager method names for filters `F17` / `F18` in §4.7.3 (firewall-policy, forwarding-rule and project-move methods) | Per-service audit-logging pages |
| `VD-71` | BigQuery, KMS and Secret Manager `setIamPolicy` audit method names (`storage.setIamPermissions` is verified) | Per-service audit-logging pages |
| `VD-72` | IAP per-connection tunnel-authorization audit method name — **`AuthorizeUser` is NOT in the documented method list** (test `LM-14`) | IAP audit-logging page |
| `VD-73` | Numeric TA ID for the ATT&CK v19 **Stealth** tactic (Defense Impairment is `TA0112`, verified) | ATT&CK site |
| `VD-74` | GCP framings for `T1578`, `T1666` and `T1685.002`: the ATT&CK pages carry only AWS/Azure/Office examples. Present these as an analyst mapping, not as ATT&CK text | ATT&CK technique pages |

### Network, compute, GKE, PSC, DNS

| ID | Item | What would settle it |
|---|---|---|
| `VD-75` | Atomic permission strings `resourcemanager.tagValues.use` and `resourcemanager.tagValueBindings.create` (the role `roles/resourcemanager.tagUser` is verified) | Resource Manager permissions reference |
| `VD-76` | gcloud flag spelling `--policy-enforcement-order` on `gcloud compute networks update` (the API field `networkFirewallPolicyEnforcementOrder` and both enum values are verified) | gcloud reference |
| `VD-77` | `--purpose-data network=PROJECT/NETWORK` form for network-scoped secure tag keys, and `gcloud resource-manager tags keys list` flags | gcloud reference |
| `VD-78` | `gcloud network-security address-groups` command-group spelling | gcloud reference |
| `VD-79` | Max rules per firewall policy, and max region codes per rule (the quotas page did not list them) | Firewall quotas page |
| `VD-80` | Flag lists for `gcloud compute networks get-effective-firewalls`, `gcloud compute instances network-interfaces get-effective-firewalls`, and `gcloud compute firewall-policies list` | gcloud reference |
| `VD-81` | `gcloud compute routers get-status` synopsis, `--region`, GA status and output fields (`list-bgp-routes` with `--route-direction` / `--policy-applied` is verified) | gcloud reference |
| `VD-82` | `gcloud compute networks peerings list` flag set | gcloud reference |
| `VD-83` | GA status of `gcloud dns policies`, the `gcloud dns response-policy-rules` nesting, and the flags `--enable-inbound-forwarding`, `--alternative-name-servers`, `--private-alternative-name-servers`, `--enable-logging` | gcloud reference |
| `VD-84` | Cloud DNS private-zone recipe for the sibling domains `*.gcr.io` and `*.pkg.dev` in the restricted-VIP configuration (§7.3.4, row 5) | Private Google Access DNS page |
| `VD-85` | Cloud Logging log names `compute.googleapis.com/vpc_flows` and `compute.googleapis.com/firewall`, and the `--logging-metadata` flag | VPC Flow Logs page |
| `VD-86` | Service-attachment connection-preference enum values (`ACCEPT_AUTOMATIC` / `ACCEPT_MANUAL`), PSC connection-limit numbers, and the PSC NEG filter value | PSC pages |
| `VD-87` | Secure Web Proxy CEL `sessionMatcher` / `applicationMatcher` syntax | Secure Web Proxy page |
| `VD-88` | Launch stage of geo-location objects, and the GA-vs-Beta split between `*_network_scope` and `*_network_context` in Terraform | Provider registry + firewall docs |
| `VD-89` | Whether `layer4_configs { ip_protocol = "all" }` is accepted on the hierarchical-firewall-policy rule resource, and the block name there | Provider registry page |
| `VD-90` | MACsec availability on Cloud Interconnect | Interconnect security page |
| `VD-91` | Whether `v1beta1` metadata endpoints still answer, and whether any header-less legacy metadata endpoint still answers (the `v1` endpoint requiring `Metadata-Flavor: Google` is verified) | Compute metadata page |
| `VD-92` | Metadata keys `enable-oslogin-sk`, and the removal version for GKE metadata concealment | Compute + GKE docs |
| `VD-93` | `container.clusters.getCredentials` as a distinct permission string | GKE permissions reference |
| `VD-94` | The minimal GKE node-SA role set (`roles/logging.logWriter`, `roles/monitoring.metricWriter`, `roles/monitoring.viewer`, `roles/stackdriver.resourceMetadata.writer`, `roles/artifactregistry.reader`) | GKE hardening page |
| `VD-95` | Binary Authorization policy `evaluationMode` string values and the dry-run flag name (`--binauthz-evaluation-mode=project-singleton-policy-enforce` and `disabled` are verified as gcloud values) | Binary Authorization page |
| `VD-96` | GKE control-plane endpoint field paths in `gcloud container clusters describe` for the three independently-switchable endpoints (test `LM-23`) | GKE cluster API reference |
| `VD-97` | Cloud Run `run.routes.invoke` permission string, and whether `constraints/iam.allowedPolicyMemberDomains` is the recommended public-access block for Cloud Run | Cloud Run IAM page |
| `VD-98` | Whether secure tags (as opposed to network tags) can target Cloud Run Direct VPC egress | Cloud Run networking page |
| `VD-99` | Cloud Asset Inventory asset-type strings for Composer, Dataflow, Dataproc and Vertex AI, and the REST `ContentType` enum members beyond `RESOURCE` / `RELATIONSHIP` (the gcloud lowercase-hyphenated values are verified) | CAI asset-types page |
| `VD-100` | `gcloud workbench instances list` command spelling, and `gcloud compute service-attachments list` flags | gcloud reference |

### Data services, classification tooling, IaC

| ID | Item | What would settle it |
|---|---|---|
| `VD-101` | `bq extract` flag set, and Cloud SQL `gcloud sql export`, Firestore `gcloud firestore export`, Spanner export / backup-restore paths | Per-service CLI references |
| `VD-102` | BigQuery authorized-view and authorized-dataset semantics, and cross-project query-result read mechanics | BigQuery access-control pages |
| `VD-103` | BigQuery row-access-policy (row-level security) syntax | BigQuery RLS page |
| `VD-104` | `roles/datacatalog.categoryAdmin` exact role ID (the reader role `roles/datacatalog.categoryFineGrainedReader` is verified) | Data Catalog IAM page |
| `VD-105` | BigQuery dataset ACL-change audit method name (worked chain `AP-11f-2`, step 2) | BigQuery audit-logging page |
| `VD-106` | Dataflow worker networking flags (`--no-use-public-ips` exact spelling) | Dataflow reference |
| `VD-107` | Vertex AI model-export command/API | Vertex AI reference |
| `VD-108` | Looker / Looker Studio access model and VPC-SC coverage — **the entire surface is unverified**; do not assert a control over it | Looker docs |
| `VD-109` | Cloud EKM behaviour and key-availability failure modes | Cloud EKM page |
| `VD-110` | Sensitive Data Protection `gcloud dlp` command syntax, and the sensitive-data-based IAM access-control mechanism (used for the classification map in §2.2, row 26) | SDP docs |
| `VD-111` | Managed-folder and object-prefix IAM Condition semantics as the object-level control under uniform bucket-level access (test `ISO-34`) | Cloud Storage managed-folders page |
| `VD-112` | Per-resource `get-iam-policy` flag spellings used in §2.2, row 4 | Per-service CLI references |
| `VD-113` | Per-product support matrix for **direct resource access** by a federated principal versus impersonation (test `WI-12`) — the matrix does not render reliably on that page | Identity-federation supported-products page |
| `VD-114` | Deny **permission-group** support per service beyond the confirmed list in test `DN-03`: the `accesscontextmanager.googleapis.com/{servicePerimeters,accessLevels,policies,authorizedOrgsDescs,gcpUserAccessBindings}.*` families, `logging.googleapis.com/exclusions.*`, `iam.googleapis.com/workloadIdentityPoolProviders.*`, `iam.googleapis.com/workforcePoolProviders.*`, `iam.googleapis.com/oauthClientCredentials.*` (used in recommended deny rules #9, #10, #11) | Deny-supported-permissions reference table |
| `VD-115` | The three deny permission-group **forms** — `SERVICE_FQDN/RESOURCE.*`, `SERVICE_FQDN/*.*`, `SERVICE_FQDN/*.VERB` — as a taxonomy (test `DN-03`); official documentation confirms individual group strings but not the pattern list | `docs.cloud.google.com/iam/docs/deny-overview` |

---

## Skill self-check — run before emitting

Run all seventeen checks over the finished report file — checks `0a`–`0c` first, then 1–14. Record
each result in your working notes, not in the report. A report that fails any check is revised and re-checked before emission; a caveat
saying a check failed **is** the failure. If a check cannot be satisfied because the environment did
not supply the evidence, that is not a gate failure — convert the affected item to an `[INTERVIEW]`
finding with the severity cap from §11.1.7, put the missing artifact in Appendix A and the literal
question in Appendix F, and re-run.

1. **Every finding names a resource.** No finding body without at least one fully-qualified,
   backticked identifier from the §11.2.2 table.
2. **Every recommendation names an exact identifier and target value** — a `constraints/…`, a
   `roles/…`, a `service.resource.verb` permission, a VPC-SC rule field, a firewall rule name, a
   metadata key — and the value to set it to.
3. **Every chain step names the specific permission, route, or misconfiguration** that makes it
   possible, the control that should have interrupted it, and whether that control exists.
4. **Every GCP API-surface claim is verified or marked.** Constraint names, permission strings, role
   IDs, audit-log method names, VIP ranges, rule-schema fields, feature GA status: either it is
   verified against official documentation, or it carries the literal marker
   `(verify against current docs)` at its point of use. No hedged claim without the marker; no marker on a verified claim.
5. **Every finding has a remediation snippet** — `gcloud` or Terraform, runnable after substitution —
   plus blast radius and rollback. Where no technical enforcement exists, the remediation names the
   compensating review gate (who, what query, what trigger) instead.
6. **Every severity line shows all five rubric inputs and the modifier arithmetic** (§11.1.8).
7. **Evidence caps respected**: no `[INTERVIEW]` finding is `CRITICAL`; every `[EVIDENCE]` finding
   names the artifact and its collection timestamp.
8. **Banned-phrase grep returns zero admissible hits.** A hit is admissible **only** inside a
   backticked identifier or a block-quoted verbatim documentation string; everything else is revised.
   The pattern covers **every** phrase in §11.6.2 — including `should be reviewed`, `misconfigured`,
   `unauthorized access`, `critical importance` and `sensitive data should be protected`, which are
   hand-cleared exactly like `consider`. `$REPORT` is the **absolute** path written in §11.4.2 step 1;
   a bare relative glob matches nothing when the report is written outside the cwd, and a grep that
   matches no file passes vacuously.
   ```bash
   # $REPORT is the absolute path written in 11.4.2 step 1. Fail loudly if it does not exist.
   test -f "$REPORT" || { echo "GATE ERROR: report not found at $REPORT"; exit 2; }
   grep -n -i -E "ensure|as appropriate|where appropriate|review carefully|carefully review|should be reviewed|regularly review|periodically|best practice|industry standard|consider|least privilege|restrict service account permissions|excessive permissions|overly permissive|properly configured|misconfigured|unauthorized access|critical importance|sensitive data should be protected|robust|adequate|as needed|if necessary|it is recommended|may want to|harden|lock down|tighten|defense in depth|monitor for suspicious|implement monitoring|poses a risk|could potentially|attackers may|increases the attack surface|significant risk" \
     "$REPORT"
   ```
9. **Every chain names its cheapest severing control**, the finding ID that carries that remediation,
   and a one-line reason it is cheapest.
10. **Every roadmap row has an owner and a dependency cell** that is a finding ID, a row number, or
    the literal `none`; and every roadmap row references at least one finding ID.
11. **Every supplementary requirement is accounted for** in Appendix C as `satisfied`, `SR-nnn gap`, or
    `SR-nnn (conflict)`. Zero silently dropped.
12. **Every data-bearing resource in the inventory carries a classification**, or has a `DC-` finding
    against it.
13. **Every `(verify against current docs)` marker resolves to an Appendix D row, and every row
    resolves back.** Run it, do not eyeball it:
    ```bash
    grep -c -o '(verify against current docs' "$REPORT"          # marker count
    grep -o '^| `VD-[0-9]\+`' "$REPORT" | sort -u | wc -l        # Appendix D row count
    ```
    Then, for each marker, the **identifier it marks** must appear verbatim in some `VD-` row's text,
    and for each `VD-` row the identifier it names must appear at least once in the body. A marker
    whose identifier matches no row is a gate failure — open a new `VD-` row for it before emitting.
    A row whose identifier appears nowhere in the body is a stale row — delete it. The counts need not
    be equal (one row may cover two identifiers that carry one marker each), but every marker and
    every row must be reachable from the other side by identifier.
14. **No unimplementable recommendation appears anywhere** — check the report against the blocklist in
    §11.6.5.

Three checks on the review itself, not on the prose. They are numbered `0a`–`0c` because they run
**before** check 1, and they are not optional: skipping them is the same gate failure as skipping 1–14.

- **0a. Every finding cites an `AP-nn` and an `A1`–`A7` adversary.** A finding that cites neither is a
  configuration observation, not a security finding: move it to the appendix.
- **0b. The reachability closure ran to fixpoint**, not to a fixed depth, and the `TOP CUTS` list from
  §6.5 drives the roadmap ordering. Re-run the helper after each proposed sever: a fix that does not
  reduce the reported chain count severed nothing.
- **0c. Both directions of the cloud↔on-prem link have a measured answer**, not a design-document
  answer. A direction you did not measure is reported as unmeasured, never as absent.
