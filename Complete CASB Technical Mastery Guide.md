# Complete CASB Technical Mastery Guide
## From Zero to Expert Technical Support Engineer

---

## Table of Contents

1. [Foundation: Understanding Cloud Security Basics](#section-1)
2. [CASB Core Concepts and Architecture](#section-2)
3. [Symantec CloudSOC Platform Deep Dive](#section-3)
4. [Securlets: API-Based Protection (Data at Rest)](#section-4)
5. [Gatelets: Inline Protection (Data in Motion)](#section-5)
6. [User Management and Access Control](#section-6)
7. [Policy Enforcement and DLP Configuration](#section-7)
8. [Monitoring, Investigation, and Analytics](#section-8)
9. [Advanced Integration: SIEM, API, and Third-Party Tools](#section-9)
10. [Troubleshooting Methodology and Common Issues](#section-10)
11. [Real-World Scenarios and Case Studies](#section-11)
12. [Performance Optimization and Best Practices](#section-12)
13. [Compliance and Regulatory Requirements](#section-13)
14. [Advanced Technical Support Skills](#section-14)
15. [Daily Practice Labs and Exercises](#section-15)

---

<a name="section-1"></a>
## 1. Foundation: Understanding Cloud Security Basics

### 1.1 The Cloud Computing Paradigm Shift

Before diving into CASB, you must understand WHY organizations need these tools.

**Traditional Security Model:**
```
[Users] → [Corporate Firewall] → [Internal Applications]
         ↑
    Security boundary is clear
    All traffic inspected at perimeter
```

**Modern Cloud Reality:**
```
[Users - Office/Home/Mobile] → [Internet] → [SaaS Apps: O365, Box, Salesforce, etc.]
                                          → [IaaS: AWS, Azure, GCP]
                                          → [Collaboration: Slack, Teams, Zoom]
```

**The Problem:** Traditional security controls (firewalls, web proxies) can't effectively:
- Inspect encrypted HTTPS traffic to cloud services
- Understand application-layer activities (who shared what file with whom)
- Enforce granular policies (block upload but allow download)
- Detect data exposure in files already stored in the cloud

### 1.2 Shadow IT: The Hidden Threat

**Shadow IT** = Cloud applications used by employees without IT department approval or knowledge.

**Why It Happens:**
- Employees need quick solutions (file sharing, collaboration)
- Official tools are too slow or restrictive
- Free consumer versions are easily accessible
- BYOD (Bring Your Own Device) culture

**Real Example:**
```
Marketing team needs to share large video files
↓
Official tool: Corporate SharePoint (slow, complex)
↓
Shadow solution: Employee creates free Dropbox account
↓
Result: Sensitive company videos now stored outside corporate control
        No DLP policies applied
        No audit trail
        Potential compliance violation
```

**CASB Solution:** Discovers ALL cloud app usage (sanctioned and unsanctioned) and provides visibility.

### 1.3 Key Cloud Security Challenges

| Challenge | Traditional Security | CASB Solution |
|-----------|---------------------|---------------|
| **Visibility** | Can see network traffic but not application activities | Logs every file access, share, download, permission change |
| **Data Location** | Data is on-premises, controlled | Data is in cloud, need to track where it goes and who accesses it |
| **Encryption** | Can decrypt at perimeter | Uses API access or SSL interception to inspect content |
| **Compliance** | Auditors can physically verify controls | Must prove cloud data meets regulatory requirements |
| **Insider Threats** | Monitor internal network behavior | Track unusual cloud activity patterns (UBA) |

### 1.4 Understanding Data States

This is CRITICAL for CASB architecture:

**Data at Rest (DAR):**
- Files already stored in cloud applications
- Existing documents in Box, SharePoint, Google Drive
- Database records in Salesforce
- **Inspection Method:** API-based scanning (Securlets)
- **When Checked:** Retroactively (after upload) or on-demand rescans

**Data in Motion (DIM):**
- Files being uploaded, downloaded, or shared RIGHT NOW
- Email attachments being sent
- Chat messages being posted
- **Inspection Method:** Inline proxy (Gatelets)
- **When Checked:** Real-time (during the activity)

**Analogy:**
- **DAR = Library books already on shelves** → You audit them periodically
- **DIM = Books being checked out right now** → You inspect them at the checkout desk

### 1.5 Quick Self-Check Quiz

Before moving forward, ensure you can answer:

1. Why can't a traditional firewall detect if an employee shared a confidential document on Google Drive with an external email?
2. What is Shadow IT and why is it a security risk?
3. What's the difference between inspecting data at rest vs. data in motion?
4. If a file was uploaded to Box 6 months ago, which CASB component would find policy violations in it?

**Answers:**
1. Firewall sees only encrypted HTTPS traffic to google.com, not application-layer sharing activities
2. Unsanctioned cloud apps used without IT knowledge = no security controls, no visibility, compliance risk
3. DAR = already stored files (API scan); DIM = files in transit during upload/download (inline inspection)
4. Securlet (API-based scan of data at rest)

---

<a name="section-2"></a>
## 2. CASB Core Concepts and Architecture

### 2.1 What is a CASB? (The 30-Second Explanation)

**Cloud Access Security Broker (CASB)** = A security policy enforcement point between your users and cloud providers.

**Think of it as:** A security guard stationed between your employees and their cloud applications, who:
- Checks ID badges (authentication)
- Inspects briefcases (DLP scanning)
- Logs everyone coming and going (activity monitoring)
- Blocks unauthorized actions (policy enforcement)
- Reports suspicious behavior (threat detection)

### 2.2 The Four Pillars of CASB

Every CASB solution focuses on four core capabilities (remember: **V-D-T-C**):

#### **1. Visibility**
- **What:** See ALL cloud application usage across the organization
- **Includes:** Sanctioned apps (approved) + Shadow IT (unsanctioned)
- **Metrics:** Number of users, data volume, risk scores, geographic locations
- **Example:** Discover that 30% of employees are using unauthorized file-sharing apps

#### **2. Data Security (DLP)**
- **What:** Prevent sensitive data from leaking to unauthorized locations
- **Includes:** Credit cards, SSN, HIPAA data, PII, intellectual property
- **Actions:** Block uploads, quarantine files, remove sharing permissions
- **Example:** Automatically quarantine any file containing credit card numbers uploaded to Box

#### **3. Threat Protection**
- **What:** Detect and block malicious activities
- **Includes:** Malware, ransomware, compromised accounts, privilege abuse
- **Methods:** Anti-malware scanning, behavioral analytics, anomaly detection
- **Example:** Detect that a user account is downloading 10,000 files at 3 AM (compromised credential)

#### **4. Compliance**
- **What:** Ensure cloud usage meets regulatory requirements
- **Includes:** GDPR, HIPAA, PCI-DSS, SOX, industry standards
- **Proof:** Audit reports showing data handling, access controls, encryption status
- **Example:** Generate report proving no HIPAA data is stored in non-compliant cloud regions

### 2.3 CASB Deployment Architectures (The Three Methods)

Understanding WHERE the CASB sits in the network is essential for troubleshooting.

#### **Architecture 1: API Connector (Out-of-Band)**

```
[User] → [Cloud App] ← API Connection ← [CASB]
         ↑
    Data flows directly
    CASB monitors via API logs
```

**How It Works:**
1. CASB connects to cloud provider's API (like a service account)
2. Reads activity logs and scans stored files
3. Takes remediation actions via API (delete, quarantine, change permissions)

**Characteristics:**
- ✅ **No impact on user experience** (not in traffic path)
- ✅ **Works for BYOD and unmanaged devices** (no client software needed)
- ✅ **Deep inspection of data at rest** (scans existing files)
- ❌ **Retrospective detection** (finds violations AFTER they happen)
- ❌ **Cannot block in real-time** (can remediate but not prevent)
- ❌ **Only works with sanctioned apps** (needs API credentials)

**Best For:** Monitoring sanctioned SaaS apps like Office 365, Box, Salesforce

**Symantec Term:** **Securlet**

#### **Architecture 2: Forward Proxy (Inline)**

```
[User] → [CASB Forward Proxy] → [Cloud App]
         ↑
    All traffic passes through CASB
    Requires client configuration
```

**How It Works:**
1. User's device configured to route traffic through CASB (agent or PAC file)
2. CASB intercepts and inspects traffic in real-time
3. Enforces policies before traffic reaches cloud app

**Characteristics:**
- ✅ **Real-time blocking** (prevent violations before they happen)
- ✅ **Works with unsanctioned apps** (any HTTPS traffic)
- ✅ **Granular control** (block upload but allow download)
- ❌ **Requires endpoint configuration** (agent or proxy settings)
- ❌ **Can impact performance** (adds latency to every request)
- ❌ **Doesn't work for unmanaged BYOD** (can't install agent)

**Configuration Methods:**
- **Agent:** Software installed on endpoints
- **PAC File:** Proxy Auto-Configuration script (browser setting)
- **DNS Redirect:** Point cloud app domains to CASB IP

**Best For:** Enforcing policies on managed corporate devices

#### **Architecture 3: Reverse Proxy (Inline)**

```
[User] → DNS Redirect → [CASB Reverse Proxy] → [Cloud App]
                        ↑
                   Sits close to cloud app
                   No endpoint configuration
```

**How It Works:**
1. DNS for cloud app (e.g., mycompany.box.com) points to CASB IP
2. User thinks they're connecting directly to cloud app
3. CASB proxies the connection transparently

**Characteristics:**
- ✅ **No endpoint configuration** (works immediately)
- ✅ **Real-time policy enforcement**
- ✅ **Works with BYOD** (network-level control)
- ❌ **Only works with apps where you control DNS** (your custom domain)
- ❌ **Can't control personal accounts** (user's personal Gmail, not company's)

**Best For:** Corporate instances of SaaS apps (company.slack.com, company-domain.box.com)

### 2.4 Symantec CloudSOC Multi-Mode Approach

Symantec CloudSOC uses a **hybrid architecture** combining multiple methods:

```
                    ┌─────────────────────┐
                    │  Symantec CloudSOC  │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
   [Securlets]            [Gatelets]            [Audit/Detect]
   API Connector          Inline Proxy          Analytics Engine
        │                      │                      │
   Data at Rest          Data in Motion         Behavioral Analysis
   (Box, O365, etc.)     (Real-time traffic)    (Threat Scoring)
```

**Why Hybrid?**
- Securlets handle retroactive scanning and remediation
- Gatelets provide real-time blocking for critical controls
- Combined = comprehensive coverage of both DAR and DIM

---

<a name="section-3"></a>
## 3. Symantec CloudSOC Platform Deep Dive

### 3.1 CloudSOC Components Overview

CloudSOC is not a single product but an integrated platform with multiple modules:

| Component | Purpose | What It Does |
|-----------|---------|-------------|
| **Securlets** | Data at Rest protection | API-based scanning of stored files and activity logs |
| **Gatelets** | Data in Motion protection | Inline proxy for real-time traffic inspection |
| **CloudSOC Audit** | Shadow IT discovery | Identifies all cloud apps being used (sanctioned/unsanctioned) |
| **Investigate** | Post-incident analysis | Search and analyze historical activity logs with detailed filters |
| **Detect** | Real-time threat monitoring | User Behavior Analytics (UBA) with ThreatScore™ |
| **Risk Analytics** | On-demand forensics | Ad-hoc exploration of risk patterns and policy effectiveness |
| **Cloud Detection Service (CDS)** | DLP engine | Hosted service that performs content inspection using DLP detectors |

### 3.2 Authentication and User Provisioning

Before using CloudSOC, you must provision authentication:

#### **Step 1: Broadcom Login / AuthHub**
- CloudSOC uses Broadcom's centralized authentication system
- **AuthHub** = Identity Provider (IdP) integration hub
- Supports federated identity (SAML, OIDC)

**Common IdPs:**
- Azure AD (Entra ID)
- Okta
- Google Workspace
- Active Directory Federation Services (ADFS)

#### **Step 2: User Synchronization Methods**

**Method A: Manual User Creation**
- Log into CloudSOC console
- Navigate to **Users > New > User**
- Enter email, name, assign role (System Admin, Admin, End User)

**Method B: CSV Import (Bulk)**
- Download template from **Users > Import/Export**
- Fill in user details, group assignments, access profiles
- Upload CSV file
- System auto-creates users and assigns permissions

**Method C: SpanVA Synchronization**
- Deploy **SpanVA** (Symantec Proxy and Network Virtual Appliance)
- Configure Active Directory connection
- Automatic sync of AD users and groups to CloudSOC

**SpanVA Additional Functions:**
- Collects firewall/proxy logs for Audit analysis (Shadow IT detection)
- Required for **closed networks** (air-gapped or highly restricted environments)
- Deployed as a virtual appliance (VMware, Hyper-V)

### 3.3 Enterprise Console vs. CloudSOC Console

**Two separate interfaces - don't confuse them:**

#### **Enterprise Console (EC)**
- **URL:** enterprise.symantec.com (or similar)
- **Purpose:** License and subscription management
- **Used For:**
  - Activating CloudSOC subscriptions
  - Provisioning Cloud Detection Service (CDS) detectors
  - Managing product licenses across Broadcom security portfolio

#### **CloudSOC Console**
- **URL:** portal-region.cloudsocsecurity.com (region-specific)
- **Purpose:** Day-to-day CASB operations
- **Used For:**
  - Configuring Securlets and Gatelets
  - Creating and managing policies
  - Investigating incidents
  - User and access control management

**Common Mistake:** Trying to configure DLP policies before provisioning CDS in the Enterprise Console.

**Correct Flow:**
```
1. Enterprise Console → Activate Cloud DLP Subscription
2. Enterprise Console → Select Detector Type (Cloud DLP or Enforce-managed)
3. CloudSOC Console → Settings > Data Loss Prevention → Add Detection Service
4. CloudSOC Console → Create policies using the provisioned detector
```

### 3.4 Initial Configuration Checklist

Use this checklist when setting up a new CloudSOC environment:

- [ ] **Week 1: Foundation**
  - [ ] Provision Broadcom Login / AuthHub
  - [ ] Configure IdP integration (Azure AD, Okta, etc.)
  - [ ] Activate CloudSOC subscription in Enterprise Console
  - [ ] Log into CloudSOC console and verify access

- [ ] **Week 2: DLP Setup**
  - [ ] Activate Cloud DLP subscription in Enterprise Console
  - [ ] Provision CDS Detector (Cloud DLP or Enforce-managed)
  - [ ] Add Detection Service in CloudSOC (Settings > DLP)
  - [ ] Test detector connectivity (verify token acceptance)

- [ ] **Week 3: User Management**
  - [ ] Create System Administrator account
  - [ ] Create Access Profiles for different admin roles
  - [ ] Import users (CSV or SpanVA sync)
  - [ ] Assign users to appropriate groups

- [ ] **Week 4: Application Integration**
  - [ ] Enable first Securlet (recommend starting with Box or O365)
  - [ ] Configure API credentials for cloud service
  - [ ] Enable first Gatelet (recommend O365 or custom app)
  - [ ] Verify traffic flow in Investigate logs

- [ ] **Week 5: Policy Configuration**
  - [ ] Create baseline DLP policy (e.g., block credit cards)
  - [ ] Test policy with known violation (upload test file)
  - [ ] Configure notification recipients
  - [ ] Document policy exceptions

### 3.5 Understanding CloudSOC Regions and Data Residency

CloudSOC is deployed in regional instances for performance and data sovereignty:

**Common Regions:**
- **Americas:** portal-us.cloudsocsecurity.com
- **EMEA:** portal-eu.cloudsocsecurity.com
- **APAC:** portal-ap.cloudsocsecurity.com

**Why It Matters:**
- **Latency:** Users should connect to nearest region for best performance
- **Compliance:** Some regulations require data to stay in specific geographic regions (GDPR, data localization laws)
- **Troubleshooting:** Always verify which region the customer is using - configurations don't transfer between regions

**Data Flow Example:**
```
User in Germany → Uploads file to Box
                ↓
File routed through EU Gatelet (portal-eu)
                ↓
Content sent to EU CDS detector for DLP scan
                ↓
Logs stored in EU CloudSOC database
                ↓
Compliance requirement: EU GDPR data never leaves EU
```

---

<a name="section-4"></a>
## 4. Securlets: API-Based Protection (Data at Rest)

### 4.1 What is a Securlet?

**Securlet** = API connector between CloudSOC and a specific cloud service.

**Core Function:** Monitor and remediate **Data at Rest** (files already stored in the cloud).

### 4.2 How Securlets Work (Technical Deep Dive)

#### **Step-by-Step Process:**

**1. API Authentication:**
```
CloudSOC → Authenticates to cloud service API using service account credentials
         → Receives OAuth token or API key
         → Token periodically refreshed
```

**2. Activity Log Collection:**
```
Cloud Service → Generates activity logs (file uploads, shares, permissions changes)
              → CloudSOC polls API every X minutes (configurable)
              → Logs ingested into CloudSOC database
```

**3. File Scanning:**
```
When policy triggers a scan:
1. CloudSOC requests file download via API
2. File downloaded to CDS (Cloud Detection Service)
3. DLP detectors scan content
4. Match result returned to CloudSOC
5. Policy action executed (if violation found)
```

**4. Remediation Actions:**
```
If policy violated:
→ Change file permissions (remove external sharing)
→ Quarantine file (move to admin-only folder)
→ Delete file
→ Remove shared link
→ Notify admin/user
→ Log incident
```

### 4.3 Supported Securlets (As of CASB 3.x)

#### **SaaS Securlets:**
- **Microsoft 365** (OneDrive, SharePoint, Exchange Online, Teams)
- **Google Workspace** (Drive, Gmail, Calendar)
- **Box**
- **Salesforce**
- **Slack**
- **Dropbox**
- **ServiceNow**
- **Zoom**
- **Webex**

#### **IaaS Securlets:**
- **AWS** (S3, EC2, IAM)
- **Azure** (Blob Storage, VMs)
- **Google Cloud Platform**

### 4.4 Configuring a Securlet (Hands-On Example: Box)

#### **Prerequisites:**
- Box Enterprise account
- Box Admin credentials
- CloudSOC System Administrator access

#### **Configuration Steps:**

**Step 1: Enable Securlet in CloudSOC**
```
1. Log into CloudSOC console
2. Navigate to: Store > Cloud Services
3. Find "Box (API)" in the list
4. Click "Enable" or "Configure"
5. Read the prerequisites (API permissions required)
```

**Step 2: Create Service Account in Box**
```
1. Log into Box Admin Console
2. Go to: Admin Console > Apps > Custom Apps
3. Click "Create New App"
4. Select "Server Authentication (with JWT)"
5. Name it "CloudSOC Integration"
6. Generate keypair and download JSON config
7. Authorize app in Box (grant admin permissions)
```

**Step 3: Connect Securlet to Box**
```
1. Return to CloudSOC console
2. In Box Securlet configuration screen:
   → Upload JSON config file from Box
   → Or manually enter:
     - Client ID
     - Client Secret
     - Enterprise ID
     - Public Key ID
     - Private Key
3. Click "Test Connection"
4. If successful, click "Save"
```

**Step 4: Configure Scanning Options**
```
Options:
☑ Scan existing files (initial scan of all DAR)
☑ Scan new files automatically (as they're uploaded)
☑ Scan on policy change (rescan after policy update)
□ Scan only specific folders (optional filter)

Frequency:
- Full scan: Weekly
- Incremental scan: Every 4 hours
```

**Step 5: Verify Connection**
```
1. Go to: Investigate app in CloudSOC
2. Filter: Source = Box (API)
3. You should see activity logs appearing:
   - File uploads
   - File downloads
   - Sharing changes
   - Permission modifications
```

### 4.5 Securlet Dashboards and Visibility

Each Securlet provides a dedicated dashboard:

**Navigation:** CloudSOC Console > Select Securlet > Dashboard

**Key Metrics Displayed:**
- **Total files scanned**
- **Policy violations found**
- **Files quarantined/deleted**
- **External collaborators** (users outside your domain with access)
- **Files shared publicly**
- **Geographic distribution of data**
- **Most active users**
- **Riskiest files** (files with most violations or widest exposure)

**Example Dashboard Insights:**
```
Box Securlet Dashboard:
┌────────────────────────────────────────┐
│ Total Files Scanned: 127,453          │
│ Policy Violations: 89                  │
│ Publicly Shared Files: 12             │
│ External Collaborators: 45             │
│                                        │
│ Top Violators:                         │
│ 1. john.doe@company.com (23 violations)│
│ 2. jane.smith@company.com (18)        │
│                                        │
│ Most Common Violation:                 │
│ Credit Card Number Detected (34 files) │
└────────────────────────────────────────┘
```

### 4.6 Remediation Actions (Detailed)

**Action: Remove External Sharing**
```
Scenario: File contains PII and is shared with external contractors

Securlet Action:
1. Identify all external collaborators on the file
2. Remove their share permissions via API
3. Change file to "Internal Only" sharing
4. Notify file owner of action taken
5. Log remediation in Investigate
```

**Action: Quarantine File**
```
Scenario: File contains malware or highly sensitive data

Securlet Action:
1. Move file to admin-controlled quarantine folder
2. Remove all user access permissions
3. Grant access only to security team
4. Preserve original metadata (owner, upload date, etc.)
5. Create incident ticket
```

**Action: Delete Shared Link**
```
Scenario: File has public link allowing anonymous access

Securlet Action:
1. Revoke public link via API
2. File remains accessible to authenticated users
3. Link becomes invalid (404 error if accessed)
4. Optionally notify file owner
```

**Action: Preserve Content (Backup)**
```
Scenario: Policy violation requires deletion but content must be preserved for investigation

Securlet Action:
1. Download file content
2. Store encrypted copy in CloudSOC vault
3. Delete file from cloud service
4. Maintain audit trail linking deleted file to backup
5. Allow admin to restore if needed
```

### 4.7 Content Rescanning (Critical Concept)

**Why Rescan?**
- You updated a DLP policy (now detecting additional sensitive data)
- You added a new policy type (e.g., now checking for source code leaks)
- You want to verify remediation effectiveness

**Rescan Process:**
```
1. CloudSOC flags all files as "needs rescan"
2. Securlet re-downloads each file
3. Current policies applied to file content
4. New violations detected (if any)
5. Remediation actions taken on newly-detected violations
```

**Initiating a Rescan:**
```
Method 1: Automatic (Policy Change)
- Edit a DLP policy → Save changes
- CloudSOC prompt: "Rescan existing files with updated policy?"
- Select "Yes"

Method 2: Manual (On-Demand)
- Go to Securlet dashboard
- Click "Actions" > "Rescan All Files"
- Select scope (all files or specific folders)
- Confirm rescan

Method 3: Scheduled
- Configure rescan schedule in Securlet settings
- Example: Full rescan every Sunday at 2 AM
```

**Rescan Performance Considerations:**
- Large environments (millions of files) can take days to rescan
- CDS has throughput limits (files scanned per hour)
- Rescans consume API rate limits from cloud provider
- Plan rescans during off-hours to minimize user impact

### 4.8 Common Securlet Issues (Troubleshooting Preview)

We'll cover full troubleshooting later, but here are common Securlet problems:

**Issue 1: No Activity Logs Appearing**
```
Symptoms:
- Securlet shows "Connected" status
- But Investigate shows no logs from this service

Troubleshooting Steps:
1. Verify API credentials haven't expired
2. Check cloud service admin hasn't revoked app permissions
3. Confirm Securlet is enabled in Store
4. Check for recent service outages (CloudSOC status page)
5. Review API rate limits (may be throttled)
```

**Issue 2: Files Not Being Scanned**
```
Symptoms:
- Activity logs present
- But file uploads not triggering DLP scans

Troubleshooting Steps:
1. Verify CDS detector is configured (Settings > DLP)
2. Check if policy applies to this file type (policy may exclude .txt files)
3. Confirm file size is within CDS limits (typically 50MB max)
4. Check if scanning is enabled for this Securlet (may be set to logs-only mode)
```

**Issue 3: Remediation Actions Failing**
```
Symptoms:
- Policy detects violation
- But quarantine/delete action fails

Troubleshooting Steps:
1. Verify Securlet has necessary API permissions (e.g., file.delete permission)
2. Check if file is locked by another user (currently being edited)
3. Confirm file owner hasn't restricted admin access
4. Review CloudSOC error logs for specific API error code
```

---

<a name="section-5"></a>
## 5. Gatelets: Inline Protection (Data in Motion)

### 5.1 What is a Gatelet?

**Gatelet** = Application-aware inline cloud proxy that monitors and protects **Data in Motion** in real-time.

**Key Difference from Securlet:**
- Securlet = Retroactive (finds violations after upload)
- Gatelet = Preventive (blocks violations during upload)

### 5.2 Gatelet Architecture (Technical Details)

#### **Network Flow with Gatelet:**

```
Without Gatelet:
[User] → [Internet] → [Cloud App]

With Gatelet:
[User] → [Cloud SWG/WSS] → [Gatelet] → [Cloud App]
         ↑                   ↑
     SSL Interception    App-Aware Inspection
```

**Step-by-Step Traffic Flow:**

**1. DNS Resolution:**
```
User browses to: teams.microsoft.com

DNS resolution:
- Corporate DNS returns Symantec Cloud SWG IP (not Microsoft IP)
- Traffic redirected to Symantec infrastructure
```

**2. SSL Interception:**
```
User's browser → Attempts HTTPS connection to teams.microsoft.com
               ↓
Cloud SWG → Intercepts SSL handshake
          → Presents Symantec SSL certificate (trusted by corporate devices)
          → Decrypts HTTPS traffic
          → Forwards to Gatelet for inspection
```

**3. Application-Layer Parsing:**
```
Gatelet → Identifies application protocol (Teams API calls)
        → Parses activity type:
          - Sending chat message
          - Uploading file to channel
          - Starting video call
          - Sharing screen
        → Extracts metadata:
          - User identity
          - File name and size
          - Destination (which channel/user)
          - Timestamp
```

**4. DLP Inspection (If Applicable):**
```
If activity involves content (file upload, message with text):
1. Content sent to CDS
2. DLP detectors scan for sensitive data
3. Match result returned
4. Policy decision made
```

**5. Policy Enforcement:**
```
Based on policy:
→ Allow (let activity proceed)
→ Block (show user "Activity Blocked" message)
→ Adaptive Auth (require MFA step-up authentication)
→ Notify (alert admin but allow)
→ Log Only (no action, just record)
```

**6. Forward to Cloud App:**
```
If allowed:
- Gatelet re-encrypts traffic
- Forwards to actual cloud app (Microsoft servers)
- User sees normal application response
- Total added latency: typically 50-200ms
```

### 5.3 Full Gatelets vs. Custom Gatelets

#### **Full Gatelets (Deep Inspection)**

**Definition:** Pre-built integrations for popular SaaS apps with full API understanding.

**Supported Applications:**
- Microsoft 365 (OneDrive, SharePoint, Outlook Web App, Teams)
- Google Workspace (Drive, Gmail, Calendar)
- Box
- Dropbox
- Salesforce
- Slack
- Zoom
- Webex
- iCloud

**Capabilities:**
- **Granular activity visibility:**
  - Not just "file uploaded" but "file uploaded to shared channel named 'Project X' with external collaborators"
  - Not just "email sent" but "email sent with attachment named 'Q4-Financial.xlsx' to external recipient"
- **Context-aware policies:**
  - Block file shares to specific external domains
  - Allow downloads but block uploads
  - Require MFA for accessing specific folders
- **Session-level controls:**
  - Monitor entire user session (login to logout)
  - Detect anomalous session behavior (session hijacking)

**Example Full Gatelet Log Entry:**
```json
{
  "timestamp": "2025-11-17T14:23:45Z",
  "user": "john.doe@company.com",
  "source_ip": "203.0.113.42",
  "device_type": "Windows Desktop",
  "application": "Microsoft Teams",
  "activity": "File Upload",
  "object": "Financial_Report_Q4.pdf",
  "destination": "Marketing Team Channel",
  "external_participants": true,
  "file_size": 2457600,
  "policy_matched": "Block Financial Data Upload to External Channels",
  "action_taken": "Blocked",
  "violation_details": "File contains credit card numbers (Visa: 12 instances)"
}
```

#### **Custom Gatelets (Basic Monitoring)**

**Definition:** Generic proxy for ANY web application not covered by Full Gatelets.

**Capabilities (Limited):**
- Detect user login/logout
- Monitor file uploads (basic detection, filename only)
- Monitor file downloads
- Log URLs accessed
- **Cannot:** Parse application-specific activities (e.g., can't tell what Slack channel a message was posted to)

**Use Cases:**
- Shadow IT applications discovered by Audit
- Custom internal web apps
- Less common SaaS applications
- Testing/evaluation before vendor creates Full Gatelet

**Example Custom Gatelet Configuration:**
```
Application Name: ProtonMail
Domain: protonmail.com
Monitoring Modes:
☑ Track logins
☑ Track uploads
☑ Track downloads
□ SSL inspection required (default: yes)

DLP Scanning:
☑ Scan file uploads
☐ Scan page content (text on screen)
```

**Example Custom Gatelet Log Entry:**
```json
{
  "timestamp": "2025-11-17T14:23:45Z",
  "user": "john.doe@company.com",
  "source_ip": "203.0.113.42",
  "device_type": "Windows Desktop",
  "application": "ProtonMail (Custom Gatelet)",
  "activity": "File Upload",
  "object": "document.pdf",
  "destination": "protonmail.com",
  "file_size": 1245600,
  "policy_matched": "Block All Uploads to Unapproved Email Services",
  "action_taken": "Blocked",
  "violation_details": null
}
```

**Key Limitation Notice:**
```
Custom Gatelet knows:
✅ WHO uploaded a file
✅ WHEN it was uploaded
✅ FILE NAME and size
❌ NOT WHAT'S IN THE FILE (no deep content inspection)
❌ NOT WHO IT WAS SENT TO (no recipient information)
❌ NOT CONTEXT (can't distinguish between draft save vs. sending)
```

### 5.4 Enabling and Configuring Gatelets

#### **Prerequisites:**
1. **Symantec Cloud SWG (WSS) subscription** - Gatelets require traffic to flow through WSS first
2. **WSS/CASB integration enabled** - Support must activate sync between WSS and CloudSOC
3. **SSL interception configured** - Gatelet domains must be SSL intercepted
4. **Corporate devices with certificates** - Devices must trust Symantec SSL certificate

#### **Configuration Steps (Full Gatelet Example: Microsoft Teams)**

**Step 1: Enable Gatelet in CloudSOC Store**
```
1. Log into CloudSOC console
2. Navigate to: Store > Cloud Services
3. Find "Microsoft Teams (Gateway)"
4. Click "Enable"
5. Wait 5-15 minutes for WSS sync to complete
```

**Step 2: Verify WSS Integration**
```
1. Log into WSS Threatpulse Portal (separate URL)
2. Navigate to: Integration > CASB Gateway
3. Verify status shows: "Synced"
4. Check last sync time (should be within last 15 minutes)
5. Confirm Teams is listed in "Enabled Gatelets"
```

**Step 3: Configure SSL Interception in WSS**
```
1. In WSS Portal, go to: Security > SSL Settings
2. Ensure "SSL Inspection" is enabled globally
3. Check "Domains of Interest" section
4. Verify Microsoft Teams domains are in SSL intercept list:
   - teams.microsoft.com
   - *.teams.microsoft.com
   - teams.office.com
5. CRITICAL: Ensure these domains are NOT in any bypass list
```

**Step 4: Test Traffic Flow**
```
1. From a managed device, browse to: teams.microsoft.com
2. Log in with corporate credentials
3. Perform test activity:
   - Upload a test file to a channel
   - Send a chat message
   - Download a file from a conversation
4. Wait 2-3 minutes for log processing
```

**Step 5: Verify in CloudSOC Investigate**
```
1. Open CloudSOC Console > Investigate app
2. Apply filters:
   - Source: Microsoft Teams (Gateway)
   - User: [your test account]
   - Time: Last 15 minutes
3. Expected results:
   ✅ Login activity logged
   ✅ File upload activity logged with filename
   ✅ File download activity logged
   ✅ User and device information present
   ✅ IP address captured
```

#### **Configuration Steps (Custom Gatelet Example: ProtonMail)**

**Step 1: Create Custom Gatelet**
```
1. CloudSOC Console > Store > Custom Gatelets
2. Click "Add Custom Gatelet"
3. Configuration:
   Name: ProtonMail
   Domain: protonmail.com
   Category: Email Service
   Risk Level: High (justification: encrypted email, potential data exfiltration)
   
4. Monitoring Options:
   ☑ Enable Upload Detection
   ☑ Enable Download Detection
   ☑ Enable Login/Logout Tracking
   ☑ Enable DLP Scanning (if available)
   
5. SSL Interception: Required (default: yes)
6. Save configuration
```

**Step 2: Wait for WSS Sync**
```
- Sync window: 5-15 minutes
- During sync: WSS updates proxy rules to route protonmail.com through Gatelet
- After sync: Traffic to protonmail.com will be inspected
```

**Step 3: Test and Verify**
```
1. Browse to protonmail.com from managed device
2. Attempt to upload a test file
3. Check CloudSOC Investigate for log entry
4. Verify policy enforcement (if block policy configured)
```

### 5.5 Gatelet Policies and Real-Time Enforcement

#### **Policy Types for Gatelets:**

**1. Activity-Based Policies**
```
Policy: Block File Uploads to External Collaboration Tools

Configuration:
- Trigger: Activity Type = "File Upload"
- Scope: Application = "Slack (Gateway)"
- Condition: User Group = "All Users"
- Action: Block
- Notification: Display message to user + Email admin

Result:
User uploads file to Slack → Gatelet intercepts → Shows "Activity Blocked" error
```

**2. Content-Based Policies (DLP)**
```
Policy: Block Credit Card Numbers in Email

Configuration:
- Trigger: Activity Type = "Send Email"
- Scope: Application = "Gmail (Gateway)"
- Condition: Content matches "Credit Card Number" detector
- Action: Block
- Notification: User notification + DLP incident created

Result:
User types email with credit card number → 
Sends email → 
Gatelet extracts content → 
CDS scans content → 
Credit card detected → 
Email blocked before sending
```

**3. Context-Aware Policies**
```
Policy: Require MFA for Accessing Shared Drives Outside Office

Configuration:
- Trigger: Activity Type = "Access Resource"
- Scope: Application = "Google Drive (Gateway)"
- Condition: 
  - Resource Location = "Shared Drives" (not My Drive)
  - Source IP = NOT in "Corporate Office IP Range"
- Action: Adaptive Authentication (step-up MFA)
- MFA Method: Push notification via Duo/Okta

Result:
Employee at coffee shop tries to access shared drive →
Gatelet detects location outside office →
Triggers MFA challenge →
Employee completes MFA →
Access granted
```

**4. Threat-Based Policies**
```
Policy: Block File Downloads from Compromised Accounts

Configuration:
- Trigger: Activity Type = "File Download"
- Scope: Application = "Box (Gateway)"
- Condition: User ThreatScore > 80 (high risk)
- Action: Block + Force logout
- Notification: SOC team alert

Result:
User account shows signs of compromise (unusual location, mass file access) →
ThreatScore increases to 85 →
User attempts to download files →
All downloads blocked automatically →
User logged out, password reset required
```

### 5.6 Gatelet Performance and User Experience

#### **Understanding Latency Impact**

**Latency Breakdown:**
```
Without Gatelet:
User → Internet → Cloud App
Total time: ~50ms (direct connection)

With Gatelet:
User → Cloud SWG → Gatelet → CDS (if DLP scan) → Cloud App
Total time: ~150-300ms

Latency added by:
- SSL decrypt/encrypt: 20-40ms
- Application parsing: 10-20ms
- DLP scan (if content): 50-200ms (depends on file size)
- Geographic routing: 10-50ms (if Gatelet region != user region)
```

**User Experience Impact:**
- **Interactive activities (clicks, navigation):** Barely noticeable (< 100ms added)
- **File downloads:** Minimal impact (streaming starts quickly)
- **File uploads:** Noticeable for large files (DLP scanning adds time)
- **Heavy DLP scanning:** Can delay upload by 2-5 seconds for large documents

#### **Performance Optimization Tips:**

**1. Regional Gatelet Placement**
```
Problem: US users connecting to EU Gatelet
Solution: Use geo-aware routing in WSS
         Route users to nearest Gatelet region
         
Configuration:
WSS Portal > Routing > Geographic Policies
- US users → US Gatelet
- EU users → EU Gatelet  
- APAC users → APAC Gatelet
```

**2. Selective DLP Scanning**
```
Problem: Scanning every file upload causes delays
Solution: Risk-based scanning

Policy Configuration:
High-risk activities (upload to external share): ALWAYS scan
Low-risk activities (personal OneDrive): Scan sample only (10%)
Known safe file types (.jpg, .png): Skip DLP scan
Unknown/risky file types (.exe, .zip): ALWAYS scan
```

**3. Caching and Whitelisting**
```
Problem: Repeated access to same content scanned multiple times
Solution: Implement content hash caching

CloudSOC automatically:
- Calculates file hash (SHA-256)
- Checks if hash was scanned recently
- If yes, reuse previous scan result (cache hit)
- If no, perform new scan (cache miss)

Cache duration: Configurable (default 24 hours)
```

### 5.7 Gatelet Monitoring and Analytics

#### **Real-Time Activity Dashboard**

**Location:** CloudSOC Console > Gatelets > Dashboard

**Key Metrics:**
```
┌─────────────────────────────────────────────────┐
│ Gatelet Activity - Last 24 Hours               │
├─────────────────────────────────────────────────┤
│ Total Transactions: 45,234                     │
│ Blocked Activities: 127                         │
│ Adaptive Auth Triggered: 89                     │
│ Average Latency: 85ms                           │
│                                                 │
│ Most Active Applications:                       │
│ 1. Microsoft 365 (18,432 transactions)         │
│ 2. Slack (12,221)                               │
│ 3. Box (8,901)                                  │
│                                                 │
│ Top Blocked Activities:                         │
│ 1. File upload with PII (45 blocks)           │
│ 2. External file sharing (32 blocks)           │
│ 3. Unapproved application access (28 blocks)   │
└─────────────────────────────────────────────────┘
```

#### **Per-User Activity Tracking**

**Use Case:** Investigate specific user's cloud application usage

```
Navigation: Investigate > Filter by User

Example Investigation Query:
- User: john.doe@company.com
- Source: All Gatelets
- Time Range: Last 7 days
- Activity Type: File Upload

Results Show:
┌────────────┬──────────────┬──────────────┬────────────┐
│ Date       │ App          │ File         │ Action     │
├────────────┼──────────────┼──────────────┼────────────┤
│ 11/17 2PM  │ Teams        │ report.pdf   │ Allowed    │
│ 11/17 10AM │ Slack        │ data.csv     │ Blocked    │
│ 11/16 3PM  │ Box          │ contract.doc │ Allowed    │
│ 11/15 9AM  │ ProtonMail   │ finance.xlsx │ Blocked    │
└────────────┴──────────────┴──────────────┴────────────┘

Pattern Detected: User attempting to upload sensitive files to 
unapproved email service (ProtonMail) - potential data exfiltration
```

### 5.8 Gatelet Troubleshooting Scenarios

**Scenario 1: Traffic Not Being Inspected**

```
Symptoms:
- Gatelet enabled in CloudSOC
- User can access application
- No logs appearing in Investigate

Troubleshooting Steps:

Step 1: Verify WSS Sync
→ Check WSS Portal: Integration > CASB Gateway
→ Status should be "Synced"
→ Last sync time < 15 minutes
→ If not synced: Open support ticket for sync activation

Step 2: Verify SSL Interception
→ User's browser goes to application
→ Check SSL certificate in browser
→ Certificate issuer should be "Symantec" (or your corporate CA)
→ If certificate is from actual app (e.g., Microsoft): SSL NOT intercepted

Step 3: Check Bypass Lists
→ WSS Portal > Security > SSL Bypass
→ Look for application domain in bypass lists:
  - Mobile App Bypass
  - Certificate Pinning Bypass
  - Custom Bypass Rules
→ If found: Remove from bypass OR disable Gatelet for this app

Step 4: Verify Traffic Routing
→ From user device: traceroute to application domain
→ Should route through Symantec Cloud SWG IP
→ If routes directly to app: DNS/Proxy configuration issue
```

**Scenario 2: Policy Not Enforcing (Block Not Working)**

```
Symptoms:
- Gatelet logs show activity
- Policy configured to block
- User's activity NOT blocked (allowed through)

Troubleshooting Steps:

Step 1: Verify Policy Scope
→ Check policy in Protect module
→ Confirm "Data Transfer via Gatelet" (not Securlet)
→ Verify application is selected (e.g., "Microsoft Teams (Gateway)")
→ Check user/group scope (does it apply to this user?)

Step 2: Check Policy Priority
→ Multiple policies may conflict
→ Lower priority number = higher precedence
→ Example conflict:
   Policy 1 (Priority 10): Block all uploads → SHOULD block
   Policy 2 (Priority 5): Allow uploads for IT group → OVERRIDES

Step 3: Verify DLP Detector
→ If policy uses DLP condition (e.g., "contains credit cards")
→ Settings > DLP > Verify detector status = "Active"
→ Test detector with known violation sample

Step 4: Check Real-Time Sync
→ Policy changes may take 2-5 minutes to propagate to Gatelets
→ After policy change: Wait 5 minutes, then test again
→ CloudSOC Console > Settings > Cache > "Clear Policy Cache" (force immediate sync)
```

**Scenario 3: Partial Inspection (Some Activities Logged, Others Missing)**

```
Symptoms:
- File uploads logged correctly
- But Teams messages NOT logged
- Same user, same application

Root Cause: Domain-Specific SSL Interception

Explanation:
Microsoft Teams uses multiple domains:
- teams.microsoft.com (main app)
- *.teams.microsoft.com (various services)
- teams.office.com (legacy)
- *.broadcast.skype.com (live events)

If only teams.microsoft.com is SSL intercepted:
✅ File uploads work (use teams.microsoft.com)
❌ Chat messages fail (use different subdomain)

Solution:
WSS Portal > SSL Settings > Domains of Interest
Add ALL Teams-related domains:
- teams.microsoft.com
- *.teams.microsoft.com
- teams.office.com
- *.office.com
- *.broadcast.skype.com

Save → Wait for policy propagation → Test again
```

---

<a name="section-6"></a>
## 6. User Management and Access Control

### 6.1 CloudSOC User Role Hierarchy

Understanding user roles is CRITICAL for troubleshooting access issues and preventing privilege escalation.

#### **Role Matrix:**

```
┌──────────────────┬──────────────┬──────────────┬──────────────┐
│ Capability       │ System Admin │ Admin        │ End User     │
├──────────────────┼──────────────┼──────────────┼──────────────┤
│ Full Console     │      ✅      │   ✅ (limited)│      ❌      │
│ Manage Users     │      ✅      │   ⚠️ (via AP) │      ❌      │
│ Configure        │      ✅      │   ⚠️ (via AP) │      ❌      │
│  Securlets       │              │              │              │
│ Configure        │      ✅      │   ⚠️ (via AP) │      ❌      │
│  Gatelets        │              │              │              │
│ Create Policies  │      ✅      │   ⚠️ (via AP) │      ❌      │
│ View Investigate │      ✅      │   ⚠️ (via AP) │   ⚠️ (via AP)│
│ View Detect      │      ✅      │   ⚠️ (via AP) │      ❌      │
│ Remediate        │      ✅      │   ⚠️ (via AP) │      ❌      │
│  Incidents       │              │              │              │
│ Access Profiles  │      ✅      │      ❌      │      ❌      │
│ DPO Role         │      ❌      │      ❌      │      ✅      │
│ API Keys         │      ✅      │      ✅      │   ⚠️ (limited)│
└──────────────────┴──────────────┴──────────────┴──────────────┘

Legend:
✅ = Full access
⚠️ = Access controlled by Access Profile
❌ = No access
AP = Access Profile
```

#### **Role Definitions:**

**System Administrator:**
- **Purpose:** Full control for initial setup and emergency access
- **Capabilities:** Everything - no restrictions
- **Security Contact:** Can be designated to receive security alerts
- **Limitation:** Cannot be assigned Access Profiles (always has full access)
- **Best Practice:** Limit to 2-3 users; use Admin role for day-to-day operations

**Administrator (Admin):**
- **Purpose:** Day-to-day operations with controlled scope
- **Capabilities:** Defined by assigned Access Profile
- **Security Contact:** Can be designated
- **Flexibility:** Different Admins can have different Access Profiles
- **Use Cases:**
  - Regional administrators (EU Admin only sees EU data)
  - Service-specific administrators (Box Admin only manages Box)
  - Read-only administrators (audit/compliance team)

**End User:**
- **Purpose:** Analysts, investigators, compliance reviewers
- **Capabilities:** Typically read-only access to specific apps
- **Data Protection Officer:** MUST be End User role (not Admin)
- **API Access:** Can create API keys with limited scope
- **Common Assignment:** SOC analysts who need to view Investigate logs

### 6.2 Access Profiles (Advanced Role Customization)

Access Profiles are the KEY to granular permission control. They define FOUR dimensions of access:

#### **Dimension 1: CloudSOC Apps (Which Tools Can They Use?)**

```
Available Apps:
☑ Investigate (view activity logs)
☑ Protect (manage policies)
☑ Detect (view threat analytics)
☑ Audit (view app discovery)
☑ Risk Analytics (perform risk queries)
☑ Store (enable/disable Securlets and Gatelets)
☐ Settings (system configuration)

Example Profile: "SOC Analyst"
- Investigate: View only (no export)
- Protect: No access
- Detect: View only
- Audit: View only
```

#### **Dimension 2: Cloud Services (Which Apps Can They Manage?)**

```
Available Services:
☑ Box (API) - Securlet
☑ Microsoft 365 (API) - Securlet
☐ Google Workspace (API) - Securlet
☑ Slack (Gateway) - Gatelet
☐ All other services

Permissions per service:
- View: Can see logs and dashboards
- Modify: Can change configurations
- None: Service hidden from user

Example Profile: "Box Administrator"
- Box (API): View + Modify
- All other services: None
Result: User only sees Box in console, can manage Box policies
```

#### **Dimension 3: Information Level (What Severity Can They See?)**

```
For Investigate Logs:
○ Full Access (all severity levels)
● Selective (choose which levels):
  ☑ Critical
  ☑ High
  ☐ Medium
  ☐ Low
  ☐ Informational

For Detect ThreatScores:
○ All ThreatScores (0-100)
● Threshold: Only show users with ThreatScore > 70

Example Profile: "Senior Security Analyst"
- Investigate: Critical + High only
- Detect: ThreatScore > 50
Result: User only sees serious incidents, not routine activities
```

#### **Dimension 4: Domain Control (Which Users Can They See?)**

```
Your organization uses multiple email domains:
- company.com (primary)
- subsidiary.com (acquired company)
- contractor.domain.com (external contractors)

Access Profile Options:
○ All Domains (no restrictions)
● Specific Domains:
  ☑ company.com
  ☐ subsidiary.com
  ☐ contractor.domain.com

Example Profile: "Subsidiary Administrator"
- Domain: subsidiary.com only
Result: User CANNOT see activity from company.com users
        Can only view/manage subsidiary.com users and their data
```

### 6.3 Creating Access Profiles (Step-by-Step Lab)

#### **Lab Scenario:**
Create an Access Profile for a regional compliance officer who should:
- View Investigate logs for GDPR audits
- Only see EU users (company.eu domain)
- Only see High and Critical severity incidents
- Cannot modify any policies
- Cannot access Box (contains non-EU data)

#### **Lab Steps:**

**Step 1: Log In as System Administrator**
```
URL: portal-eu.cloudsocsecurity.com
Login with System Admin credentials
```

**Step 2: Navigate to Access Profiles**
```
CloudSOC Console > Users > Access Profiles
Click: "New"
```

**Step 3: Configure Basic Settings**
```
Access Profile Name: EU Compliance Officer
Description: Read-only access for GDPR compliance audits in EU region
Status: Active
```

**Step 4: Configure CloudSOC Apps Tab**
```
Investigate:
- Access Level: View
- Export Logs: Disabled (compliance requirement)

Protect:
- Access Level: None (cannot modify policies)

Detect:
- Access Level: View

Audit:
- Access Level: View

Store:
- Access Level: None (cannot enable/disable services)

Settings:
- Access Level: None
```

**Step 5: Configure Cloud Services Permissions Tab**
```
Microsoft 365 (API):
- Permission: View

Google Workspace (API):
- Permission: View

Box (API):
- Permission: None (CRITICAL: contains non-EU data)

All Gatelets:
- Permission: View

Rationale: Officer can see EU user activity but NOT access Box which stores non-EU data
```

**Step 6: Configure Information Level Tab**
```
Investigate Log Severity:
- Access Mode: Selective
- Allowed Severities:
  ☑ Critical
  ☑ High
  ☐ Medium (excluded)
  ☐ Low (excluded)
  ☐ Informational (excluded)

Detect ThreatScore Visibility:
- Threshold: Show users with ThreatScore > 60
- Rationale: Focus on higher-risk users only
```

**Step 7: Configure Domain Control Tab**
```
Domain Access Mode: Specific Domains

Allowed Domains:
☑ company.eu
☐ company.com (excluded - US domain)
☐ company.asia (excluded - APAC domain)

Result: User will ONLY see:
- Activity from users with @company.eu email
- Files/data owned by company.eu users
- Investigate logs where user = *.@company.eu
```

**Step 8: Save and Assign**
```
Click: "Save Access Profile"
Confirmation message: "Access Profile created successfully"

Assign to user:
1. Navigate to: Users > Users
2. Find user: marie.dubois@company.eu
3. Click: "Edit"
4. Access Profile dropdown: Select "EU Compliance Officer"
5. Save
```

**Step 9: Verify Access Profile**
```
Test 1: Log out as System Admin

Test 2: Log in as marie.dubois@company.eu

Test 3: Verify visible apps:
✅ Investigate app is visible
✅ Detect app is visible
✅ Audit app is visible
❌ Protect app is NOT visible
❌ Settings is NOT visible

Test 4: Open Investigate
✅ Can see logs from company.eu users
❌ CANNOT see logs from company.com users (domain restriction working)
✅ Only sees High and Critical severity logs
❌ Medium/Low logs not visible

Test 5: Try to access Box
Navigate to: Store > Cloud Services
Result: Box (API) is not listed OR shows "Access Denied"

Test 6: Try to modify a policy (should fail)
Protect app: Not accessible
If manually navigate to policy URL: "403 Forbidden" error
```

### 6.4 User and Group Management Operations

#### **Creating Users Manually**

```
Navigation: CloudSOC Console > Users > Users > New > User

Required Fields:
- Email: john.doe@company.com (becomes username)
- First Name: John
- Last Name: Doe
- User Type:
  ○ System Administrator
  ● Administrator (selected)
  ○ End User
- Access Profile: [Select from dropdown]
- Password: [Auto-generated or manual]
- Status: Active / Disabled

Optional Fields:
- Phone: +1-555-0123
- Mobile: +1-555-0456
- Manager: jane.manager@company.com
- Department: IT Security
- Employee ID: EMP-12345
- Primary Domain: company.com
- Secondary Domains: subsidiary.com (additional email aliases)

Security Contact Settings:
☐ Designate as Security Contact (receives alert emails)
☐ Enable Multi-Factor Authentication (MFA)

Save → User created → Activation email sent
```

#### **Bulk User Import via CSV**

**Step 1: Download Template**
```
Navigation: Users > Import/Export > Download Template
File received: CloudSOC_User_Import_Template.csv
```

**Step 2: Populate Template**
```csv
Email,FirstName,LastName,UserType,AccessProfile,Groups,Status,SecurityContact
john.doe@company.com,John,Doe,Admin,Box Admin,IT Team;Security,Active,No
jane.smith@company.com,Jane,Smith,EndUser,SOC Analyst,Security;SOC,Active,Yes
mike.jones@company.com,Mike,Jones,Admin,EU Compliance Officer,Compliance,Active,No
```

**Column Details:**
- **Email:** Must be unique (required)
- **UserType:** SystemAdmin, Admin, or EndUser
- **AccessProfile:** Must exactly match existing profile name
- **Groups:** Semicolon-separated list; groups auto-created if don't exist
- **SecurityContact:** Yes/No

**Step 3: Upload CSV**
```
Navigation: Users > Import/Export > Upload File
Select file → Upload
Processing time: ~2 minutes per 100 users
Result: Email confirmation with import summary
```

**Step 4: Verify Import**
```
Navigation: Users > Users
Filter by: Recently Created
Verify:
- Correct user count
- Correct Access Profiles assigned
- Users added to correct groups
- Activation emails sent (check mail server logs if needed)
```

#### **Active Directory Synchronization via SpanVA**

**SpanVA = Symantec Proxy and Network Virtual Appliance**

**Use Cases:**
- Closed networks (no direct internet access from AD)
- Automatic user provisioning from on-premises AD
- Firewall/proxy log collection for Audit analysis

**Deployment Steps:**

**Step 1: Deploy SpanVA Virtual Appliance**
```
Download: SpanVA OVA file from Broadcom portal
Deploy to: VMware vSphere, Hyper-V, or compatible hypervisor
Resources:
- vCPUs: 4
- RAM: 8 GB
- Disk: 100 GB
- Network: Management interface + data interface
```

**Step 2: Initial Configuration**
```
Console access (via hypervisor):
- Set management IP address
- Configure DNS and gateway
- Set NTP server (time sync critical for logs)
- Create admin password
```

**Step 3: Configure AD Sync**
```
Web UI: https://spanva-ip:8443

Navigation: Configuration > Active Directory

Settings:
- AD Domain: company.local
- AD Server: dc01.company.local
- LDAP Port: 389 (or 636 for LDAPS)
- Bind DN: CN=CloudSOC Service,OU=ServiceAccounts,DC=company,DC=local
- Bind Password: [service account password]
- Base DN: OU=Users,DC=company,DC=local
- Sync Schedule: Every 4 hours
- User Filter: (&(objectClass=user)(mail=*))  (only users with email)
- Group Sync: Enabled
- Group Filter: (objectCategory=group)

Test Connection → Success → Save
```

**Step 4: Configure CloudSOC Connection**
```
Navigation: Configuration > CloudSOC

Settings:
- CloudSOC Region: EU (portal-eu.cloudsocsecurity.com)
- API Key: [Generate in CloudSOC Console > Settings > API Keys]
- Sync Mode: Full Sync (initial), then Incremental
- Conflict Resolution: CloudSOC Wins (cloud data takes precedence)

Test Connection → Success → Save
```

**Step 5: Initiate First Sync**
```
Navigation: Operations > Sync Now
Initial sync time: ~5 minutes per 1,000 users
Monitor: Real-time sync progress displayed

Completion notification:
- Total users synchronized: 2,450
- New users created: 2,450
- Users updated: 0
- Groups synchronized: 125
- Errors: 0
```

**Step 6: Verify in CloudSOC**
```
CloudSOC Console > Users > Users
Filter by: Created Today
Verify:
- User count matches AD count
- Email addresses correct
- Groups properly mapped
- Default Access Profile applied (configure in sync settings)
```

### 6.5 Data Protection Officer (DPO) Role

**Special Role for GDPR Compliance**

#### **DPO Requirements (Critical Rules):**

1. **MUST be End User role** (not Admin or System Admin)
   - Rationale: Prevents DPO from having administrative privileges that could conflict with oversight duties

2. **MUST use local CloudSOC password** (SSO not supported)
   - Rationale: Ensures DPO access independent from corporate identity system

3. **Has special "Undelete" privileges**
   - Can restore files that were automatically deleted by policies
   - Required for handling "Right to Erasure" requests (GDPR Article 17)

4. **Receives specific notifications**
   - Data subject access requests (GDPR Article 15)
   - Data breach notifications (GDPR Article 33)
   - Automated decision-making alerts (GDPR Article 22)

#### **Configuring a DPO:**

```
Step 1: Create End User Account
Users > Users > New > User
- User Type: End User (mandatory)
- Email: dpo@company.com
- Authentication: Local Password (not SSO)

Step 2: Enable DPO Role
Edit user → Advanced Settings
☑ Enable Data Protection Officer Role
☑ Enable Undelete Privileges
☑ Receive Data Subject Requests

Step 3: Configure Notification Preferences
DPO Settings:
- Notification Email: dpo@company.com
- Escalation Email: legal@company.com
- Notification Types:
  ☑ Data Subject Access Requests
  ☑ Right to Erasure Requests
  ☑ Data Breach Detection
  ☑ Regulatory Report Generation
  
Step 4: Test DPO Workflow
Simulate data subject request:
1. User submits request: "Delete all my data"
2. DPO receives notification in CloudSOC
3. DPO reviews data associated with user
4. DPO executes deletion OR preserves for legal hold
5. DPO generates compliance report
```

### 6.6 Troubleshooting Access Issues

**Scenario 1: User Can't See Expected Logs**

```
Problem: Admin complains they can't see activity from Office 365

Diagnostic Steps:

1. Verify user's Access Profile:
   Users > Users > Select user > View Access Profile
   Check: Cloud Services Permissions
   → Is "Microsoft 365 (API)" set to
   → Is "Microsoft 365 (API)" set to "View" or "Modify"?
   → If set to "None": User cannot see O365 logs

2. Check Domain restrictions:
   View Access Profile > Domain Control tab
   → If profile restricts to specific domains: User only sees activity from those domains
   → Example: Profile limited to "company.com"
             User trying to view "subsidiary.com" activity = denied

3. Check Information Level filters:
   View Access Profile > Information Level tab
   → If set to "Selective" with only High/Critical: Low severity logs invisible
   → User might be looking for logs that exist but are filtered out

4. Verify Securlet/Gatelet is enabled:
   Store > Cloud Services > Microsoft 365 (API)
   → Status must be "Active"
   → If "Disabled": No logs will be collected

5. Check time range:
   Investigate > Time filter
   → Default might be "Last 24 hours"
   → Expected activity might be older

Fix Actions:
- Adjust Access Profile if scope is incorrect
- Educate user on severity filters
- Verify Securlet status
- Expand time range in search
```

**Scenario 2: Admin Can't Modify Policy**

```
Problem: Admin receives "Access Denied" when trying to save policy changes

Diagnostic Steps:

1. Verify user is Admin (not End User):
   Users > Users > Select user > User Type
   → End Users CANNOT modify policies under any circumstances
   → Must be Admin or System Admin

2. Check Access Profile permissions:
   View user's Access Profile > CloudSOC Apps tab
   → Protect app: Must be "Modify" (not just "View")
   → If "View": Can see policies but cannot change them

3. Check Cloud Service scope:
   Access Profile > Cloud Services Permissions tab
   → Policy applies to "Box (API)"?
   → User must have "Modify" permission for Box specifically
   → If user has "View" only: Cannot modify Box policies

4. Check if policy is globally managed:
   Protect > Policies > Select policy
   → Look for "Managed by Enforce" indicator
   → Enforce-managed policies CANNOT be edited in CloudSOC
   → Must be modified in Symantec DLP Enforce console

5. Verify license/subscription:
   Settings > Subscriptions
   → DLP module must be active
   → If expired: Policy modification disabled

Fix Actions:
- Escalate to System Admin to adjust Access Profile
- If Enforce-managed: Direct user to Enforce console
- Renew subscription if expired
```

**Scenario 3: User Suddenly Loses Access**

```
Problem: User logged in fine yesterday, now gets "Access Denied" on login

Diagnostic Steps:

1. Check user account status:
   Users > Users > Search for user
   → Status: Should be "Active"
   → If "Disabled": Account manually disabled or AD sync changed status

2. Check license assignment:
   Users > Users > Select user > View Details
   → Verify CloudSOC license assigned
   → Enterprise license count may be exhausted

3. Verify SSO/IdP status:
   Settings > Authentication > Identity Provider
   → Check IdP connection status
   → Azure AD/Okta may have connectivity issues
   → Test: Can other users log in? (isolated vs. widespread)

4. Check Access Profile changes:
   Users > Users > Select user > Access Profile
   → Compare to yesterday's configuration (audit log)
   → Profile may have been modified or deleted

5. Review audit logs:
   Investigate > Filter:
   - Object: [username]
   - Activity Type: "Account Modified" or "Access Profile Changed"
   - Time: Last 24 hours
   → Look for administrative changes

6. Check password expiration (if local auth):
   Users > Users > Select user
   → Last Password Change date
   → Corporate policy may enforce 90-day rotation

Fix Actions:
- Re-enable account if disabled
- Reassign Access Profile
- Reset password (if local auth)
- Troubleshoot IdP connection (if SSO)
- Check with System Admin for recent changes
```

**Scenario 4: API Key Not Working**

```
Problem: Automated integration stopped working; API returns 403 Forbidden

Diagnostic Steps:

1. Verify API key validity:
   Settings > API Keys
   → Check key status: "Active" vs "Disabled"
   → Check expiration date
   → Disabled or expired = immediate failure

2. Check user who created API key:
   API Keys > Select key > View Details
   → "Created By" field shows originating user
   → If that user was deleted/disabled: API key inherits restriction
   → If user's Access Profile changed: API key scope changed

3. Verify API key inherited permissions:
   Critical concept: API key inherits creator's Access Profile
   
   Example:
   - Admin "John" has Access Profile limiting to "Box (API)" only
   - John creates API key
   - API key can ONLY access Box endpoints
   - Trying to call O365 endpoints = 403 Forbidden

4. Check rate limiting:
   Review API logs for rate limit errors
   Audit API limit: 30 calls/minute (as of CASB 3.158)
   
   Error message in API response:
   {"error": "Rate limit exceeded", "retry_after": 60}

5. Verify API endpoint permissions:
   Settings > API Keys > Select key > Permissions
   → Check which endpoints are allowed:
     ☑ Investigate API
     ☐ Protect API (might be disabled)
     ☑ Audit API

Fix Actions:
- Regenerate API key if expired
- Create new API key from user with correct Access Profile
- Implement rate limiting in integration code
- Enable required API endpoints in key permissions
- Document API key ownership and renewal schedule
```

---

<a name="section-7"></a>
## 7. Policy Enforcement and DLP Configuration

### 7.1 Understanding CloudSOC DLP Architecture

#### **The Complete DLP Flow:**

```
                  ┌──────────────────────────────────┐
                  │     CloudSOC Console             │
                  │  (Policy Configuration)          │
                  └──────────────┬───────────────────┘
                                 │
                                 │ Policy pushed to:
                ┌────────────────┼────────────────┐
                │                │                │
         [Securlets]      [Gatelets]      [Cloud SWG]
                │                │                │
                │                │                │
    Scan Data at Rest   Scan Data in Motion   Scan Web Traffic
                │                │                │
                └────────────────┼────────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────────┐
                  │  Cloud Detection Service (CDS)   │
                  │  (DLP Scanning Engine)            │
                  └──────────────┬───────────────────┘
                                 │
                                 │ Uses:
                  ┌──────────────┼───────────────┐
                  │              │               │
            [Detectors]    [Detection      [Managed
             (Policies)     Libraries)      Databases]
                  │              │               │
             Cloud DLP      Pattern          EDM/IDM
              or Enforce    Matching         Databases
```

### 7.2 Cloud Detection Service (CDS) Configuration

#### **Understanding Detector Types:**

**1. Cloud DLP Detector (SaaS-Managed)**
```
Management: Entirely within CloudSOC console
Policies: Created in CloudSOC Protect module
Detection Types:
- Pre-built detectors (Credit Cards, SSN, PII)
- Custom regular expressions
- Keywords and phrases
- File type blocking

Pros:
✅ Quick setup (no on-premises infrastructure)
✅ Managed by Symantec (updates automatic)
✅ Easy to configure (GUI-based)

Cons:
❌ Limited to pre-built detection patterns
❌ Cannot use existing Symantec DLP Enforce policies
❌ No advanced features (EDM, IDM, VML)

Best For: Small to medium deployments, new CASB implementations
```

**2. Enforce-Managed Detector (Hybrid)**
```
Management: Symantec DLP Enforce server (on-premises or cloud VM)
Policies: Created in DLP Enforce console, synced to CloudSOC
Detection Types:
- Everything from Cloud DLP, PLUS:
- Exact Data Matching (EDM) - scan for specific database records
- Indexed Document Matching (IDM) - scan for copyrighted documents
- Described Content Matching (DCM) - complex multi-condition rules
- Vector Machine Learning (VML) - AI-powered classification

Pros:
✅ Advanced detection capabilities
✅ Reuse existing DLP Enforce policies (unified policy management)
✅ Custom detection libraries
✅ Supports structured data (databases)

Cons:
❌ Requires DLP Enforce infrastructure
❌ More complex setup and maintenance
❌ Higher licensing cost

Best For: Enterprises with existing Symantec DLP, complex compliance needs
```

#### **Provisioning CDS Detector (Step-by-Step)**

**Phase 1: Enterprise Console Activation**

```
Step 1: Log into Enterprise Console
URL: enterprise.symantec.com (or regional equivalent)
Credentials: Broadcom account with subscription admin rights

Step 2: Navigate to Subscriptions
Menu: Products > Cloud Access Security > CloudSOC
View: Active Subscriptions

Step 3: Activate Cloud DLP Subscription
Click: "Activate Cloud DLP"
Select Region: EU / US / APAC (must match CloudSOC region)
Subscription Type:
○ Cloud DLP (SaaS-managed)
● Enforce-Managed (with existing DLP Enforce) [example selection]

Click: "Activate"
Processing: 2-5 minutes

Step 4: Generate Detector Token
After activation, screen displays:
- Detector Name: CloudSOC-EU-Detector-01
- Detector Token: eyJhbGciOiJIUzI1NiIs... (long string)
- Detector Region: EU
- Status: Active

CRITICAL: Copy the token immediately
Token is shown only once; cannot retrieve later
Store securely (password manager or secure doc)

Step 5: Verify Activation
Enterprise Console > CloudSOC > Detectors
Verify status shows: "Active"
Note the Detector ID (needed for troubleshooting)
```

**Phase 2: CloudSOC Console Configuration**

```
Step 1: Log into CloudSOC Console
URL: portal-eu.cloudsocsecurity.com
Credentials: System Administrator account

Step 2: Navigate to DLP Settings
Menu: Settings > Data Loss Prevention
Current view: "No Detection Services configured"

Step 3: Add Detection Service
Click: "Add Detection Service"

Configuration Form:
- Name: EU Production Detector
- Type: 
  ○ Cloud DLP
  ● Enforce-Managed [matches Enterprise Console selection]
- Detector Token: [Paste token from Enterprise Console]
- Description: Primary detector for EU region scanning
- Status: Active

Click: "Test Connection"
Expected: "Connection successful" message
If fails: Verify token, check network connectivity, confirm regions match

Click: "Save"

Step 4: Verify Detector Status
Settings > Data Loss Prevention > Detectors
Detector shows:
- Status: Active (green)
- Last Heartbeat: < 2 minutes ago
- Policies Synced: 0 (initial state)
- Files Scanned Today: 0 (initial state)

Step 5: Configure Scanning Preferences
Click detector name > Settings

Options:
File Size Limit: 50 MB (default, max supported)
Timeout per file: 30 seconds
Supported file types:
  ☑ Documents (.doc, .docx, .pdf, .txt, etc.)
  ☑ Spreadsheets (.xls, .xlsx, .csv)
  ☑ Archives (.zip, .rar, .7z) - scan contents
  ☑ Images (.jpg, .png) - OCR text extraction
  ☐ Videos (.mp4, .avi) - typically excluded (performance)
  ☐ Audio files (.mp3, .wav) - typically excluded

OCR Settings:
☑ Enable OCR for image files
Languages: English, German, French, Spanish

Save settings
```

### 7.3 Creating DLP Policies (Cloud DLP Mode)

#### **Policy Structure:**

```
CloudSOC DLP Policy Components:
1. Policy Name & Description
2. Scope (which services/users)
3. Trigger Conditions (what to scan)
4. Detection Rules (what to find)
5. Actions (what to do when found)
6. Notifications (who to alert)
7. Exceptions (when to ignore)
```

#### **Policy Creation Lab: Block Credit Card Uploads**

**Scenario:** Prevent users from uploading files containing credit card numbers to any cloud service.

**Step 1: Navigate to Policy Management**
```
CloudSOC Console > Protect > Policies
Click: "New Policy"
```

**Step 2: Basic Configuration**
```
Policy Name: Block Credit Card Numbers
Description: Prevent upload of files containing credit card data to cloud services
Priority: 10 (lower number = higher priority)
Status: 
○ Disabled (for testing)
● Active (enforce immediately)
```

**Step 3: Select Policy Type**
```
Policy Type:
○ Data Exposure via Securlet (Data at Rest)
● Data Transfer via Gatelet (Data in Motion) [real-time blocking]

Rationale: Gatelet blocks DURING upload; Securlet would find AFTER upload
```

**Step 4: Configure Scope**
```
Apply to Services:
☑ All Gatelets (comprehensive coverage)
OR
☑ Microsoft 365 (Gateway)
☑ Box (Gateway)
☑ Slack (Gateway)
☐ Google Workspace (Gateway)

Apply to Users:
● All Users
○ Specific Users (select individual users)
○ User Groups (select from AD-synced groups)
○ Exclude Users (all except specified)

Apply to Locations:
○ All Locations
● Specific Locations:
  ☐ Corporate Office (IP range: 203.0.113.0/24)
  ☑ Remote/External (any IP outside corporate)

Rationale: Block credit cards from remote workers (higher risk)
```

**Step 5: Configure Detection Rules**
```
Content Matching:
● Use DLP Detector

Detector Selection:
Select: EU Production Detector (configured earlier)

Detection Conditions:
☑ Credit Card Numbers
  Sub-types:
  ☑ Visa
  ☑ MasterCard
  ☑ American Express
  ☑ Discover
  
  Confidence Level:
  ● High (95%+ confidence - strict)
  ○ Medium (80%+ confidence)
  ○ Low (60%+ confidence)
  
  Minimum Occurrences: 1 (block even single credit card)

Additional Conditions (AND logic):
☐ File Size > 1 MB
☐ File Name contains specific keywords
☐ User ThreatScore > 50
```

**Step 6: Configure Actions**
```
Primary Action:
● Block Activity
○ Adaptive Authentication (require MFA)
○ Log Only (no enforcement)

Secondary Actions:
☑ Create Incident (generate DLP incident record)
☑ Notify User (display message)
  Message: "This file contains credit card numbers and cannot be uploaded. Contact IT Security if you believe this is an error."

☑ Notify Administrator
  Recipients: security-team@company.com
  Include: File name, user, timestamp, service

☐ Quarantine (not applicable for blocked uploads)
☐ Encrypt File (alternative to blocking)
```

**Step 7: Configure Exceptions**
```
Exceptions allow policy bypass for specific scenarios:

Exception 1: Finance Department Authorized Users
Condition:
- User Group = "Finance-Approved"
- Service = "Corporate SharePoint Only"
- Time = Business Hours (9 AM - 5 PM)
Action: Allow (but still log)
Justification: Finance team processes credit card refunds

Exception 2: Encrypted Files
Condition:
- File has password protection
- File extension = .zip with encryption
Action: Allow (cannot scan encrypted content)
Justification: User responsible for encryption security

Exception 3: Test Data
Condition:
- File name contains "[TEST]" prefix
- User = QA Team
Action: Allow
Justification: Test credit card numbers (e.g., 4111111111111111)
```

**Step 8: Schedule and Priority**
```
Active Schedule:
● Always Active (24/7)
○ Business Hours Only
○ Custom Schedule:
  Days: Monday-Friday
  Hours: 8 AM - 6 PM ET

Policy Priority: 10
Note: Lower priority policies checked if higher priority doesn't match
Example:
- Priority 5: Allow Finance team
- Priority 10: Block credit cards (this policy)
If user is Finance team member: Priority 5 allows, Priority 10 never evaluated
```

**Step 9: Save and Test**
```
Click: "Save Policy"
Confirmation: "Policy created successfully"
Propagation time: 2-5 minutes to all Gatelets

Testing:
1. Create test file containing credit card number:
   Filename: test-creditcard.txt
   Content: "Customer Visa: 4532-1488-0343-6467"

2. From test user account (non-Finance), attempt upload to Teams

3. Expected result:
   - Upload blocked immediately
   - User sees message: "This file contains credit card numbers..."
   - Incident created in CloudSOC

4. Verify in Investigate:
   Filter: Policy = "Block Credit Card Numbers"
   Should show:
   - Blocked activity
   - User, file name, service
   - Detection details (Visa card detected)
```

### 7.4 Advanced Detection Techniques

#### **Exact Data Matching (EDM) - Enforce-Managed Only**

**Use Case:** Prevent upload of files containing specific employee records from HR database.

**EDM Concept:**
Instead of pattern matching (like "SSN format"), EDM matches against actual database records.

**Example:**
```
HR Database contains:
- Employee ID: 12345
- Name: John Doe
- SSN: 123-45-6789
- DOB: 1980-01-15

EDM indexes this data:
- Creates cryptographic hash of each record
- Scans files for ANY combination of these fields
- Match triggers if 2+ fields appear together

File content: "John Doe, hired 1980-01-15, contact HR"
EDM detects: Name + DOB from same employee record = MATCH
```

**Configuration (High-Level):**
```
In Symantec DLP Enforce Console:
1. Create EDM Data Profile:
   - Connect to database (JDBC/ODBC)
   - Select table (Employees)
   - Select indexed columns (ID, Name, SSN, DOB)
   - Generate index (hashed representation)

2. Create EDM Detection Rule:
   - Use EDM Profile: HR_Employees
   - Match Threshold: 2 of 4 fields
   - Confidence: High

3. Sync to CloudSOC:
   - Enforce syncs policy to CDS
   - CloudSOC policies can reference EDM rules
   - Files scanned against EDM index
```

**Performance Note:**
EDM scanning is slower than pattern matching (5-10x overhead).
Reserve for high-value data (HR records, customer databases, IP).

#### **Indexed Document Matching (IDM) - Enforce-Managed Only**

**Use Case:** Prevent upload of copyrighted internal documents, source code, or confidential reports.

**IDM Concept:**
Index a collection of protected documents (fingerprinting). Scans detect partial or full matches.

**Example:**
```
Index these protected documents:
- Product roadmap 2025
- M&A confidential proposal
- Source code repository

User uploads file: "Q1 Strategy.pptx"
Contains slides 3-7 copied from "Product roadmap 2025"
IDM detects: 45% match with indexed document = VIOLATION
```

**Configuration (High-Level):**
```
In Symantec DLP Enforce Console:
1. Create IDM Repository:
   - Add documents to index:
     - File path: \\fileserver\confidential\
     - OR upload individual files
   - Set match threshold: 30% (how much similarity triggers match)

2. Generate Index:
   - Enforce creates fingerprint of each document
   - Breaks document into chunks (paragraphs, code blocks)
   - Creates hash signatures

3. Create IDM Detection Rule:
   - Use IDM Repository: Confidential_Docs
   - Match Threshold: 30%
   - Allow partial matches: Yes

4. Sync to CloudSOC via Enforce
```

**Advanced Scenario:**
```
Use Case: Prevent source code leaks

IDM Configuration:
- Index entire Git repository
- Match threshold: 20% (even small code snippets)
- File types: .java, .py, .js, .cpp

Policy Action:
- Block upload to ANY external service
- Exception: GitHub.com/company-official (corporate repo)
- Immediate alert to CISO on violation
```

### 7.5 Policy Testing and Validation

#### **Testing Methodology:**

**Phase 1: Lab Testing (Disabled Policy)**
```
Step 1: Create policy in "Disabled" status
Step 2: Configure all rules and actions
Step 3: Enable "Log Only" mode (if available)
Step 4: Test with known violation samples
Step 5: Review logs in Investigate
Step 6: Verify detection accuracy (no false positives)
```

**Phase 2: Pilot Deployment**
```
Step 1: Enable policy with limited scope
Scope examples:
- Single user group (IT Security team)
- Single service (Box only, not all services)
- Single location (HQ office, not remote)

Step 2: Monitor for 1-2 weeks
Metrics to track:
- Total policy triggers
- False positive rate
- User complaints
- Performance impact

Step 3: Adjust policy based on feedback
Common adjustments:
- Add exceptions for legitimate use cases
- Tune detection threshold (reduce false positives)
- Modify notifications (reduce alert fatigue)
```

**Phase 3: Production Rollout**
```
Step 1: Expand scope incrementally
Week 1: IT department
Week 2: Finance department
Week 3: Engineering
Week 4: All users

Step 2: Communication plan
- Email announcement before policy goes live
- User training on acceptable file handling
- Help desk preparation for support questions

Step 3: Monitor post-deployment
- Daily review of policy triggers (first week)
- Weekly review (first month)
- Monthly review (ongoing)
```

#### **Common False Positives and How to Fix:**

**False Positive 1: Test Credit Card Numbers**
```
Problem: Policy blocks files with test/sample credit card numbers

Root Cause: DLP detector cannot distinguish real vs. test numbers

Solutions:
Solution A: File naming convention exception
- Exception: File name contains "[TEST]" or "SAMPLE"
- Action: Allow but log

Solution B: Designated testing area
- Exception: Files in "Testing" folder/channel only
- Exception: User group = QA Team

Solution C: Use invalid Luhn checksums
- Educate users: Use 4111111111111111 (invalid test number)
- DLP detectors validate Luhn algorithm
```

**False Positive 2: News Articles Containing SSNs**
```
Problem: Marketing team shares news article about data breach; article quotes exposed SSNs as examples

Root Cause: Policy detects SSN pattern without context

Solutions:
Solution A: Source-based exception
- Exception: File downloaded from trusted news sites
- Requires integration with web categorization

Solution B: Count threshold
- Adjust policy: Trigger only if 5+ SSNs detected
- Rationale: News article has 1-2 examples; real violation has many

Solution C: User education
- Train users: Redact SSNs before sharing articles
- Use format like "XXX-XX-1234"
```

**False Positive 3: Product Codes Matching SSN Pattern**
```
Problem: Company product SKUs formatted like SSNs (123-45-6789)

Root Cause: Regex pattern matches any ###-##-#### format

Solutions:
Solution A: Context-based detection
- Use Enforce DCM (Described Content Matching)
- Require SSN + context keywords ("Social Security", "DOB", "SSN:")
- Product code alone without context = no match

Solution B: Whitelist known SKUs
- Maintain list of valid product codes
- Exception: If number matches SKU list, allow

Solution C: Change product code format
- Long-term solution: Use different format (ABC-123-45-6789)
```

### 7.6 Policy Compliance Reporting

#### **Generating Compliance Reports:**

```
Navigation: CloudSOC Console > Protect > Reports

Report Types:
1. Policy Violation Summary
2. User Risk Summary
3. Data Exposure by Service
4. Regulatory Compliance Status (GDPR, HIPAA, PCI)
5. Incident Response Metrics
```

**Example Report Configuration: GDPR Compliance**

```
Report Name: EU GDPR Compliance - Q4 2025

Scope:
- Domain: company.eu
- Services: All with EU data
- Time Range: Oct 1 - Dec 31, 2025

Metrics Included:
☑ Total policy violations detected
☑ Files containing PII (by type)
☑ External data sharing incidents
☑ Data subject access requests processed
☑ Right to erasure requests fulfilled
☑ Data breach incidents (severity High+)
☑ Mean time to remediation (MTTR)
☑ Geographic data distribution

Grouping:
- By Department
- By User Risk Level
- By Service (O365, Box, etc.)

Format: PDF with executive summary
Recipients:
- DPO (dpo@company.eu)
- Legal (legal@company.eu)
- CISO (ciso@company.com)

Schedule: Quarterly (auto-generated)
```

**Report Output Example:**
```
═══════════════════════════════════════════════════
GDPR Compliance Report - Q4 2025
Company EU Operations
Generated: 2025-12-31
═══════════════════════════════════════════════════

EXECUTIVE SUMMARY:
- Total Policy Violations: 234 (-12% vs Q3)
- High Severity Incidents: 18
- Data Breach Notifications: 0
- MTTR (Mean Time to Remediate): 4.2 hours

PII DETECTION BY TYPE:
- Email Addresses: 145 files
- Phone Numbers: 89 files
- EU National IDs: 34 files
- IBAN Bank Accounts: 12 files

EXTERNAL SHARING INCIDENTS:
- Files Shared Outside EU: 45
  → Remediated: 43 (95.6%)
  → Under Review: 2 (legal hold)

DATA SUBJECT REQUESTS:
- Access Requests: 23 (avg response: 18 days)
- Erasure Requests: 7 (avg fulfillment: 12 days)
- Rectification Requests: 4

COMPLIANCE STATUS: ✅ COMPLIANT
- All requests processed within GDPR timelines
- No unresolved data breaches
- All high-severity incidents remediated

TOP RISK USERS (by violation count):
1. john.doe@company.eu - 12 violations
2. jane.smith@company.eu - 9 violations
3. mike.jones@company.eu - 7 violations

RECOMMENDATIONS:
1. Additional training for top 3 risk users
2. Review PII handling procedures in Marketing dept
3. Implement EDM for customer database protection
═══════════════════════════════════════════════════
```

---

<a name="section-8"></a>
## 8. Monitoring, Investigation, and Analytics

### 8.1 CloudSOC Investigate - Log Analysis and Forensics

**Investigate** is your primary tool for post-incident analysis and historical activity review.

#### **Understanding Investigate Data Model:**

```
Log Entry Structure:
{
  "id": "evt_8273645",
  "timestamp": "2025-11-17T14:23:45.123Z",
  "user": "john.doe@company.com",
  "source_ip": "203.0.113.42",
  "geolocation": "New York, USA",
  "device_type": "Windows 10 Desktop",
  "device_name": "LAPTOP-JD-01",
  "application": "Box (API)",
  "activity_type": "File Share Modified",
  "object": "/Projects/Q4-Financial-Report.xlsx",
  "destination": "external-partner@clientcorp.com",
  "severity": "High",
  "policy_matched": "Block External Sharing of Financial Data",
  "action_taken": "Allowed (Exception: Finance Group)",
  "violation": false,
  "threatScore": 35,
  "details": {
    "share_type": "Direct Share",
    "permissions": "View Only",
    "expiration": "2025-12-31",
    "previous_state": "Internal Only"
  }
}
```

#### **Investigate Interface Components:**

**1. Search Bar (Boolean Query Support)**
```
Basic Search:
user:john.doe

AND Operator:
user:john.doe AND application:"Box (API)"

OR Operator:
severity:High OR severity:Critical

NOT Operator:
application:"Microsoft 365" NOT activity:"Login"

Wildcard:
file:*.xlsx

Grouping:
(user:john.doe OR user:jane.smith) AND severity:High

Field-Specific Search:
ip:203.0.113.* (IP range)
time:[2025-11-01 TO 2025-11-30] (date range)
file:"financial" (partial match)
```

**2. Filter Panel (Visual Filters)**
```
Available Filters:
┌─────────────────────────────────┐
│ Time Range                       │
│  ● Last 24 hours                │
│  ○ Last 7 days                  │
│  ○ Last 30 days                 │
│  ○ Custom range                 │
├─────────────────────────────────┤
│ Severity                         │
│  ☑ Critical (3)                 │
│  ☑ High (45)                    │
│  ☐ Medium (234)                 │
│  ☐ Low (1,234)                  │
├─────────────────────────────────┤
│ Application/Source               │
│  ☑ Box (API) - 456 events       │
│  ☑ Microsoft 365 (Gateway)      │
│  ☐ Google Workspace (API)       │
├─────────────────────────────────┤
│ Activity Type                    │
│  ☑ File Upload (123)            │
│  ☑ File Share (89)              │
│  ☐ File Download (567)          │
│  ☐ Login (2,345)                │
├─────────────────────────────────┤
│ User                            │
│  Search: [john.doe]             │
│  ☑ john.doe@company.com (234)   │
│  ☐ jane.smith@company.com (189) │
├─────────────────────────────────┤
│ Policy                           │
│  ☑ Block Credit Cards           │
│  ☑ Block External Sharing       │
│  ☐ Require MFA for Downloads    │
├─────────────────────────────────┤
│ Location/IP                      │
│  ☑ External IPs                 │
│  ☐ Corporate Network            │
│  ☐ Specific Country: [Select]   │
└─────────────────────────────────┘
```

**3. Results Table (Customizable Columns)**
```
Default Columns:
| Time | User | App | Activity | Object | Severity | Action |

Customizable - Add/Remove:
- Source IP
- Geolocation
- Device Type
- ThreatScore
- Policy Matched
- Destination
- File Size
- Share Permissions

Sort Options:
- By Time (newest first)
- By Severity (critical first)
- By ThreatScore (highest first)
- By User (alphabetical)

Export Options:
- CSV (for Excel analysis)
- JSON (for SIEM integration)
- PDF (for reports)
```

**4. Details Pane (Expanded View)**
```
Click any log entry → Right panel expands

Tabs:
1. Overview
   - Full activity description
   - User information
   - Device details
   - Geographic location map

2. Policy Details
   - Which policy was evaluated
   - Match conditions
   - Action taken and why
   - Exceptions applied (if any)

3. Object Details
   - File/object name and path
   - File size and type
   - Owner information
   - Current sharing status
   - Download link (if admin has access)

4. Timeline
   - Related activities by same user
   - Before: Previous actions (2 hours before)
   - After: Subsequent actions (2 hours after)
   - Pattern detection

5. Remediation Actions (if applicable)
   - Actions taken automatically
   - Manual remediation options:
     ☐ Quarantine file
     ☐ Remove sharing permissions
     ☐ Delete file
     ☐ Notify user
     ☐ Reset user password
     ☐ Disable account
```

### 8.2 Real-World Investigation Scenarios

#### **Scenario 1: Suspected Data Exfiltration**

**Alert Received:**
```
Detect module flags user: sarah.jones@company.com
ThreatScore increased from 25 → 85 (critical threshold)
Reason: Mass file download activity
```

**Investigation Steps:**

**Step 1: Initial Scope Assessment**
```
Navigate to: Investigate

Query:
user:sarah.jones@company.com AND time:[last 24 hours]

Sort by: Time (chronological view)

Initial findings:
- Total activities: 234 (unusually high for this user)
- File downloads: 187 (normal average: 5-10/day)
- Time pattern: All downloads between 2:00 AM - 4:30 AM
- Location: IP 198.51.100.45 (geolocation: Unknown/VPN)
```

**Step 2: Activity Pattern Analysis**
```
Filter refinement:
activity_type:"File Download" AND user:sarah.jones

Results show:
┌──────────┬─────────────────┬─────────────────────┬──────────┐
│ Time     │ Service         │ File                │ Size     │
├──────────┼─────────────────┼─────────────────────┼──────────┤
│ 02:03 AM │ Box (API)       │ Customer_List.xlsx  │ 15 MB    │
│ 02:05 AM │ Box (API)       │ Q4_Financial.pdf    │ 8 MB     │
│ 02:07 AM │ SharePoint      │ Product_Roadmap.ppt │ 12 MB    │
│ 02:09 AM │ Box (API)       │ Employee_Data.csv   │ 22 MB    │
│ 02:11 AM │ SharePoint      │ Source_Code.zip     │ 145 MB   │
│ ... (182 more files)                                        │
└──────────┴─────────────────┴─────────────────────┴──────────┘

Pattern identified:
- Systematic download (alphabetical order)
- Multiple sensitive data types
- Total data volume: ~1.2 GB
- No corresponding uploads (not legitimate sync)
```

**Step 3: Baseline Comparison**
```
Query historical behavior:
user:sarah.jones AND time:[last 30 days] NOT time:[last 24 hours]

Average daily activity:
- Logins: 2-3 per day
- File downloads: 5-10 per day
- File uploads: 3-5 per day
- Time: 9 AM - 6 PM (business hours)
- Location: Corporate office IP range

Deviation analysis:
Current activity is 30x normal download rate
Outside normal working hours
Unknown/suspicious IP location
```

**Step 4: Device and Authentication Check**
```
Expand log details → Device tab

Current suspicious session:
- Device Type: Linux (curl/7.68.0) - NOT user's typical device
- Device Name: Unknown
- Authentication: API token (not interactive login)
- 2FA: Not required for API access (security gap identified)

User's normal devices:
- Windows 10 Laptop (LAPTOP-SJ-01)
- iPhone (Sarah's iPhone)
- Both authenticated with MFA

Conclusion: API token compromise, not user's legitimate device
```

**Step 5: Immediate Response Actions**
```
Actions taken (within Investigate):

1. Disable User Account:
   Investigate → Select user → Actions → "Disable Account"
   Effect: Immediately terminates all active sessions

2. Revoke API Tokens:
   Settings → API Keys → Search for sarah.jones
   Action: Revoke all tokens created by this user

3. Force Password Reset:
   Users → sarah.jones → "Force Password Reset"
   User must reset password at next login

4. Session Termination:
   Active Sessions → sarah.jones → "Terminate All Sessions"
   Logs out all devices immediately

5. Quarantine Downloaded Files:
   Investigate → Select all downloaded files
   Bulk Action → "Quarantine" (if still in cloud storage)
```

**Step 6: Collect Evidence**
```
Export investigation logs:
Investigate → Current query results
Export Format: JSON (preserves all metadata)
Include:
☑ Full activity details
☑ IP addresses and geolocation
☑ Device fingerprints
☑ File hashes (for forensics)

Store evidence:
- Export to secure incident response folder
- Generate incident report (for legal/HR)
- Document timeline of events
```

**Step 7: Root Cause Analysis**
```
Additional investigation:

Timeline reconstruction:
Nov 15, 3:00 PM - sarah.jones creates API key
                   (legitimate: for automation script)
Nov 15, 3:15 PM - API key used from corporate IP (normal)
Nov 17, 2:00 AM - Same API key used from 198.51.100.45 (suspicious)

Root cause hypotheses:
A) Sarah's laptop compromised (malware stole API key)
B) Sarah shared API key inappropriately (ex-employee?)
C) Sarah's GitHub repository exposed (API key in code)

Further investigation:
- Check GitHub: Search for sarah.jones repositories
- Found: API key hardcoded in public repository!
- Repository: "automation-scripts" (set to public accidentally)
- Committed: Nov 15, 3:20 PM (5 minutes after key creation)
- First suspicious use: Nov 17, 2:00 AM (48 hours later - discovered by attacker)

Root cause confirmed: API key exposure via public GitHub repository
```

**Step 8: Remediation and Prevention**
```
Immediate remediation:
1. Delete public GitHub repository (remove exposed key)
2. Scan for other exposed credentials in all repos
3. Notify affected users (if customer data downloaded)
4. File data breach notification (if required by regulation)

Long-term prevention:
1. Implement API key rotation policy (30-day expiration)
2. Add API key usage monitoring (alert on unusual patterns)
3. Require MFA for API key creation
4. Deploy secret scanning tools (GitHub Advanced Security)
5. User training: Never commit API keys to version control
6. Update policy: API keys must use environment variables
```

#### **Scenario 2: Insider Threat - Gradual Data Collection**

**Alert Received:**
```
Detect module: User michael.brown shows gradually increasing ThreatScore
Current: 68 (was 25 two weeks ago)
Behavior: Increased file access to departments outside his role
```

**Investigation Approach:**

**Step 1: Trend Analysis**
```
Navigate to: Detect → Users → michael.brown

ThreatScore trend (last 30 days):
Week 1: 25 (baseline)
Week 2: 32 (slight increase)
Week 3: 48 (moderate increase)
Week 4: 68 (significant increase)

Contributing factors:
- Access to HR files (not in his department)
- Access to Financial reports (not in his role)
- Increased after-hours activity
- Multiple department folders accessed
```

**Step 2: Access Pattern Investigation**
```
Investigate query:
user:michael.brown AND time:[last 30 days]
Group by: Department/Folder

Access pattern:
┌─────────────────────┬────────────┬─────────────────┐
│ Department          │ Week 1-2   │ Week 3-4        │
├─────────────────────┼────────────┼─────────────────┤
│ Engineering (his)   │ 150 files  │ 160 files (↑7%) │
│ HR (not his)        │ 0 files    │ 45 files (NEW)  │
│ Finance (not his)   │ 0 files    │ 38 files (NEW)  │
│ Legal (not his)     │ 0 files    │ 23 files (NEW)  │
│ Sales (not his)     │ 5 files    │ 67 files (↑1240%)│
└─────────────────────┴────────────┴─────────────────┘

Red flags:
- Accessing multiple departments outside role
- No legitimate business reason (confirmed with manager)
- Pattern suggests preparation for departure (collecting competitive intelligence)
```

**Step 3: Search for Exfiltration Methods**
```
Check for file transfers to personal accounts:

Query 1: Personal cloud storage
user:michael.brown AND (destination:*@gmail.com OR destination:*@yahoo.com)

Results:
- 12 files emailed to michael.personal@gmail.com
- Files include: "Client_List.xlsx", "Product_Specs.pdf"

Query 2: USB device usage (if logged)
user:michael.brown AND activity:"Local File Copy"

Results:
- 8 instances of file copy to removable media
- Dates align with increased ThreatScore period

Query 3: External sharing
user:michael.brown AND activity:"Share" AND destination:external

Results:
- 5 files shared with external email: recruiter@competitorco.com
- Smoking gun: Competitor company email
```

**Step 4: Timeline Correlation with HR Events**
```
Correlate with HR data (if available):

Check Investigate logs for:
- Access to job posting sites
- Calendar events (interviews scheduled?)
- Email keywords (resignation, offer letter, etc.)

Findings:
- Week 2: Accessed competitors' job postings (via web proxy logs)
- Week 3: Calendar shows "confidential meeting" (off-site)
- Week 4: Email to manager about "discussing future" (resignation hint)

Pattern confirms: Employee planning departure, collecting sensitive data
```

**Step 5: Legal and HR Coordination**
```
Investigation now escalates beyond IT:

Actions required:
1. Contact HR immediately (do not confront employee yet)
2. Contact Legal department (potential breach of employment agreement)
3. Preserve all evidence (legal hold on user's cloud data)
4. Do NOT disable account yet (tip off employee, destroy evidence)

Surveillance mode:
- Enable detailed logging (capture all activities)
- Monitor for additional exfiltration attempts
- Track contacts with external parties
- Prepare for account freeze on legal approval
```

**Step 6: Evidence Collection for Legal Action**
```
Comprehensive evidence package:

1. Activity logs (CSV export):
   - All file access (last 30 days)
   - All external shares
   - All downloads to personal accounts

2. Policy violations:
   - List of policies violated
   - Each violation with timestamp and evidence

3. Comparative analysis:
   - Michael's access vs. typical Engineer access
   - Statistical deviation report

4. Data classification:
   - Which files were sensitive/confidential
   - Business impact assessment (if data used by competitor)

5. Communication records (if Email Securlet enabled):
   - Emails with competitor
   - Emails to personal account

Package delivered to: Legal, HR, Manager (secure distribution)
```

### 8.3 CloudSOC Detect - User Behavior Analytics (UBA)

**Detect** uses machine learning to identify anomalous user behavior and calculate individualized ThreatScores.

#### **Understanding ThreatScore™:**

```
ThreatScore Range: 0-100
- 0-30: Normal behavior (green)
- 31-60: Slightly elevated (yellow)
- 61-80: Concerning behavior (orange)
- 81-100: High risk / likely compromise (red)

ThreatScore Calculation Factors:
┌────────────────────────────────────────────────────────┐
│ Factor                         │ Weight │ Example      │
├────────────────────────────────┼────────┼──────────────┤
│ Activity Volume                │ 20%    │ 10x normal   │
│ Off-Hours Activity             │ 15%    │ 3 AM access  │
│ Unusual Locations              │ 15%    │ New country  │
│ Access Pattern Changes         │ 10%    │ New apps     │
│ Privilege Escalation Attempts  │ 15%    │ Admin access │
│ Data Exfiltration Indicators   │ 20%    │ Mass downloads│
│ Failed Authentication Attempts │ 5%     │ Wrong password│
└────────────────────────────────┴────────┴──────────────┘

Machine Learning Model:
- Baseline: 30 days of historical behavior per user
- Daily updates: Model retrains nightly with new data
- Peer comparison: User behavior compared to similar roles
- Anomaly detection: Statistical deviation from baseline
```

#### **Using Detect Dashboard:**

**Navigation:** CloudSOC Console > Detect

**Main Interface:**
```
┌─────────────────────────────────────────────────────────┐
│ Threat Overview - Last 24 Hours                         │
├─────────────────────────────────────────────────────────┤
│ Critical Users (ThreatScore > 80): 3                    │
│ High Risk Users (ThreatScore 61-80): 12                 │
│ Total Anomalies Detected: 234                           │
│ Active Investigations: 5                                │
│                                                         │
│ Top Risk Users:                                         │
│ 1. sarah.jones@company.com - Score: 85 (↑45 today)    │
│    Risk: Mass file download from unusual location      │
│                                                         │
│ 2. michael.brown@company.com - Score: 68 (↑23 today)  │
│    Risk: Access to sensitive folders outside role      │
│                                                         │
│ 3. compromised-bot@company.com - Score: 92 (↑92 today)│
│    Risk: API abuse, credential sharing detected        │
└─────────────────────────────────────────────────────────┘
```

**User Threat Tree View:**
```
Click user → Opens interactive threat tree visualization

Visual Representation:
          [User: sarah.jones]
                   │
        ┌──────────┼──────────┐
        │          │          │
   [Location]  [Activity] [Volume]
        │          │          │
   Unknown IP  Downloads   187 files
   Score: +25  Score: +30  Score: +30
        │          │          │
        └──────────┴──────────┘
               │
          ThreatScore: 85

Interactive Features:
- Click each node to see detailed logs
- Drill down into specific anomalies
- View baseline vs. current behavior
- Export threat tree as evidence
```

**Risk Vectors:**
```
Detect identifies specific risk patterns:

1. Impossible Travel:
   - User logs in from New York at 9:00 AM
   - Same user logs in from London at 9:30 AM
   - Physical travel impossible in 30 minutes
   - Conclusion: Credential sharing or compromise

2. After-Hours Anomaly:
   - User typically works 9 AM - 5 PM EST
   - Activity detected at 3:00 AM EST
   - No legitimate business reason (checked calendar)
   - Risk: Automated script or compromised account

3. Geographic Anomaly:
   - User always accesses from United States
   - Suddenly accessing from Russia
   - No travel records (checked HR)
   - Risk: Credential compromise

4. Volume Anomaly:
   - User averages 10 file downloads per day
   - Today: 200 file downloads
   - Statistical significance: 20 standard deviations
   - Risk: Data exfiltration

5. Access Creep:
   - User role: Marketing Analyst
   - Accessing: Financial database, HR records, source code
   - Role comparison: Other Marketing Analysts don't access these
   - Risk: Insider threat or social engineering victim
```

### 8.4 CloudSOC Audit - Shadow IT Discovery

**Audit** discovers and monitors all cloud applications accessed by users (sanctioned and unsanctioned).

#### **How Audit Works:**

```
Data Sources:
1. Firewall Logs (via SpanVA)
   - Captures all outbound traffic
   - Identifies cloud application destinations

2. Proxy Logs (via SpanVA or direct integration)
   - Web proxy logs analyzed for SaaS app access
   - URL patterns matched to known cloud services

3. Cloud SWG Logs (if using Symantec WSS)
   - All web traffic already flowing through SWG
   - Real-time cloud app identification

4. Endpoint Agents (if deployed)
   - Installed on user devices
   - Reports application usage directly to CloudSOC
   - Works for remote/BYOD scenarios

Analysis Process:
Raw logs → Pattern matching → Cloud app identification → 
Risk scoring → Dashboard display
```

#### **Audit Dashboard:**

```
┌─────────────────────────────────────────────────────────┐
│ Cloud Application Discovery - Last 30 Days             │
├─────────────────────────────────────────────────────────┤
│ Total Applications Discovered: 487                      │
│ Sanctioned (Approved): 23                              │
│ Unsanctioned (Shadow IT): 464                          │
│                                                         │
│ Risk Distribution:                                      │
│ ████████░░ High Risk: 89 apps                          │
│ ████████████░░ Medium Risk: 178 apps                   │
│ ██████░░ Low Risk: 197 apps                            │
│                                                         │
│ Top Unsanctioned Applications:                          │
│ 1. Dropbox (Personal) - 234 users - Risk: High        │
│ 2. WeTransfer - 189 users - Risk: High                │
│ 3. Personal Gmail - 156 users - Risk: Medium          │
│ 4. WhatsApp Web - 134 users - Risk: Medium            │
│ 5. ProtonMail - 23 users - Risk: High                 │
│                                                         │
│ Data Transfer Volume (Unsanctioned Apps):              │
│ Upload: 2.3 TB                                         │
│ Download: 1.8 TB                                       │
└─────────────────────────────────────────────────────────┘
```

#### **Business Readiness Rating (BRR):**

**Definition:** CloudSOC's proprietary risk score for cloud applications (0-100).

**Rating Categories:**
```
90-100: Excellent (Enterprise-ready)
- Example: Microsoft 365, Salesforce, Box
- Strong security controls
- Compliance certifications (SOC 2, ISO 27001)
- Data encryption, audit logs, DLP support

70-89: Good (Suitable with caution)
- Example: Zoom, Slack, Atlassian
- Good security but some limitations
- May lack advanced DLP
- Acceptable for non-sensitive data

50-69: Fair (Requires oversight)
- Example: Trello, Asana, Evernote
- Basic security features
- Limited compliance documentation
- Not suitable for sensitive data

Below 50: Poor (High risk)
- Example: Unknown file-sharing sites, personal cloud storage
- Minimal security controls
- No compliance certifications
- High data loss risk
- Should be blocked or monitored closely
```

**BRR Calculation Factors:**
```
Security Features (40%):
- Encryption (at rest and in transit)
- Access controls (MFA, SSO support)
- Audit logging
- DLP capabilities

Compliance (25%):
- SOC 2 Type II certification
- ISO 27001
- GDPR compliance
- HIPAA compliance (if applicable)
- Industry-specific standards

Data Management (20%):
- Data retention policies
- Data deletion capabilities
- Geographic data controls
- Data backup and recovery

Vendor Reputation (15%):
- Company history and stability
- Past security incidents
- Transparency in security practices
- Incident response procedures
```

#### **Audit-Driven Policy Creation:**

**Scenario:** Audit discovers widespread use of WeTransfer (unsanctioned file transfer service).

**Step 1: Assess Risk**
```
Audit Dashboard → Click "WeTransfer"

Details:
- Users: 189 (18% of organization)
- Data Uploaded: 450 GB (last 30 days)
- BRR Score: 45 (Poor - High Risk)
- Risk Factors:
  - No encryption at rest
  - Limited access controls
  - No audit trail
  - Files deleted after 7 days (data loss risk)
  - No DLP capabilities
```

**Step 2: Understand Usage**
```
Who is using it?
- Top departments: Sales (45%), Marketing (32%), Support (23%)

Why are they using it?
- Survey reveals: "Need to send large files to clients"
- Corporate email: 25 MB attachment limit
- Corporate file sharing (SharePoint): "Too complicated for clients"

Legitimate business need identified: Large file transfer to external parties
```

**Step 3: Provide Sanctioned Alternative**
```
Solution: Deploy approved large file transfer solution

Options evaluated:
A) Increase SharePoint external sharing capabilities
B) Deploy Box for external collaboration
C) Enable Microsoft OneDrive external sharing with controls

Selected: OneDrive with CloudSOC Gatelet protection

Configuration:
- Enable OneDrive Gatelet
- Allow external sharing (controlled)
- Apply DLP policies (block sensitive data)
- Require MFA for external recipients
- Auto-expire links after 30 days
- Detailed audit logging
```

**Step 4: Block Unsanctioned Alternative**
```
Create Gatelet policy:

Policy: Block WeTransfer
- Scope: All users
- Application: Custom Gatelet for wetransfer.com
- Action: Block with user notification
- Message: "WeTransfer is not approved. Use OneDrive for large file transfers. Visit: https://intranet/filesharing-guide"
- Exception: None (hard block)

Implement policy:
- Deploy Custom Gatelet for wetransfer.com
- Activate block policy
- Monitor for user complaints
```

**Step 5: User Communication and Training**
```
Rollout plan:

Week 1: Announcement
- Email to all users: "New approved method for large file sharing"
- Include: OneDrive quick start guide
- Explain: Why WeTransfer is blocked (security risks)

Week 2: Training
- Webinar: "How to share large files securely"
- Demonstrate: OneDrive external sharing
- Q&A session

Week 3: Policy Enforcement
- Activate WeTransfer block
- Monitor help desk tickets
- Provide additional support as needed

Week 4: Review
- Audit dashboard: Verify WeTransfer usage dropped to 0
- User satisfaction survey
- Adjust sanctioned solution if needed
```

### 8.5 Risk Analytics - Forensic Analysis

**Risk Analytics** provides on-demand, ad-hoc exploration of risk patterns.

#### **Use Cases:**

**1. Policy Effectiveness Analysis**
```
Question: Is our "Block Credit Card" policy actually preventing violations?

Risk Analytics Query:
Time Range: Last 90 days
Metric: Policy violations over time
Policy: Block Credit Card Numbers
Group By: Week

Results Visualization:
Week 1: 45 violations
Week 2: 38 violations
Week 3: 52 violations (spike - investigate)
Week 4: 31 violations
...
Week 12: 12 violations (trend: decreasing)

Interpretation:
- Policy is working (violations decreasing)
- Week 3 spike: Traced to new employee training gap
- Recommendation: Add credit card handling to onboarding training
```

**2. Department Risk Comparison**
```
Question: Which department has the highest cloud security risk?

Risk Analytics Query:
Metric: Average user ThreatScore by department
Time Range: Last 30 days

Results:
┌──────────────────┬─────────────────┬──────────────┐
│ Department       │ Avg ThreatScore │ Risk Level   │
├──────────────────┼─────────────────┼──────────────┤
│ Sales            │ 58              │ Medium-High  │
│ Marketing        │ 42              │ Medium       │
│ Engineering      │ 35              │ Low-Medium   │
│ Finance          │ 28              │ Low          │
│ HR               │ 25              │ Low          │
└──────────────────┴─────────────────┴──────────────┘

Insight: Sales department highest risk
Root causes (drill-down analysis):
- Extensive external collaboration (clients)
- Frequent travel (unusual locations)
- High volume of file sharing
- Use of personal devices (BYOD)

Actions:
- Additional security training for Sales
- Stricter DLP policies for Sales team
- Require MFA for all Sales external shares
```

**3. Geographic Risk Heat Map**
```
Question: Where is our data being accessed from?

Risk Analytics Query:
Metric: Activity count by geographic location
Overlay: ThreatScore by location

Visual Output: World map with heat overlay
- USA (Corporate HQ): 15,000 activities, Avg ThreatScore 28 (green)
- UK (Regional office): 3,500 activities, Avg ThreatScore 32 (green)
- Germany (Regional office): 2,800 activities, Avg ThreatScore 30 (green)
- Russia: 45 activities, Avg ThreatScore 78 (red) ← ALERT
- China: 23 activities, Avg ThreatScore 82 (red) ← ALERT

Drill-down into Russia activities:
- All activities from 3 users
- Users: Compromised credentials (confirmed)
- Data accessed: Customer database
- Action: Disable accounts, force password reset globally
```

---

## Part 2 ====> continue advanced stuffs!

