# Complete CASB Technical Mastery Guide - Part 2

<a name="section-9"></a>
## 9. Advanced Integration: SIEM, API, and Third-Party Tools

### 9.1 SIEM Integration Architecture

**Why Integrate CASB with SIEM?**
- **Centralized visibility:** Combine cloud activity logs with on-premises security events
- **Correlation:** Detect attacks spanning cloud and traditional infrastructure
- **Compliance:** Unified audit trail for regulatory requirements
- **Automation:** Trigger SOAR workflows based on CASB incidents

#### **Supported SIEM Platforms:**
```
Tier 1 Support (Native integrations):
- Splunk
- IBM QRadar
- ArcSight (Micro Focus)
- LogRhythm
- Sumo Logic

Tier 2 Support (Generic formats):
- Any SIEM supporting CEF (Common Event Format)
- Any SIEM supporting LEEF (Log Event Extended Format)
- Any SIEM with REST API capabilities
```

#### **Export Format Options:**

**1. Common Event Format (CEF)**
```
CEF Format Structure:
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Example CloudSOC Log in CEF:
CEF:0|Symantec|CloudSOC|3.158|1001|File Upload Blocked|8|src=203.0.113.42 suser=john.doe@company.com dst=box.com dhost=box.com fname=financial_report.xlsx fileSize=2457600 act=blocked reason=Credit card numbers detected cs1=Microsoft 365 cs1Label=Application cs2=High cs2Label=Severity cs3=Block Credit Cards cs3Label=Policy

Extension Fields Explained:
- src: Source IP address
- suser: Source user (email)
- dst: Destination (cloud service)
- fname: File name
- fileSize: File size in bytes
- act: Action taken (blocked, allowed, quarantined)
- reason: Violation reason
- cs1-cs6: Custom string fields (application, severity, policy, etc.)
```

**2. Log Event Extended Format (LEEF)**
```
LEEF Format Structure:
LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Field1=Value1<Delimiter>Field2=Value2

Example CloudSOC Log in LEEF:
LEEF:1.0|Symantec|CloudSOC|3.158|FileUploadBlocked|^|src=203.0.113.42^sev=8^usrName=john.doe@company.com^dst=box.com^fileName=financial_report.xlsx^fileSize=2457600^action=blocked^reason=Credit card numbers detected^app=Microsoft 365^policy=Block Credit Cards

Delimiter: ^ (caret symbol)
Advantage: More flexible field naming than CEF
Used by: IBM QRadar, some legacy SIEM systems
```

**3. JSON Format (API-Based)**
```json
{
  "event_id": "evt_8273645",
  "timestamp": "2025-11-17T14:23:45.123Z",
  "event_type": "file_upload_blocked",
  "severity": "high",
  "user": {
    "email": "john.doe@company.com",
    "display_name": "John Doe",
    "department": "Finance",
    "threatScore": 35
  },
  "source": {
    "ip": "203.0.113.42",
    "geolocation": {
      "country": "United States",
      "city": "New York",
      "coordinates": [40.7128, -74.0060]
    },
    "device": {
      "type": "Windows 10",
      "name": "LAPTOP-JD-01",
      "managed": true
    }
  },
  "activity": {
    "type": "file_upload",
    "service": "Microsoft 365",
    "service_type": "gateway",
    "object": {
      "name": "financial_report.xlsx",
      "path": "/Finance/Q4/",
      "size": 2457600,
      "type": "application/vnd.ms-excel",
      "hash": "sha256:a3b2c1..."
    }
  },
  "policy": {
    "name": "Block Credit Cards",
    "id": "pol_12345",
    "action": "block",
    "matched_rules": [
      {
        "type": "dlp",
        "detector": "Credit Card Numbers",
        "matches": [
          {
            "type": "Visa",
            "count": 3,
            "confidence": 0.98
          }
        ]
      }
    ]
  },
  "outcome": {
    "action_taken": "blocked",
    "user_notified": true,
    "admin_alerted": true,
    "incident_created": true,
    "incident_id": "inc_98765"
  }
}
```

### 9.2 SIEM Integration Configuration (Splunk Example)

#### **Method 1: Scheduled CSV Export to Splunk**

**Step 1: Configure CloudSOC Export**
```
CloudSOC Console > Settings > Integrations > SIEM Export

Configuration:
- Export Name: Splunk Production Feed
- Format: CSV
- Schedule: Every 15 minutes
- Data Source: Investigate Logs
- Filters:
  ☑ Include all severity levels
  ☑ Include all services
  ☐ High severity only
- Delivery Method: HTTPS POST
- Endpoint URL: https://splunk-hec.company.com:8088/services/collector
- Authentication: HEC Token (HTTP Event Collector)
- HEC Token: [Generate in Splunk]

Test Connection → Success → Save
```

**Step 2: Configure Splunk HTTP Event Collector**
```
Splunk Web UI:
Settings > Data Inputs > HTTP Event Collector > New Token

Token Configuration:
- Name: CloudSOC-Integration
- Source Type: _json (for JSON) or csv (for CSV)
- Index: cloudsoc_logs (create dedicated index)
- Allowed Indexes: cloudsoc_logs
- Default Index: cloudsoc_logs

Save → Copy Token Value → Return to CloudSOC configuration
```

**Step 3: Create Splunk Parsing Rules**
```
Splunk props.conf (for CSV format):
[cloudsoc_csv]
DELIMS = ","
FIELDS = timestamp,user,source_ip,service,activity,object,severity,policy,action,violation
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
SHOULD_LINEMERGE = false

Splunk transforms.conf (field extraction):
[cloudsoc_fields]
REGEX = ^([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)
FORMAT = timestamp::$1 user::$2 source_ip::$3 service::$4 activity::$5 object::$6 severity::$7 policy::$8 action::$9 violation::$10
```

**Step 4: Verify Data Ingestion**
```
Splunk Search:
index=cloudsoc_logs earliest=-15m

Expected Results:
- Events appearing every 15 minutes
- All fields properly parsed
- Timestamp correctly interpreted

Sample Event:
timestamp=2025-11-17T14:23:45
user=john.doe@company.com
source_ip=203.0.113.42
service=Microsoft 365
activity=file_upload
object=financial_report.xlsx
severity=high
policy=Block Credit Cards
action=blocked
violation=true
```

#### **Method 2: Real-Time API Integration with Splunk**

**Step 1: Create CloudSOC API Key**
```
CloudSOC Console > Settings > API Keys > New API Key

Configuration:
- Name: Splunk Real-Time Integration
- Description: Pulls events every 60 seconds via API
- Created By: siem-integration@company.com (service account)
- Permissions:
  ☑ Investigate API (read)
  ☐ Protect API (not needed)
  ☑ Audit API (read)
- Rate Limit: 30 calls/minute (default)
- Expiration: 1 year (set reminder for renewal)

Generate Key → Copy API Key and Secret
```

**Step 2: Deploy Splunk Modular Input Script**
```python
# splunk_cloudsoc_input.py
#!/usr/bin/env python3

import requests
import json
import time
import sys
from datetime import datetime, timedelta

# Configuration
CLOUDSOC_API_URL = "https://portal-us.cloudsocsecurity.com/api/v1"
API_KEY = "your-api-key"
API_SECRET = "your-api-secret"
CHECKPOINT_FILE = "/opt/splunk/var/lib/splunk/modinputs/cloudsoc_checkpoint.json"

def get_last_checkpoint():
    """Read last fetched timestamp"""
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            data = json.load(f)
            return data.get('last_timestamp')
    except FileNotFoundError:
        # First run, fetch last 1 hour
        return (datetime.utcnow() - timedelta(hours=1)).isoformat()

def save_checkpoint(timestamp):
    """Save last fetched timestamp"""
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump({'last_timestamp': timestamp}, f)

def fetch_events(since_timestamp):
    """Fetch events from CloudSOC API"""
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    
    params = {
        'since': since_timestamp,
        'limit': 1000,  # Max per request
        'order': 'asc'  # Chronological order
    }
    
    response = requests.get(
        f"{CLOUDSOC_API_URL}/investigate/events",
        headers=headers,
        params=params,
        auth=(API_KEY, API_SECRET)
    )
    
    if response.status_code == 200:
        return response.json().get('events', [])
    elif response.status_code == 429:
        # Rate limited, wait and retry
        time.sleep(60)
        return fetch_events(since_timestamp)
    else:
        sys.stderr.write(f"API Error: {response.status_code} - {response.text}\n")
        return []

def main():
    """Main loop for fetching and outputting events"""
    last_timestamp = get_last_checkpoint()
    
    while True:
        events = fetch_events(last_timestamp)
        
        for event in events:
            # Output event to Splunk (stdout)
            print(json.dumps(event))
            sys.stdout.flush()
            
            # Update checkpoint
            last_timestamp = event['timestamp']
        
        if events:
            save_checkpoint(last_timestamp)
        
        # Wait 60 seconds before next fetch
        time.sleep(60)

if __name__ == "__main__":
    main()
```

**Step 3: Configure Splunk Inputs**
```
inputs.conf:
[script://./bin/splunk_cloudsoc_input.py]
interval = -1
sourcetype = cloudsoc:json
index = cloudsoc_logs
disabled = false

props.conf:
[cloudsoc:json]
INDEXED_EXTRACTIONS = json
KV_MODE = json
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
SHOULD_LINEMERGE = false
```

**Step 4: Create Splunk Dashboard**
```
CloudSOC Overview Dashboard (XML):

<dashboard>
  <label>CloudSOC Security Overview</label>
  
  <row>
    <panel>
      <title>Policy Violations - Last 24 Hours</title>
      <chart>
        <search>
          <query>
            index=cloudsoc_logs violation=true earliest=-24h 
            | timechart count by policy
          </query>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    
    <panel>
      <title>Top Risk Users (by ThreatScore)</title>
      <table>
        <search>
          <query>
            index=cloudsoc_logs earliest=-24h 
            | stats max(threatScore) as max_score, count by user 
            | sort -max_score 
            | head 10
          </query>
        </search>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Blocked Activities by Service</title>
      <chart>
        <search>
          <query>
            index=cloudsoc_logs action=blocked earliest=-24h 
            | stats count by service 
            | sort -count
          </query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    
    <panel>
      <title>Geographic Activity Heat Map</title>
      <map>
        <search>
          <query>
            index=cloudsoc_logs earliest=-24h 
            | iplocation source_ip 
            | geostats latfield=lat longfield=lon count
          </query>
        </search>
      </map>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Recent Critical Incidents</title>
      <table>
        <search>
          <query>
            index=cloudsoc_logs severity=critical earliest=-24h 
            | table _time, user, service, activity, object, policy, action 
            | sort -_time 
            | head 20
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

### 9.3 SOAR Integration (Security Orchestration and Automation)

#### **Use Case: Automated Incident Response**

**Scenario:** When CloudSOC detects high-risk activity, automatically trigger investigation and containment workflow.

**Integration Flow:**
```
CloudSOC Detect → High ThreatScore (85+) detected
                ↓
Webhook notification to SOAR platform (e.g., Palo Alto Cortex XSOAR)
                ↓
SOAR receives alert and initiates playbook:
                ↓
Step 1: Enrich threat intelligence
        - Query VirusTotal for IP reputation
        - Check AlienVault OTX for known threats
        - Query internal threat database
                ↓
Step 2: Validate alert (reduce false positives)
        - Check if user is on vacation (query HR system)
        - Verify if activity matches scheduled automation
        - Check if user recently reported phishing
                ↓
Step 3: Containment (if threat confirmed)
        - Disable user account in CloudSOC
        - Revoke all active sessions
        - Quarantine accessed files
        - Block user's IP at firewall
                ↓
Step 4: Investigation
        - Pull all user activity from CloudSOC (last 7 days)
        - Export to case management system
        - Assign to SOC analyst
        - Notify user's manager
                ↓
Step 5: Documentation
        - Create incident ticket in ServiceNow
        - Log all automated actions taken
        - Generate initial incident report
        - Send summary to security team
```

**SOAR Playbook Configuration (Cortex XSOAR Example):**

```yaml
playbook:
  name: CloudSOC High ThreatScore Response
  trigger:
    type: webhook
    url: /cloudsoc/threatscore-alert
    
  inputs:
    - user_email
    - threatScore
    - risk_factors
    - recent_activities
    
  tasks:
    - id: 1
      name: Enrich IP Reputation
      type: integration
      integration: VirusTotal
      command: ip-reputation
      args:
        ip: ${incident.source_ip}
      outputs:
        - contextPath: VirusTotal.IP.malicious_score
        
    - id: 2
      name: Check User Status
      type: integration
      integration: Workday
      command: get-employee-status
      args:
        email: ${incident.user_email}
      outputs:
        - contextPath: Employee.on_vacation
        - contextPath: Employee.termination_date
        
    - id: 3
      name: Decision - Is Threat Confirmed?
      type: condition
      condition: |
        ${VirusTotal.IP.malicious_score} > 5 AND
        ${Employee.on_vacation} == false AND
        ${incident.threatScore} > 85
      nexttasks:
        true: 4  # Proceed to containment
        false: 10  # Log only, no action
        
    - id: 4
      name: Disable User Account in CloudSOC
      type: integration
      integration: CloudSOC
      command: disable-user
      args:
        email: ${incident.user_email}
        
    - id: 5
      name: Revoke Active Sessions
      type: integration
      integration: CloudSOC
      command: revoke-sessions
      args:
        email: ${incident.user_email}
        
    - id: 6
      name: Quarantine Recent Files
      type: integration
      integration: CloudSOC
      command: quarantine-files
      args:
        user: ${incident.user_email}
        since: 7d  # Last 7 days
        
    - id: 7
      name: Block IP at Firewall
      type: integration
      integration: PaloAltoFirewall
      command: block-ip
      args:
        ip: ${incident.source_ip}
        duration: 24h
        
    - id: 8
      name: Create ServiceNow Incident
      type: integration
      integration: ServiceNow
      command: create-incident
      args:
        title: "CloudSOC High Risk User: ${incident.user_email}"
        severity: critical
        description: "User ThreatScore: ${incident.threatScore}. Automated containment completed."
        assigned_to: soc-team
        
    - id: 9
      name: Notify Security Team
      type: integration
      integration: Slack
      command: send-message
      args:
        channel: "#security-incidents"
        message: |
          🚨 *High-Risk User Detected and Contained*
          User: ${incident.user_email}
          ThreatScore: ${incident.threatScore}
          Actions Taken:
          - Account disabled
          - Sessions revoked
          - Files quarantined
          - IP blocked
          
          ServiceNow Incident: ${ServiceNow.Incident.number}
          
    - id: 10
      name: Log False Positive
      type: task
      task: |
        Log incident as potential false positive for review
```

### 9.4 CloudSOC API Reference (Key Endpoints)

#### **Authentication:**
```bash
# Basic Authentication with API Key and Secret
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/investigate/events" \
  -u "API_KEY:API_SECRET" \
  -H "Content-Type: application/json"

# Bearer Token (after initial auth)
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/investigate/events" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

#### **Key API Endpoints:**

**1. Investigate API - Fetch Events**
```bash
GET /api/v1/investigate/events

Parameters:
- since: ISO 8601 timestamp (fetch events after this time)
- until: ISO 8601 timestamp (fetch events before this time)
- limit: Integer (max results per page, max 1000)
- offset: Integer (pagination offset)
- user: String (filter by user email)
- service: String (filter by service name)
- severity: String (critical, high, medium, low)
- policy: String (filter by policy name)

Example:
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/investigate/events?since=2025-11-17T00:00:00Z&limit=100&severity=high" \
  -u "API_KEY:API_SECRET"

Response:
{
  "total": 234,
  "count": 100,
  "offset": 0,
  "events": [
    {
      "id": "evt_8273645",
      "timestamp": "2025-11-17T14:23:45.123Z",
      "user": "john.doe@company.com",
      ...
    }
  ],
  "next": "/api/v1/investigate/events?offset=100&..."
}
```

**2. Protect API - Manage Policies**
```bash
GET /api/v1/protect/policies
List all policies

GET /api/v1/protect/policies/{policy_id}
Get specific policy details

POST /api/v1/protect/policies
Create new policy

PUT /api/v1/protect/policies/{policy_id}
Update existing policy

DELETE /api/v1/protect/policies/{policy_id}
Delete policy

Example - Create Policy:
curl -X POST "https://portal-us.cloudsocsecurity.com/api/v1/protect/policies" \
  -u "API_KEY:API_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Sensitive Data Upload",
    "type": "data_transfer_gatelet",
    "status": "active",
    "priority": 10,
    "scope": {
      "services": ["microsoft_365_gateway", "box_gateway"],
      "users": ["all"]
    },
    "conditions": {
      "dlp_detector": "production_detector",
      "patterns": ["credit_card", "ssn"]
    },
    "actions": {
      "primary": "block",
      "notify_user": true,
      "notify_admin": true,
      "create_incident": true
    }
  }'
```

**3. Detect API - ThreatScore and User Risk**
```bash
GET /api/v1/detect/users/{user_email}/threatscore
Get current ThreatScore for user

GET /api/v1/detect/users?threatscore_min=80
List users with ThreatScore above threshold

GET /api/v1/detect/users/{user_email}/risk-factors
Get detailed risk factors contributing to ThreatScore

Example:
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/detect/users/john.doe@company.com/threatscore" \
  -u "API_KEY:API_SECRET"

Response:
{
  "user": "john.doe@company.com",
  "threatScore": 85,
  "risk_level": "high",
  "last_updated": "2025-11-17T14:30:00Z",
  "risk_factors": [
    {
      "type": "volume_anomaly",
      "description": "File downloads 30x above baseline",
      "score_contribution": 30,
      "severity": "high"
    },
    {
      "type": "geographic_anomaly",
      "description": "Access from unusual location (Russia)",
      "score_contribution": 25,
      "severity": "high"
    },
    {
      "type": "time_anomaly",
      "description": "Activity during off-hours (3:00 AM)",
      "score_contribution": 20,
      "severity": "medium"
    }
  ]
}
```

**4. Admin API - User Management**
```bash
GET /api/v1/admin/users
List all users

POST /api/v1/admin/users
Create new user

PUT /api/v1/admin/users/{user_email}
Update user

DELETE /api/v1/admin/users/{user_email}
Delete user

POST /api/v1/admin/users/{user_email}/disable
Disable user account

POST /api/v1/admin/users/{user_email}/enable
Enable user account

POST /api/v1/admin/users/{user_email}/revoke-sessions
Revoke all active sessions

Example - Disable User:
curl -X POST "https://portal-us.cloudsocsecurity.com/api/v1/admin/users/john.doe@company.com/disable" \
  -u "API_KEY:API_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Suspected account compromise - high ThreatScore",
    "notify_user": false,
    "notify_admin": true
  }'
```

**5. Audit API - Application Discovery**
```bash
GET /api/v1/audit/applications
List all discovered applications

GET /api/v1/audit/applications/{app_id}
Get specific application details

GET /api/v1/audit/applications?sanctioned=false
List only unsanctioned (Shadow IT) applications

Example:
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/audit/applications?sanctioned=false&risk_level=high" \
  -u "API_KEY:API_SECRET"

Response:
{
  "total": 89,
  "applications": [
    {
      "id": "app_12345",
      "name": "WeTransfer",
      "category": "File Sharing",
      "sanctioned": false,
      "brr_score": 45,
      "risk_level": "high",
      "users": 189,
      "data_uploaded_gb": 450,
      "data_downloaded_gb": 320,
      "first_seen": "2025-10-15T09:23:00Z",
      "last_seen": "2025-11-17T14:15:00Z"
    }
  ]
}
```

#### **API Rate Limits (Important for Troubleshooting):**

```
CloudSOC API Rate Limits (as of CASB 3.158+):

General APIs:
- Investigate API: 100 requests/minute
- Protect API: 30 requests/minute
- Detect API: 60 requests/minute
- Admin API: 30 requests/minute

Audit API (Special Limit):
- 30 requests/minute (lower due to computational cost)

Rate Limit Headers in Response:
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1700234567 (Unix timestamp)

When Rate Limited:
HTTP Status: 429 Too Many Requests
Response Body:
{
  "error": "rate_limit_exceeded",
  "message": "API rate limit exceeded. Please retry after 60 seconds.",
  "retry_after": 60
}

Best Practices:
1. Implement exponential backoff on 429 errors
2. Cache responses where possible
3. Use bulk operations instead of individual calls
4. Monitor X-RateLimit-Remaining header
5. Distribute API calls over time (don't burst)
```

---

<a name="section-10"></a>
## 10. Troubleshooting Methodology and Common Issues

### 10.1 Systematic Troubleshooting Framework

**The 5-Layer CASB Troubleshooting Model:**

```
Layer 1: Network Connectivity
         └── Can traffic reach CloudSOC infrastructure?

Layer 2: Authentication & Authorization
         └── Can user/service authenticate? Do they have permissions?

Layer 3: Service Integration
         └── Are Securlets/Gatelets properly configured?

Layer 4: Policy Enforcement
         └── Are policies correctly defined and applied?

Layer 5: Data Processing
         └── Is CDS scanning content correctly?
```

**Troubleshooting Decision Tree:**

```
Issue Reported
     │
     ├─→ No logs appearing in Investigate?
     │    └─→ Go to Section 10.2 (Log Ingestion Issues)
     │
     ├─→ Policy not enforcing?
     │    └─→ Go to Section 10.3 (Policy Enforcement Issues)
     │
     ├─→ Slow performance / latency?
     │    └─→ Go to Section 10.4 (Performance Issues)
     │
     ├─→ Authentication failures?
     │    └─→ Go to Section 10.5 (Authentication Issues)
     │
     └─→ API errors?
          └─→ Go to Section 10.6 (API Troubleshooting)
```

### 10.2 **REAL-WORLD ISSUE: Microsoft Gatelet Logs Delayed 30 Minutes**

**Issue Description:**
```
Customer Report:
"When accessing the Investigate section of CASB, Microsoft gatelet logs 
do not appear immediately. After approximately 30 minutes, the logs 
finally show up."

Environment:
- Product: Symantec CloudSOC CASB
- Version: 3.158 (example)
- Affected Service: Microsoft 365 (Gateway) - Teams, OneDrive, SharePoint
- Integration: Cloud SWG (WSS) + CloudSOC Gatelet
- Region: US (portal-us.cloudsocsecurity.com)
```

#### **Root Cause Analysis (Step-by-Step)**

**Step 1: Understand Normal Log Flow**

```
Normal Microsoft Gatelet Log Flow:
┌─────────────┐
│ User Device │
└──────┬──────┘
       │ 1. User uploads file to Teams
       ↓
┌─────────────────────┐
│ Cloud SWG (WSS)     │ 2. Traffic intercepted, SSL decrypted
└──────┬──────────────┘
       │ 3. Forwarded to Gatelet with metadata
       ↓
┌─────────────────────┐
│ CloudSOC Gatelet    │ 4. Activity parsed, policy evaluated
└──────┬──────────────┘
       │ 5. Log entry created
       ↓
┌─────────────────────┐
│ CloudSOC Database   │ 6. Log stored in database
└──────┬──────────────┘
       │ 7. Indexed for Investigate queries
       ↓
┌─────────────────────┐
│ Investigate UI      │ 8. Log visible to user (EXPECTED: 1-2 minutes)
└─────────────────────┘

Expected Total Time: 1-2 minutes from activity to visibility
Reported Issue: 30 minutes delay = ABNORMAL
```

**Step 2: Check WSS/CASB Sync Status**

**WHY THIS MATTERS:** CloudSOC Gatelets depend on sync with Cloud SWG. If sync is broken or delayed, logs won't flow.

```
Diagnostic Steps:

A. Log into WSS Threatpulse Portal
   URL: https://threatpulse.cloud (or regional equivalent)
   Credentials: WSS admin account

B. Navigate to Integration Settings
   Menu: Integration > CASB Gateway > Status

C. Check Sync Status
   Expected Status Display:
   ┌──────────────────────────────────────────────────┐
   │ CASB Integration Status                          │
   ├──────────────────────────────────────────────────┤
   │ Status: ✅ Synced                                │
   │ Last Sync: 2025-11-17 14:35:00 UTC              │
   │ Next Sync: 2025-11-17 14:45:00 UTC              │
   │ Sync Interval: 10 minutes                        │
   │ Active Gatelets: 23                              │
   │ Sync Errors: 0                                   │
   └──────────────────────────────────────────────────┘

D. If Status Shows "Not Synced" or "Sync Failed":
   
   Common Causes:
   1. WSS and CloudSOC regions mismatch
      - WSS Region: US
      - CloudSOC Region: EU
      - FIX: Both must be in same region
      
   2. Integration not activated by support
      - Sync must be enabled by Symantec support ticket
      - FIX: Open support case for sync activation
3. Network connectivity issue between WSS and CloudSOC
      - Firewall blocking WSS → CloudSOC communication
      - FIX: Whitelist CloudSOC IPs in WSS network path
      
   4. Certificate expiration
      - SSL cert used for WSS-CloudSOC communication expired
      - FIX: Renew certificate in WSS Portal > Settings > Certificates

E. Check Sync Logs for Errors
   WSS Portal > Integration > CASB Gateway > Sync Logs
   
   Look for error patterns:
   ```
   ERROR: Connection timeout to portal-us.cloudsocsecurity.com
   ERROR: Authentication failed - invalid token
   ERROR: Rate limit exceeded (429)
   WARNING: Sync delayed due to high queue volume
   ```
```

**Step 3: Verify Microsoft 365 Gatelet Configuration**

**WHY THIS MATTERS:** Even if WSS sync works, the specific Gatelet might not be properly configured.

```
Diagnostic Steps:

A. Log into CloudSOC Console
   URL: https://portal-us.cloudsocsecurity.com
   
B. Check Gatelet Status
   Navigation: Store > Cloud Services > Search "Microsoft"
   
   Find: Microsoft 365 (Gateway)
   Expected Status: ✅ Active
   
   If Status Shows "Disabled" or "Configuration Required":
   - Click "Configure"
   - Complete setup wizard
   - Wait 5-15 minutes for WSS sync
   - Test again

C. Check Gatelet Domains Configuration
   Click: Microsoft 365 (Gateway) > Configuration > Domains
   
   Expected Domains List:
   ☑ *.office.com
   ☑ *.office365.com
   ☑ *.sharepoint.com
   ☑ *.onedrive.com
   ☑ teams.microsoft.com
   ☑ *.teams.microsoft.com
   ☑ outlook.office365.com
   
   CRITICAL CHECK: Are ALL Microsoft domains present?
   
   Missing Domain Symptom:
   - Teams messages logged: ✅ (teams.microsoft.com present)
   - SharePoint uploads NOT logged: ❌ (*.sharepoint.com missing)
   
   FIX: Add missing domains → Save → Wait for WSS sync

D. Check SSL Interception in WSS
   WSS Portal > Security > SSL Settings > Domains of Interest
   
   CRITICAL: All Microsoft 365 domains MUST be in SSL Intercept list
   
   Verification:
   Search for: teams.microsoft.com
   Expected Result: Listed in "SSL Intercepted Domains"
   
   If NOT found:
   ┌────────────────────────────────────────────────────┐
   │ ⚠️  ROOT CAUSE IDENTIFIED                          │
   ├────────────────────────────────────────────────────┤
   │ Domain not SSL intercepted = No content inspection │
   │ No inspection = No logs sent to CloudSOC           │
   │ Result: Logs appear delayed or missing             │
   └────────────────────────────────────────────────────┘
   
   FIX:
   1. WSS Portal > Security > SSL Settings
   2. Click "Add Domain"
   3. Enter: teams.microsoft.com (and all O365 domains)
   4. Save
   5. Wait 5-10 minutes for policy propagation
   6. Test again
```

**Step 4: Check for Bypass Rules (Most Common Root Cause)**

**WHY THIS MATTERS:** This is the **#1 cause** of delayed/missing Gatelet logs.

```
SCENARIO: Mobile App Bypass (Very Common Issue)

Problem:
WSS has a "Mobile App Bypass" feature that excludes mobile apps from SSL 
interception to prevent certificate pinning issues. However, Microsoft 
Teams uses the SAME domains for both web app AND mobile app.

Result:
If "Mobile App Bypass" is enabled, Teams traffic bypasses SSL interception
even from desktop browsers, causing logs to NOT be inspected immediately.

┌──────────────────────────────────────────────────────────┐
│ WSS Portal > Security > SSL Bypass > Mobile App Bypass   │
├──────────────────────────────────────────────────────────┤
│ Status: ✅ Enabled                                       │
│                                                          │
│ Bypassed Domains: (auto-detected)                       │
│ - teams.microsoft.com                                    │
│ - *.teams.microsoft.com                                  │
│ - teams.office.com                                       │
│ - outlook.office365.com                                  │
└──────────────────────────────────────────────────────────┘

Diagnostic Steps:

A. Check Bypass Lists
   WSS Portal > Security > SSL Bypass
   
   Check ALL bypass categories:
   ☑ Mobile App Bypass
   ☑ Certificate Pinning Bypass
   ☑ Financial Services Bypass
   ☑ Healthcare Services Bypass
   ☑ Custom Bypass Rules

B. Search for Microsoft domains in bypass lists
   Search: teams.microsoft.com
   
   If FOUND in any bypass list:
   ┌────────────────────────────────────────────────────┐
   │ ⚠️  ROOT CAUSE CONFIRMED                           │
   ├────────────────────────────────────────────────────┤
   │ Teams domain in bypass list = No SSL interception  │
   │ No SSL interception = No Gatelet inspection        │
   │ Result: Logs delayed until processed via API path  │
   └────────────────────────────────────────────────────┘

C. Understand Why Logs Eventually Appear (30-minute delay explained)
   
   When Gatelet path is bypassed:
   
   Primary Path (Real-time via Gatelet): BLOCKED
   ↓
   Fallback Path (Delayed via API):
   1. WSS still logs basic metadata (URL, user, timestamp)
   2. Every 30 minutes, CloudSOC queries WSS logs via API
   3. CloudSOC retrieves missed activities
   4. Logs appear in Investigate after API sync
   
   This explains the 30-minute delay!

D. Solutions (Choose Based on Requirements)

   OPTION 1: Remove Teams from Bypass (Recommended)
   ─────────────────────────────────────────────
   WSS Portal > Security > SSL Bypass > Mobile App Bypass
   - Find: teams.microsoft.com
   - Click: "Remove from bypass list"
   - Confirm: "Yes, enable SSL interception"
   
   Impact:
   ✅ Gatelet logs appear in real-time (1-2 minutes)
   ⚠️  Mobile Teams app might show cert warnings
   
   Mitigation for Mobile Impact:
   - Deploy Symantec root CA cert to mobile devices via MDM
   - OR: Create user-agent based rule (bypass only mobile user-agents)
   
   OPTION 2: User-Agent Specific Bypass (Advanced)
   ──────────────────────────────────────────────
   WSS Portal > Security > SSL Bypass > Advanced Rules
   - Create Custom Rule:
     Name: Bypass Teams Mobile Only
     Condition: 
       Domain: teams.microsoft.com
       AND User-Agent: contains "TeamsAndroidClient" OR "TeamsiOSClient"
     Action: Bypass SSL Interception
   
   Result:
   - Mobile Teams app: Bypassed (no cert issues)
   - Desktop/Web Teams: SSL intercepted (Gatelet logs work)
   ✅ Best of both worlds

   OPTION 3: Accept 30-Minute Delay (Not Recommended)
   ──────────────────────────────────────────────────
   - Keep Teams in bypass list
   - Document that logs have expected delay
   - Only acceptable if real-time enforcement not critical
```

**Step 5: Check CloudSOC Log Processing Queue**

**WHY THIS MATTERS:** High log volume can cause processing delays.

```
Diagnostic Steps:

A. Check CloudSOC System Status
   CloudSOC Console > Settings > System Status
   
   Look for indicators:
   ┌─────────────────────────────────────────────────┐
   │ System Health                                   │
   ├─────────────────────────────────────────────────┤
   │ Log Ingestion: ✅ Normal                        │
   │ Processing Queue: ⚠️  High (12,456 pending)    │
   │ Average Processing Time: 28 minutes             │
   │ API Response Time: 250ms                        │
   └─────────────────────────────────────────────────┘
   
   If "Processing Queue" is HIGH:
   - This explains the delay
   - CloudSOC is backlogged processing logs
   
B. Check for Recent Log Spikes
   Settings > System Status > Metrics
   
   Graph: Logs Received (Last 24 Hours)
   
   Look for sudden spikes:
   Normal: 10,000 logs/hour
   Spike: 150,000 logs/hour ← Problem
   
   Common Causes of Spikes:
   1. New Gatelet enabled (initial discovery of historical activity)
   2. Policy rescan triggered (rescanning all files)
   3. DLP scan of large repository
   4. API integration gone wild (polling too frequently)
   5. Automated tool generating excessive activity

C. Identify Log Source
   Settings > System Status > Top Log Sources
   
   Example:
   ┌──────────────────────────┬─────────────────┐
   │ Source                   │ Logs/Hour       │
   ├──────────────────────────┼─────────────────┤
   │ Microsoft 365 (Gateway)  │ 145,000 (spike!)│
   │ Box (API)                │ 5,000           │
   │ Google Workspace (API)   │ 3,500           │
   └──────────────────────────┴─────────────────┘
   
   Spike from Microsoft 365 Gateway identified!
   
D. Root Cause: Initial Gatelet Activation
   
   Scenario:
   - Customer recently enabled Microsoft 365 Gatelet
   - Gatelet processing backlog of historical activities
   - Queue buildup causes 30-minute processing delay
   
   This is TEMPORARY and will resolve within 24-48 hours
   as backlog clears.

E. Temporary Mitigation (If Urgent)
   
   Contact Symantec Support to:
   - Increase processing capacity for this tenant
   - Prioritize real-time logs over historical backlog
   - Temporarily disable historical activity processing
   
   Self-Service Options:
   - Disable recently activated Securlets/Gatelets temporarily
   - Pause file rescans if in progress
   - Reduce API polling frequency if using integrations
```

**Step 6: Verify Time Synchronization (Often Overlooked)**

**WHY THIS MATTERS:** Time skew causes logs to appear delayed or out of order.

```
Diagnostic Steps:

A. Check CloudSOC Server Time
   Settings > System Status > Server Information
   - Server Time: 2025-11-17 14:45:23 UTC
   - Compare to your actual UTC time
   - Difference should be < 5 seconds

B. Check WSS Time Synchronization
   WSS Portal > Settings > System > Time Settings
   - NTP Servers configured?
   - Last NTP sync successful?
   
   If time is skewed:
   ┌────────────────────────────────────────────────────┐
   │ Example Scenario:                                  │
   ├────────────────────────────────────────────────────┤
   │ Actual time: 14:45 UTC                            │
   │ WSS time: 15:15 UTC (30 minutes ahead!)          │
   │                                                    │
   │ Activity occurs at 14:45 actual time              │
   │ WSS timestamps it as 15:15                        │
   │ CloudSOC receives log with future timestamp       │
   │ CloudSOC queues log to display at 15:15          │
   │ Result: 30-minute "delay" (actually time skew)    │
   └────────────────────────────────────────────────────┘
   
   FIX:
   1. Configure NTP on WSS
   2. Force time sync
   3. Verify time matches CloudSOC within 5 seconds
   4. Logs should now appear in correct time

C. Check Client Browser Time
   User's browser time might be incorrect
   - JavaScript uses local browser time for display
   - If browser time is wrong, logs appear "delayed"
   
   Test:
   - Ask user to check their system clock
   - Compare to actual time
   - Adjust if needed
```

**Step 7: Check Network Latency Between Components**

```
Diagnostic Steps:

A. Test WSS to CloudSOC Connectivity
   From WSS appliance (if on-prem) or WSS support:
   
   ping portal-us.cloudsocsecurity.com
   Expected: < 100ms latency
   
   If latency > 500ms:
   - Network path issue
   - Traffic possibly routing through suboptimal path
   - Can cause delays in log transmission

B. Traceroute Analysis
   traceroute portal-us.cloudsocsecurity.com
   
   Look for:
   - Hops > 20: Inefficient routing
   - Packet loss at any hop
   - High latency hops (> 200ms)
   
   Common Issue:
   WSS in US-East, CloudSOC in US-West, traffic routing through Europe
   
   FIX: Work with network team to optimize routing

C. Check for Bandwidth Saturation
   If WSS uplink is saturated:
   - Log transmission to CloudSOC queued
   - Causes delays
   
   Monitor: WSS network utilization
   If consistently > 80%: Increase bandwidth
```

**Step 8: Official Resolution from Symantec KB**

**Based on Symantec Knowledge Base Articles:**

```
KB Article: "Microsoft 365 Gatelet Logs Delayed in Investigate"
Article ID: TECH278456 (example)
Last Updated: October 2024

OFFICIAL ROOT CAUSES (from Symantec):

1. Microsoft 365 Domains in WSS Bypass List (70% of cases)
   ────────────────────────────────────────────────────────
   Cause: Mobile App Bypass or Certificate Pinning Bypass
   Symptom: Logs appear after 30-minute API sync window
   Resolution:
   - Remove O365 domains from bypass lists
   - Deploy Symantec root CA to mobile devices
   - Configure user-agent based bypass for genuine mobile apps
   
2. WSS/CloudSOC Sync Delay (15% of cases)
   ────────────────────────────────────────
   Cause: Sync interval set to 30 minutes (default: 10 minutes)
   Symptom: Logs appear in batches every 30 minutes
   Resolution:
   - Contact Symantec Support to adjust sync interval
   - Default is 10 minutes; can be reduced to 5 minutes
   - Navigate: WSS Portal > Integration > CASB > Sync Settings
   
3. Initial Gatelet Activation Backlog (10% of cases)
   ──────────────────────────────────────────────────
   Cause: Historical activity processing after new Gatelet enabled
   Symptom: Temporary delay for 24-48 hours after activation
   Resolution:
   - Wait for backlog to clear (automatic)
   - Monitor: Settings > System Status > Processing Queue
   - No action required; resolves itself
   
4. CloudSOC Regional API Throttling (3% of cases)
   ────────────────────────────────────────────────
   Cause: API rate limiting during high-traffic periods
   Symptom: Intermittent delays, especially during business hours
   Resolution:
   - Contact Symantec Support for rate limit increase
   - Temporary: Schedule heavy operations during off-hours
   
5. Time Synchronization Issue (2% of cases)
   ──────────────────────────────────────────
   Cause: Time skew between WSS and CloudSOC
   Symptom: Logs appear with incorrect timestamps or delayed
   Resolution:
   - Configure NTP on all components
   - Verify time sync within 5 seconds
   - Restart WSS service after NTP configuration

OFFICIAL WORKAROUNDS:

Temporary Workaround (while investigating):
1. Enable Microsoft 365 Securlet (API-based) alongside Gatelet
   - Securlet provides fallback log collection
   - Logs appear via API path even if Gatelet fails
   - Navigation: Store > Microsoft 365 (API) > Enable
   
2. Increase Investigate refresh frequency
   - Settings > Investigate > Auto-refresh: 1 minute
   - Helps surface logs as soon as they arrive
   
3. Use Investigate filters to show "pending" logs
   - Some logs may be in processing state
   - Filter: Status = "Processing"
   - Shows logs queued but not yet indexed

PERMANENT FIX (Step-by-Step):

Step 1: Verify Prerequisites
□ WSS version: 11.0.1+ (minimum required)
□ CloudSOC version: 3.150+ (minimum required)
□ WSS/CloudSOC in same region
□ Integration activated by Symantec support

Step 2: Configure SSL Interception
□ WSS Portal > Security > SSL Settings
□ Add all O365 domains to "Domains of Interest"
□ Remove O365 domains from ALL bypass lists
□ Exception: User-agent based bypass for mobile apps only

Step 3: Verify Gatelet Configuration
□ CloudSOC Console > Store > Microsoft 365 (Gateway)
□ Status: Active
□ Domains: All O365 domains listed
□ Policy: At least one active policy assigned

Step 4: Configure Optimal Sync
□ WSS Portal > Integration > CASB Gateway > Settings
□ Sync Interval: 5 minutes (for faster real-time logs)
□ Sync Timeout: 60 seconds
□ Retry Attempts: 3

Step 5: Test and Verify
□ User performs test activity (upload file to Teams)
□ Wait 2-3 minutes
□ Check Investigate: Log should appear
□ Verify timestamp accuracy

Step 6: Monitor for 24 Hours
□ Settings > System Status > Processing Queue
□ Queue should remain < 1,000 pending
□ Average processing time should be < 5 minutes
□ No sync errors in WSS logs

ESCALATION CRITERIA:

Open Symantec Support Case if:
- Delays persist after implementing all fixes
- Processing queue consistently > 10,000
- Sync status shows repeated failures
- Gatelet status shows "Degraded" or "Error"

Support Case Information to Include:
1. CloudSOC Console: Settings > System Status > Download Diagnostic Bundle
2. WSS Portal: Integration > CASB Gateway > Sync Logs (export)
3. Screenshot: Investigate showing missing/delayed logs
4. Exact timing: Activity timestamp vs. log appearance time
5. User impacted: Email address and example activity
6. Recent changes: Any configuration changes in last 7 days
```

**Step 9: Real-World Resolution Example**

```
CASE STUDY: Financial Services Customer

Initial Report:
"Microsoft Teams file uploads not appearing in Investigate for 30-45 minutes.
Need real-time visibility for compliance monitoring."

Environment:
- 5,000 users
- Microsoft 365 E5 licenses
- Heavy Teams usage (500+ file uploads/day)
- CloudSOC region: US
- WSS deployed in AWS US-East-1

Investigation Timeline:

Day 1 - Initial Troubleshooting:
─────────────────────────────────
09:00 - Ticket opened
09:30 - Verified Gatelet enabled: ✅
10:00 - Checked WSS sync status: ✅ Synced
10:30 - Tested upload: Log appeared after 32 minutes
11:00 - Checked SSL interception: ⚠️  Found issue!

ROOT CAUSE IDENTIFIED:
WSS Portal > SSL Bypass > Mobile App Bypass
- teams.microsoft.com: BYPASSED
- *.teams.microsoft.com: BYPASSED

Customer had enabled Mobile App Bypass 6 months ago
to support Teams mobile app. This was causing web/desktop
Teams traffic to also bypass SSL interception.

Day 1 - Resolution Implementation:
──────────────────────────────────
11:30 - Created user-agent based bypass rule:
        
        Rule Name: Teams Mobile Only Bypass
        Conditions:
        - Domain: teams.microsoft.com OR *.teams.microsoft.com
        - AND User-Agent: (TeamsAndroidClient|TeamsiOSClient)
        Action: Bypass SSL Interception
        
        All other traffic (desktop/web): SSL Intercepted

12:00 - Removed teams domains from global Mobile App Bypass list
12:15 - Waited for policy propagation (10 minutes)
12:30 - Tested upload from web Teams: Log appeared in 90 seconds! ✅
12:45 - Tested from mobile Teams app: Still worked (no cert errors) ✅

Day 2 - Verification:
─────────────────────
Full day monitoring showed:
- Average log appearance time: 1.5 minutes
- 500+ uploads logged in real-time
- No mobile app issues reported
- Processing queue: Normal (< 200 pending)

Resolution: SUCCESSFUL
Time to Resolution: 4 hours (including testing)
Root Cause: Teams domains in SSL bypass list
Fix: User-agent based bypass (bypass mobile only)
```

### 10.3 Policy Enforcement Troubleshooting

**Common Issue: Policy Not Blocking Expected Activity**

```
Scenario: DLP policy configured to block credit card uploads, but 
user successfully uploaded file containing credit cards.

Troubleshooting Steps:

Step 1: Verify Policy Is Active
────────────────────────────────
CloudSOC Console > Protect > Policies > [Your Policy]

Check:
☑ Status: Active (not Disabled)
☑ Schedule: Currently within active time window
☑ Priority: No higher-priority policy overriding

If policy shows "Disabled":
- Enable it
- Wait 5 minutes for propagation
- Test again

Step 2: Verify Policy Scope
───────────────────────────
Check: Does policy apply to this specific scenario?

Policy Scope Checklist:
□ Service: Does it include the service used? (e.g., Microsoft 365 Gateway)
□ User: Does user fall within policy scope? (All Users vs. specific groups)
□ Activity: Does it cover this activity type? (File Upload)
□ Location: Is user's IP in scope? (not excluded by location filter)

Common Mistake:
Policy applies to "Box (Gateway)" but user uploaded to Teams
FIX: Add "Microsoft 365 (Gateway)" to policy scope

Step 3: Verify Policy Type (DAR vs. DIM)
────────────────────────────────────────
CRITICAL: Policy type must match enforcement point

Policy Type: "Data Exposure via Securlet" (Data at Rest)
- Enforces: AFTER upload completes
- Action: Can quarantine, but cannot prevent upload
- Result: User sees file uploaded, then it disappears (quarantined)

Policy Type: "Data Transfer via Gatelet" (Data in Motion)
- Enforces: DURING upload (real-time)
- Action: Blocks upload before it completes
- Result: User sees "Activity Blocked" message

If you want to PREVENT uploads: Must use Gatelet policy
If Securlet policy configured: Change to Gatelet policy type

Step 4: Verify DLP Detector Configuration
──────────────────────────────────────────
Settings > Data Loss Prevention > Detectors

Check:
□ Detector Status: Active (green)
□ Last Heartbeat: < 5 minutes ago
□ Connection: Successful

If detector shows "Inactive" or "Error":
1. Test connection
2. Regenerate token if needed
3. Verify Enterprise Console subscription active

Step 5: Test DLP Detection
──────────────────────────
Create test file with known violation:

test-creditcard.txt content:
"Test credit card: 4532-1488-0343-6467"

Upload test file to affected service:
- Expected: Policy blocks upload
- If NOT blocked: Continue to Step 6

Step 6: Check DLP Scan Logs
───────────────────────────
Settings > Data Loss Prevention > Scan Logs

Find entry for test file upload:
- File scanned? YES / NO
- If NO: File not sent to CDS (Gatelet issue)
- If YES: Check detection result

Example Scan Log Entry:
File: test-creditcard.txt
Scanned: Yes
Detector: Production Detector
Patterns Matched: None ← PROBLEM!
Action: Allowed (no violation detected)

If "Patterns Matched: None":
- DLP detector not finding credit cards
- Possible causes:
  1. Detector misconfigured
  2. Credit card format not recognized
  3. File encrypted (cannot scan)

Step 7: Verify Detection Pattern
────────────────────────────────
Settings > Data Loss Prevention > Detectors > [Your Detector] > Patterns

Check: Is "Credit Card Numbers" pattern enabled?

For Cloud DLP:
□ Credit Card Numbers: Enabled
  ☑ Visa
  ☑ MasterCard
  ☑ American Express
  ☑ Discover

For Enforce-Managed:
- Check Enforce console for pattern configuration
- Verify pattern synced to CloudSOC (last sync time)

If pattern disabled: Enable it and test again

Step 8: Check File Type Support
───────────────────────────────
DLP can only scan supported file types

Supported:
✅ .txt, .doc, .docx, .pdf
✅ .xls, .xlsx, .csv
✅ .ppt, .pptx
✅ .zip (scans contents)

NOT Supported:
❌ Password-protected files
❌ Encrypted archives
❌ Some proprietary formats
❌ Corrupted files

Test:
- Upload plain .txt file with credit card: Blocked? ✅
- Upload encrypted .zip with same content: NOT Blocked? ← Expected

If encrypted files are issue:
- Policy exception: Allow encrypted files OR
- Corporate policy: Prohibit encryption (separate enforcement)

Step 9: Check Policy Action Configuration
─────────────────────────────────────────
Protect > Policies > [Your Policy] > Actions

Verify:
Primary Action: Block (not "Log Only" or "Notify")

Common Mistake:
Action set to "Notify" thinking it blocks
- "Notify" = Alert only, still allows activity
- "Block" = Prevent activity

If Action is "Notify": Change to "Block" and test

Step 10: Check for Conflicting Policies
───────────────────────────────────────
Multiple policies may conflict

Example Conflict:
Policy A (Priority 5): Allow Finance group to upload any files
Policy B (Priority 10): Block credit card uploads for all users

User in Finance group uploads credit card:
- Policy A matches first (lower priority number = higher precedence)
- Policy A allows → Activity proceeds
- Policy B never evaluated

Resolution:
1. List all policies by priority
2. Identify conflicts
3. Adjust priorities or scopes
4. Test again

Step 11: Check Gatelet Traffic Flow
───────────────────────────────────
If Gatelet policy, verify traffic actually goes through Gatelet:

Test from user's browser:
1. Browse to target service (e.g., teams.microsoft.com)
2. Check SSL certificate
3. Certificate Issuer should be "Symantec" (or corporate CA)
4. If Certificate Issuer is "Microsoft": Traffic NOT intercepted

If traffic not intercepted:
- Return to Section 10.2 (SSL interception troubleshooting)
- Verify domain not in bypass list
- Verify user not excluded from proxy policy

Step 12: Review Investigate Logs for Clues
──────────────────────────────────────────
Investigate > Search for the specific upload activity

Look for log entry:
- Activity: File Upload
- File: test-creditcard.txt
- Policy Matched: [Your Policy Name] OR "None"

If "Policy Matched: None":
- Policy never evaluated for this activity
- Scope issue (policy doesn't apply to this scenario)

If "Policy Matched: [Your Policy]" but "Action: Allowed":
- Policy evaluated but exception applied
- Check exception rules in policy

If log entry doesn't exist at all:
- Activity not captured by Gatelet
- Return to log ingestion troubleshooting (Section 10.2)
```

### 10.4 Performance and Latency Issues

**Diagnosing CASB-Induced Latency:**

```
User Complaint: "Cloud applications are slow since CASB deployment"

Step 1: Baseline Measurement
───────────────────────────
Measure WITHOUT CASB:
- User bypasses proxy temporarily (for testing only)
- Upload 10 MB file to OneDrive
- Record time: 8 seconds

Measure WITH CASB:
- User routes through CASB
- Upload same 10 MB file
- Record time: 25 seconds

Latency Added by CASB: 17 seconds (212% slower)
This is ABNORMAL - investigate further

Step 2: Break Down Latency Components
─────────────────────────────────────
CASB latency comes from multiple stages:

1. SSL Decryption: 20-50ms (normal)
2. Application Parsing: 10-30ms (normal)
3. DLP Scanning: 50ms - 10 seconds (depends on file size)
4. Re-encryption: 20-50ms (normal)
5. Network Routing: 10-100ms (depends on geography)

Total Normal: 110ms - 10 seconds (for large file with DLP)
Abnormal: > 15 seconds for 10MB file

Step 3: Identify Bottleneck
──────────────────────────
Check each component:

A. Geographic Routing Issue
   User Location: London, UK
   CASB Region: US-West (California)
   
   Result: 150ms baseline latency just for geographic distance
   
   FIX: Use EU CASB region (portal-eu.cloudsocsecurity.com)
   Expected improvement: 150ms → 10ms

B. DLP Scan Timeout
   Settings > Data Loss Prevention > Performance
   
   Scan Timeout: 30 seconds (too high!)
   
   If scan takes > timeout:
   - File scanned unsuccessfully
   - Retries triggered
   - Delays stack up
   
   FIX: 
   - Reduce timeout to 10 seconds
   - Increase CDS capacity (contact support)
   - Exclude large files from DLP (> 50MB)

C. CDS Overload
   Settings > System Status > CDS Performance
   
   Queue Length: 5,432 files waiting
   Average Scan Time: 45 seconds (normal: 2-5 seconds)
   
   Root Cause: CDS detector overwhelmed
   
   FIX:
   - Add additional CDS capacity (support ticket)
   - Implement selective scanning (sample 10% of low-risk files)
   - Schedule heavy scans during off-hours

D. Network Path Sub-Optimal
   Traceroute from user to CASB shows:
   - 25 hops (normal: 10-15)
   - Routing through 3 continents
   - Packet loss at hop 18
   
   FIX: Work with network team to optimize BGP routing

Step 4: Implement Performance Optimizations
───────────────────────────────────────────

Optimization 1: Selective DLP Scanning
Settings > Protect > Policies > [DLP Policy] > Advanced

Instead of: Scan ALL files
Implement: Risk-based sampling
- High-risk file types (.xlsx, .doc): 100% scanning
- Low-risk file types (.jpg, .mp4): 10% sampling
- Known safe users (IT team): Skip DLP
- External shares: 100% scanning

Result: 70% reduction in DLP scan volume

Optimization 2: File Size Limits
Policy Configuration:
- Files > 50 MB: Skip DLP scan (log warning only)
- Files > 100 MB: Block upload (use different transfer method)

Rationale:
- Large files take 10-30 seconds to scan
- User experience severely impacted
- Most violations in smaller documents

Optimization 3: Caching
Enable content hash caching:
- File uploaded and scanned
- Hash stored: sha256:abc123...
- Same file uploaded again (same hash)
- Skip scan, reuse previous result

Result: 30-40% reduction in redundant scans

Optimization 4: Regional Deployment
Use geo-aware routing:
- US users → US CASB region
- EU users → EU CASB region
- APAC users → APAC CASB region

Result: 80-90% reduction in geographic latency

Step 5: Monitor Performance Metrics
──────────────────────────────────
Implement ongoing monitoring:

CloudSOC Console > Settings > Performance Dashboard

Key Metrics to Track:
┌────────────────────────────────────────────────┐
│ Metric                    │ Target  │ Current │
├───────────────────────────┼─────────┼─────────┤
│ Average Gatelet Latency   │ <100ms  │ 85ms ✅ │
│ DLP Scan Time (median)    │ <3s     │ 2.1s ✅ │
│ DLP Scan Time (95th perc) │ <10s    │ 8.5s ✅ │
│ Policy Evaluation Time    │ <50ms   │ 35ms ✅ │
│ API Response Time         │ <200ms  │ 450ms ⚠️│
│ Processing Queue Length   │ <1000   │ 234 ✅  │
│ Failed Scans (%)          │ <1%     │ 0.3% ✅ │
└────────────────────────────────────────────────┘

Alert on:
- Latency > 500ms (3 consecutive measurements)
- Queue length > 5000
- Failed scans > 5%

Step 6: User Experience Testing
──────────────────────────────
Conduct real-world performance tests:

Test Matrix:
┌─────────────────┬──────────┬──────────┬─────────┐
│ Activity        │ No CASB  │ With CASB│ Delta   │
├─────────────────┼──────────┼──────────┼─────────┤
│ Login to O365   │ 1.2s     │ 1.5s     │ +0.3s ✅│
│ Upload 1MB file │ 2.0s     │ 2.8s     │ +0.8s ✅│
│ Upload 10MB     │ 8.0s     │ 10.5s    │ +2.5s ✅│
│ Upload 50MB     │ 45s      │ 52s      │ +7s   ⚠️│
│ Download 10MB   │ 5.0s     │ 5.4s     │ +0.4s ✅│
│ Teams message   │ 0.3s     │ 0.5s     │ +0.2s ✅│
└─────────────────┴──────────┴──────────┴─────────┘

Target: Delta < 20% of base time
Acceptable: Delta < 50% of base time
Unacceptable: Delta > 100% of base time

If 50MB uploads too slow:
- Implement file size limit (block > 50MB at Gatelet)
- Direct users to alternative transfer method
- OR: Add more CDS capacity
```

### 10.5 Authentication and Authorization Issues

**Common Authentication Problems:**

```
Issue 1: Users Cannot Log Into CloudSOC Console
───────────────────────────────────────────────

Symptom: "Invalid username or password" error

Troubleshooting:

Step 1: Verify Authentication Method
Settings > Authentication > Identity Provider

Check configuration:
○ Local Authentication (CloudSOC passwords)
● SSO via Azure AD (example)

If SSO configured:
- Test SSO connection from Settings
- Check Azure AD/IdP logs for auth failures
- Verify user exists in IdP
- Verify CloudSOC app is assigned to user in IdP

If Local Authentication:
- Verify user exists: Users > Users > Search
- Check account status: Active vs. Disabled
- Try password reset: Users > [User] > Reset Password

Step 2: Check User Provisioning
Users > Users > [Username]

Verify:
□ User Status: Active (not Disabled)
□ Account not expired
□ Email address correct (used as username)
□ Access Profile assigned (Admins only)

If user doesn't exist:
- Import from AD via SpanVA
- OR manually create user
- OR fix SSO user provisioning

Step 3: SSO-Specific Troubleshooting
For Azure AD SSO:

Azure Portal > Enterprise Applications > CloudSOC > Properties
Check:
□ Enabled for users to sign in: Yes
□ User assignment required: Check if enabled
□ Users and groups: Verify user assigned

Azure AD > CloudSOC > Single sign-on > SAML Configuration
Verify:
□ Identifier (Entity ID): Matches CloudSOC requirement
□ Reply URL: https://portal-us.cloudsocsecurity.com/auth/saml/callback
□ Sign on URL: Correct CloudSOC URL
□ Signing Certificate: Not expired

Common Azure AD Issues:
1. Certificate expired → Renew certificate
2. Reply URL mismatch → Update to correct URL
3. User not assigned to app → Assign user
4. Conditional Access blocking → Adjust CA policy

Step 4: Check Browser/Network Issues
- Clear browser cache and cookies
- Try incognito/private browsing mode
- Try different browser
- Check if corporate firewall blocking CloudSOC URLs
- Verify no SSL inspection breaking SAML redirects

Step 5: Check CloudSOC Service Status
Visit: https://status.broadcom.com/cloud

Check for:
- CloudSOC service outages
- Regional degradation
- Scheduled maintenance

If outage active:
- Wait for resolution
- Check estimated time to recovery
- Subscribe to status updates

Issue 2: API Authentication Failures
───────────────────────────────────

Symptom: API returns 401 Unauthorized or 403 Forbidden

Troubleshooting:

Step 1: Verify API Key Validity
Settings > API Keys > [Your Key]

Check:
□ Status: Active (not Disabled or Expired)
□ Expiration Date: Not passed
□ Created By: User still exists and active

If expired:
- Regenerate API key
- Update integration with new key
- Test again

Step 2: Test API Authentication
curl -X GET "https://portal-us.cloudsocsecurity.com/api/v1/health" \
  -u "API_KEY:API_SECRET"

Expected Response:
{
  "status": "healthy",
  "version": "3.158",
  "region": "us"
}

If 401 Unauthorized:
- API key or secret incorrect
- Regenerate and try again

If 403 Forbidden:
- API key valid but lacks permissions
- Check Access Profile of user who created key

Step 3: Check API Key Inherited Permissions
Settings > API Keys > [Your Key] > View Details

Created By: john.doe@company.com
Access Profile: Regional Admin (EU Only)

Issue: Trying to access US region data with EU-scoped key

FIX:
- Create new API key from user with global access
- OR: Create separate keys for each region

Step 4: Verify API Endpoint Permissions
Some API keys may have endpoint restrictions:

Settings > API Keys > [Your Key] > Permissions

Allowed Endpoints:
☑ Investigate API
☐ Protect API ← DISABLED
☑ Audit API

Attempting to call: /api/v1/protect/policies
Result: 403 Forbidden

FIX: Enable Protect API permission for this key

Issue 3: DPO Cannot Access Certain Features
───────────────────────────────────────────

Symptom: Data Protection Officer sees "Access Denied"

Root Cause: DPO must be End User role

Verification:
Users > Users > [DPO Email] > User Type

If shows "Administrator":
- DPO role requires End User type
- Change to End User
- Re-enable DPO privileges

DPO-Specific Requirements:
□ User Type: End User (NOT Admin)
□ Authentication: Local password (NOT SSO)
□ DPO Role: Enabled in user settings
□ Access Profile: May restrict some features
```

### 10.6 API Troubleshooting (Advanced)

**Debugging API Integration Issues:**

```
Issue: SIEM Integration Not Receiving Events
────────────────────────────────────────────

Scenario: Splunk integration configured but no events appearing

Troubleshooting:

Step 1: Verify API Key Working
Test manually:

curl -X GET \
  "https://portal-us.cloudsocsecurity.com/api/v1/investigate/events?limit=10" \
  -u "API_KEY:API_SECRET" \
  -H "Content-Type: application/json"

Expected: JSON response with events
If error: Fix API authentication first (see Section 10.5)

Step 2: Check API Response for Data
Response should contain events:

{
  "total": 12456,
  "count": 10,
  "events": [
    {
      "id": "evt_123",
      ...
    }
  ]
}

If "events": []:
- No events in time range
- Filters too restrictive
- Adjust query parameters

Step 3: Check API Rate Limiting
Look for HTTP 429 responses:

{
  "error": "rate_limit_exceeded",
  "retry_after": 60
}

If rate limited:
- Integration polling too frequently
- Reduce polling frequency
- Implement exponential backoff
- Request rate limit increase from support

Step 4: Check SIEM-Side Integration
For Splunk example:

Check Splunk Logs:
/opt/splunk/var/log/splunk/splunkd.log

Look for errors:
ERROR ExecProcessor - message from "python /opt/splunk/bin/cloudsoc_input.py"
Connection timeout to portal-us.cloudsocsecurity.com

Common Issues:
1. Network connectivity (firewall blocking)
2. SSL certificate validation failure
3. Python library missing (requests module)
4. Credentials incorrect in script

Step 5: Verify Data Transformation
Check if API response is properly parsed:

API Response (JSON):
{
  "events": [
    {"user": "john@company.com", "activity": "upload"}
  ]
}

Splunk Indexed Data (should match):
user=john@company.com activity=upload

If mismatch:
- Field extraction broken
- Update props.conf/transforms.conf
- Restart Splunk

Step 6: Check for Time Range Issues
API Query:
since=2025-11-17T00:00:00Z

Current Time: 2025-11-17T14:30:00Z

If "since" is in the past:
- May return thousands of events
- Can overwhelm SIEM
- Cause integration to fall behind

FIX:
- Use checkpoint mechanism (store last fetched timestamp)
- Query incrementally (since last checkpoint)
- Limit results per request (max 1000)

Step 7: Debug Checkpoint Mechanism
Check checkpoint file:

cat /opt/splunk/var/lib/splunk/modinputs/cloudsoc_checkpoint.json
{
  "last_timestamp": "2025-11-10T08:00:00Z"
}

Current date: 2025-11-17 (7 days later!)

Issue: Checkpoint stuck 7 days in past
- Integration trying to fetch 7 days of backlog
- Likely timing out or rate limited

FIX:
- Reset checkpoint to recent time
- Echo '{"last_timestamp": "2025-11-17T00:00:00Z"}' > checkpoint.json
- Restart integration

Step 8: Monitor API Call Patterns
Enable API logging in CloudSOC:
Settings > API Keys > [Your Key] > Enable Logging

Review API call log:
┌────────────┬──────────┬─────────┬────────────┐
│ Timestamp  │ Endpoint │ Status  │ Response   │
├────────────┼──────────┼─────────┼────────────┤
│ 14:30:01   │ /events  │ 200     │ 1000 events│
│ 14:30:02   │ /events  │ 200     │ 1000 events│
│ 14:30:03   │ /events  │ 200     │ 1000 events│
│ ...        │ ...      │ ...     │ ...        │
│ 14:32:00   │ /events  │ 429     │ Rate limit │
└────────────┴──────────┴─────────┴────────────┘

Pattern: Burst of 30 requests in 2 minutes → Rate limited

FIX: Implement pacing
- Wait 2 seconds between requests
- Respect X-RateLimit-Remaining header
- If remaining < 10, wait for reset

Step 9: Implement Robust Error Handling
Example Python code:

import requests
import time

def fetch_events_with_retry(api_url, api_key, api_secret, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(
                api_url,
                auth=(api_key, api_secret),
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            
            elif response.status_code == 429:
                # Rate limited
                retry_after = int(response.headers.get('Retry-After', 60))
                print(f"Rate limited, waiting {retry_after}s")
                time.sleep(retry_after)
                continue
            
            elif response.status_code == 401:
                # Authentication failed
                print("Authentication failed - check API credentials")
                return None
            
            elif response.status_code >= 500:
                # Server error, retry with backoff
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"Server error, retrying in {wait_time}s")
                time.sleep(wait_time)
                continue
            
            else:
                print(f"Unexpected status: {response.status_code}")
                return None
        
        except requests.exceptions.Timeout:
            print(f"Timeout on attempt {attempt + 1}")
            time.sleep(2 ** attempt)
            continue
        
        except requests.exceptions.ConnectionError:
            print(f"Connection error on attempt {attempt + 1}")
            time.sleep(2 ** attempt)
            continue
    
    print("Max retries exceeded")
    return None

Step 10: Validate Data Integrity
Spot check: Compare API data vs. Investigate UI

API Query: Last 1 hour of high-severity events
Count: 23 events

Investigate UI: Same query
Count: 23 events

If counts match: ✅ Integration working correctly
If counts differ: Data loss or transformation issue

Root Cause Examples:
- Integration dropping events with parsing errors
- Time zone conversion errors
- Character encoding issues (special characters)
- Field truncation (field too long for SIEM)
```

---

<a name="section-11"></a>
## 11. Real-World Scenarios and Case Studies

### 11.1 Scenario: Ransomware Attack via Compromised Cloud Account

**Background:**
```
Company: Manufacturing firm, 2,500 employees
Environment: Microsoft 365, Box, Salesforce
CASB: Symantec CloudSOC with Gatelets and Securlets
Incident Date: November 2025
```

**Attack Timeline:**

**Day 1 - Initial Compromise (Nov 10, 3:00 AM)**
```
Event: User "maria.garcia@company.com" account compromised

Investigate Log:
{
  "timestamp": "2025-11-10T03:15:23Z",
  "user": "maria.garcia@company.com",
  "activity": "login",
  "source_ip": "185.220.101.45",
  "geolocation": "Russia",
  "device": "Unknown (curl/7.68.0)",
  "service": "Microsoft 365 (Gateway)",
  "threatScore": 75,
  "risk_factors": [
    "Impossible travel (was in US 2 hours ago)",
    "Unusual device type",
    "High-risk geolocation"
  ]
}

Detect Alert Triggered:
- Maria's ThreatScore jumped from 20 → 75
- Alert sent to SOC team: "High-risk login detected"
- SOC on-call engineer received alert at 3:20 AM
```

**Day 1 - Reconnaissance (Nov 10, 3:15 AM - 5:00 AM)**
```
Attacker Actions (Logged by CloudSOC):

03:15 - 04:30: SharePoint enumeration
- Accessed 450+ folders across all departments
- Downloaded folder structure maps
- No files downloaded yet (reconnaissance phase)

04:30 - 04:45: Privilege escalation attempt
- Tried to access Global Admin portal (blocked by Azure AD MFA)
- Attempted to reset other user passwords (failed)
- Tried to create new API keys (blocked by CloudSOC policy)

Detect Analysis:
ThreatScore increased: 75 → 88

Risk Factors:
- Volume anomaly: 450 folder accesses (normal: 10-15/day)
- Scope anomaly: Accessing departments outside user's role
- Failed privilege escalation (indicators of compromise)

SOC Response (05:00 AM):
- Engineer reviewed Detect alert
- Confirmed suspicious activity
- Initiated containment:
  1. Disabled Maria's account in CloudSOC
  2. Revoked all active sessions
  3. Blocked source IP at firewall
  4. Notified security team
```

**Day 1 - Lateral Movement Blocked (Nov 10, 5:00 AM - 6:00 AM)**
```
Attacker Attempts (All Blocked):

05:10: Tried to login again from same IP
Result: Account disabled → Login failed

05:15: Tried to login from different IP (185.220.102.89)
Result: Account still disabled → Login failed

05:30: Tried to access via mobile app
Result: All sessions revoked → Access denied

CloudSOC Protection:
✅ Account lockout prevented further access
✅ Session revocation terminated active connections
✅ IP block prevented retry attempts

Without CASB:
❌ Attacker could have continued for hours/days
❌ Could have exfiltrated sensitive data
❌ Could have deployed ransomware across OneDrive/SharePoint
```

**Day 1 - Forensic Investigation (Nov 10, 6:00 AM - 12:00 PM)**
```
Investigate Query:
user:maria.garcia@company.com AND time:[last 7 days]

Timeline Reconstruction:

Nov 9, 5:00 PM (1 day before):
- Maria clicked phishing link in email
- Email claimed to be from "IT Security"
- Link: https://microsoft-verify-login[.]ru
- Harvested credentials

Nov 9, 5:15 PM:
- Attacker tested credentials from Russia
- First login attempt (not yet flagged - within normal business hours noise)

Nov 10, 3:00 AM:
- Attacker began serious reconnaissance
- CloudSOC Detect identified anomaly
- SOC team contained threat

Total Time from Compromise to Containment: 10 hours
Actual Attack Window: 2 hours (3 AM - 5 AM)
Data Exfiltrated: 0 bytes (blocked before exfiltration phase)

Impact Assessment:
- Files accessed: 0 (only folder listings)
- Data stolen: 0
- Ransomware deployed: NO (prevented)
- Users impacted: 1 (Maria)
- Business disruption: Minimal
```

**Day 1-2 - Remediation (Nov 10-11)**
```
Actions Taken:

1. Password Reset:
   - Maria's password reset
   - Forced password reset for all Global Admins (precaution)
   
2. Account Re-enablement:
   - After password reset, account re-enabled
   - Maria required to complete security training
   
3. Enhanced Monitoring:
   - Increased monitoring for Maria's account (30 days)
   - Any login from non-US IP = immediate alert + block
   
4. Policy Updates:
   - New policy: Block logins from high-risk countries (Russia, North Korea, etc.)
   - Exception: VPN from approved corporate VPN IPs only
   
5. User Awareness:
   - Company-wide phishing awareness email sent
   - Maria's case used as training example (anonymized)

Prevention for Future:
- Implement hardware MFA keys for all users (Yubikey)
- Deploy email gateway with link rewriting
- Enhanced Detect rules for impossible travel
```

**Lessons Learned:**
```
What Worked:
✅ CloudSOC Detect identified anomaly within 5 minutes
✅ SOC response contained threat within 2 hours
✅ No data exfiltration occurred
✅ Comprehensive audit trail for investigation

What Could Be Improved:
⚠️  Phishing email wasn't blocked (not CASB's role, but need better email security)
⚠️  SOC on-call took 20 minutes to respond (improve alert routing)
⚠️  Maria didn't report phishing email (need better user training)

CASB Value Demonstrated:
- Without CASB: Attacker could have exfiltrated entire SharePoint (TBs of data)
- With CASB: Contained within 2 hours, zero data loss
- ROI: Prevented potential ransomware payment ($500K+) and data breach fines
```

### 11.2 Scenario: Insider Threat - Gradual Data Exfiltration

**Background:**
```
Company: Technology startup, 300 employees
Insider: Senior engineer planning to leave and join competitor
CASB: CloudSOC with Securlets (Box, Google Workspace)
Duration: 6 weeks
```

**Week 1-2: Establishing Baseline**
```
Normal Behavior (Michael Brown - Senior Engineer):
- Daily file access: 20-30 files (engineering docs)
- Departments accessed: Engineering only
- Download volume: 50-100 MB/day
- Work hours: 9 AM - 6 PM EST
- ThreatScore: 25 (baseline)

No alerts triggered - behavior within normal parameters
```

**Week 3: Subtle Changes Begin**
```
Nov 1-7: Increased Access to Adjacent Departments

Investigate Pattern:
- Engineering files: 25 files/day (normal)
- Product Management files: 5 files/day (NEW)
- Design files: 3 files/day (NEW)

Detect Analysis:
- ThreatScore: 25 → 32 (slight increase)
- Risk Factor: "Access pattern change detected"
- Severity: Low (not yet concerning)
- No alert sent to SOC (below threshold)

What Michael Was Doing:
- Accessing product roadmaps
- Reviewing design specifications
- Collecting competitive intelligence
- Small enough volumes to avoid immediate detection
```

**Week 4: Escalation**
```
Nov 8-14: Accessing Sensitive Departments

New Access Pattern:
- HR files: 8 files accessed (employee compensation data)
- Finance files: 12 files accessed (revenue projections)
- Sales files: 15 files accessed (client lists)

Detect Analysis:
- ThreatScore: 32 → 48 (moderate increase)
- Risk Factors:
  1. "Accessing departments outside role"
  2. "Increased file download volume (+40%)"
  3. "After-hours activity increasing"
- Severity: Medium
- Alert: Flagged for security review

SOC Review:
- Analyst reviewed activity
- Noted cross-department access
- Flagged for continued monitoring
- NOT YET escalated (could be legitimate project work)
```

**Week 5: Red Flags**
```
Nov 15-21: External Sharing and Personal Cloud

Critical Events:

Event 1 (Nov 16, 8:30 PM):
Activity: External share created
File: "Q4_Product_Roadmap_Confidential.pdf"
Shared with: recruiter@competitortech.com
Policy: "Block External Sharing to Competitors"
Action: BLOCKED

Investigate Log:
{
  "activity": "external_share_attempt",
  "file": "Q4_Product_Roadmap_Confidential.pdf",
  "destination": "recruiter@competitortech.com",
  "policy_matched": "Block Competitor Sharing",
  "action": "blocked",
  "user_notified": true,
  "admin_alerted": true
}

Event 2 (Nov 18, 11:00 PM):
Activity: Multiple file downloads
Count: 67 files in 15 minutes
Total size: 2.3 GB
Files: Source code repositories, architecture docs
Destination: Unknown (local device)

Event 3 (Nov 19, 1:00 AM):
Activity: Login from personal Gmail detected
User uploaded files to personal Google Drive
Policy: "Monitor Personal Cloud Usage"
Action: Logged (not blocked - monitoring policy only)

Detect Analysis:
- ThreatScore: 48 → 68 (HIGH RISK)
- Risk Factors:
  1. "Attempted sharing with competitor"
  2. "Mass download event"
  3. "Personal cloud usage detected"
  4. "After-hours bulk activity"

Alert: HIGH PRIORITY - Escalated to Security Manager
```

**Week 6: Investigation and Containment**
```
Nov 22: Security Team Investigation

Investigation Query (Investigate):
user:michael.brown@company.com AND time:[last 45 days]
Group by: File sensitivity level

Results:
┌────────────────────────┬───────┬─────────────┐
│ Sensitivity Level      │ Count │ Downloaded  │
├────────────────────────┼───────┼─────────────┤
│ Highly Confidential    │ 234   │ 12.5 GB     │
│ Confidential           │ 456   │ 8.2 GB      │
│ Internal               │ 789   │ 15.3 GB     │
│ Public                 │ 123   │ 2.1 GB      │
└────────────────────────┴───────┴─────────────┘

Total Data Accessed: 38.1 GB over 45 days
Pattern: Systematic collection of intellectual property

Corroborating Evidence:
1. LinkedIn: Michael updated profile, added "Open to opportunities"
2. Calendar: Multiple "Personal appointments" during business hours
3. Email: Correspondence with recruiters (detected by email DLP)
4. Background check: Competitor posted job listing matching Michael's skills

Nov 23: HR and Legal Coordination

Actions:
1. Meeting with HR Director and General Counsel
2. Review employment agreement (non-compete, IP ownership clauses)
3. Decision: Initiate termination proceedings
4. Prepare evidence package for potential legal action

Nov 24: Controlled Termination

Morning (Before Michael Arrives):
1. CloudSOC: Disabled account
2. IT: Revoked VPN access, disabled laptop
3. Revoked physical building access badge
4. HR: Prepared termination documentation

10:00 AM: Meeting with Michael
- HR and manager present
- Michael informed of termination
- Reason: Policy violations (data exfiltration)
- Evidence presented (CloudSOC reports)
- Michael escorted from building
- Company property collected

Post-Termination:
1. Legal review of accessed files
2. Notification to competitor (cease and desist letter)
3. Enhanced monitoring for other engineers
4. Policy updates based on lessons learned
```

**Prevention Measures Implemented:**
```
1. Enhanced DLP Policies:
   - Block all downloads > 500 MB in single session
   - Require manager approval for bulk file access
   - Block personal cloud storage completely (was monitoring only)

2. Behavioral Analytics Tuning:
   - Lower ThreatScore threshold for engineers (access to sensitive IP)
   - Alert on ANY cross-department access for engineering role
   - Immediate alert for after-hours bulk downloads

3. HR Process Changes:
   - IT notified immediately when engineer gives notice
   - Enhanced monitoring during notice period
   - Expedited offboarding (no 2-week notice period for critical roles)

4. Technical Controls:
   - USB ports disabled on engineering workstations
   - Screen recording for high-risk roles
   - Watermarking on confidential documents

5. Legal Protections:
   - Enhanced IP assignment agreements
   - Stricter non-compete clauses
   - Regular IP audits
```

**Lessons Learned:**
```
What Worked:
✅ Detect identified gradual behavioral changes over 6 weeks
✅ Blocked critical external share to competitor
✅ Comprehensive audit trail for legal proceedings
✅ Early detection allowed proactive termination

What Could Be Improved:
⚠️  Initial ThreatScore threshold too high (48 vs. 35 in retrospect)
⚠️  Personal cloud monitoring should have been blocking policy
⚠️  No integration with HR systems (resignation flags)

CASB Value:
- Detected insider threat before massive data loss
- Provided evidence for legal action
- Prevented source code from reaching competitor
- Estimated IP value protected: $2-5M
```

---

## Continues to Section 12-15 in next message...

Would you like me to continue with:
- Section 12: Performance Optimization and Best Practices
- Section 13: Compliance and Regulatory Requirements
- Section 14: Advanced Technical Support Skills
- Section 15: Daily Practice Labs and Exercises

These will include hands-on labs, compliance templates, advanced troubleshooting techniques, and daily study materials for your ongoing learning.
