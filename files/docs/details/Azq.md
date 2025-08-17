/ Query to get all policies under initiative definitions 
// where category is "org governance" and type is "custom"

policyresources
| where type == "microsoft.authorization/policysetdefinitions"
| where properties.policyType == "Custom"
| where properties.metadata.category == "org governance" 
    or properties.metadata.category == "Org Governance"
    or properties.metadata.category == "Organization Governance"
| extend initiativeName = properties.displayName
| extend initiativeId = id
| mv-expand policyDefinition = properties.policyDefinitions
| extend policyDefinitionId = tostring(policyDefinition.policyDefinitionId)
| extend policyParameters = policyDefinition.parameters
| join kind=leftouter (
    policyresources
    | where type == "microsoft.authorization/policydefinitions"
    | extend policyDefId = id
    | extend policyName = properties.displayName
    | extend policyDescription = properties.description
    | extend policyCategory = properties.metadata.category
    | extend policyType = properties.policyType
) on $left.policyDefinitionId == $right.policyDefId
| project 
    InitiativeName = initiativeName,
    InitiativeId = initiativeId,
    PolicyName = policyName,
    PolicyId = policyDefinitionId,
    PolicyDescription = policyDescription,
    PolicyCategory = policyCategory,
    PolicyType = policyType,
    PolicyParameters = policyParameters
| order by InitiativeName, PolicyName



Got it — you want to use Azure Resource Graph (ARG) to query and return policy assignments that are linked to a specific policy definition.

Here’s the key part to understand:
In Azure, policy assignments reference either:

a policyDefinitionId (for individual policies)

or an initiativeDefinitionId (for policy initiatives — a collection of policies).



---

Example: Azure Resource Graph Query

If you know the Policy Definition ID (or its name), you can run:

PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId has "<your-policy-definition-name-or-guid>"
| project name, id, scope = properties.scope, policyDefinitionId


---

For Initiative (Policy Set Definition)

If the definition is an initiative, and you want all assignments that come from it:

PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId has "<your-initiative-definition-name-or-guid>"
| project name, id, scope = properties.scope, policyDefinitionId


---

If You Only Have the Display Name

You can first fetch the definition ID, then filter:

// Step 1: Get the policy definition ID
PolicyResources
| where type in ('microsoft.authorization/policydefinitions', 'microsoft.authorization/policysetdefinitions')
| where properties.displayName == "<Your Policy or Initiative Display Name>"
| project id

// Step 2: Use the ID from above in the assignments query
PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId == "<ID from above>"
| project name, id, scope = properties.scope


---

Note:

PolicyResources in Azure Resource Graph includes both policy definitions and assignments.

You’ll need Reader access at least on the scopes where these policies are assigned.

Run the query in Azure Portal → Resource Graph Explorer or via Azure CLI:


az graph query -q "<KQL query here>"


---

If you want, I can also write you a single ARG query that:

1. Takes a policy definition display name


2. Finds its ID


3. Lists all policy assignments linked to it



so you don’t have to do it in two steps.

Do you want me to prepare that one-step query?





let policyDisplayName = "<Your Initiative Display Name>";
// Step 1: Get initiative definition ID
let initiativeDef = toscalar(
    PolicyResources
    | where type == 'microsoft.authorization/policysetdefinitions'
    | where properties.displayName =~ policyDisplayName
    | project id
);
// Step 2: Get all child policy definitions inside the initiative
let childPolicyDefs = PolicyResources
    | where id == initiativeDef
    | mv-expand policies = properties.policyDefinitions
    | extend childPolicyId = tostring(policies.policyDefinitionId)
    | project childPolicyId;
// Step 3: Combine initiative ID and child policy IDs
let allPolicyIds = union (
    print policyDefinitionId = initiativeDef
),
(
    childPolicyDefs | project policyDefinitionId = childPolicyId
);
// Step 4: Get all assignments matching any of these IDs
PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId in (allPolicyIds)
| project AssignmentName = name,
          AssignmentId = id,
          Scope = properties.scope,
          PolicyDefinitionId = policyDefinitionId
































try this:

policyassignments
| where properties.status.value == "Enabled"
| join kind=inner (
    policydefinitions
    | project policyDefinitionId = id, policyDefinitionName = properties.displayName
) on $left.policyDefinitionId == $right.policyDefinitionId
| where policyDefinitionName == "<YourPolicyDisplayName>"
| project
    policyAssignmentId = id,
    policyAssignmentName = properties.displayName,
    scope = properties.scope,
    policyDefinitionName,
    policyDefinitionId,
    properties.description,
    properties.metadata,
    properties.policyType,
    properties.mode,
    properties.version



To retrieve a list of **Azure Policies** applied on an **Azure Tenant** filtered by a **specific policy definition name or display name**, you can use **Azure Resource Graph (ARG)** with the following query.

This query is particularly useful in **Quality Assurance (QA)** reporting to ensure your **baseline policies** are consistently applied across **subscriptions** or **management groups**.

---

### ✅ Azure Resource Graph Query: Get Policy Assignments by Definition Name/Display Name

```kusto
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| extend assignmentScope = tostring(properties.scope)
| extend displayName = tostring(properties.displayName)
| where displayName =~ "Your Policy Display Name" // Case-insensitive exact match
// Optional: Filter by a specific scope pattern like management group, subscription, or resource group
// | where assignmentScope startswith '/subscriptions/' or assignmentScope startswith '/providers/Microsoft.Management/managementGroups/'
// Join with PolicyDefinition to verify full metadata
| join kind=leftouter (
    PolicyResources
    | where type == "microsoft.authorization/policydefinitions"
    | extend definitionDisplayName = tostring(properties.displayName)
) on $left.policyDefinitionId == $right.id
| project 
    assignmentName = name,
    assignmentDisplayName = displayName,
    assignmentScope,
    policyDefinitionId,
    policyDefinitionName = name1,
    definitionDisplayName,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
```

---

### 🔍 What This Query Does:

* **Filters** resources to only include `policyassignments`.
* Filters further on **Display Name** to find a specific baseline policy (e.g., `"Audit VMs that do not use managed disks"`).
* **Joins** the assignments to their associated **policy definitions** for completeness.
* Returns key fields like:

  * Assignment Name and Display Name
  * Scope of the assignment
  * Policy Definition Name and Display Name
  * Enforcement Mode (Default/DoNotEnforce)
  * Any excluded scopes (`notScopes`)
  * Resource ID of the assignment

---

### 📌 Tips:

* If you're managing policies via **Initiatives**, consider querying `policysetdefinitions` similarly.
* To make this more dynamic, you could use parameters or wrap the query in a script.
* Run this via **Azure Resource Graph Explorer** or **PowerShell/CLI** using `az graph query`.

---

### 🧪 Example Use Case:

Check if the policy **"Audit VMs that do not use managed disks"** is applied:

```kusto
| where displayName =~ "Audit VMs that do not use managed disks"
```

Replace this string with the **policy name in your baseline**.

---
Great! Here's a **comprehensive solution** tailored for **Quality Assurance (QA)** and **baseline policy compliance checks** across your **Azure Tenant**. I’ll include:

1. ✅ **Initiative-aware version** of the query (to capture `policySetDefinitions`)
2. 🧪 **Filters** for `management group`, `subscription`, and `displayName`
3. 💾 Option to **export to CSV using Azure CLI + PowerShell**

---

## ✅ 1. Azure Resource Graph Query: Policies + Initiatives by Display Name

```kusto
// Query Policy Assignments across the tenant for a specific Policy or Initiative display name
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| extend assignmentScope = tostring(properties.scope)
| extend assignmentDisplayName = tostring(properties.displayName)
| where assignmentDisplayName =~ "Your Baseline Policy or Initiative Display Name"
// Join with Policy Definitions
| join kind=leftouter (
    PolicyResources
    | where type == "microsoft.authorization/policydefinitions" or type == "microsoft.authorization/policysetdefinitions"
    | extend policyDisplayName = tostring(properties.displayName)
) on $left.policyDefinitionId == $right.id
| project 
    assignmentName = name,
    assignmentDisplayName,
    assignmentScope,
    policyDefinitionId,
    policyType = type1,
    policyDefinitionName = name1,
    policyDisplayName,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
```

### 🔍 Notes:

* **`policysetdefinitions`** = Initiatives
* Works **across management groups**, subscriptions, and resource groups
* Use `=~` for **case-insensitive** match

---

## 🔄 2. Customize It:

### Filter by Management Group Scope:

```kusto
| where assignmentScope startswith '/providers/Microsoft.Management/managementGroups/<your-mg-name>'
```

### Or by Subscription ID:

```kusto
| where assignmentScope startswith '/subscriptions/<your-subscription-id>'
```

---

## 💾 3. Export to CSV (Azure CLI + PowerShell)

If you're running this in Azure CLI or PowerShell, here’s how you can **run and export** the results:

### PowerShell (Azure CLI):

```powershell
$policyName = "Your Baseline Policy or Initiative Display Name"
$query = @"
PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| extend assignmentScope = tostring(properties.scope)
| extend assignmentDisplayName = tostring(properties.displayName)
| where assignmentDisplayName =~ '$policyName'
| join kind=leftouter (
    PolicyResources
    | where type == 'microsoft.authorization/policydefinitions' or type == 'microsoft.authorization/policysetdefinitions'
    | extend policyDisplayName = tostring(properties.displayName)
) on \$left.policyDefinitionId == \$right.id
| project 
    assignmentName = name,
    assignmentDisplayName,
    assignmentScope,
    policyDefinitionId,
    policyType = type1,
    policyDefinitionName = name1,
    policyDisplayName,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
"@

az graph query -q $query | ConvertFrom-Json | Select-Object -ExpandProperty data | Export-Csv -Path ".\PolicyComplianceReport.csv" -NoTypeInformation
```

---

## 🧪 QA Checklist Integration

You can include this query in your **policy compliance pipeline** or as part of your **CI/CD validation** to ensure that key policies like:

* **"Audit VMs without managed disks"**
* **"Deny public IP on NICs"**
* **"Require tag 'Environment'"**

...are **present and active** across all defined scopes.

---

Perfect — thank you for the clarification. Here's the distilled goal:

---

### 🎯 **Objective:**

You want an **Azure Resource Graph (ARG) query** that gives you a list of **policy assignments** (or initiative assignments) that were **created using a specific policy definition or initiative** — for **QA/QC** to verify against your **baseline**.

---

### ✅ Use Case:

> **“Given a known Policy Definition ID or Initiative (Policy Set) ID**, list all **assignments** made from that definition, across the tenant.”

---

## ✅ ARG Query: List All Assignments from a Specific Policy Definition or Initiative

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/your-policy-definition-id'; // or use policySetDefinitions
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project 
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
```

---

### 🔁 If Target is an **Initiative (Policy Set)**:

If your baseline is an **initiative**, use:

```kusto
let targetInitiativeId = '/providers/Microsoft.Authorization/policySetDefinitions/your-policy-set-id';
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetInitiativeId
| project 
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
```

---

## 🧪 Output Fields (QA-Ready):

* **assignmentName** – Name of the policy assignment
* **assignmentDisplayName** – Friendly name shown in the portal
* **scope** – Subscription, MG, or resource group where assigned
* **policyDefinitionId** – ID of the source policy or initiative
* **enforcementMode** – Whether enforced (`Default`) or `DoNotEnforce`
* **notScopes** – Any exclusions from assignment
* **assignmentId** – Full Azure resource ID of the assignment

---

## 📌 How to Get the Policy Definition/Set ID

To get the exact ID you need to filter on:

* Go to **Azure Portal > Policy > Definitions**
* Select your **policy** or **initiative**
* Copy the **Resource ID** (starts with `/providers/Microsoft.Authorization/...`)

Example:

```text
/providers/Microsoft.Authorization/policyDefinitions/0c5b5e7f-3b8f-4f0a-9c45-20f40165f04d
/providers/Microsoft.Authorization/policySetDefinitions/benchmark-baseline-initiative
```

---

## 🔄 Want to Cross-Check Multiple Baselines?

You can check for multiple baseline definitions at once:

```kusto
let baselineIds = dynamic([
  "/providers/Microsoft.Authorization/policyDefinitions/policy1-id",
  "/providers/Microsoft.Authorization/policyDefinitions/policy2-id"
]);
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId in (baselineIds)
| project assignmentName, assignmentDisplayName = tostring(properties.displayName), scope = tostring(properties.scope), policyDefinitionId
```


Certainly! Below is a **Confluence-style documentation draft** written from the perspective of an **Azure Policy SME (Subject Matter Expert)**. This guide is aimed at teams responsible for **QA/QC validation of baseline policies** using **Azure Resource Graph (ARG)**.

---

# 🛡️ Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

**Owner:** Azure Policy SME
**Audience:** Cloud Governance, Compliance, SecOps, Cloud Center of Excellence (CCoE), DevSecOps
**Last Updated:** 2025-08-17
**Purpose:** To verify that all policy/initiative assignments applied in the environment are still intact and aligned with the intended **baseline configuration** using **Azure Resource Graph (ARG)**.

---

## 📌 Overview

In enterprise Azure environments, **baseline policies and initiatives** are defined to enforce standards such as:

* Security best practices (e.g., no public IPs)
* Resource tagging
* Identity protection (e.g., MFA, conditional access)
* Cost governance

To ensure these policies are continuously enforced and haven't been accidentally removed or altered, **QA/QC checks** must be conducted regularly.

This document outlines an **end-to-end method** to identify **which policy assignments are active** based on a known **Policy Definition or Initiative** using **Azure Resource Graph (ARG)**.

---

## 🎯 Objective

> Given a known **Policy Definition ID** or **Initiative (Policy Set) ID**, identify all **Policy Assignments** across the tenant that were created from it — including scope, exclusions, and enforcement mode — to validate against your approved **baseline**.

---

## 🛠️ Tools Required

| Tool                              | Purpose                                           |
| --------------------------------- | ------------------------------------------------- |
| **Azure Resource Graph Explorer** | Execute queries interactively in the Azure Portal |
| **Azure CLI / PowerShell**        | Automation, export to CSV, scripting              |
| **Azure Portal (Policy blade)**   | For ID lookup, manual verification                |

---

## 📑 Step-by-Step Procedure

### 1️⃣ Identify Your Baseline Policy or Initiative

Go to **Azure Portal > Policy > Definitions**, locate your baseline policy or initiative, and **copy its Resource ID**. Example:

* **Policy Definition ID**
  `/providers/Microsoft.Authorization/policyDefinitions/0c5b5e7f-3b8f-4f0a-9c45-20f40165f04d`

* **Initiative (Policy Set) ID**
  `/providers/Microsoft.Authorization/policySetDefinitions/benchmark-baseline-initiative`

---

### 2️⃣ Query ARG for Assignments Based on That ID

#### 🔹 A. Query for a Single Policy or Initiative

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/0c5b5e7f-3b8f-4f0a-9c45-20f40165f04d';
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project 
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
```

> Replace `policyDefinitions` with `policySetDefinitions` for initiatives.

---

#### 🔹 B. Query for Multiple Baseline Definitions

```kusto
let baselineIds = dynamic([
  "/providers/Microsoft.Authorization/policyDefinitions/policy1-id",
  "/providers/Microsoft.Authorization/policySetDefinitions/init1-id"
]);
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId in (baselineIds)
| project assignmentName, assignmentDisplayName = tostring(properties.displayName), scope = tostring(properties.scope), policyDefinitionId
```

---

### 3️⃣ (Optional) Export to CSV for QA Reporting

If you need a downloadable report:

```powershell
# Azure CLI + PowerShell
$query = @"
<ARG_QUERY_FROM_ABOVE>
"@

az graph query -q $query | ConvertFrom-Json | Select-Object -ExpandProperty data | Export-Csv -Path "PolicyAssignments-QA.csv" -NoTypeInformation
```

---

## ✅ Must-Know Details

| Item                      | Details                                                                       |
| ------------------------- | ----------------------------------------------------------------------------- |
| **Assignment Types**      | Only `policyassignments` are returned.                                        |
| **ARG is read-only**      | Cannot modify policy states. Only reporting.                                  |
| **Non-Compliance Status** | Not available in ARG. Use Policy Insights for compliance results.             |
| **Case Sensitivity**      | Use `=~` for case-insensitive string matches.                                 |
| **Initiatives**           | Return only the outer assignment, not inner policy members.                   |
| **Scopes**                | Validate scope alignment — subscription, management group, or resource group. |
| **Exclusions**            | Review `notScopes` for any exclusions that may impact enforcement.            |

---

## 🧪 Validation Checklist (for QA/QC)

| Validation Step                              | Description                          | Status |
| -------------------------------------------- | ------------------------------------ | ------ |
| Baseline policy definition/initiative exists | Validate by checking in Azure Portal | ✅/❌    |
| Assignments found in ARG                     | Confirm via query                    | ✅/❌    |
| Scope matches expected hierarchy             | Subscription / MG level              | ✅/❌    |
| Enforcement Mode is 'Default'                | If DoNotEnforce, flag it             | ✅/❌    |
| No unauthorized exclusions                   | Review `notScopes`                   | ✅/❌    |
| Matches baseline document                    | Cross-reference IDs, scope, etc.     | ✅/❌    |

---

## ⚠️ Common Pitfalls

| Pitfall                    | Description                                                    |
| -------------------------- | -------------------------------------------------------------- |
| ❌ Wrong policy ID used     | Always use the full resource ID, not just the name             |
| ❌ ARG used for compliance  | ARG doesn't show compliance status – use Policy Insights       |
| ❌ Forgot about initiatives | Initiative assignments and policy assignments are separate     |
| ❌ Scopes not checked       | Assignment may exist at resource group, not subscription level |

---

## 🔍 Alternatives and Enhancements

* **Policy Insights**: Use for compliance states and historical evaluations.
* **Workbook Dashboards**: Visualize assignments across scopes and time.
* **Azure Blueprints**: If used, also include blueprint-based assignments.
* **Azure Change Tracking (Activity Log)**: Audit changes to policy assignments.

---

## 📦 Appendix

### 📘 Sample Policy Definition ID Format

```text
/providers/Microsoft.Authorization/policyDefinitions/allow-tag-environment
```

### 📘 Sample Initiative ID Format

```text
/providers/Microsoft.Authorization/policySetDefinitions/security-baseline-2024
```

---
Absolutely! Below are both the **Markdown** and **Confluence-ready** versions of the document.

---

## 📄 MARKDOWN VERSION

````markdown
# 🛡️ Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

**Owner:** Azure Policy SME  
**Audience:** Cloud Governance, Compliance, SecOps, Cloud Center of Excellence (CCoE), DevSecOps  
**Last Updated:** 2025-08-17  
**Purpose:** To verify that all policy/initiative assignments applied in the environment are still intact and aligned with the intended **baseline configuration** using **Azure Resource Graph (ARG)**.

---

## 📌 Overview

In enterprise Azure environments, **baseline policies and initiatives** are defined to enforce standards such as:

- Security best practices (e.g., no public IPs)
- Resource tagging
- Identity protection (e.g., MFA, conditional access)
- Cost governance

To ensure these policies are continuously enforced and haven't been accidentally removed or altered, **QA/QC checks** must be conducted regularly.

This document outlines an **end-to-end method** to identify **which policy assignments are active** based on a known **Policy Definition or Initiative** using **Azure Resource Graph (ARG)**.

---

## 🎯 Objective

> Given a known **Policy Definition ID** or **Initiative (Policy Set) ID**, identify all **Policy Assignments** across the tenant that were created from it — including scope, exclusions, and enforcement mode — to validate against your approved **baseline**.

---

## 🛠️ Tools Required

| Tool               | Purpose                            |
|--------------------|-------------------------------------|
| **Azure Resource Graph Explorer** | Execute queries interactively in the Azure Portal |
| **Azure CLI / PowerShell**        | Automation, export to CSV, scripting               |
| **Azure Portal (Policy blade)**   | For ID lookup, manual verification                |

---

## 📑 Step-by-Step Procedure

### 1️⃣ Identify Your Baseline Policy or Initiative

Go to **Azure Portal > Policy > Definitions**, locate your baseline policy or initiative, and **copy its Resource ID**. Example:

- **Policy Definition ID**  
  `/providers/Microsoft.Authorization/policyDefinitions/0c5b5e7f-3b8f-4f0a-9c45-20f40165f04d`

- **Initiative (Policy Set) ID**  
  `/providers/Microsoft.Authorization/policySetDefinitions/benchmark-baseline-initiative`

---

### 2️⃣ Query ARG for Assignments Based on That ID

#### 🔹 A. Query for a Single Policy or Initiative

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/0c5b5e7f-3b8f-4f0a-9c45-20f40165f04d';
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project 
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
````

> Replace `policyDefinitions` with `policySetDefinitions` for initiatives.

---

#### 🔹 B. Query for Multiple Baseline Definitions

```kusto
let baselineIds = dynamic([
  "/providers/Microsoft.Authorization/policyDefinitions/policy1-id",
  "/providers/Microsoft.Authorization/policySetDefinitions/init1-id"
]);
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId in (baselineIds)
| project assignmentName, assignmentDisplayName = tostring(properties.displayName), scope = tostring(properties.scope), policyDefinitionId
```

---

### 3️⃣ (Optional) Export to CSV for QA Reporting

If you need a downloadable report:

```powershell
# Azure CLI + PowerShell
$query = @"
<ARG_QUERY_FROM_ABOVE>
"@

az graph query -q $query | ConvertFrom-Json | Select-Object -ExpandProperty data | Export-Csv -Path "PolicyAssignments-QA.csv" -NoTypeInformation
```

---

## ✅ Must-Know Details

| Item                      | Details                                                                       |
| ------------------------- | ----------------------------------------------------------------------------- |
| **Assignment Types**      | Only `policyassignments` are returned.                                        |
| **ARG is read-only**      | Cannot modify policy states. Only reporting.                                  |
| **Non-Compliance Status** | Not available in ARG. Use Policy Insights for compliance results.             |
| **Case Sensitivity**      | Use `=~` for case-insensitive string matches.                                 |
| **Initiatives**           | Return only the outer assignment, not inner policy members.                   |
| **Scopes**                | Validate scope alignment — subscription, management group, or resource group. |
| **Exclusions**            | Review `notScopes` for any exclusions that may impact enforcement.            |

---

## 🧪 Validation Checklist (for QA/QC)

| Validation Step                              | Description                          | Status |
| -------------------------------------------- | ------------------------------------ | ------ |
| Baseline policy definition/initiative exists | Validate by checking in Azure Portal | ✅/❌    |
| Assignments found in ARG                     | Confirm via query                    | ✅/❌    |
| Scope matches expected hierarchy             | Subscription / MG level              | ✅/❌    |
| Enforcement Mode is 'Default'                | If DoNotEnforce, flag it             | ✅/❌    |
| No unauthorized exclusions                   | Review `notScopes`                   | ✅/❌    |
| Matches baseline document                    | Cross-reference IDs, scope, etc.     | ✅/❌    |

---

## ⚠️ Common Pitfalls

| Pitfall                    | Description                                                    |
| -------------------------- | -------------------------------------------------------------- |
| ❌ Wrong policy ID used     | Always use the full resource ID, not just the name             |
| ❌ ARG used for compliance  | ARG doesn't show compliance status – use Policy Insights       |
| ❌ Forgot about initiatives | Initiative assignments and policy assignments are separate     |
| ❌ Scopes not checked       | Assignment may exist at resource group, not subscription level |

---

## 🔍 Alternatives and Enhancements

* **Policy Insights**: Use for compliance states and historical evaluations.
* **Workbook Dashboards**: Visualize assignments across scopes and time.
* **Azure Blueprints**: If used, also include blueprint-based assignments.
* **Azure Change Tracking (Activity Log)**: Audit changes to policy assignments.

---

## 📦 Appendix

### 📘 Sample Policy Definition ID Format

```text
/providers/Microsoft.Authorization/policyDefinitions/allow-tag-environment
```

### 📘 Sample Initiative ID Format

```text
/providers/Microsoft.Authorization/policySetDefinitions/security-baseline-2024
```

---

## 📞 Support

For assistance with this QA/QC process or extending it with automation:

* Contact: **[cloudgovernance@yourcompany.com](mailto:cloudgovernance@yourcompany.com)**
* Slack: `#azure-governance`
* Policy SME: *Your Name*

````

---

## 📄 CONFLUENCE COPY-PASTE VERSION

Simply paste the following into a Confluence page (with **"Code Block"** or **"Panel"** macros used for code/query snippets).

---

> *Page Title:* **Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)**  
> *Labels:* `azure-policy`, `governance`, `qa`, `baseline-validation`

---

### 🛡️ Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

**Owner:** Azure Policy SME  
**Audience:** Cloud Governance, Compliance, SecOps, Cloud Center of Excellence (CCoE), DevSecOps  
**Last Updated:** 2025-08-17

---

### 📌 Overview

This document describes how to validate that Azure Policy and Initiative assignments are intact and in accordance with your baseline using **Azure Resource Graph (ARG)**. This is part of your QA/QC process for policy governance.

---

### 🎯 Objective

> Given a known **Policy Definition ID** or **Policy Set (Initiative) ID**, find all **policy assignments** made from that definition across the tenant.

---

### 🛠️ Tools Required

| Tool                             | Purpose                                  |
|----------------------------------|------------------------------------------|
| Azure Resource Graph Explorer    | Run ARG queries in the Azure Portal      |
| Azure CLI / PowerShell           | Automate reporting and CSV exports       |
| Azure Policy Blade               | Lookup definition and assignment IDs     |

---

### 📑 Step-by-Step Procedure

#### 1️⃣ Identify Your Baseline Policy or Initiative

Navigate to:  
**Azure Portal > Policy > Definitions**,  
then copy the **resource ID** of the policy or initiative.

Example IDs:

- Policy Definition:  
  `/providers/Microsoft.Authorization/policyDefinitions/your-policy-id`

- Initiative (Policy Set):  
  `/providers/Microsoft.Authorization/policySetDefinitions/your-initiative-id`

---

#### 2️⃣ Query ARG for Assignments

##### Query for Single Policy or Initiative

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/your-policy-id';
PolicyResources
| where type == "microsoft.authorization/policyassignments"
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project 
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
````

##### Query for Multiple Definitions

```kusto
let baselineIds = dynamic([
  "/providers/Microsoft.Authorization/policyDefinitions/policy1-id",
  "/providers/Microsoft.Authorization/policySetDefinitions/init1-id"
]);
PolicyResources
| where type == "m
```


Here’s an enhanced Confluence-ready *and* Markdown version of the document—with authoritative refinements backed by official Microsoft guidance to ensure precision, clarity, and best practices.

---

# Confluence & Markdown: Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

---

## 1. MARKDOWN VERSION

````markdown
# ​​ Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

**Owner:** Azure Policy SME  
**Audience:** Cloud Governance, Compliance, SecOps, Cloud Center of Excellence (CCoE), DevSecOps  
**Last Updated:** 2025‑08‑17  
**Purpose:** Validate that all policy/initiative assignments remain intact and aligned with the intended **baseline configuration**, leveraging **Azure Resource Graph (ARG)** for compliance assurance.

---

##  Overview

Baseline policies and initiatives (security, tagging, governance) must remain consistently enforced. This guide illustrates how to retrieve all active assignments from a known policy definition or initiative ID—vital for QA/QC validation.

---

##  Objective

> Given a known **Policy Definition ID** or **Initiative (Policy Set) ID**, report all **Policy Assignments** across the tenant created from that baseline, including scope, enforcement mode, and exclusions.

---

##  Tools Required

| Tool                           | Purpose                                       |
|--------------------------------|-----------------------------------------------|
| Azure Resource Graph Explorer  | Execute queries interactively                  |
| Azure CLI / PowerShell         | Automate queries, export to CSV                |
| Azure Portal (Policy Blade)    | Lookup definition/initiative IDs for querying  |

---

##  Step‑by‑Step Procedure

### ​​​ Find the Policy Definition / Initiative ID

In Azure Portal, navigate to **Policy → Definitions**, select your baseline policy or initiative, and copy the full **Resource ID**:

- **Policy Definition ID**:  
  `/providers/Microsoft.Authorization/policyDefinitions/{your-policy-id}`  

- **Initiative (PolicySet) ID**:  
  `/providers/Microsoft.Authorization/policySetDefinitions/{your-initiative-id}`

---

### ​​​ ARG Query: Find Assignments for a Given Definition

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/{your-policy-id}';
PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    policyDefinitionId,
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
````

> Use `policySetDefinitions` for initiatives as appropriate.

---

### &#x20;ARG Query: Inventory of All Policy Assignments with Definition Metadata

```kusto
PolicyResources
| where type =~ 'Microsoft.Authorization/PolicyAssignments'
| project
    assignmentId = tolower(tostring(id)),
    assignmentDisplayName = tostring(properties.displayName),
    assignmentDefinitionId = tolower(properties.policyDefinitionId)
| join kind=leftouter (
    PolicyResources
    | where type =~ 'Microsoft.Authorization/PolicyDefinitions'
      or type =~ 'Microsoft.Authorization/PolicySetDefinitions'
    | project definitionId = tolower(id),
               definitionDisplayName = tostring(properties.displayName),
               definitionType = iff(type =~ 'Microsoft.Authorization/PolicySetDefinitions', 'Initiative', 'Policy')
) on $left.assignmentDefinitionId == $right.definitionId
```

This query aligns assignment records with their corresponding baseline definitions/initiatives, as outlined in ARG samples ([Gist][1]).

---

## Must-Know Limitations & Tips

| Consideration    | Notes                                                                                                                                                             |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Assignment Scope | Ensure scope filters align with subscriptions, MGs, or tenant root. ARG supports `authorizationScopeFilter` for custom behavior ([Microsoft Learn][2]).           |
| Policy Insights  | To retrieve compliance status and resource-level details, use **PolicyStates** queries from `microsoft.policyinsights/policystates` table ([Microsoft Learn][3]). |
| Exemptions       | Policy exemptions are now queryable under `microsoft.authorization/policyexemptions` in ARG ([Cloud, Systems Management and Automation][4]).                      |
| KQL Join Limits  | ARG restricts cross-table joins; use up to 3 joins or `mv-expand` instances per query ([Microsoft Learn][2]).                                                     |

---

## QA/QC Validation Checklist

| Step                     | Description                                                  | Status |
| ------------------------ | ------------------------------------------------------------ | ------ |
| Policy/Initiative ID     | Confirm the correct full Resource ID                         |        |
| Assignment Found         | Validate query results match expected baseline               |        |
| Scope Accuracy           | Ensure assignments are assigned at the intended level        |        |
| Enforcement Mode         | Check for `Default` vs `DoNotEnforce` and flag abnormal ones |        |
| Exclusions Review        | Audit `notScopes` to detect unplanned gaps                   |        |
| Baseline Cross‑Reference | Match against baseline documentation for QA confirmation     |        |

---

## Additional Enhancements

* Compliance Tracking: Use `PolicyStates` queries or integrate **Policy Insights** for resources compliance views.
* Dashboards: Build **Azure Monitor workbooks** visualizing policy distribution and exceptions.
* Automation: Integrate into CI/CD pipelines or periodically scheduled CLI/PowerShell checks.
* Auditing: Query **Policy Exemptions** and **History** via ARG, Activity Logs, or Policy Insights.

---

## Support & Contact

For automation help or deeper integration:

* Reach out: **[cloudgovernance@yourcompany.com](mailto:cloudgovernance@yourcompany.com)**
* Slack channel: `#azure-governance`
* Policy SME: *Your Name*

---

````

---

## 2. CONFLUENCE COPY‑AND‑PASTE VERSION

Use the following content in a Confluence page—leveraging **Code Block**, **Table**, and **Panel** macros as needed.

---

**Page Title:** Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)  
**Labels:** azure‑policy, governance, QA, baseline‑validation  

---

### ​​ Azure Policy QA/QC Reporting Using Azure Resource Graph (ARG)

**Owner:** Azure Policy SME  
**Audience:** Cloud Governance, Compliance, SecOps, CCoE, DevSecOps  
**Last Updated:** 2025‑08‑17  

---

#### Overview

This guide describes how to verify that policy assignments from your defined baseline (either as a policy or initiative) are consistently applied across the tenant using **Azure Resource Graph (ARG)**—crucial for QA/QC and governance.

---

#### Objective

> Given a known **Policy Definition ID** or **Initiative (Policy Set) ID**, retrieve and validate all **Policy Assignments** deriving from that baseline, including scope, enforcement mode, and exclusions.

---

#### Tools Required

| Tool                          | Purpose                                         |
|-------------------------------|-------------------------------------------------|
| **Azure Resource Graph Explorer** | Execute ARG queries interactively             |
| **Azure CLI / PowerShell**        | Automate queries and export outputs to CSV   |
| **Azure Portal (Policy blade)**   | Locate and copy Resource IDs                 |

---

#### Procedure

**1. Copy the Baseline Resource ID**
- Navigate: *Azure Portal → Policy → Definitions*
- Copy the full Resource ID of the policy or initiative, for example:
  - `/providers/Microsoft.Authorization/policyDefinitions/{...}`
  - `/providers/Microsoft.Authorization/policySetDefinitions/{...}`

**2. ARG Query: Assignments by Definition**

```kusto
let targetDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/{your-policy-id}';
PolicyResources
| where type == 'microsoft.authorization/policyassignments'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| where policyDefinitionId =~ targetDefinitionId
| project
    assignmentName = name,
    assignmentDisplayName = tostring(properties.displayName),
    scope = tostring(properties.scope),
    enforcementMode = tostring(properties.enforcementMode),
    notScopes = properties.notScopes,
    assignmentId = id
````

> To filter by initiative, switch to `policySetDefinitions`.

**3. ARG Query: Full Assignment Inventory with Metadata**

```kusto
policyResources
| where type =~ 'Microsoft.Authorization/PolicyAssignments'
| project assignmentId = tolower(tostring(id)), assignmentDisplayName = tostring(properties.displayName), assignmentDefinitionId = tolower(properties.policyDefinitionId)
| join kind = leftouter (
  policyResources
  | where type =~ 'Microsoft.Authorization/PolicyDefinitions' or type =~ 'Microsoft.Authorization/PolicySetDefinitions'
  | project definitionId = tolower(id), definitionDisplayName = tostring(properties.displayName), definitionType = iff(type =~ 'Microsoft.Authorization/PolicySetDefinitions', 'Initiative', 'Policy')
) on $left.assignmentDefinitionId == $right.definitionId
```

This maps assignments to their baseline definitions as per Microsoft ARG inventory samples ([Gist][1]).

---

#### Must‑Know Considerations

* **Query Scope Control:** You can use `authorizationScopeFilter` for more refined query scoping via API ([Microsoft Learn][2]).
* **Compliance Status Needs:** Use `PolicyStates` under `microsoft.policyinsights` to analyze compliance metrics ([Microsoft Learn][3]).
* **Exemptions:** Query `microsoft.authorization/policyexemptions` for exemptions details via ARG ([Cloud, Systems Management and Automation][4]).
* **Join Limitations:** ARG limits multiple joins—avoid exceeding three per query ([Microsoft Learn][2]).

---

#### QA/QC Checklist

| Step                          | Description                                                   | Status |
| ----------------------------- | ------------------------------------------------------------- | ------ |
| Baseline ID Confirmed         | Verify you’re using the correct full Resource ID              |        |
| Assignment Query Results      | Confirm matches expected baseline assignments                 |        |
| Scope Validation              | Ensure assignments are present at intended scope              |        |
| Enforcement Mode Review       | Flag assignments using `DoNotEnforce` if not expected         |        |
| Exclusion Audit               | Review `notScopes` for any unintended exclusions              |        |
| Cross‑Reference with Baseline | Verify each assignment against written baseline documentation |        |

---

#### Enhancements and Next Steps

* Incorporate **Policy Insights** for compliance assessment.
* Visualize data in **Azure Monitor workbooks**.
* Automate via **CLI/PowerShell exports**.
* Use **exemption tracking** and **activity logs** for audit trails.

---


---

Let me know if you’d like templated exports (PDF, HTML), automation scripts, or dashboards built from this foundation!

[1]: https://gist.github.com/timothywarner/8e5b6dea296f506871223883eb33059e?utm_source=chatgpt.com "Azure Resource Graph Explorer built-in sample that inventories Azure Policy assignments. · GitHub"
[2]: https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/query-language?utm_source=chatgpt.com "Understand the query language - Azure Resource Graph | Microsoft Learn"
[3]: https://learn.microsoft.com/en-us/azure/governance/policy/samples/resource-graph-samples?utm_source=chatgpt.com "Azure Resource Graph sample queries for Azure Policy - Azure Policy | Microsoft Learn"
[4]: https://www.cloudsma.com/2023/09/azure-policy-exemptions-resource-graph/?utm_source=chatgpt.com "Azure Policy Exemptions Added to Resource Graph - Cloud, Systems Management and Automation"

