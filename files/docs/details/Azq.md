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

