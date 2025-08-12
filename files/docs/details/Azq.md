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
