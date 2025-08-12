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
