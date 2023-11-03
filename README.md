# DeathCon Workshop - Historically grown Active Directory Environments - The dead bodies in your basement
***
## Identification of permission issues on AD object

### Installation of Bloodhound and neo4j
As told in my talk we will use Bloodhound and neo4j to identify potential dangerous permissions within the Active Directory environment.

To do this you will need to install neo4j and Bloodhound on your machine:
	[Windows — BloodHound 4.3.1 documentation](https://bloodhound.readthedocs.io/en/latest/installation/windows.html)
	

## Go to the neo4j webserver and run a testquery

After the installation is done you should be able to reach the neo4j web interface on:
- http://127.0.0.1:7474/browser/

Logon to the web interface and run a test cypher query:

```cypher
MATCH (n:Domain) return n.name as Domain, n.functionallevel as FunctionalLevel, n.highvalue as HighValue, n.domain as DNS
```

## Object owners

### Identifying object owners using neo4j
Let´s identify users that are object owners

```cypher
MATCH (u:User)-[:Owns]->(n) RETURN count(DISTINCT(n.name)) AS OwnedObjects, u.name AS USER ORDER BY count(DISTINCT(n.name)) DESC
```

### Resolving the object ownerships of a user
Now, we can resolve the object ownership for the users we identified in the query we ran earlier.

We will use Bloodhound for this. Open Bloodhound and login with the neo4j credentials. 
After successful logon, please import the Bloodhound data that is delivered when you download this repository.
You drag the ZIP File into the Bloodhound application and wait until the import is done.

Now, we can also run cypher queries and return a visual representation of the data.

The following query lookups up all ownership permissions of the user `ABAR@PWNYFARM.LOCAL`

```cypher
MATCH (n:User) WHERE n.name =~ 'ABAR@PWNYFARM.LOCAL'
MATCH (m) WHERE NOT m.name = n.name
MATCH p=allShortestPaths((n)-[r:Owns|SQLAdmin*1..]->(m))
RETURN p
```

You could also get the resolving done using Cypher a cypher query in the neo4j web interface: 
- Try to use a cypher query to return all AD object ownerships in the domain

### Identifying first degree object controllers

When BloodHound refers to "outbound first degree object," it is talking about direct relationships or connections that a given object (such as a user or computer) has within the Active Directory environment. These relationships are the initial set of direct links an object has to other entities within the domain, which could include group memberships, permissions, and trusts, among other connections.

By understanding the direct relationships and permissions (first-degree connections), security teams can identify potential paths an attacker might use to compromise systems. This is crucial for preventing lateral movement within a network, which is a common tactic used by attackers after gaining initial access.

The following cypher query returns first degree object controller:

```cypher
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true 
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, controlled 
ORDER BY controlled DESC 
LIMIT 500
```

### Identifying group delegated object controllers

For example, if User A is member of Group B, and Group B has control over an object, then User A is a group delegated object controller for that object because they can potentially leverage their membership in Group B to control the object. There is no first degree connection between the object and the users. 


The following cypher query returns group delegated object controllers:

```cypher
MATCH p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) WHERE r2.isacl=true
WITH u.name as name, LABELS(u)[1] as type, g.highvalue as highly_privileged,
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL 
RETURN type, name, highly_privileged, controlled 
ORDER BY controlled DESC 
LIMIT 500
```

### Identifying transitive object controllers

This is the most exhaustive query you can probably run... This will resolve all transitive object controllers. In big environments that can take days to resolve...

But for the sake of completeness... here it is.

```cypher
// Transitive Object Control in domain (TAKES ENORMOUS TIME TO COMPUTE! You were warned)
MATCH p=shortestPath((u)-[r1:MemberOf|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(n))
WHERE u<>n
WITH u.name as name, LABELS(u)[1] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL
RETURN type, name, controlled 
ORDER BY controlled DESC 
LIMIT 500
```


## File permission issues

For this exercise you can use the following repository:
- https://github.com/michiiii/Get-FileShareAccessRights

To identify file permission issues I added the `NETLOGON_permissions.clixml` this is an export from my environment that I made vulnerable.

```powershell
## Import the NETLOGON_permissions.clixml into a variable
### Normally you would do this by running: 
###### $permissions = Get-FileShareCriticalPermissions -NetworkSharePath "\\pwnyfarm.local\netlogon"
###### $permissions = Get-FileShareCriticalPermissions -NetworkSharePath "\\pwnyfarm.local\sysvol"
$permissions = Import-Clixml -Path .\NETLOGON_permissions.clixml

# See users that have potential critical rights
Get-CriticalPermissionOverview -SharePermissions $permissions

# Finally you can search for one of the users that have been shown in the overview
Get-CriticalPermissionsByUser -SharePermissions $permissions -UserName "Authenticated Users"

```

 

***
# References
- TBD
