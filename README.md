# DeathCon Workshop - Historically grown Active Directory Environments - The dead bodies in your basement
***
This is the repository for the workshop to my DeathCon Talk:

- https://www.youtube.com/watch?v=m5QHyQk-9ys

## Identification of permission issues on AD object

### Installation of Bloodhound and neo4j
As told in my talk we will use Bloodhound and neo4j to identify potential dangerous permissions within the Active Directory environment.

To do this you will need to install neo4j and Bloodhound on your machine:
- [Windows — BloodHound 4.3.1 documentation](https://bloodhound.readthedocs.io/en/latest/installation/windows.html)
	

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
WITH u.name as name, LABELS(u)[0] as type, 
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
WITH u.name as name, LABELS(u)[0] as type, g.highvalue as highly_privileged,
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
WITH u.name as name, LABELS(u)[0] as type, 
COUNT(DISTINCT(n)) as controlled 
WHERE name IS NOT NULL
RETURN type, name, controlled 
ORDER BY controlled DESC 
LIMIT 500
```

There is also a tool you can use with a bigger collection of neo4j queries:
- https://github.com/PlumHound/PlumHound

More intersting cypher queries
- https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md
- https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12
- https://gist.github.com/seajaysec/c7f0995b5a6a2d30515accde8513f77d

PS: Some of the queries referenced don´t work anymore

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

### Detection
I am not a detection engineer, but I can just think about placing a useless honeypot file with interesting permissions on one of the shares.
Edit the SACL to log specific operations on that file e.g. write operations and trigger alarms as they happen.




## Further points not mentioned in this talk but to be considered:

 ## Legacy Protocols and Services
- Net-NTLMv1: Older authentication protocols like Net-NTLMv1 can be are vulnerable and the use of these protocols can be exploited
- SMBv1 (Server Message Block version 1): If still in use, this file-sharing protocol is known for vulnerabilities such as those exploited by the WannaCry ransomware.

### Weak passwords
- The standards in 2005 and 2023 differ greatly when we are speaking about password security.
- Perform regular password audit to identify accounts with deprecated and weak passwords.

## Deprecated Configuration
- **Unconstrained Delegation**: Configurations that permit unconstrained delegation can allow attackers to impersonate any user to any service, which is particularly dangerous.
- **Old Group Policies**: Legacy GPOs might inadvertently enforce insecure settings on newer systems.

## Orphaned Objects and Accounts
- **Stale User Accounts**: Accounts belonging to former employees could be compromised and used as entry points.
- **Orphaned SID (Security Identifier) Histories**: When domains are merged or migrated, SID history can allow for privilege escalation if not managed properly.

## Lack of Monitoring and Auditing
- **Inadequate Auditing**: Without proper auditing settings, malicious activities can go unnoticed.

## Unstructured Access Permissions
- **Excessive User Privileges**: Over time, users may accumulate unnecessary permissions, leading to a violation of the principle of least privilege.
- **Nested Group Permissions**: Complex nested group memberships can obscure who has access to what, making oversight difficult.

## Disjointed Administrative Practices
- **Inconsistent Administrative Approaches**: Each generation of IT administrators may have brought its own approach to managing the AD, resulting in a patchwork of practices that can be hard to secure.
- **Lack of Standardization**: Without standard practices, it becomes challenging to ensure that configurations meet security best practices.

## Remediation Strategies
### Auditing and Clean-Up:
- Conduct a comprehensive audit of the AD environment to identify and rectify any outdated configurations, unnecessary user rights assignments, and legacy protocols still in use.

### Implementing a Least Privilege Model:
- Ensure that users only have the permissions necessary to perform their job functions, minimizing the potential damage of a compromised account.

### Streamlining Group Policy Objects:
- Review and consolidate GPOs to avoid conflicting settings and to ensure they meet current security standards.

### Regularly Scheduled Reviews:
- Institute periodic reviews of the AD environment to ensure it evolves in line with current best practices and security standards. 

### Education and Training:
- Teach your administrators to work with tools like PingCastle and Bloodhound. It´s best thing you can do. Provide ongoing education for IT staff regarding the latest AD management and security best practices.

### Documentation and Change Management:
- Establish a rigorous documentation and change management process to maintain a history of modifications and to support the troubleshooting of issues.

### Employing Advanced Security Measures:
- Utilize tools for anomaly detection, implement advanced threat protection solutions, and embrace a Zero Trust model to further bolster security.

***
# References

