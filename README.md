<p align="center">
  <img src="https://specterops.io/wp-content/uploads/sites/3/2025/04/1_E0I-QO-1U8yROC6FbUyHGA.png" alt="BloodHound logo" width="220">
</p>
# BloodHound Cypher Queries – Red Team Operation

**Sources:** SpecterOps BloodHound Query Library, Hausec cheat sheet, knavesec custom queries, stmxcsr, arth0s, community.  
**Use:** BloodHound CE/Enterprise or Neo4j browser. Replace `DOMAIN.GR` / `TESTLAB.LOCAL` / `EXAMPLE.LOCAL` with your domain.

---

## Quick Checklist (start here)

**What:** Map your goal to the sections that have the right queries.  
**Why:** Use as a reminder: “I need persistence” → KRBTGT, GPO, AddMember, DCSync; “I need creds” → Kerberoast, AS-REP, GMSA, LAPS, DCSync.

| Goal | Section to query |
|------|------------------|
| **Persistence** | KRBTGT (§29), DA sessions (§8), GPO control (§6), AddMember to DA (§21), DCSync (§5) |
| **Lateral movement** | CanRDP, AdminTo (§10), ExecuteDCOM (§20), LAPS (§7), unconstrained delegation + coerced auth (§4) |
| **Privilege escalation** | Shortest path to DA (§2), ACL abuse (§9), AddMember (§21), GpLink (§6) |
| **Credential access** | Kerberoast, AS-REP (§3), GMSA (§19), LAPS (§7), DCSync (§5) |
| **Cross-domain** | Trusts (§28), cross-domain HasSession (§24) |
| **Cloud pivot** | Azure/Entra (§32) |
| **Stealth** | Paths excluding high-value nodes (§33) |
| **Misconfig** | Password not required, AS-REP (§3, §15), unconstrained delegation (§4), MAQ (§31), Domain Users dangerous rights (§22) |

---

## Replace Your Domain (do this first)

In queries below, change:
- `DOMAIN.GR`, `TESTLAB.LOCAL`, `EXAMPLE.LOCAL` → **your domain** (e.g. `CONTOSO.LOCAL`)
- `-513` (Domain Users) / `-512` (Domain Admins) / `-516` (Domain Controllers) stay the same unless your domain uses different RIDs.

---

## 1. Where to Get More Queries

**What:** Links to official and community Cypher query libraries and cheat sheets.  
**Why:** Built-in BloodHound queries don’t cover every abuse; custom Cypher unlocks trust paths, DCSync, Azure, and niche misconfigs.

| Resource | URL / Notes |
|----------|-------------|
| **SpecterOps Query Library** | https://queries.specterops.io/ – searchable, official + community |
| **BloodHound Query Library (GitHub)** | https://github.com/SpecterOps/BloodHoundQueryLibrary – download `Queries.zip`, import in BloodHound: Explore → Cypher → Import |
| **Hausec Cypher Cheatsheet** | https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/ |
| **knavesec Custom Queries** | https://github.com/knavesec/BloodHound-Custom-Queries |
| **Compass Security** | https://github.com/CompassSecurity/BloodHoundQueries |
| **BloodHound Cypher docs** | https://bloodhound.specterops.io/analyze-data/cypher-search |

---

## 2. Attack Paths – Shortest Path to Domain Admins

**What:** Queries that find the shortest graph path from a starting node (user, computer, owned) to the Domain Admins group.  
**Why:** Shows the exact abuse chain to DA (e.g. “you → GenericAll → User X → MemberOf DA”); follow each edge to escalate.

**Shortest path from a user/computer to Domain Admins (GUI-friendly):**
```cypher
MATCH (n:User),(m:Group) WHERE m.name =~ '(?i).*DOMAIN ADMINS@.*'
MATCH p = shortestPath((n)-[*1..]->(m))
RETURN p
```

**Shortest path from owned users to Domain Admins:**
```cypher
MATCH p = shortestPath((m:User)-[r]->(b:Group)) 
WHERE m.owned AND b.name CONTAINS 'DOMAIN ADMINS' 
RETURN p
```

**Shortest path from computers to Domain Admins (include common abuse edges):**
```cypher
MATCH (n:Computer),(m:Group {name:'DOMAIN ADMINS@EXAMPLE.LOCAL'})
MATCH p = shortestPath((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(m))
RETURN p
```

**Shortest path from non-privileged users (admincount=false) to Domain Admins:**
```cypher
MATCH (n:User {admincount:false}),(m:Group {name:'DOMAIN ADMINS@EXAMPLE.LOCAL'})
MATCH p = shortestPath((n)-[*1..]->(m))
RETURN p
```

**Kerberoastable users that have a path to Domain Admins:**
```cypher
MATCH (u:User {hasspn:true})
MATCH (g:Group) WHERE g.name CONTAINS 'DOMAIN ADMINS'
MATCH p = shortestPath((u)-[*1..]->(g))
RETURN p
```

**BloodHound CE – shortest path to Domain Admins with full edge list (includes ADCS, DCSync, ReadGMSAPassword, etc.):**
```cypher
MATCH p = shortestPath((n:User)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GpLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor*1..]->(m:Group))
WHERE n.enabled = True AND m.objectid ENDS WITH '-512' RETURN p
```

**From owned principals (BloodHound CE uses `system_tags`; legacy used `owned`):**
```cypher
MATCH p = shortestPath((n:User)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GpLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor*1..]->(m:Group))
WHERE n.system_tags CONTAINS 'owned' AND m.objectid ENDS WITH '-512' RETURN p
```

**From computers excluding DCs (same full edge list):**
```cypher
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(c1.name) AS domainControllers
MATCH p = shortestPath((n:Computer)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GpLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor*1..]->(m:Group))
WHERE NOT n.name IN domainControllers AND m.objectid ENDS WITH '-512' RETURN p
```

---

## 3. Kerberoast & AS-REP Roasting

**What:** Find users with SPNs (Kerberoast) or “do not require preauth” (AS-REP roast) so you can request ticket material and crack hashes offline.  
**Why:** Kerberoast/AS-REP yield crackable hashes; high-value or old passwords often crack quickly. No DA needed to request; then use cracked creds for lateral movement or privilege escalation.

**All Kerberoastable users (has SPN):**
```cypher
MATCH (n:User) WHERE n.hasspn = true RETURN n
```

**Kerberoastable users with old passwords (>5 years):**
```cypher
MATCH (u:User) WHERE u.hasspn = true 
  AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) 
  AND NOT u.pwdlastset IN [-1.0, 0.0] 
RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset
```

**SPNs containing a keyword (e.g. SQL):**
```cypher
MATCH (u:User) WHERE ANY(x IN u.serviceprincipalnames WHERE toUpper(x) CONTAINS 'SQL')
RETURN u
```

**MSSQL SPNs (PowerUpSQL-style):**
```cypher
MATCH (n {hasspn:true}) 
UNWIND [spn IN n.serviceprincipalnames WHERE spn STARTS WITH 'MSSQLSvc'] AS list 
RETURN n.name, list
```

**AS-REP Roastable (Do not require Kerberos preauth):**  
*(Property may be `dontreqpreauth` or `donotreqpreauth` depending on collector.)*
```cypher
MATCH (u:User {dontreqpreauth: true}) RETURN u
```
```cypher
MATCH (u:User {enabled:true, donotreqpreauth:true}) RETURN u
```

---

## 4. Unconstrained & Constrained Delegation

**What:** Find computers/users that can delegate to other services (unconstrained = any service; constrained = specific SPNs).  
**Why:** Unconstrained on a DC or workstation: coerce a DA to authenticate there (e.g. printer bug), steal their TGT from memory → DCSync or full DA. Constrained: if you control the account, request a ticket for a high-value SPN.

**All computers with unconstrained delegation:**
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

**Unconstrained delegation on non-DC computers (high value):**
```cypher
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(c1.name) AS domainControllers
MATCH (c2:Computer {unconstraineddelegation:true}) 
WHERE NOT c2.name IN domainControllers 
RETURN c2.name, c2.operatingsystem ORDER BY c2.name
```

**Users with constrained delegation and targets:**
```cypher
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name ORDER BY u.name
```

**Constrained delegation – users:**
```cypher
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate
```

**Constrained delegation – computers:**
```cypher
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate
```

---

## 5. DCSync / Replication (GetChanges, GetChangesAll)

**What:** Find principals that have GetChanges and GetChangesAll on the domain/DC object—i.e. can perform DCSync (replicate all hashes from the DC).  
**Why:** DCSync dumps every account’s NTLM hash without touching the DC; then pass-the-hash or crack. Often the fastest path to full domain compromise.

**Important:** Default BloodHound path queries may omit `GetChanges` and `GetChangesAll`. Use `[*1..]` or explicitly include these edges to see DCSync paths.

**Principals with control that can lead to DCSync (query domain/DC nodes for GetChanges/GetChangesAll in BloodHound).**  
Use “Shortest path to Domain Controllers” or “Shortest path to High Value” and ensure your relationship list includes **GetChanges** and **GetChangesAll** when running custom path queries.

**Example – paths from a user to DC (include replication rights):**
```cypher
MATCH (u:User {name:'USER@EXAMPLE.LOCAL'}), (dc:Computer) WHERE dc.isdc = true
MATCH p = shortestPath((u)-[r:MemberOf|GetChanges|GetChangesAll|AllExtendedRights|GenericAll|WriteDacl|Owns|GenericWrite|WriteOwner*1..]->(dc))
RETURN p
```

---

## 6. GPO Abuse (WriteGPLink, GpLink)

**What:** Find who can create/modify GPOs or link GPOs to the domain/OUs (WriteGPLink, GenericAll, etc. on GPO or domain).  
**Why:** With GpLink on the domain: create a GPO that runs a scheduled task or sets a password; link it to the domain → instant DA or backdoor. SharpGPOAbuse, New-GPOImmediateTask.

**Users/Groups with interesting rights over GPOs:**
```cypher
MATCH p = (u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO)
RETURN p LIMIT 25
```

**All GPOs:**
```cypher
MATCH (n:GPO) RETURN n
```

**GPOs with keyword in name:**
```cypher
MATCH (n:GPO) WHERE n.name CONTAINS 'SERVER' RETURN n
```

---

## 7. LAPS (Local Administrator Password Solution)

**What:** Find principals that can read (or sync) the LAPS-managed local admin password on computers.  
**Why:** LAPS stores a unique local admin password per machine in AD; if you can read it, you get local admin on that host → lateral movement, then look for DA sessions or further abuse.

**Computers where a principal can read LAPS password:**  
Use BloodHound’s built-in “Can read LAPS password” / **ReadLAPSPassword** edge, or:

**Paths from a user to computers (include ReadLAPSPassword):**
```cypher
MATCH (u:User)-[r:ReadLAPSPassword]->(c:Computer) RETURN u.name, c.name
```

**Groups that can read LAPS on computers:**
```cypher
MATCH (g:Group)-[:ReadLAPSPassword]->(c:Computer) RETURN g.name, c.name ORDER BY g.name
```

---

## 8. High-Value Targets & Sessions

**What:** List DA/EA members and where they have active sessions (HasSession from computers to those users).  
**Why:** If a DA is logged into a box you can reach (RDP, AdminTo, etc.), compromise that box and dump their creds (e.g. Mimikatz) → instant DA. Sessions = where to hunt.

**All Domain Admins (by group):**
```cypher
MATCH (g:Group) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*'
MATCH (g)<-[:MemberOf*1..]-(u) RETURN u.name AS User
```

**Active Domain Admin sessions (where DAs are logged in):**
```cypher
MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512'
MATCH p = (c:Computer)-[:HasSession]->(n) RETURN p
```

**Domain Admins or Administrators with HasSession on non-DC computers (high-value targets):**
```cypher
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516'
WITH COLLECT(c1.name) AS domainControllers
MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-544'
MATCH p = (c:Computer)-[:HasSession]->(n) WHERE NOT c.name IN domainControllers RETURN p
```
*(DA/Admin sessions on workstations = prime targets; exclude DCs since compromising a DC is already game over.)*

**Sessions of a specific group (e.g. Domain Admins):**
```cypher
MATCH (n:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@EXAMPLE.LOCAL'})
MATCH p = (c:Computer)-[:HasSession]->(n) RETURN p
```

**Paths from any principal to high-value groups:**
```cypher
MATCH p = (n:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN p
```

**Users with path to high-value (list):**
```cypher
MATCH (u:User) MATCH (g:Group {highvalue:true})
MATCH p = shortestPath((u)-[*1..]->(g))
RETURN DISTINCT u.name AS USER, u.enabled AS ENABLED, count(p) AS PATHS ORDER BY u.name
```

---

## 9. ACL Abuse (GenericAll, WriteDacl, ForceChangePassword, etc.)

**What:** Find low-priv users who have dangerous rights on other users or computers (GenericAll, WriteDacl, ForceChangePassword, Owns, etc.).  
**Why:** ForceChangePassword → set a known password and log in as that user. GenericAll/WriteDacl/Owns → add yourself to a group, reset password, or take ownership and grant yourself rights. One-hop to privilege escalation.

**Unprivileged users with ACL-type rights over other users:**
```cypher
MATCH (n:User {admincount:false}) MATCH (m:User) WHERE NOT m.name = n.name
MATCH p = allShortestPaths((n)-[r:AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(m))
RETURN p
```

**Unprivileged users with ACL-type rights over computers:**
```cypher
MATCH (n:User {admincount:false})
MATCH p = allShortestPaths((n)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AdminTo|CanRDP|ExecuteDCOM|ForceChangePassword*1..]->(m:Computer))
RETURN p
```

**Who can reset passwords (ForceChangePassword):**
```cypher
MATCH p = (m:Group)-[r:ForceChangePassword]->(n:User) RETURN m.name, n.name ORDER BY m.name
```

**Who has local admin (AdminTo) on computers:**
```cypher
MATCH p = (m:User)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
```

**Who can RDP (CanRDP):**
```cypher
MATCH p = (m:Group)-[r:CanRDP]->(n:Computer) RETURN m.name, n.name ORDER BY m.name
```

---

## 10. Local Admin & RDP

**What:** Find who can RDP to or has local admin (AdminTo) on which computers; also machines with no admins or GenericAll without AdminTo.  
**Why:** RDP/AdminTo = lateral movement. Compromise a box, look for sessions (DA?), LAPS, or next hop. No-admins or GenericAll-only machines can be quick wins (RCE or takeover).

**Workstations Domain Users can RDP to (replace -513 with your Domain Users RID if needed):**
```cypher
MATCH p = (g:Group)-[:CanRDP]->(c:Computer) 
WHERE g.objectid ENDS WITH '-513' AND NOT c.operatingsystem CONTAINS 'Server' 
RETURN p
```

**Servers Domain Users can RDP to:**
```cypher
MATCH p = (g:Group)-[:CanRDP]->(c:Computer) 
WHERE g.objectid ENDS WITH '-513' AND c.operatingsystem CONTAINS 'Server' 
RETURN p
```

**Computers with no local admins (potential misconfig):**
```cypher
MATCH (n)-[r:AdminTo]->(c:Computer) WITH COLLECT(c.name) AS compsWithAdmins
MATCH (c2:Computer) WHERE NOT c2.name IN compsWithAdmins RETURN c2.name ORDER BY c2.name
```

**Users with GenericAll on a computer but not AdminTo (potential escalation):**
```cypher
MATCH (u:User)-[:GenericAll]->(c:Computer) 
WHERE NOT u.admincount AND NOT (u)-[:AdminTo]->(c) 
RETURN u.name, c.name
```

---

## 11. Sensitive Data & Misconfigurations

**What:** Find objects with descriptions, userPassword, or broad groups (Domain Users, Everyone) with dangerous rights.  
**Why:** Descriptions sometimes contain passwords; userPassword in LDAP = plaintext creds; if Domain Users have GenericAll/CanRDP/etc., every domain user can abuse it—massive blast radius.

**Computer descriptions (admins sometimes put passwords here):**
```cypher
MATCH (c:Computer) WHERE c.description IS NOT NULL RETURN c.name, c.description
```

**User objects with userPassword set (wald0):**
```cypher
MATCH (u:User) WHERE u.userpassword IS NOT NULL RETURN u.name, u.userpassword
```

**Enabled users who have never logged in:**
```cypher
MATCH (n:User) WHERE n.lastlogontimestamp = -1.0 AND n.enabled = TRUE RETURN n.name ORDER BY n.name
```

**What Domain Users / Authenticated Users / Everyone have (dangerous rights):**
```cypher
MATCH p = (m:Group)-[r:AddMember|AdminTo|AllExtendedRights|AllowedToDelegate|CanRDP|Contains|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|GetChanges|GetChangesAll|Owns|ReadLAPSPassword|WriteDacl|WriteOwner]->(t)
WHERE m.objectid ENDS WITH '-513' OR m.objectid ENDS WITH '-515' OR m.objectid ENDS WITH '-11' OR m.objectid ENDS WITH '-1-0'
RETURN m.name, TYPE(r), t.name, t.enabled
```

**Domain Users with rights they shouldn’t have (Owns, WriteDacl, GenericAll, ExecuteDCOM, etc.) on computers:**
```cypher
MATCH p = (m:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer)
WHERE m.name STARTS WITH 'DOMAIN USERS' RETURN p
```

---

## 12. AD CS / Certificate Templates (ESC1-style)

**What:** Identify certificate templates that allow enrollee-supplied subject and client auth (ESC1) and who can enroll.  
**Why:** ESC1 lets a low-priv user request a cert as any user (e.g. DA); use that cert to authenticate (PKINIT) → domain takeover without touching passwords. Certipy, PSPKIAudit.

BloodHound CE/Enterprise has **AD CS** and **Cert Template** nodes and built-in AD CS attack path analysis. Use the UI “Certificate template” and “AD CS” path queries when available.

**Certificate templates (if modeled as nodes):**  
Use built-in “Abusable certificate templates” or “Shortest path to Domain Admins” and ensure cert template → enrollment → domain escalation paths are enabled in your BloodHound version.

**Concept for ESC1:** Find templates where enrollee supplies subject, no manager approval, and Client Authentication EKU; then find who can enroll. This is often done via Certipy or BloodHound’s AD CS features rather than raw Cypher alone.

**ESC3 – Certificate Request Agent (EKU 1.3.6.1.4.1.311.20.2.1), no manager approval:**
```cypher
MATCH p = ()-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE "1.3.6.1.4.1.311.20.2.1" IN ct.ekus AND ct.requiresmanagerapproval = False
AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1) RETURN p
```

**ESC3 excluding admin accounts:**
```cypher
MATCH p = (n)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE n.admincount = False AND "1.3.6.1.4.1.311.20.2.1" IN ct.ekus AND ct.requiresmanagerapproval = False
AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1) RETURN p
```

**All ADCS escalation edges (ESC1, ESC3, ESC4, etc.) for non-admin principals:**
```cypher
MATCH p = (n)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->()
WHERE n.admincount = False RETURN p
```

**ESC4 – Write privileges on certificate template (excluding DA/Administrators):**
```cypher
MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-544'
WITH COLLECT(n.name) AS adminsGroups
MATCH p = (u:User)-[:WriteDacl|GenericAll|AllExtendedRights|GenericWrite|Owns]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE NOT u.name IN adminsGroups RETURN p
```

**ESC7 – ManageCA on Enterprise CA (excluding DA/Administrators):**
```cypher
MATCH (n:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-544'
WITH COLLECT(n.name) AS adminsGroups
MATCH p = (u:User)-[:ManageCA]->(:EnterpriseCA) WHERE NOT u.name IN adminsGroups RETURN p
```

---

## 13. Neo4j for Threat Hunting (Different Use Case)

**What:** BloodHound’s Neo4j is for AD attack paths; separate “threat intel” graphs may use Neo4j for IOCs and reports.  
**Why:** Don’t expect BloodHound Cypher to query IOCs; use these queries for AD abuse. For threat intel, use a different graph schema.

**BloodHound Neo4j** is for **Active Directory attack paths** (users, computers, groups, ACLs, sessions).

**Threat-hunting / intel Neo4j** usually means a **separate graph** of:
- IOCs (IPs, domains, hashes, emails)
- Threat reports, malware families, CVE
- Links between IOCs and reports

For AD-focused red teaming, the queries in sections 1–12 are what you want. For **threat intel** graphs, use different node/edge schemas and Cypher (e.g. “all IOCs linked to report X”, “all malware sharing this C2”).

---

## 14. Console-Only / Export-Friendly Queries

**What:** Queries that return tabular or text output (names, dates, path as string) for Neo4j console or CSV export.  
**Why:** GUI shows graphs; for reports, ticketing, or scripting you need lists and exportable data.

**List Kerberoastable users with password last set (for CSV export):**
```cypher
MATCH (u:User) WHERE u.hasspn = true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset
```

**Epoch to readable date (password last set):**
```cypher
MATCH (n:User) WHERE n.enabled = TRUE 
RETURN n.name, datetime({epochSeconds: toInteger(n.pwdlastset)}), datetime({epochSeconds: toInteger(n.lastlogon)}) ORDER BY n.pwdlastset
```

**Full path as text (replace `p` with your path variable from another query):**
```cypher
MATCH p = ...
WITH [node IN nodes(p) | coalesce(node.name, '')] AS nodeLabels,
     [rel IN relationships(p) | type(rel)] AS relLabels,
     length(p) AS path_len
WITH reduce(path = '', x IN range(0, path_len - 1) | path + nodeLabels[x] + ' - ' + relLabels[x] + ' -> ') AS path,
     nodeLabels[path_len] AS final_node
RETURN path + final_node AS full_path
```

---

## 15. Password & Account Misconfigurations

**What:** Find accounts with “password not required,” “never expires,” blank/weak policy, or never logged in / disabled.  
**Why:** Password not required = easier relay or abuse; never expires = old creds still valid; never logged in / disabled = good for persistence or backdoor if you re-enable.

**Enabled users – password not required (blank / no password):**
```cypher
MATCH (u:User {enabled:true, passwordnotreqd:true}) RETURN u.name, u.displayname
```

**Enabled users – password never expires:**
```cypher
MATCH (u:User {enabled:true}) WHERE u.pwdneverexpires = true RETURN u.name
```

**Enabled users – password not required AND never expires:**
```cypher
MATCH (u:User {enabled:true}) WHERE u.passwordnotreqd = true AND u.pwdneverexpires = true RETURN u.name
```

**Active accounts that have never logged in:**
```cypher
MATCH (u:User {enabled:true}) WHERE u.lastlogon = -1 AND u.lastlogontimestamp = -1 RETURN u.name
```
```cypher
MATCH (n:User) WHERE n.lastlogontimestamp = -1.0 AND n.enabled = TRUE RETURN n.name ORDER BY n.name
```

**Disabled users (for cleanup / stale account hunting):**
```cypher
MATCH (u:User {enabled:false}) RETURN u.name, u.displayname
```

**Users with last logon in last N days (e.g. 90):**
```cypher
MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) AND NOT u.lastlogon IN [-1.0, 0.0] RETURN u.name, u.lastlogon ORDER BY u.lastlogon
```

**Users with password last set in last N days (e.g. 90):**
```cypher
MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (90 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset
```

---

## 16. Owned Nodes & Paths From Owned

**What:** List nodes you marked as “owned” and find paths from them (RDP, shortest path to DA/high-value).  
**Why:** During an engagement you mark compromised accounts; these queries show “from what I own, where can I go next?”—RDP targets and escalation paths.

*(BloodHound CE uses `n.system_tags CONTAINS 'owned'`; legacy BloodHound used `n.owned = true`. Use the one that matches your version.)*

**List owned users (legacy: owned = true):**
```cypher
MATCH (u:User {owned:true}) RETURN u.name
```

**List owned users (BloodHound CE: system_tags):**
```cypher
MATCH (u:User) WHERE u.system_tags CONTAINS 'owned' RETURN u.name
```

**List owned computers:**
```cypher
MATCH (c:Computer {owned:true}) RETURN c.name, c.operatingsystem
```

**Hosts an owned user can RDP to (MemberOf or CanRDP):**
```cypher
MATCH (u:User {owned:true}), (c:Computer {enabled:true})
MATCH p = (u)-[:MemberOf|CanRDP*1..]->(c) WHERE u <> c RETURN p
```

**Shortest path from an owned principal to any computer:**
```cypher
MATCH p = shortestPath((u:User {owned:true})-[r]->(c:Computer)) RETURN p
```

**Shortest path from any owned node to high-value targets:**
```cypher
MATCH p = shortestPath((o {owned:true})-[*1..]->(hvt {highvalue:true})) WHERE o <> hvt RETURN p
```

**All edges an owned user has to computers:**
```cypher
MATCH p = shortestPath((m:User)-[r]->(b:Computer)) WHERE m.owned RETURN p
```

---

## 17. Descriptions, Home Directories & Keyword Hunting

**What:** Find objects with descriptions (often “PASS” or service names), UNC home directories, or security/AV/EDR keywords in name/description.  
**Why:** Descriptions may leak passwords or roles; UNC homes = writable shares for persistence; security product names = high-value or monitoring targets.

**Enabled computers with description set (often contains role or sensitive info):**
```cypher
MATCH (c:Computer {enabled:true}) WHERE c.description IS NOT NULL RETURN c.name, c.description
```

**Enabled users with description set:**
```cypher
MATCH (u:User {enabled:true}) WHERE u.description IS NOT NULL RETURN u.name, u.description
```

**User descriptions containing “PASS” (possible password in description):**
```cypher
MATCH (u:User {enabled:true}) WHERE toUpper(u.description) CONTAINS 'PASS' RETURN u.name, u.description
```

**Computer descriptions containing a keyword (e.g. TOMCAT):**
```cypher
MATCH (c:Computer {enabled:true}) WHERE toUpper(c.description) CONTAINS 'TOMCAT' RETURN c.name, c.description
```

**Users with network home directory (UNC path – potential share abuse):**
```cypher
MATCH (u:User) WHERE u.homedirectory =~ '^\\\\\\\\.+' RETURN u.name, u.homedirectory
```

**Security / AV / EDR keywords in name or description (edit list as needed):**
```cypher
UNWIND ['carbonblack', 'crowdstrike', 'cylance', 'defender', 'falcon', 'sentinelone', 'splunk', 'nessus', 'carbon', 'huntress', 'canary', 'trapmine', 'security', 'antivirus', 'edr'] AS word
MATCH (n) WHERE toLower(n.name) CONTAINS toLower(word) OR toLower(n.description) CONTAINS toLower(word) OR (n.distinguishedname IS NOT NULL AND toLower(n.distinguishedname) CONTAINS toLower(word))
RETURN word AS keyword, LABELS(n)[0] AS type, n.name, n.description ORDER BY n.name
```

---

## 18. Unsupported OS & Obsolete Systems

**What:** Find enabled computers running old/unsupported OS (e.g. 2003, 2008, XP, Vista, 7).  
**Why:** Older OS = missing patches and weaker configs; prioritize for vuln scans and quick wins. Often weaker credential protection (e.g. NTLM, no LAPS).

**Enabled computers with unsupported/old OS (2000, 2003, 2008, XP, Vista, 7, etc.):**
```cypher
MATCH (c:Computer {enabled:true}) WHERE c.operatingsystem =~ '(?i).*(2000|2003|2008|xp|vista|7|me).*' RETURN c.name, c.operatingsystem
```

*(Prioritize these for vuln scanning / quick wins.)*

---

## 19. GMSA (ReadGMSAPassword)

**What:** Find principals that can read a GMSA’s password (ReadGMSAPassword / AllExtendedRights on the GMSA object) and first-degree control from “password not required” accounts.  
**Why:** GMSA passwords are stored in AD; if you can read them (SharpGMSAPwd, Get-GMSAPassword), you get that service account—often used for ADFS, SQL, or other high-value services.

**Principals that can read a GMSA password (direct path):**  
*(Use BloodHound’s “Can read GMSA password” / ReadGMSAPassword edge when available.)*

**All GMSA accounts (often have SPN):**
```cypher
MATCH (u:User) WHERE u.objectid CONTAINS '-' AND u.hasspn = true AND u.name CONTAINS '$' RETURN u.name, u.serviceprincipalnames
```
*(Refine with gMSA-specific properties if your collector sets them.)*

**First-degree object control for enabled accounts that do not require password (abuse path):**
```cypher
MATCH (u:User {enabled:true, passwordnotreqd:true}), p = (u)-[r1]->(n) WHERE r1.isacl = true RETURN p
```

---

## 20. ExecuteDCOM & RBCD (AllowedToAct / AddAllowedToAct)

**What:** ExecuteDCOM = DCOM execution on a computer (lateral movement without admin). AllowedToAct = RBCD (principal can act as the computer). AddAllowedToAct = can configure who can act as the computer.  
**Why:** ExecuteDCOM can give RCE on a host; AddAllowedToAct lets you add a computer you control to “allowed to act” → RBCD abuse → impersonate the target computer and get a TGT. No DA required if you have MAQ + AddAllowedToAct.

**ExecuteDCOM** = principal can use Distributed COM on the computer (lateral movement without admin).  
**AllowedToAct** = RBCD (Resource-Based Constrained Delegation) – principal can act on behalf of the computer.  
**AddAllowedToAct** = principal can add who can act on behalf of the computer (RBCD abuse).

**Paths including ExecuteDCOM (already in shortest-path edge lists above).**  
**Principals with AddAllowedToAct on computers (can configure RBCD):**
```cypher
MATCH p = (n)-[r:AddAllowedToAct]->(c:Computer) RETURN p
```

**Principals with AllowedToAct to computers (already have RBCD):**
```cypher
MATCH p = (n)-[r:AllowedToAct]->(c:Computer) RETURN p
```

*(Include `ExecuteDCOM`, `AllowedToAct`, `AddAllowedToAct` in custom shortest-path queries to Domain Admins / DCs.)*

---

## 21. AddMember & Group Abuse

**What:** Find principals that can add members to groups (AddMember edge), especially high-value groups like Domain Admins.  
**Why:** AddMember on DA (or a group that’s in DA) = add yourself → instant DA. Also shows which groups are admins to which computers (targeting for lateral movement).

**Unprivileged users who can add members to groups (add self to high-value group):**
```cypher
MATCH (n:User {admincount:false})
MATCH p = allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) RETURN p
```

**Who can add members to a specific group:**
```cypher
MATCH p = (n)-[r:AddMember]->(g:Group {name:'DOMAIN ADMINS@EXAMPLE.LOCAL'}) RETURN p
```

**Which domain groups are admins to what computers (with nesting):**
```cypher
MATCH (g:Group)
OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer)
OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer)
WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS computers
RETURN g.name AS GroupName, COLLECT(computers.name) AS AdminRights
```

---

## 22. Domain Users / Everyone – Excessive Rights

**What:** Find where Domain Users (or Everyone/Authenticated Users) have Owns, WriteDacl, GenericAll, ExecuteDCOM, etc. on computers or users.  
**Why:** If every domain user has GenericAll on a DA, the domain is trivially owned. These are “blast radius” misconfigs—fix or abuse first.

**Domain Users with dangerous rights on computers (Owns, WriteDacl, GenericAll, ExecuteDCOM, etc.):**
```cypher
MATCH p = (m:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer)
WHERE m.name STARTS WITH 'DOMAIN USERS' RETURN p
```

*(Also use the “What Domain Users / Authenticated Users / Everyone have” query in section 11.)*

---

## 23. Kerberoastable High-Value & Delegation Combos

**What:** Kerberoastable users in high-value groups; Kerberoastable + unconstrained delegation; users who are admin to a box AND have a session on an unconstrained-delegation host.  
**Why:** Kerberoast a DA = crack and become DA. Unconstrained + session = steal their TGT from the delegation host. “AdminTo + session on unconstrained” = prime target for coercion + ticket theft.

**Kerberoastable users who are in high-value groups:**
```cypher
MATCH (n:User)-[r:MemberOf]->(g:Group) WHERE g.highvalue = true AND n.hasspn = true RETURN n, g, r
```

**Kerberoastable users configured with unconstrained delegation (user object):**
```cypher
MATCH (u:User {enabled:true}) WHERE u.hasspn = true AND NOT u.name CONTAINS '$' AND u.unconstraineddelegation = true RETURN u.name, u.description
```

**Users not “Sensitive and Cannot Be Delegated” who are admin to a computer AND have a session on a computer with unconstrained delegation (ticket-theft scenario):**
```cypher
MATCH (u:User {sensitive:false})-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c1:Computer)
WITH u, c1
MATCH (c2:Computer {unconstraineddelegation:true})-[:HasSession]->(u)
RETURN u.name AS user, COLLECT(DISTINCT(c1.name)) AS AdminTo, COLLECT(DISTINCT(c2.name)) AS TicketLocation ORDER BY user
```

---

## 24. Cross-Domain & Path Filtering

**What:** Cross-domain sessions (user from domain A on computer in domain B) and paths to a target that avoid high-value nodes.  
**Why:** Cross-domain session = trust abuse or lateral movement across forests. Excluding high-value from paths finds “stealth” routes that don’t touch DA/EA until the end.

**Cross-domain HasSession (user logged into computer in different domain):**
```cypher
MATCH p = (c:Computer)-[r:HasSession*1]->(u:User) WHERE c.domain <> u.domain RETURN p
```

**Shortest path to a target but exclude paths that go through any high-value node:**
```cypher
MATCH (n), (t {name: 'TARGET@DOMAIN.LOCAL'})
MATCH p = allShortestPaths((n)-[*1..10]->(t))
WHERE NONE(node IN nodes(p) WHERE node.highvalue = true) AND n <> t RETURN p
```
*(Replace target name; useful to find “stealth” paths that don’t touch DA/EA.)*

---

## 25. Admin Counts & Ranking

**What:** Count how many computers each user/group is admin on; rank users by “admin reach”; list users admin on more than one machine.  
**Why:** High “admin count” = high-value targets (compromise one account, get many boxes). Also finds over-privileged accounts and which machines have the most admins (noisy or high-value).

**Users who are admin (direct or via group) on at least one computer:**
```cypher
MATCH (u:User)-[r:AdminTo|MemberOf*1..]->(c:Computer) RETURN DISTINCT u.name ORDER BY u.name
```

**Top N users by number of computers they are admin on:**
```cypher
MATCH (u:User)-[r:MemberOf|AdminTo*1..]->(c:Computer)
WITH u.name AS n, COUNT(DISTINCT(c)) AS c
RETURN n, c ORDER BY c DESC LIMIT 10
```

**Top N groups by number of computers they are admin on:**
```cypher
MATCH (g:Group)-[r:MemberOf|AdminTo*1..]->(c:Computer)
WITH g.name AS n, COUNT(DISTINCT(c)) AS c
RETURN n, c ORDER BY c DESC LIMIT 10
```

**Users who are admin on more than one computer:**
```cypher
MATCH (u:User)-[r:MemberOf|AdminTo*1..]->(c:Computer)
WITH u.name AS n, COUNT(DISTINCT(c)) AS c
WHERE c > 1 RETURN n ORDER BY c DESC
```

**Per-computer: number of admins (explicit + via groups):**
```cypher
MATCH (c:Computer)
OPTIONAL MATCH (n)-[r:AdminTo]->(c) WITH c, COUNT(n) AS expAdmins
OPTIONAL MATCH (n)-[r:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(c) WITH c, expAdmins, COUNT(DISTINCT(n)) AS unrolledAdmins
RETURN SPLIT(c.name,'.')[0] AS name, expAdmins, unrolledAdmins, expAdmins + unrolledAdmins AS totalAdmins ORDER BY totalAdmins DESC
```

**Users ranked by total machines they are admin on (explicit + unrolled):**
```cypher
MATCH (u:User)
OPTIONAL MATCH (u)-[:AdminTo]->(c:Computer) WITH u, COUNT(c) AS expAdmin
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)-[:AdminTo]->(c:Computer) WHERE NOT (u)-[:AdminTo]->(c)
WITH u, expAdmin, COUNT(DISTINCT(c)) AS unrolledAdmin
RETURN u.name, expAdmin, unrolledAdmin, expAdmin + unrolledAdmin AS totalAdmin ORDER BY totalAdmin DESC
```

---

## 26. Hosts with SPNs & Specific SPN Search

**What:** List computers (or users) with SPNs; filter by keyword (MSSQL, HTTP, etc.); list groups for a user; filter computers by domain.  
**Why:** SPNs reveal services (SQL, web, ADFS); target Kerberoast or service abuse. Group membership and domain scope help target and scope attacks.

**All enabled computers that have at least one SPN:**
```cypher
MATCH (c:Computer {enabled:true}) WHERE c.serviceprincipalnames IS NOT NULL RETURN c.name, c.serviceprincipalnames
```

**Computers with SPN containing a string (e.g. MSSQL, HTTP):**
```cypher
MATCH (c:Computer {enabled:true}) WHERE ANY(x IN c.serviceprincipalnames WHERE toUpper(x) CONTAINS 'MSSQL') RETURN c.name, c.serviceprincipalnames ORDER BY c.name
```

**List groups a specific user is member of:**
```cypher
MATCH p = (n:User {name:'USERNAME@EXAMPLE.LOCAL'})-[:MemberOf]->(g:Group) RETURN g.name
```

**List enabled computers in a specific domain:**
```cypher
MATCH (c:Computer {enabled:true}) WHERE c.domain =~ '(?i).*EXAMPLE\\.LOCAL' RETURN c.name, c.description
```

---

## 27. SyncLAPSPassword & LAPS Sync

**What:** Find principals that can sync LAPS passwords (SyncLAPSPassword edge) to the directory.  
**Why:** SyncLAPSPassword = can push or change LAPS passwords; combined with ReadLAPSPassword gives full LAPS abuse (read + sync). Useful for persistence or lateral movement.

**Principals that can sync LAPS password (SyncLAPSPassword edge):**
```cypher
MATCH p = (n)-[r:SyncLAPSPassword]->(c:Computer) RETURN p
```
*(Use with ReadLAPSPassword for full LAPS abuse picture.)*

---

## 28. Trusts & Cross-Domain / Cross-Forest

**What:** Find edges from one domain to another (cross-domain abuse) and cross-domain HasSession.  
**Why:** Trusts extend attack surface: compromise domain A, abuse trust to domain B (SID history, DA in trusted domain, etc.). Cross-domain session = where to pivot.

**All relationships from domain A to domain B (cross-domain abuse):**
```cypher
MATCH (n {domain:'DOMAIN-A.LOCAL'})-[r]->(m {domain:'DOMAIN-B.LOCAL'})
RETURN LABELS(n)[0] AS fromType, n.name AS fromName, TYPE(r) AS edge, LABELS(m)[0] AS toType, m.name AS toName
```

**Any connection to a different domain/forest:**
```cypher
MATCH (n)-[r]->(m) WHERE n.domain <> m.domain
RETURN LABELS(n)[0], n.name, TYPE(r), LABELS(m)[0], m.name
```

**Cross-domain HasSession (user from domain A logged into computer in domain B):**
```cypher
MATCH p = (c:Computer)-[:HasSession]->(u:User) WHERE c.domain <> u.domain RETURN p
```

*(BloodHound CE/Enterprise also has **CrossForestTrust** and trust-based pathfinding; use built-in trust path queries when available.)*

---

## 29. KRBTGT & Golden Ticket

**What:** Find the KRBTGT account (password last set = last rotation) and principals with a path to KRBTGT.  
**Why:** Golden Ticket = forge TGT with KRBTGT hash; valid until next KRBTGT password reset. Path to KRBTGT (e.g. DCSync or DA) = can create Golden Ticket. Detection: monitor 4768/4769; rotation breaks existing Golden Tickets.

**KRBTGT account (password last set = last rotation; Golden Ticket valid until next rotation):**
```cypher
MATCH (u:User) WHERE u.name =~ '(?i).*KRBTGT@.*' RETURN u.name, u.pwdlastset, u.enabled
```

**KRBTGT with human-readable password last set:**
```cypher
MATCH (u:User) WHERE u.name =~ '(?i).*KRBTGT@.*'
RETURN u.name, datetime({epochSeconds: toInteger(u.pwdlastset)}) AS pwdLastSet
```

**Principals with path to KRBTGT (potential to reset = Golden Ticket):**
```cypher
MATCH (u:User) WHERE u.name =~ '(?i).*KRBTGT@.*'
MATCH p = shortestPath((n)-[*1..]->(u)) WHERE n <> u RETURN p LIMIT 25
```

*(Golden Ticket detection: monitor DC events 4768/4769; KRBTGT rotation breaks existing Golden Tickets.)*

---

## 30. SID History (HasSIDHistory)

**What:** Find users or computers that have SID History (HasSIDHistory edge)—often from domain migration.  
**Why:** SID History can grant rights from the old domain; abuse = add a high-value SID to an account you control (e.g. DA SID) to get those rights. Also indicates migration paths for trust abuse.

**Accounts with SID History (migration / privilege abuse):**
```cypher
MATCH (u:User)-[r:HasSIDHistory]->() RETURN u.name, u.objectid
```
```cypher
MATCH (c:Computer)-[r:HasSIDHistory]->() RETURN c.name, c.objectid
```

*(HasSIDHistory can indicate domain migration; abuse = add SID of high-value group to gain rights.)*

---

## 31. Machine Account Quota (MAQ)

**What:** Domain-level setting: how many machine accounts a normal user can create (default 10). BloodHound may not store it; enumerate via LDAP.  
**Why:** If MAQ > 0, any domain user can create a computer object → use it for RBCD (AddAllowedToAct on a target), unconstrained delegation abuse, or a backdoor account. No DA needed.

**Note:** MAQ (ms-DS-MachineAccountQuota) is a **domain-level** attribute. BloodHound may not store it as a graph property; check **Domain** node properties in the UI or enumerate via LDAP (`nxc ldap DC -d DOMAIN -u user -p pass -M maq`).

**When MAQ > 0:** Unprivileged users can create machine accounts → RBCD abuse, unconstrained delegation abuse, or backdoor accounts. After creating a computer object, abuse **AddAllowedToAct** (RBCD) on a target.

**Find users who could create machine accounts (low-priv, no admincount) and have path to computers for RBCD:**
```cypher
MATCH (u:User {admincount:false})
MATCH p = shortestPath((u)-[r:AddAllowedToAct|AdminTo|GenericAll|WriteDacl|Owns*1..]->(c:Computer))
RETURN p LIMIT 25
```

---

## 32. Azure / Entra (Hybrid – AZUser, AZGroup, AZRole)

**What:** Azure/Entra nodes (AZUser, AZGroup, AZRole) and edges from on-prem User/Computer to Azure. Requires AzureHound (or equivalent) data.  
**Why:** Hybrid = AD → cloud pivot. On-prem compromise can lead to Azure (synced users, AAD Connect, MSOL). Find Global Admin, sync accounts, and on-prem users with Azure rights.

*Requires **AzureHound** (or equivalent) data in the same BloodHound graph.*

**Azure high-value groups:**
```cypher
MATCH (g:AZGroup) WHERE g.highvalue = true RETURN g
```

**Azure users with privileged roles (Global Admin, User Admin, Cloud App Admin):**
```cypher
MATCH p = (n)-[:AZHasRole|AZMemberOf*1..2]->(r:AZRole)
WHERE r.displayname =~ '(?i)Global Administrator|User Administrator|Cloud Application Administrator'
RETURN p
```

**On-prem users with edges to Azure (AD → cloud abuse):**
```cypher
MATCH (m:User)-[r]->(n) WHERE m.objectid CONTAINS 'S-1-5-21' AND (n:AZUser OR n:AZGroup OR n:AZRole)
RETURN m.name, TYPE(r), n.name
```

**AAD Connect / MSOL / sync accounts (on-prem → cloud pivot):**
```cypher
MATCH (u) WHERE (u:User OR u:AZUser) AND (u.name =~ '(?i)^MSOL_.*|.*AADConnect.*' OR u.userprincipalname =~ '(?i)^sync_.*')
OPTIONAL MATCH (u)-[:HasSession]->(s) RETURN u, s
```

**Azure users synced from on-prem (onpremisesyncenabled – if collected):**
```cypher
MATCH (n:AZUser) WHERE n.onpremisesyncenabled = true RETURN n
```

---

## 33. Tier Zero & Stealth Paths

**What:** Shortest path to Tier Zero/DA; paths to high-value that don’t go through other high-value nodes; who controls high-value but isn’t in a high-value group.  
**Why:** Tier Zero = crown jewels; path = full escalation chain. “Stealth” paths avoid obvious DA hops. Controllers not in high-value group = often over-privileged or misconfigured—good targets.

**Shortest path from a start node to Tier Zero / Domain Admins (generic):**
```cypher
MATCH (start:User {name:'USER@EXAMPLE.LOCAL'}), (end:Group) WHERE end.name =~ '(?i).*DOMAIN ADMINS@.*'
MATCH p = shortestPath((start)-[*1..]->(end)) RETURN p
```

**Paths to high-value that do NOT go through any other high-value node (stealth path):**
```cypher
MATCH (n), (t:Group) WHERE t.highvalue = true
MATCH p = allShortestPaths((n)-[*1..10]->(t))
WHERE NONE(node IN nodes(p) WHERE node.highvalue = true AND node <> t) AND n <> t RETURN p LIMIT 25
```

**Controllers of high-value assets where the controller is NOT in a high-value group:**
```cypher
MATCH (n) WHERE n.highvalue = true
OPTIONAL MATCH (m)-[r]->(n) WHERE NOT (m)-[:MemberOf*1..]->(:Group {highvalue:true})
RETURN n.name, m.name, TYPE(r)
```

---

## 34. OU & Containment

**What:** OUs by number of computers; OUs containing servers; sessions of users in a specific OU (by GUID).  
**Why:** OUs define GPO scope and targeting. Servers in an OU = high-value; user sessions in an OU = who to target for that segment. Useful for scoped GPO abuse or hunting.

**OUs by computer count (targeting):**
```cypher
MATCH (o:OU)-[:Contains]->(c:Computer) RETURN o.name, o.guid, COUNT(c) AS computerCount ORDER BY computerCount DESC
```

**OUs that contain Windows Servers:**
```cypher
MATCH (o:OU)-[:Contains]->(c:Computer) WHERE toUpper(c.operatingsystem) STARTS WITH 'WINDOWS SERVER' RETURN o.name
```

**Sessions of users in a specific OU (by GUID):**
```cypher
MATCH (o:OU {guid:'GUID-HERE'})-[:Contains*1..]->(u:User)
MATCH (c:Computer)-[:HasSession]->(u) RETURN u.name, c.name
```

---

## 35. Neo4j Statistics & Console (arth0s)

**What:** Queries for Neo4j console that return tabular/statistics output (group member counts, OS counts, password dates, descriptions).  
**Why:** Quick environment overview and export to CSV; find over-privileged groups, unsupported OS, stale passwords, and useful descriptions.

**Users by group (name, description, member count) – find over-privileged groups:**
```cypher
MATCH (g:Group)<-[:MemberOf*1..]-(u:User)
RETURN g.name AS groupName, g.description AS groupDescription, COUNT(DISTINCT u) AS numberOfMembers
ORDER BY numberOfMembers DESC
```

**Operating systems in use (distinct OS and count) – find unsupported systems:**
```cypher
MATCH (c:Computer) RETURN DISTINCT c.operatingsystem AS operatingSystem, COUNT(c.operatingsystem) AS osCount
```

**KRBTGT accounts with password last set (readable date):**
```cypher
MATCH (u:User) WHERE u.hasspn = True AND u.name STARTS WITH 'KRBTGT'
RETURN u.name AS accountName, datetime({epochSeconds: toInteger(u.pwdlastset)}) AS passwordLastSet
```

**Domain Admins with password last set and date created:**
```cypher
MATCH (g:Group) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*'
WITH g MATCH (g)<-[:MemberOf*1..]-(u)
RETURN u.name AS User, datetime({epochSeconds: toInteger(u.pwdlastset)}) AS passwordLastSet,
datetime({epochSeconds: toInteger(u.whencreated)}) AS dateCreated ORDER BY u.pwdlastset
```

**Service accounts (Kerberoastable, excluding KRBTGT) – password last set and date created:**
```cypher
MATCH (u:User) WHERE u.hasspn = true AND (NOT u.name STARTS WITH 'KRBTGT')
RETURN u.name AS accountName, datetime({epochSeconds: toInteger(u.pwdlastset)}) AS passwordLastSet,
datetime({epochSeconds: toInteger(u.whencreated)}) AS dateCreated ORDER BY u.pwdlastset
```

**Users and descriptions (optionally add `WHERE u.enabled = True`):**
```cypher
MATCH (u:User) RETURN u.name AS username, u.description AS description
```

**Password never expires (excluding KRBTGT) with last logon:**
```cypher
MATCH (u:User {pwdneverexpires: True}) WHERE NOT u.name STARTS WITH 'KRBTGT'
RETURN u.name AS username, u.description AS description,
datetime({epochSeconds: toInteger(u.lastlogon)}) AS lastLogon ORDER BY lastLogon DESC
```

---

*Generated for red team use. Prefer BloodHound CE’s built-in path queries first; use these for custom hunts and exports. Covers abuse paths, access, passwords, misconfigurations, trusts, KRBTGT, and Azure/Entra.*
