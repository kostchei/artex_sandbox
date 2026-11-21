# Wire diagram: object, connection and KEV logic

> **Current engine note:** Wire playback uses the timed compatibility evaluator. Its manifest records the estate, attacker, defense switches, and exact playback events. The causal comparison API uses `simulateScenario` and `projectRun`, with its own replayable manifests. Both use synthetic estates. The calibration register in `assets/calibration.json` distinguishes historical observations from presentation assumptions.

The intentional Demo-Ready route uses F5 BIG-IP 16.1.0, WSO2 API Manager 3.2.0, and Spring Framework 5.3.17. The broader Mixed estate draws from the appliance pool below. Deployment conditions and access are scenario assumptions. [CISA on BIG-IP](https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf) · [CISA on WSO2](https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf) · [Spring advisory](https://spring.io/security/cve-2022-22965/)

## Layer 1 appliance pool

Each estate contains five to seven of these families. **New Infra** changes the selection. Demo-Ready reserves a slot for BIG-IP so its intentional path remains available. Mixed assigns one appliance finding alongside the diagnostics opening and can add a third edge finding. An appliance without an assigned finding shows its product reference in the tooltip. All ten CVEs appear in the CISA KEV catalog. [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

| Appliance family | Advisory reference |
| --- | --- |
| F5 BIG-IP | [CVE-2022-1388](https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf) |
| Ivanti Connect Secure | [CVE-2023-46805](https://www.ivanti.com/blog/security-update-for-ivanti-connect-secure-and-ivanti-policy-secure-gateways) |
| Fortinet FortiGate SSL VPN | [CVE-2018-13379](https://www.fortinet.com/blog/psirt-blogs/fortios-ssl-vulnerability) |
| Palo Alto Networks firewall with GlobalProtect | [CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400) |
| Citrix NetScaler ADC | [CVE-2023-3519](https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf) |
| Cisco ASA Firewall | [CVE-2020-3452](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ro-path-KJuQhB86.html) |
| SonicWall SMA 100 | [CVE-2021-20016](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2021-005/) |
| Sophos Firewall | [CVE-2022-1040](https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce) |
| Zyxel ATP Firewall | [CVE-2023-28771](https://www.zyxel.com/global/en/support/security-advisories/zyxels-guidance-for-the-recent-attacks-on-the-zywall-devices) |
| Check Point Quantum Security Gateway | [CVE-2024-24919](https://advisories.checkpoint.com/defense/advisories/public/2024/cpai-2024-0353.html/) |

Mixed picks one of three diagnostics openings. **Low exposure** means an approved support capture retains a staging credential. **Misconfiguration** means overly broad sharing exposes a restricted build log. **Low-impact vulnerability** means a modeled read-only diagnostics flaw exposes the credential. Each grants staging-status access only.

## External misconfiguration pool

The third Mixed edge slot draws one of the cases below or the Datadog proxy example. The case appears on a matching synthetic service. Historical cases stop at that service. Cases involving accounts use an assumed synthetic credential scoped to the node. Incident reports supply context for the example.

| Misconfiguration | Incident or campaign |
| --- | --- |
| Internet-facing device with default admin credentials | [Unitronics device intrusions](https://www.cisa.gov/sites/default/files/2024-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors.pdf) |
| Remote Desktop exposed directly to the internet | [SamSam ransomware incidents](https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a) |
| Legacy VPN account left enabled without MFA | [Colonial Pipeline](https://www.govinfo.gov/content/pkg/CHRG-117hhrg45085/html/CHRG-117hhrg45085.htm) |
| Nonproduction cloud tenant account excluded from MFA | [Microsoft Midnight Blizzard incident](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) |
| Cloud warehouse login unrestricted by a trusted-network allowlist | [Snowflake customer compromises](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) |
| Sensitive cloud storage configured for anonymous access | [Ascension mortgage document breach](https://search.ftc.gov/system/files/documents/cases/1923126ascensioncomplaint.pdf) |
| Public Kubernetes dashboard without authentication | [RedLock investigation of Tesla cryptojacking](https://www.ten-inc.com/documents/RedLock_Whitepaper_2018.pdf) |
| Public Docker management API without authentication | [Unit 42 investigation of compromised Docker hosts](https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/) |
| WAF configuration allows unintended backend access | [Capital One cloud data breach](https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson) |
| Public web server exposes deployment configuration containing secrets | [Unit 42 cloud extortion investigation](https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/) |

The pool also includes a user-supplied scenario with an unauthenticated, customer-managed Datadog proxy. Its synthetic logs show a Git token. The dashed illustration continues through Git repository access, CI runner access, a higher-privilege runner, and IdP admin access. These are authored display labels. The evaluated estate result for this branch is the log read. [Datadog Agent Data Security](https://docs.datadoghq.com/data_security/agent/)

This specification describes `wire.html`, the synthetic wire-diagram simulation. Its assets, links, vulnerabilities and defenses are scenario assumptions; they are not a discovery of a real environment or proof that a product is vulnerable. A KEV is a CVE in CISA's Known Exploited Vulnerabilities catalog.

Run `node scripts/test-wire-model.cjs` after changing the model. It checks that
asset group IDs are unique, icons exist, variant CVE mappings resolve in the
appropriate layer, and connection and external-entry references are valid. It
does not verify vulnerability applicability, scenario outcomes, or rendering;
those still need source review and browser testing.

## 1. Is the object in the right layer?

Each object family is declared in `LAYER_CONFIG`. Place the object according to its function in this scenario, not its icon or the consequence of an attack.

| Layer | Intended role | Examples and boundaries |
| --- | --- | --- |
| 01 — Cloud ingress | External gateways and network ingress, plus cloud and network context. | Ivanti Connect Secure VPN, GlobalProtect and NetScaler ADC are modeled as externally accessible gateways. Cloud accounts and projects are context, not vulnerable gateway products. |
| 02 — Gateways and auth | API gateways, identity services and boundary controls. | WSO2 API Manager, Ivanti Sentry, identity providers and the Active Directory domain controller. Monitoring and security controls are contextual unless a path is explicitly modeled. |
| 03 — Services mesh | Applications, middleware, service and operational tooling. | Spring MVC, Confluence, services using Log4j 2, and MOVEit Transfer / GoAnywhere MFT. File-transfer products are applications even when they handle valuable data. |
| 04 — Data stores and secrets | Data destinations, databases, storage and secret stores. | Customer S3 data, RDS, analytics stores, document databases and storage vaults. |

A cluster is a visual grouping, not proof of network connectivity or common ownership. The layout is simplified: a cloud account is an administrative container, and a data store can be reached by many paths not shown here. Objects without a modeled path can remain isolated. Treat mixed technology families cautiously when adding variants: each variant must belong in its declared layer and must support every relationship assigned to its family.

## 2. Does each connection make sense?

`ALLOWED_CONNECTIONS` defines directional, illustrative attack-relevant paths between named object families. An edge represents assumed access or a service interaction useful for the scenario, not a discovered route, verified authorization, or a guarantee that compromise automatically crosses a trust boundary. A source and target must be in adjacent layers and the pairing must have a plausible purpose in this deployment. For example, an API gateway may route requests to an application; an application or transfer service may access a data store. These specific deployments and permissions are assumed.

The generator chooses instances from permitted families and may add additional permitted links to connect variants. Proximity is used only to choose among allowed instances, never to approve a relationship. Family-level rules apply to *every* variant; split a family or use more specific rules if a relationship is not plausible for every variant. There is no fallback that connects an otherwise isolated node to an arbitrary neighbor. Attack propagation follows displayed outgoing wires; membership in a cluster does not itself permit a jump.

`EXTERNAL_ENTRY_GROUPS` limits off-screen attack arrows and initial attack origins to the modeled internet-facing Ivanti Connect Secure, GlobalProtect and NetScaler gateways. One or two are selected when new infrastructure is generated. Those selections persist across defense scenarios; resize or new infrastructure regenerates them. Placement in the ingress layer alone does not imply public reachability.

The model omits many real interactions, including application-to-identity authentication and monitoring telemetry. An isolated object means the simulation has no modeled attack path for it, not that the real-world technology has no connections.

## 3. Is the KEV right for the object?

`kevByVariant` maps a particular displayed variant to a CVE in the matching layer's `LAYER_KEVS` catalog. Do not assign a CVE merely because an asset is in the same layer, uses the same icon, holds data, or is near another object. Check the affected product, affected version, configuration and attack surface against the vendor advisory and CISA/NVD. Catalog membership alone does not establish applicability to every installation.

| Modeled object | Assigned KEV | Scope assumed for this scenario |
| --- | --- | --- |
| Ivanti Connect Secure VPN | [CVE-2023-46805](https://nvd.nist.gov/vuln/detail/CVE-2023-46805) | Affected Ivanti Connect Secure deployment. |
| PAN-OS GlobalProtect Gateway | [CVE-2024-3400](https://nvd.nist.gov/vuln/detail/CVE-2024-3400) | Affected PAN-OS version and GlobalProtect configuration. |
| Citrix NetScaler ADC Gateway | [CVE-2023-3519](https://nvd.nist.gov/vuln/detail/CVE-2023-3519) | Affected NetScaler ADC deployment and relevant gateway configuration. |
| WSO2 API Manager | [CVE-2022-29464](https://nvd.nist.gov/vuln/detail/CVE-2022-29464) | Affected API Manager version and accessible vulnerable endpoint. |
| Ivanti Sentry gateway | [CVE-2023-38035](https://nvd.nist.gov/vuln/detail/CVE-2023-38035) | Affected Sentry deployment and accessible administrative interface. |
| Service using Log4j 2 | [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Affected Log4j 2 version and exploitable logging configuration. |
| Spring MVC WAR on Tomcat / JDK 9+ | [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | Affected Spring Framework version and exploitable deployment; an ordinary Spring Boot executable JAR is not sufficient for the documented Tomcat WAR exploit. |
| Confluence Data Center | [CVE-2023-22527](https://nvd.nist.gov/vuln/detail/CVE-2023-22527) | Affected Confluence Data Center version. |
| MOVEit Transfer | [CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362) | Affected MOVEit Transfer web application and HTTP(S) access. |
| GoAnywhere MFT | [CVE-2023-0669](https://nvd.nist.gov/vuln/detail/CVE-2023-0669) | Affected GoAnywhere MFT deployment and access to the vulnerable interface. |

The diagram does not inventory versions or verify configuration: the table records assumptions. Unmapped assets display `SIMULATED ACCESS` when reached; no CVE is inferred, and CVE-specific mitigations do not apply to them. Multiple instances may share the same valid CVE. The assigned CVE remains fixed for the infrastructure across scenario runs and is used for both mitigation and display. The catalog contains additional CVEs that are not necessarily assigned to any object.

## Recheck procedure and limitations

1. Review every family and each variant against the layer table; confirm labels distinguish products from components and data stores.
2. Inspect every `ALLOWED_CONNECTIONS` pairing against every source and target variant. Confirm its role and direction can be justified as a modeled interaction. Verify external entry groups separately.
3. Review every `kevByVariant` entry against the current vendor advisory and CISA KEV catalog, including prerequisites. Confirm it resolves within its layer and that unmapped assets receive no arbitrary fallback.
4. Exercise randomized layouts: check all generated wires against the allowlist, mapped CVEs against their variant, and selected entry arrows against the external-entry set; verify at least one route from each selected entry to a data target. Recheck behavior after switching scenarios, changing connector style, regenerating infrastructure and resizing.

Mitigation outcomes are simplified scenario rules, not validated product efficacy. A permitted edge is an assumed attack path and does not independently prove that a CVE can be exploited across it. Manual node clicks can mark an object hit outside automatic propagation. The simulation does not model all trust, protocol, access-control, monitoring or deployment details.
# Additional modeled products and path assumptions

WAF management, identity, and detection/SOC consoles each receive a vulnerability independently
with 25% probability when new infrastructure is generated. An unassigned
control has no modeled exploit, so an attack stops there without a defense
detection being counted. Assignment and paths persist with the infrastructure.
Splunk CVE-2023-32707 is a CVE, not represented here as a verified CISA KEV;
its scenario assumes a user with the `edit_user` capability, as described in
[Splunk's advisory](https://advisory.splunk.com/advisories/SVD-2023-0602).
The IDP, WAF management, and SOC connections assume management access and
service relationships; they do not imply that monitoring traffic itself grants
access or that exploitation automatically disables defensive controls.

The product pools are F5, Fortinet, Citrix and Imperva for WAF; VMware,
Microsoft, Red Hat and Okta for identity; and Splunk, IBM, Elastic and Wazuh
for SOC. They are representative products, not a verified market-share ranking.
Okta has no CVE assigned in this scenario. The other products use explicitly
mapped CVEs; some are not known to be CISA KEVs. See the relevant NVD records:
[FortiWeb](https://nvd.nist.gov/vuln/detail/CVE-2025-64446),
[NetScaler](https://nvd.nist.gov/vuln/detail/CVE-2023-3519),
[Imperva](https://nvd.nist.gov/vuln/detail/CVE-2018-5412),
[Keycloak](https://nvd.nist.gov/vuln/detail/CVE-2021-3827),
[AD FS](https://nvd.nist.gov/vuln/detail/CVE-2018-8340),
[QRadar](https://nvd.nist.gov/vuln/detail/CVE-2020-4888),
[Kibana](https://nvd.nist.gov/vuln/detail/CVE-2026-78597), and
[Wazuh](https://nvd.nist.gov/vuln/detail/CVE-2026-25769).
The Imperva CVE assumes local access; Keycloak and AD FS assume appropriate
credentials; Splunk assumes `edit_user`; QRadar and Kibana assume the relevant
authenticated privileges; Wazuh assumes a compromised cluster worker and the
shared cluster key; and NetScaler assumes an affected Gateway or AAA
configuration. The diagram assumes these prerequisites rather than modeling
their acquisition. A compromised WAF is an appliance or management foothold;
subsequent connections represent assumed access to its integrated services.

The expanded catalog also includes FortiOS CVE-2018-13379, Pulse Connect Secure
CVE-2019-11510, Apache HTTP Server CVE-2021-42013, Exchange CVE-2021-26855,
Ivanti EPM CVE-2024-29824, Confluence CVE-2023-22515, and WebLogic
CVE-2020-14882. The data tier includes Debian-packaged Redis CVE-2022-0543,
SQL Server Reporting Services CVE-2020-0618, and FortiClient EMS
CVE-2023-48788. These are assumed vulnerable product deployments. Apache
traversal requires a vulnerable configuration (CGI for code execution);
Redis is specifically the affected Debian package and requires access to Redis;
the reporting-service scenario assumes any necessary privileges; EMS is the
affected application with a SQL backend, not a vulnerability in SQL Server.
The model assumes the intervening network reachability and credentials required
for each hop; it does not simulate them or guarantee exfiltration.
References: [Redis](https://nvd.nist.gov/vuln/detail/CVE-2022-0543),
[reporting services](https://nvd.nist.gov/vuln/detail/CVE-2020-0618),
[Ivanti EPM](https://nvd.nist.gov/vuln/detail/CVE-2024-29824),
[Apache HTTP Server](https://nvd.nist.gov/vuln/detail/CVE-2021-42013),
[Pulse Connect Secure](https://nvd.nist.gov/vuln/detail/CVE-2019-11510), and
[CISA's exploited-vulnerability advisory](https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf).

The wire simulation includes vulnerable instances of F5 BIG-IP (CVE-2022-1388),
JetBrains TeamCity (CVE-2023-42793), Apache ActiveMQ (CVE-2023-46604), and
Cacti (CVE-2022-46169). Affected versions and configurations are assumed, not
detected. Sources: [CISA F5 advisory](https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf),
[CISA TeamCity advisory](https://www.cisa.gov/sites/default/files/2023-12/aa23-347a-russian-foreign-intelligence-service-svr-exploiting-jetbrains-teamcity-cve-globally_0.pdf),
[CISA ActiveMQ catalog announcement](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/3790dfb), and
[NVD Cacti record](https://nvd.nist.gov/vuln/detail/CVE-2022-46169).

These are hypothetical service relationships: the F5 management interface is
exposed and fronts API services; the API services can reach the ActiveMQ broker;
and the identity gateway gives access to internal TeamCity and Cacti services.
The final connections assume the broker, build service, or monitoring service
has credentials or integration access to its respective data target. A wire
represents that assumed reachability, not proof that exploitation automatically
grants the next hop. The simulation does not model credentials, network rules,
or exploit prerequisites in detail.


### AI gateway scenario

The simulated LiteLLM Proxy 1.83.6 is associated with CVE-2026-42271. The scenario assumes the attacker has a valid proxy API key and can reach the affected MCP test endpoints. The vendor identifies versions 1.74.2 through 1.83.6 as affected and 1.83.7 as fixed. The connection to a PostgreSQL database is an illustrative deployment relationship, not a claim about a real environment.

Source: https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g

The Confluence Server 8.5.1 example is within the affected version range for CVE-2023-22515: https://support.atlassian.com/atlassian-knowledge-base/kb/faq-for-cve-2023-22515/


### Exposure assignment and scenario calibration

Each infrastructure assigns independent simulated exposures to asset instances: 80% by default, or the asset's explicit vulnerability chance where specified. The assignment, topology, and defense seed persist when changing scenarios. Public access and assumed credentials are scenario findings, not invented CVEs. The generator resamples an infrastructure if the actual baseline probe order cannot reach a data target; the baseline probe order does not use hidden exposure assignments. In the combined scenario, one reachable backend target is replaced by a yellow canary decoy. Access triggers an alert and a simulated SOAR containment playbook; earlier defenses can stop the attack before it reaches the decoy.

Baseline displays at most three successful targets in each layer and at least one data target. Defended scenarios show at most one backend data target hit. A blocked or unexploitable node cannot be used as a stepping stone; agents continue checking other modeled connections. WAF coverage and SOAR detection are synthetic scenario assumptions, not measured security product performance. A defense is credited only when its modeled rule applies and coverage or detection succeeds.

### Wire playback and comparisons

**New Infra** generates a seeded estate. In **Authored walkthrough**, the selected template installs and validates its declared route, including the dataset access check. **Exploratory** keeps the generated weaknesses and credentials. The Mixed catalog rotation supplies a reference case, and the simulation evaluates the findings actually present in the estate. **Full enterprise** also exposes orienting service links before playback reveals findings, credentials and activity.

The **Pre-LLM Path** dropdown can pin a historical-style pattern or use the current estate's rotation. Replay, attacker switches and defense changes keep the estate. Conventional patterns use one worker and ARTEX-like uses three. The graph, tickets, dataset evidence and comparison cells all derive from the causal run trace.

Virtual patching follows the configured route and rule coverage. SOC uses observations from deployed sensors and qualifying decoy interactions. A response needs applicable authority and confirmed scope. The intervention contract establishes when confirmation changes a dependent action. Display duration follows the trace after these decisions. See [Stopwatch calibration and limits](timing-assumptions.md).

### Network monitoring node

New infrastructures include at most one network-monitoring server, selected with a 90% inclusion probability before topology filtering. The product is selected uniformly from Cacti, LibreNMS, SolarWinds NPM, Zabbix, PRTG and ManageEngine OpManager. Cacti, LibreNMS 22.3.0 and SolarWinds NPM 2020.2.6 have respective simulated CVE mappings (CVE-2022-46169, CVE-2022-29712 and CVE-2021-35225); the latter two are NVD records and are not asserted to be CISA KEVs. Affected versions, access and configuration are assumed. The remaining products have no assigned CVE. The independent exposure assignment still applies. Sources: [LibreNMS](https://nvd.nist.gov/vuln/detail/CVE-2022-29712), [SolarWinds NPM](https://nvd.nist.gov/vuln/detail/CVE-2021-35225).
