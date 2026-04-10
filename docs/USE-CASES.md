# ZTLP Use Cases — Real-World Scenarios

*How the Zero Trust Layer Protocol solves problems people actually have.*

---

## Healthcare: Ransomware Can't Move Laterally

**The problem:** A nurse clicks a phishing link. The attacker gets a foothold on her workstation. Within minutes, they're scanning the network — finding the EMR server, the imaging system, the backup NAS. Everything is on the same flat network. The hospital pays $4.5 million in ransom because the alternative is patients dying.

**With ZTLP:** The compromised workstation has a ZTLP identity that's authorized to reach the EMR system and nothing else. There are no open ports to scan. The imaging system doesn't exist to that workstation — it literally cannot see it. The backup NAS requires a separate hardware-backed identity that the nurse's workstation doesn't have. The attacker has one machine. That's all they'll ever have.

**Who cares:** Hospital IT directors, CISO teams, HIPAA compliance officers, healthcare MSPs.

**Bottom line:** Ransomware spreads through flat networks. ZTLP eliminates flat networks. There's nothing to spread to.

---

## MSP: One Compromised Client Doesn't Take Down Twenty

**The problem:** You're an MSP managing 40 small businesses. Your RMM tool connects to all of them through a VPN mesh. An attacker compromises one client's network, pivots to your management infrastructure, and now has access to every client you manage. This is the Kaseya attack. This is the SolarWinds attack. This keeps happening.

**With ZTLP:** Each client network is a separate ZTLP zone. Your technicians' devices have identities enrolled in your MSP zone with cross-zone policy granting access to specific client services. Compromising Client A's network gives the attacker... Client A's network. There's no VPN tunnel to pivot through. Your management tools connect to each client via identity-authenticated ZTLP sessions — not shared network paths. The blast radius is one client, not forty.

**Who cares:** MSP owners, NOC managers, anyone who manages multi-tenant IT infrastructure.

**Bottom line:** The MSP supply chain attack is the most dangerous threat in managed IT. ZTLP makes cross-tenant lateral movement structurally impossible.

---

## Dental / Medical Office: HIPAA Without the Complexity

**The problem:** Dr. Martinez runs a 6-chair dental practice. She has a Dexis imaging server, an Open Dental server, two front desk PCs, and six operatory workstations. Her "IT" is her nephew who set it up. HIPAA says she needs access controls, audit trails, and encryption. She has a Netgear router with the default password.

**With ZTLP:** Her MSP enrolls each device with a hardware token. The imaging server only accepts connections from operatory workstations. Open Dental only accepts connections from front desk PCs and the doctor's tablet. Every connection is logged with cryptographic identity — not IP addresses that change. HIPAA compliance isn't a stack of policies taped to a wall anymore; it's enforced by the network itself.

**Who cares:** Small practice owners, dental/medical office managers, healthcare MSPs, HIPAA auditors.

**Bottom line:** Small practices can't afford a security team. ZTLP gives them network-level access control that's set-once and enforced automatically.

---

## Defense Contractor: CMMC Without Rearchitecting Everything

**The problem:** A 50-person defense subcontractor needs CMMC Level 2 to keep their DoD contracts. The assessment requires: access control (AC), identification and authentication (IA), system and communications protection (SC), and audit and accountability (AU). They're currently running a flat Windows domain with a Fortinet firewall. The gap assessment is 200 pages long.

**With ZTLP:** ZTLP maps directly to CMMC controls. AC.L2-3.1.1 (limit system access to authorized users) — ZTLP enforces identity before any network communication. IA.L2-3.5.1 (identify system users) — every packet carries a cryptographic NodeID tied to a hardware token. SC.L2-3.13.1 (monitor communications at boundaries) — the gateway logs every session with cryptographic identity. AU.L2-3.3.1 (create audit records) — audit trails are built into the protocol, not bolted on. Half the CMMC controls are structural properties of the network, not policies that someone has to remember to follow.

**Who cares:** Defense contractors, CMMC assessors, GRC teams, federal IT managers.

**Bottom line:** CMMC compliance is expensive because you're retrofitting security onto an insecure network. ZTLP makes the network do the work.

---

## Manufacturing: Protecting OT Without Air-Gapping

**The problem:** A factory floor has PLCs controlling CNC machines, a SCADA system monitoring production, and a historian server collecting data. IT needs to pull production data for ERP integration. The security team says air-gap the OT network. Operations says they need real-time data. So someone runs a cable between the networks "temporarily" and it stays there for three years until an attacker finds it.

**With ZTLP:** The SCADA system and PLCs are enrolled in an OT zone with hardware-backed identities. The ERP integration server has an IT zone identity with a cross-zone policy granting read-only access to the historian. The PLCs literally cannot receive connections from IT devices — they don't exist on the IT network and there are no ports to find. Data flows out through the gateway. Commands don't flow in unless explicitly authorized per-device. You get integration without exposure.

**Who cares:** Plant managers, OT security engineers, ICS/SCADA administrators, manufacturing CISOs.

**Bottom line:** Air gaps break because people need data. ZTLP gives you the security of an air gap with the connectivity of a network.

---

## Remote Workforce: VPN Is Dead, Long Live Identity

**The problem:** Your 200-person company went remote. Everyone connects through a VPN concentrator that's now a single point of failure and the fattest target on your network. It's always at capacity. Split tunneling is a security nightmare. Full tunneling is a performance nightmare. And once someone's on the VPN, they can see the entire internal network.

**With ZTLP:** There is no VPN. Each employee's laptop has a hardware-backed ZTLP identity. They connect directly to the services they're authorized to use — Jira, the internal wiki, the staging server — through ZTLP relays that handle NAT traversal and path optimization. The laptop works identically whether it's in the office, at home, or at a coffee shop. There's no "internal network" to be "on." There's just identity and policy.

**Who cares:** IT directors, network engineers, remote-first companies, anyone who's tired of VPN support tickets.

**Bottom line:** VPNs are a 1990s solution to a 1990s problem. ZTLP replaces "are you on the network?" with "can you prove who you are?"

---

## IoT Fleet: Securing 10,000 Devices That Can't Run an Agent

**The problem:** You manage a fleet of smart building sensors — HVAC, occupancy, lighting. They run on embedded Linux with 64MB of RAM. You can't install an endpoint agent. You can't run a VPN client. They connect to a central MQTT broker over the building network. Anyone on that network can publish fake sensor data or, worse, send commands to actuators.

**With ZTLP:** Each sensor has a TPM chip (increasingly standard in embedded hardware). At manufacturing, each device is enrolled with a hardware-bound ZTLP identity. The ZTLP client is lightweight — it runs in the firmware alongside the sensor application. The MQTT broker is behind a ZTLP gateway that only accepts connections from enrolled sensor identities. An attacker on the building WiFi sees... nothing. No open ports. No MQTT broker. No attack surface.

**Who cares:** IoT fleet managers, smart building operators, industrial IoT vendors, embedded systems engineers.

**Bottom line:** IoT devices can't protect themselves. ZTLP makes the network protect them.

---

## Financial Services: Zero Trust for Real, Not Just Marketing

**The problem:** Your bank's "Zero Trust" implementation is: Okta for SSO, Zscaler for web filtering, CrowdStrike for endpoint, Palo Alto for firewall, and a 14-person security team to manage the policies across all of them. You're spending $2M/year on tools that each enforce a piece of Zero Trust at a different layer. None of them talk to each other natively. An auditor asks "can server X talk to server Y?" and it takes three days to trace the path through all the policy layers.

**With ZTLP:** Zero Trust is a property of the network, not a product you buy. Server X can talk to server Y if and only if there's a signed policy record in ZTLP-NS authorizing it. The answer to the auditor's question is a single NS lookup. Access control, identity verification, encryption, and audit logging are all the same system. You still need endpoint protection and SSO — but the network layer stops pretending to be dumb and starts enforcing what it knows.

**Who cares:** Bank CISOs, financial regulators, GRC teams, security architects who are tired of "Zero Trust" being a buzzword.

**Bottom line:** Real Zero Trust means the network refuses to carry unauthorized traffic. Everything else is just firewalls with better marketing.

---

## K-12 School District: Protecting Student Data on a Budget

**The problem:** Your school district has 15 schools, 8,000 Chromebooks, and a two-person IT team. Student data (FERPA-protected) lives on servers in the district office. Teachers access it from school networks, home networks, and conference hotel WiFi. The "security" is a content filter and a prayer. The district got breached last year — student SSNs were exfiltrated. The budget for security improvements is $12,000.

**With ZTLP:** The student information system gets a ZTLP gateway. Teacher devices get enrolled with software-based identities (Chromebooks don't have TPMs, but A0 assurance is better than no assurance). Policy says: only enrolled teacher devices can reach the SIS, and only from the district's ZTLP zone. Student Chromebooks can't see the SIS at all. The SIS has no open ports on the public internet. Total hardware cost: zero (it's software). The two-person IT team manages enrollment through the Bootstrap Server web UI.

**Who cares:** School district IT directors, superintendents, FERPA compliance officers, ed-tech vendors.

**Bottom line:** Schools have the most sensitive data and the least security budget. ZTLP gives them enterprise-grade network access control for the cost of software deployment.

---

## Cloud Provider: East-West Traffic Isn't Trusted Either

**The problem:** Your microservices talk to each other over the internal VPC network. You trust it because it's "internal." Except that one compromised container now has network access to every other service in the VPC — the database, the auth service, the billing API, the admin dashboard. Your service mesh adds mTLS but the certificates are managed by the orchestrator, which is now the highest-value target in your infrastructure.

**With ZTLP:** Each microservice has its own ZTLP identity. Service-to-service policy is defined in ZTLP-NS: the billing API can talk to the database and the payment gateway, nothing else. The auth service can talk to the user database and the session store, nothing else. A compromised container can only reach services its identity is authorized for. The certificates aren't managed by the orchestrator — they're hardware-bound or tied to the container's attestation. Compromising the orchestrator doesn't give you the keys.

**Who cares:** Cloud architects, DevOps/platform engineers, SREs, cloud security teams.

**Bottom line:** "Internal" doesn't mean "trusted." ZTLP enforces identity-based access for east-west traffic, not just north-south.

---

## Law Firm: Client Confidentiality Is Non-Negotiable

**The problem:** Your 30-attorney firm handles M&A deals with material non-public information. Ethical walls require that attorneys on Deal A cannot access Deal B's documents. You enforce this with SharePoint permissions and hope nobody shares a link. The firm got hacked via a partner's compromised home router and the attackers had access to everything because the document management system was on a flat network.

**Who cares:** Law firm IT directors, managing partners, legal ethics officers.

**With ZTLP:** Each matter is a ZTLP zone. Attorneys are enrolled in the zones for their active matters. The document management system has a per-zone gateway. Attorney Smith's device, enrolled in Zone "Acme-Acquisition," can reach the Acme deal room but literally cannot see the Zone "Baker-Merger" deal room. The ethical wall is enforced at the network layer, not by permission settings that someone might misconfigure.

**Bottom line:** Ethical walls enforced by policy settings fail when the network is flat. ZTLP makes ethical walls structural.

---

## Retail / POS: Isolating Payment Systems

**The problem:** PCI-DSS requires your cardholder data environment to be segmented from the rest of the network. You spent $80,000 on VLANs, firewall rules, and a QSA assessment. Six months later, someone plugs a personal laptop into the POS VLAN because "the WiFi was slow." The segmentation is now breached and you don't know it until the next assessment.

**With ZTLP:** POS terminals have hardware-backed ZTLP identities enrolled in a payment zone. The payment processor gateway only accepts connections from enrolled POS identities. A personal laptop plugged into the physical network has no ZTLP identity — it can't see the payment gateway, it can't see the POS terminals, it can't see anything in the payment zone. VLANs enforce physical separation. ZTLP enforces cryptographic separation. One of these can be defeated by plugging in a cable.

**Who cares:** Retail IT managers, PCI QSAs, payment security teams, franchise IT directors.

**Bottom line:** Network segmentation fails when someone plugs in a cable. ZTLP segmentation can't be defeated by physical access alone — you need the cryptographic identity.

---

## Government Agency: FedRAMP and Beyond

**The problem:** Your federal agency needs to modernize from on-prem to hybrid cloud while maintaining FedRAMP compliance. The Authority to Operate (ATO) process requires demonstrating continuous monitoring, access control, and encryption in transit. Every cloud migration adds a new set of compensating controls and the ATO package is now 3,000 pages.

**With ZTLP:** The agency's ZTLP deployment spans on-prem data centers and cloud VPCs through relay infrastructure. Identity is the same everywhere — a device in the on-prem data center and a container in AWS both have ZTLP identities in the same trust hierarchy. Access control is defined once in ZTLP-NS, not duplicated across firewalls, security groups, NACLs, and WAF rules. Encryption in transit is a protocol requirement, not a configuration option. The continuous monitoring story is: every session is logged with cryptographic identity and policy evaluation. The ATO evidence is the protocol specification.

**Who cares:** Federal CISOs, FedRAMP assessors, agency IT modernization teams.

**Bottom line:** FedRAMP controls are hard because you're proving security across multiple layers that don't share an identity model. ZTLP gives you one identity model across all of them.

---

## Home Lab / Self-Hosting: Expose Services Without Exposing Ports

**The problem:** You self-host Nextcloud, Home Assistant, and a Plex server. You either open ports on your home router (and pray), use a reverse proxy with Let's Encrypt (and still have an open attack surface), or use Tailscale/Cloudflare Tunnel (and trust a third party with your traffic). Every exposed port is a target.

**With ZTLP:** Your home server runs a ZTLP gateway. Your phone and laptop have enrolled ZTLP identities. You access Nextcloud through a ZTLP session that routes through the relay mesh — no ports open on your home router, no DNS pointing to your home IP, no third-party tunnel provider seeing your traffic. The relay sees encrypted ZTLP packets it can't decrypt. Your services have zero public attack surface. Port scanners find nothing.

**Who cares:** Self-hosters, home lab enthusiasts, privacy-focused users, developers running personal infrastructure.

**Bottom line:** You shouldn't have to choose between self-hosting and security. ZTLP gives you both — zero exposed ports, no third-party trust required.

---

## Incident Response: When You Get Breached Anyway

**The problem:** Despite your best defenses, an attacker gets in. Now you need to figure out: what did they access? How did they move? What data was exfiltrated? Your firewall logs show IP addresses. Your proxy logs show URLs. Your endpoint logs show process execution. None of them agree on identity. Correlating the attack path takes weeks.

**With ZTLP:** Every session — every single connection between any two nodes — is logged with cryptographic NodeIDs, timestamps, policy evaluations, and session metadata. When you investigate, you query ZTLP-NS: "What did NodeID X connect to in the last 72 hours?" The answer is definitive, not probabilistic. You don't correlate IP addresses across log sources. You trace identity. The attacker's path is a graph of authenticated sessions, not a guess reconstructed from firewall rules.

**Who cares:** Incident response teams, SOC analysts, forensic investigators, cyber insurance underwriters.

**Bottom line:** Incident response on traditional networks is archaeology. On ZTLP networks, it's a database query.

---

## ISP / Carrier: A New Revenue Stream

**The problem:** You're an ISP. You sell bandwidth. That's a commodity race to the bottom. You'd love to sell value-added security services, but your network is a dumb pipe — you can't offer identity-based access control at the network layer because the network layer doesn't understand identity.

**With ZTLP:** You deploy ZTLP relay infrastructure at your edge PoPs. Business customers enroll their devices in your relay mesh. You offer "ZTLP Business" — identity-based connectivity, DDoS-resistant by design, with guaranteed authenticated bandwidth lanes between enrolled sites. During DDoS events, you can prioritize ZTLP traffic (it's authenticated) over random flood traffic (it's not). This is a premium service that no one else can offer at the network layer.

**Who cares:** ISP product managers, carrier network architects, business sales teams, backbone operators.

**Bottom line:** ZTLP turns ISPs from dumb pipes into identity-aware infrastructure providers. That's a different business.

---

## The Big Picture

Every scenario above has the same root cause: **the network doesn't know who's talking.** Firewalls guess. VPNs tunnel. NACs check at the door and hope nothing changes. Zero Trust products add identity at the application layer and pray the layers below don't betray them.

ZTLP fixes this at the right layer. The network itself knows who's talking, enforces who's allowed to talk, and logs who talked. Everything above — applications, services, users — gets to stop compensating for a network that doesn't care about identity.

That's the point. That's all of it.
