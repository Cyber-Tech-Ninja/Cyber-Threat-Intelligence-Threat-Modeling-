# Cyber-Threat-Intelligence-Threat-Modeling-
What is Threat Modelling?
Threat modelling is a systematic approach to identifying, prioritizing, and addressing potential security threats across the organization. By simulating possible attack scenarios and assessing the existing vulnerabilities of the organization's interconnected systems and applications, threat modelling enables organizations to develop proactive security measures and make informed decisions about resource allocation. Threat modelling aims to reduce an organization's overall risk exposure by identifying vulnerabilities and potential attack vectors, allowing for adequate security controls and strategies. This process is essential for constructing a robust defense strategy against the ever-evolving cyber threat landscape.

Threat, Vulnerability and Risk
As mentioned above, the main goal of threat modelling is to reduce the organization's risk exposure. So before we deep dive into its application, let's review first the definitions of Threat, Vulnerability and Risk.

Type	Definition
Threat	Refers to any potential occurrence, event, or actor that may exploit vulnerabilities to compromise information confidentiality, integrity, or availability. It may come in various forms, such as cyber attacks, human error, or natural disasters.
Vulnerability	A weakness or flaw in a system, application, or process that may be exploited by a threat to cause harm. It may arise from software bugs, misconfiguration, or design flaws.
Risk	The possibility of being compromised because of a threat taking advantage of a vulnerability. A way to think about how likely an attack might be successful and how much damage it could cause.

Threat, Vulnerability and Risk
As mentioned above, the main goal of threat modelling is to reduce the organization's risk exposure. So before we deep dive into its application, let's review first the definitions of Threat, Vulnerability and Risk.

Type	Definition
Threat	Refers to any potential occurrence, event, or actor that may exploit vulnerabilities to compromise information confidentiality, integrity, or availability. It may come in various forms, such as cyber attacks, human error, or natural disasters.
Vulnerability	A weakness or flaw in a system, application, or process that may be exploited by a threat to cause harm. It may arise from software bugs, misconfiguration, or design flaws.
Risk	The possibility of being compromised because of a threat taking advantage of a vulnerability. A way to think about how likely an attack might be successful and how much damage it could cause.

Applying MITRE ATT&CK in Threat Modelling Process
MITRE ATT&CK can be integrated into our threat modelling process by mapping the identified threats and vulnerabilities to the tactics and techniques described in the ATT&CK Framework. We can insert a new entry in our methodology after the "Identify Threats" step.

Identify Threats
Identify potential threats that may impact the identified assets, such as cyber attacks, physical attacks, social engineering, and insider threats.

Map to MITRE ATT&CK 
Map the identified threats to the corresponding tactics and techniques in the MITRE ATT&CK Framework. For each mapped technique, utilize the information found on the corresponding ATT&CK technique page, such as the description, procedure examples, mitigations, and detection strategies, to gain a deeper understanding of the threats and vulnerabilities in your system.

Incorporating the framework in our threat modelling process ensures a comprehensive understanding of the potential security threats. It enables a better application of countermeasures to reduce the overall risk to your organization.

Tactics are the overarching goals that adversaries are trying to achieve during an attack. Examples include Initial Access, Privilege Escalation, and Exfiltration. These goals represent "what" an adversary wants to achieve.

Techniques are the specific methods that adversaries use to achieve those goals. For example, within the Privilege Escalation tactic, techniques might include Exploiting Vulnerabilities, or Bypassing Security Controls. Techniques represent the "how" of an adversary’s actions.

Subtechniques break down techniques further into more granular actions. For example, the Spear Phishing technique can be subdivided into Spear Phishing via Email and Spear Phishing via Service.

The ATT&CK framework categorizes these components into matrices to provide security teams with a structured way to analyze and understand adversary behavior.

Tactics: The high-level objectives adversaries try to accomplish during an attack.
Techniques: Specific actions used to accomplish these objectives.
Subtechniques: Granular versions of techniques for more detailed analysis and emulation.



####CYBER KILL CHAIN####

The Cyber Kill Chain Phases
Phase 1: Reconnaissance
image.png

During the Reconnaissance phase, a malicious actor identifies a target and explores vulnerabilities and weaknesses that can be exploited within the network. The attacker will conduct research during the planning stage to decide which targets will best enable them to meet their objectives. As part of this process, the attacker may perform OSINT, harvest login credentials, or gather other information, such as email addresses, user IDs, physical locations, software applications, and operating system details, all of which may be useful in phishing or spoofing attacks. Generally speaking, the more information the attacker can gather during the Reconnaissance phase, the more sophisticated and convincing the attack will be and hence, the higher the likelihood of success. To achieve this, the attacker may employ a range of spying tools, such as automated scanners, that allow penetration through identifying weak points and vulnerabilities.

 

Phase 2: Weaponization
image.png

The attacker will now act on the data they have collected regarding the target and identify any weaknesses that they can exploit. Utilizing this exploit and coupling with malware, the attackers will generate a malicious, deliverable payload and send this to the target by using encrypted channels. During the Weaponization phase, the attacker creates an attack vector, such as remote access malware, ransomware, virus, or worm that can exploit a known vulnerability. During this phase, the attacker may also set up back doors so that they can continue to access the system if their original point of entry is identified and closed by network administrators.

For defenders, this phase is essential in understanding. Although they cannot detect weaponization as it is occurring, they can deduce by evaluating malware artifacts. Detections against weaponizer artifacts are frequently the most stable and resilient defenses against attackers.

 

Phase 3: Delivery
image.png

In the Delivery step, the intruder launches the attack. The attacker delivers the weaponized malware to the target via phishing email or some other type of medium, thereby initiating their operation. The most common delivery vectors for weaponized payloads include websites, removable disks, and emails.

The specific steps for this phase will depend on the episode they intend to carry out. For example, the attacker may send email attachments or a malicious link to spur user activity to advance the plan. This activity may be combined with social engineering techniques to increase the campaign's effectiveness. The more information that attackers can gather, the more convincing a social engineering attack can be achieved.

 

Phase 4: Exploitation
image.png

In this phase, the malicious code is delivered into the organization’s system, breaching the system by installing tools, running scripts, and adjusting security certificates. The attackers must exploit a vulnerability to gain access. At the exploitation stage, attackers will seek other victim vulnerabilities that they did not know before entering. For instance, an attacker might not have privileged access to an organization’s database from outside; however, they might spot vulnerabilities in the database that allows them to gain entry after an intrusion. 

 

Phase 5: Installation
image.png

Immediately following the Exploitation phase, the malware or other attack vector will be installed on the victim’s system. This is a turning point in the attack lifecycle, as the threat actor has entered the system and can now assume control. Generally, attackers will install a persistent backdoor or implant in the target’s environment to retain access for an extensive period. If the attacker knows what software the users or servers run in the organization, as well as OS version and type, they can enhance the likelihood of being capable to exploit and install something within the network.

 

Phase 6: Command and Control
image.png

In Command & Control, the attacker can use the malware to assume remote control of a device or identity within the target network. In this stage, the attacker may also work to move laterally throughout the network, expanding their access and establishing more points of entry for the future.

 

Phase 7: Actions on Objective
image.png

Each form of cyber-attack has a primary objective. The attacker typically has some objective involving the victim’s network, data extraction, data deletion or supply chain attacks. In this stage, the attacker takes steps to carry out their intended goals and extract data from the system. This may include data theft, destruction, encryption, or exfiltration.

Mitigation
The earlier an organization stops the threat within the cyber attack lifecycle, the less risk the organization assumes. Attacks that reach the Command and Control section require more advanced rectification efforts with in-depth sweeps of the network and endpoints to determine the scope of the attack.

 

Security Actions for Mitigation by Kill Chain Phase:
❖ Detect – Determine the attempts to penetrate an organization.

❖ Deny – Stopping the attacks when they are happening.

❖ Disrupt – Intervene is the data communication done by the attacker and stops it then.

❖ Degrade – This is to limit the effectiveness of a cybersecurity attack to minimize its ill effects.

❖ Deceive – Mislead the attacker by providing them with misinformation or misdirecting them.

❖ Contain/Destroy – Contain and limit the scope of the attack so that it is restricted to only some part of the organization

Reconnaissance Countermeasures
Identify and remediate vulnerabilities.
Limit access to sensitive assets.
Enforce least privilege: malicious code cannot execute without a higher level of privileges. By removing admin rights wherever possible and enforcing least privilege, you shrink the available actions that can be performed by an intruder or malicious code.
 

Weaponization Countermeasures
Eliminate shared accounts and password sharing.
Disable Autoplay for USB devices
Monitor and audit all privileged user, session, and file activities.
Conduct full malware analysis, not just what payload it drops, but how it was made.
 

Delivery Countermeasures
Security Awareness Training and Education program; end users should be educated on what phishing emails look like and how to report them.
Collect artifacts for reconstruction
 

Exploitation Countermeasures
Conduct frequent and competent vulnerability scanning and penetration testing
Develop secure source code
 

Installation Countermeasures
Appropriately apply NIDS/HIDS and NIPS/HIPS
Application Whitelisting
Verify certificates of all signed software
 

Command and Control Countermeasures
Discover C2 infrastructure via malware analysis
Create fewer paths into infrastructure
Require proxies for all types of traffic
Create DNS sink holing and name server poisoning
Conduct research to discover new adversary Command and Control infrastructure
image.png

JUST ONE MITIGATION BREAKS THE CHAIN
The defender has the advantage with the Cyber Kill Chain solution. All seven steps must be successful for a cyber-attack to occur. Remember there is no such thing as completely secure, only defendable


