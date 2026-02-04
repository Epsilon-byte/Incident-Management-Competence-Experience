Competency Experience Specification
Work Role: Cyber Defense Analyst

DCWF 511 (NIST: PR-DA-001); Workforce Element: Cybersecurity

Description: Uses data collected from a variety of cyber defense tools (e.g., IDS alerts, firewalls, network traffic logs.) to analyse events that occur within their environments for the purposes of mitigating threats.

Work Domain: Incident Management

ACTOR
Who is this Competency Experience designed for and what pre-requisite Knowledge, Skill, Ability and Task should they have?

Skills Prerequisites
Incident response methodologies, SIEM administration and configuration, Threat intelligence analysis, Python/PowerShell automation, Log analysis and correlation, Playbook development, REST API integration, Analytics and reporting

Tools & Technologies
TheHive incident management, MISP threat intelligence, Cortex analysers, Elasticsearch log management, Docker/container orchestration, Linux system administration, Git version control, Automation frameworks

Abilities
Incident handling and triage, Process documentation, Alert correlation analysis, Metric development, Team coordination, Technical writing, Training development, Time management

BEHAVIOUR
What Knowledge, Skills, Abilities and Task(s) will the Actor need to complete for this work role?

Knowledge:
[61] Incident response and handling methodologies

[966] Enterprise incident response program roles/responsibilities

[66] Intrusion detection methodologies for host/network-based intrusions

[967] Current and emerging threats/threat vectors

Abilities:
[6918] Apply cybersecurity strategy to cloud computing models and architectures

Tasks:
[705] Manage security monitoring for situational awareness

[824] Recognise and report security violations

[852] Supervise protective/corrective measures for incidents

[707] Manage threat analysis and threat information production

CONTEXT
What are the scenario and constraints that frame the delivery of the Tasks?

Scenario
You are a member of the Security Operations team at Catnip Games International, tasked with protecting their growing gaming infrastructure as they prepare for their first major multiplayer game launch. With over 300 Linux servers across two data centers handling sensitive player data, matchmaking services, and game hosting, the company has faced several security challenges during beta testing. Recent incidents included undetected bot attacks attempting to exploit game mechanics, delayed responses to potential account compromises, and poor coordination between development and security teams when investigating suspicious activities. A recent incident where player account data was nearly exposed due to an advanced social engineering attempt highlighted the lack of standardised incident response procedures and insufficient threat intelligence sharing between teams.

With the game launch approaching and player trust at stake, you are tasked with designing and implementing a prototype incident management platform using TheHive, MISP, and Cortex. The implementation should demonstrate your understanding of security operations, incident response procedures, and automated threat intelligence sharing

Requirements

Functional Requirements

Prototype SOC Implementation

Deploy integrated incident management platform

Configure threat intelligence sharing

Implement automated response workflows

Establish incident tracking system

Create response playbooks

Set up reporting mechanisms

 

Technology Stack

TheHive for case management

MISP for threat intelligence

Cortex for automation

Elasticsearch for logging

Python for custom integrations

Git for version control

 

Non-Functional Requirements:

Performance

15-minute maximum alert triage time

<5 minute intelligence sharing latency

Support for 100 concurrent incidents

Handle 1000 alerts per day


Reliability

24/7 operational availability

No single point of failure

Automated backup system

Data retention compliance
 

Operations Management

Clear escalation procedures

Documented response workflows

KPI tracking capabilities

Team collaboration tools
