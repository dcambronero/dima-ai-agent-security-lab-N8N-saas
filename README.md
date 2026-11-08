# 🚀 DIMA AI Agent Security Lab for N8N

Build • Red Team • Protect • Validate

---

## 🎯 Overview

This lab demonstrates the complete lifecycle of securing an AI Agent:

```text
Build Agent
     ↓
Run AI Red Team
     ↓
Analyze Findings
     ↓
Enable AI Agent Security
     ↓
Run AI Red Team Again
     ↓
Compare Results
```

The lab intentionally starts with a vulnerable AI assistant so findings can be discovered, analyzed, remediated, and validated.

---

## 🏗️ Architecture

### Vulnerable Agent

```text
User
 │
 ▼
DIMA AI Assistant
 │
 ├── Employee Directory
 ├── Corporate Email Tool
 └── Knowledge Base
```

### Protected Agent

```text
User
 │
 ▼
AI Agent Security
 │
 ▼
DIMA AI Assistant
 │
 ├── Employee Directory
 ├── Corporate Email Tool
 └── Knowledge Base
```

---

## ⚡ Features

### Employee Directory

- Employee information
- Departments
- Certifications
- Languages
- Locations

### Knowledge Base

- Finance
- Security
- Human Resources
- Operations
- Vendors
- AI Roadmap

### Corporate Email Tool

- Simulated corporate email generation
- Tool-calling demonstrations

---

## 🔴 AI Red Team Coverage

The assessment includes:

- Instruction Override
- Prompt Injection
- System Prompt Extraction
- Tool Extraction
- Data Exfiltration
- Employee Salary Leakage
- Financial Information Leakage
- Indirect Prompt Injection

---

## 📦 Requirements

- Ubuntu VM
- Docker
- Git
- OpenAI API Key
- AI Red Team API Key

---

## ⚠️ Important

This repository intentionally does **not** include:

- OpenAI API Keys
- AI Red Team API Keys
- AI Agent Security API Keys

All credentials must be configured manually during the lab.

---

## 🚀 Quick Start

Clone the repository:

```bash
git clone https://github.com/dcambronero/dima-ai-agent-security-lab-N8N

cd dima-ai-agent-security-lab-N8N
```

Deploy N8N:

```bash
docker compose up -d
```

Open:

```text
http://localhost:5678
```

---

## 📚 Lab Phases

### Part 1 – Build the Environment

- Deploy N8N
- Import Workflow
- Configure OpenAI
- Publish Chat Interface
- Validate Agent

### Part 2 – AI Red Team

- Install SDK
- Configure Environment Variables
- Create Assessment Script
- Execute Assessment
- Review Findings
- Save Baseline Results

### Part 3 – AI Agent Security

- Create Project
- Generate API Key
- Configure AI Security Guard
- Deploy Protection
- Re-run Assessment
- Compare Results

---

## 📖 Documentation

| Guide | Description |
|--------|-------------|
| GUIA-LAB.html | Complete deployment guide |
| GUIA-REDTEAM.html | AI Red Team guide |
| GUIA-AI-AGENT-SECURITY.html | AI Agent Security guide |

---

## 🎓 Learning Outcomes

After completing the lab:

- Deploy an AI Agent
- Understand AI attack techniques
- Perform AI Red Team assessments
- Analyze findings
- Implement AI Agent Security
- Validate security improvements

---

## 🧪 Warning

This environment intentionally deploys a vulnerable AI assistant.

The purpose of the lab is to:

- Discover vulnerabilities
- Learn AI Red Teaming
- Implement protections
- Compare security posture before and after remediation

This environment is for educational use only and is not intended for production deployments.

---

## 👨‍💻 Author

Diego Cambronero

Regional Architect
