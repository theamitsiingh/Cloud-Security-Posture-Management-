# 🔒 Cloud Security Posture Management (CSPM) 🚀

## 🌟 Overview
Stay ahead of security threats with this **AWS CSPM automation tool**! This Python script scans your cloud environment, detects vulnerabilities, and **automatically fixes misconfigurations**. Secure your infrastructure like a pro! 💪

## ✨ Features
✅ **S3 Bucket Security** – Detects & blocks public access automatically 🔐  
✅ **Security Group Auditing** – Finds & removes open ports 🚪  
✅ **RDS Encryption Check** – Ensures databases are encrypted 📊  
✅ **IAM MFA Enforcement** – Flags users without MFA 🔑  
✅ **AWS Security Hub Logging** – Reports security risks in real-time 📡  
✅ **Automated JSON Reporting** – Generates actionable insights 📄  

## 🔧 Requirements
🔹 **Python 3.x**  
🔹 **AWS SDK for Python (`boto3`)**  
🔹 **Configured AWS Credentials (`~/.aws/credentials` or IAM role)**  

## 🚀 Installation
Get started in seconds! Just run:
```sh
pip install boto3
```

Set up AWS credentials:
```sh
aws configure
```

## 🎯 How to Use
Run the script and let it do the magic:
```sh
python cspm_script.py
```

## 📊 Output
🔎 **Real-time security scan results**  
📡 **Findings logged to AWS Security Hub**  
📄 **JSON report saved as `cspm_report.json`**  

## 🎯 What’s Next?
🚀 **Multi-Cloud Support (Azure & GCP)**  
🛡️ **Advanced Compliance Checks (CIS, NIST, PCI-DSS)**  
📩 **Slack & Email Notifications for Alerts**  

## 📜 License
**MIT License** – Free to use and contribute! 💡


