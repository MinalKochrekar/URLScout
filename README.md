# URLScout
URLScourt uses explainable AI to detect phishing and malicious URLs, expose hidden threats, and protect people from online scams—turning every suspicious link into a smarter, safer click.
# 🔍 URLScout – Scout the Link, Spot the Risk!

### 🛡️ Your Smart Companion for Safer Browsing

URLScout is a cybersecurity project designed to help users identify potentially malicious URLs and phishing links before clicking them. It analyzes URLs, evaluates suspicious indicators, and presents a risk score to help users make informed decisions.

## 🚨 Problem Statement

Cybercriminals use fake websites and phishing links to steal personal information, passwords, and financial data. These links often look legitimate, making them difficult to identify.

## 💡 Our Solution

URLScout provides a simple interface where users can submit a URL for analysis and receive a risk assessment with explanations of suspicious indicators.

## ✨ Key Features

- 🔗 **URL Analysis:** Analyze submitted URLs.
- 🚨 **Phishing Detection:** Identify suspicious URL characteristics.
- 📊 **Risk Score:** Display a risk score from 0 to 100.
- 🛡️ **Risk Classification:** Classify URLs as safe-looking, suspicious, or potentially malicious.
- 🔬 **Deep Scan:** Additional checks for DNS, certificates, and redirects.
- 📜 **Scan History:** View previously analyzed URLs.

*Note: Detection accuracy depends on the analysis methods and available evidence. No URL scanner can guarantee complete safety.*

## 🛠️ Built With

- HTML
- CSS
- JavaScript
- Python
- SQLite
- REST API

## 📁 Project Structure

```text
URLScout/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── scans.db
└── frontend/
    └── index.html
