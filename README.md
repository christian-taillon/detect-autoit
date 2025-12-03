# 🔍 AutoIt Detection Rules

> [!IMPORTANT]
> **Sigma rules for detecting AutoIt scripting activities in enterprise environments**
> 
> Detect malicious AutoIt usage and evasion techniques commonly abused by threat actors like Darkgate.

[![Sigma Rules](https://img.shields.io/badge/Sigma-Rules-blue.svg)](https://sigmahq.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Purpose-Security-red.svg)](#)
[![Windows](https://img.shields.io/badge/Platform-Windows-orange.svg)](#)

---

## 📋 Table of Contents

- [🎯 About](#-about)
- [🚀 Why AutoIt Detection Matters](#-why-autoit-detection-matters)
- [📁 Detection Rules](#-detection-rules)
- [⚙️ Implementation](#️-implementation)
- [🔧 Configuration](#-configuration)
- [📊 False Positives](#-false-positives)
- [🤝 Contributing](#-contributing)
- [📚 References](#-references)

---

## 🎯 About

This repository contains **Sigma detection rules** designed to identify malicious AutoIt scripting activities in Windows environments. AutoIt is a powerful automation tool that, while legitimate, is increasingly abused by threat actors for:

- 🎭 **Defense Evasion** - Renamed executables to avoid detection
- 🚀 **Malware Delivery** - Script-based malware distribution
- 🔓 **Persistence** - Automated malicious activities
- 🎪 **Living-off-the-Land** - Using legitimate tools for malicious purposes

> [!TIP]
> These rules are designed to complement existing security controls and provide early detection of AutoIt-based attacks.

---

## 🚀 Why AutoIt Detection Matters

### The Threat Landscape

AutoIt has become a **favorite tool** among threat actors, particularly in campaigns like:

- **Darkgate Malware** (Dec 2023) - Used AutoIt for initial access and execution
- **Ransomware Operations** - Leveraged for encryption and lateral movement
- **APT Campaigns** - Utilized for persistence and data exfiltration

### Detection Challenges

- ⚠️ **Legitimate Usage** - AutoIt is widely used in IT automation
- 🎭 **Evasion Techniques** - Renamed executables, obfuscated scripts
- 🔍 **File Extension Independence** - Scripts can run without `.au3` extensions
- 🛡️ **Encoded Content** - Encrypted or encoded script payloads

---

## 📁 Detection Rules

### 🔧 Core Detection Rules

| Rule File | Detection Focus | Severity | Status |
|-----------|----------------|----------|---------|
| [`Basic AutoIT Exec.yaml`](Basic%20AutoIT%20Exec.yaml) | Renamed AutoIt executables | 🔴 High | Experimental |
| [`AutoIt Scripting Activity Detection...`](AutoIt%20Scripting%20Activity%20Detection%20with%20Comprehensive%20Command-Line%20Strings.yaml) | Comprehensive command-line patterns | 🟡 Low | Experimental |
| [`AutoIt Strings Detection.yaml`](AutoIt%20Strings%20Detection.yaml) | File content string analysis | 🟡 Low | Experimental |
| [`Detect AU3 EA06 String.yaml`](Detect%20AU3%20EA06%20String.yaml) | AU3!EA06 signature detection | 🟡 Low | Experimental |
| [`Renamed AutoIT Exec.yaml`](Renamed%20AutoIT%20Exec.yaml) | Executable name evasion | 🔴 High | Experimental |

### 🎯 Key Detection Capabilities

#### 1. **Renamed Executable Detection**
```yaml
# Detects AutoIt executables running under different names
OriginalFileName: 'AutoIt3.exe' OR 'AutoIt2.exe'
```

#### 2. **Command-Line Pattern Analysis**
```yaml
# Comprehensive command-line string matching
CommandLine|contains: 
  - '/AutoIt3ExecuteScript'
  - '/AutoIt3ExecuteLine'
  - 'AutoIt3GUI'
```

#### 3. **File Content Analysis**
```yaml
# Detects AutoIt signatures within files
strings:
  - "AU3!EA06"  # AutoIt magic number
  - "AutoIt v3 Script"
```

---

## ⚙️ Implementation

### 🚀 Quick Start

1. **Deploy to SIEM**
   ```bash
   # Convert Sigma rules to your SIEM format
   sigma convert -t splunk *.yaml
   ```

2. **Configure Log Sources**
   - **Sysmon** Event ID 1 (Process Creation)
   - **Windows Security** Event Logs
   - **EDR** Process Creation Events

3. **Test Rules**
   ```bash
   # Validate rule syntax
   sigma check *.yaml
   ```

### 📋 Prerequisites

- **Sigma Converter** (`sigmac`)
- **SIEM Platform** (Splunk, QRadar, Elastic, etc.)
- **Windows Logs** with process creation events
- **Sysmon** (recommended for enhanced visibility)

### 🔧 SIEM Integration

| Platform | Conversion Tool | Notes |
|----------|----------------|-------|
| **Splunk** | `sigmac -t splunk` | Use CIM data models |
| **Elastic** | `sigmac -t es-rule` | Requires ECS mapping |
| **QRadar** | `sigmac -t qradar` | Custom AQL rules |
| **Azure Sentinel** | `sigmac -t azure` | KQL format |

---

## 🔧 Configuration

### 📊 Rule Tuning

#### Reduce False Positives
```yaml
# Add exclusions for legitimate AutoIt usage
condition: selection and not filter
filter:
  Image: 'C:\\Program Files\\AutoIt3\\*'
  User: 'SYSTEM'
```

#### Increase Sensitivity
```yaml
# Lower threshold for high-risk environments
condition: 2 of selection*
```

### 🎯 Recommended Settings

| Environment | Rule Level | Monitoring Frequency |
|-------------|------------|---------------------|
| **Enterprise** | Medium | Real-time |
| **High Security** | High | Real-time + Alerting |
| **Development** | Low | Hourly |

---

## 📊 False Positives

### 🏢 Common Legitimate Usage

- **IT Automation** - Software deployment scripts
- **System Administration** - Configuration management
- **Application Development** - Testing and debugging
- **Business Processes** - Automated workflows

### 🛡️ Mitigation Strategies

1. **Whitelist Known Applications**
   ```yaml
   filter:
     Image: 
       - 'C:\\Program Files\\LegitimateApp\\*'
       - 'C:\\Windows\\System32\\*'
   ```

2. **User Context Filtering**
   ```yaml
   filter:
     User: 
       - 'DOMAIN\\ServiceAccount'
       - 'SYSTEM'
   ```

3. **Time-Based Correlation**
   - Correlate with change management tickets
   - Monitor for unusual execution times

---

## 🤝 Contributing

### 📝 How to Contribute

1. **Fork the Repository**
2. **Create Feature Branch**
   ```bash
   git checkout -b feature/new-detection-rule
   ```
3. **Add/Modify Rules**
   - Follow Sigma rule format
   - Include proper documentation
   - Test rule syntax
4. **Submit Pull Request**

### 📋 Rule Development Guidelines

- ✅ **Clear Descriptions** - Explain what the rule detects
- ✅ **Proper References** - Include threat intelligence links
- ✅ **Tested Logic** - Validate rule conditions
- ✅ **False Positive Analysis** - Document expected FPs
- ✅ **Severity Levels** - Use appropriate risk levels

### 🧪 Testing

```bash
# Validate rule syntax
sigma check *.yaml

# Test with sample data
sigma convert -t splunk -c config.yml rule.yaml
```

---

## 📚 References

### 🔗 Threat Intelligence

- [Darkgate December 2023 Analysis](https://exchange.xforce.ibmcloud.com/collection/Darkgate-December-2023-acb7c12f4befcadfabce8ef0634cd16f)
- [AutoIt Malware Techniques](https://www.youtube.com/watch?v=aL4CbfL2O_I)
- [SigmaHQ Documentation](https://sigmahq.io/docs/)

### 📖 Technical Resources

- [Sigma Rule Format](https://sigmahq.io/docs/basics/rules.html)
- [AutoIt Official Documentation](https://www.autoitscript.com/autoit3/docs/)
- [Windows Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 🛡️ Security Frameworks

- **MITRE ATT&CK®** - T1059.001 (Command and Scripting Interpreter)
- **NIST Cybersecurity Framework** - Detection and Response
- **CIS Controls** - 8.2 (Malware Defenses)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **VSRT** - Initial rule development
- **Arizona Cyber Threat Response Alliance** - Threat intelligence support
- **SigmaHQ Community** - Rule format and tools
- **Security Community** - Contributions and feedback

---

> [!NOTE]
> **These rules are designed for defensive security purposes only.** 
> 
> Please ensure proper legal authorization before deploying in production environments.

---

**🔒 Stay Secure | 🚀 Stay Vigilant | 🤝 Stay Connected**