# 🛡️ Snort IDS -- Network Reconnaissance Detection Lab

## 📌 Project Overview

This project demonstrates the implementation of **Snort 3 Intrusion
Detection System (IDS)** to detect network reconnaissance and suspicious
traffic such as **Nmap SYN scans** and **ICMP ping sweeps**. The project
focuses on creating custom Snort rules, configuring IDS monitoring, and
testing alert generation in a controlled lab environment.

------------------------------------------------------------------------

## 🎯 Objectives

-   Implement Snort as a Network Intrusion Detection System\
-   Develop custom IDS rules\
-   Detect reconnaissance activities\
-   Generate real-time alerts\
-   Understand signature-based detection techniques

------------------------------------------------------------------------

## 🧰 Tools & Technologies

-   Snort 3
-   Kali Linux / Ubuntu
-   hping3
-   Networking Lab Environment

------------------------------------------------------------------------

## 🌐 Network Configuration

    HOME_NET = 192.168.1.0/24
    EXTERNAL_NET = any

------------------------------------------------------------------------

## ⚙️ Step 1: Create Custom Snort Rules

Navigate to the Snort rules directory:

``` bash
cd /etc/snort/rules
sudo nano local.rules
```

### 🔍 Rule 1: Nmap SYN Scan Detection

``` bash
alert tcp any any -> 192.168.1.0/24 any (msg:"DETECT NMAP SYN scan - multiple SYNs"; flags:S; sid:1000001; rev:1;)
```

### 🔍 Rule 2: ICMP Ping Detection

``` bash
alert icmp any any -> 192.168.1.0/24 any (
  msg:"ICMP Ping Detected";
  itype:8;
  sid:1000002;
  rev:1;
)
```

------------------------------------------------------------------------

## ⚙️ Step 2: Configure Snort (snort.lua)

Navigate to configuration file:

``` bash
sudo nano /etc/snort/snort.lua
```

### Minimal Configuration Example

``` lua
HOME_NET = '192.168.1.0/24'
EXTERNAL_NET = 'any'

ips =
{
    rules = [[
        include /etc/snort/rules/local.rules
    ]]
}

alert_fast =
{
    file = true,
}

detection = { }
search_engine = { }
output = { }

rate_filter =
{
    {
        sid = 1000001,
        track = "by_src",
        count = 1,
        seconds = 60,
        new_action = "alert"
    }
}
```

------------------------------------------------------------------------

## ▶️ Step 3: Start Snort Monitoring

``` bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_full
```

------------------------------------------------------------------------

## 🧪 Step 4: Generate Test Traffic

### Using hping3:

``` bash
sudo hping3 -p 80 -S 192.168.1.X
```

------------------------------------------------------------------------

## 🚨 Expected Output

Snort generates alerts when suspicious traffic is detected, including: -
Nmap SYN scan detection - ICMP ping detection

------------------------------------------------------------------------

## 📊 Learning Outcomes

-   Snort IDS configuration\
-   Signature-based intrusion detection\
-   Custom rule development\
-   Traffic monitoring and alert analysis\
-   Understanding reconnaissance attack patterns

------------------------------------------------------------------------

## ⚠️ Limitations

-   Basic rule may generate false positives\
-   Threshold tuning required for production environments

------------------------------------------------------------------------

## 🚀 Future Improvements

-   Implement threshold-based detection
-   Add advanced attack signatures
-   Integrate logging with SIEM tools
-   Develop automated alert analysis

------------------------------------------------------------------------

## 📸 Suggested Screenshots

-   Snort running output\
-   Alert logs\
-   hping3 testing output

------------------------------------------------------------------------

## 📚 References

-   Snort Official Documentation\
-   Nmap Documentation\
-   Cybersecurity IDS Best Practices
