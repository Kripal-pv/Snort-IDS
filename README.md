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

-   Snort 3\
-   Kali Linux / Ubuntu\
-   hping3\
-   Networking Lab Environment

------------------------------------------------------------------------

## 🧪 Lab Environment

-   IDS System: Snort 3\
-   Attacker Simulation Tool: hping3\
-   Network Range: 192.168.1.0/24\
-   Monitoring Interface: eth0

------------------------------------------------------------------------

## 🌐 Network Configuration

    HOME_NET = 192.168.1.0/24
    EXTERNAL_NET = any

------------------------------------------------------------------------

## ⚙️ Step 1: Create Custom Snort Rules

Navigate to rules directory:

``` bash
cd /etc/snort/rules
sudo nano local.rules
```

### 🔍 Rule 1: Nmap SYN Scan Detection

``` bash
alert tcp any any -> 192.168.1.1/24 any (msg:"DETECT NMAP SYN scan - multiple SYNs"; flags:S; sid:1000001; rev:1;)
```

Detects TCP SYN packets indicating reconnaissance scanning activity.

### 🔍 Rule 2: ICMP Ping Detection

``` bash
alert icmp any any -> 192.168.1.1/24 any (
  msg:"ICMP Ping Detected";
  itype:8;
  sid:1000002;
  rev:1;
)
```

Detects ICMP echo request packets used in network discovery.

------------------------------------------------------------------------

## ⚙️ Step 2: Configure Snort (snort.lua)

``` bash
sudo nano /etc/snort/snort.lua
```

### Minimal Configuration

``` lua
--------------------------------------------------
-- Minimal Snort 3 configuration
--------------------------------------------------

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

--------------------------------------------------
-- default modules
--------------------------------------------------
detection = { }
search_engine = { }
output = { }

--------------------------------------------------
-- rate_filter configuration
--------------------------------------------------
rate_filter =
{
    {
        -- match on our ruleâ€™s SID
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

``` bash
sudo hping3 -p 80 -S 192.168.1.X
```

------------------------------------------------------------------------

## 🚨 Expected Output

Snort generates alerts when reconnaissance traffic is detected,
including:

-   Nmap SYN scan alerts\
-   ICMP ping detection alerts

------------------------------------------------------------------------

## 📊 Learning Outcomes

-   Snort IDS configuration\
-   Signature-based intrusion detection\
-   Custom rule development\
-   Traffic monitoring and alert analysis\
-   Understanding reconnaissance attack patterns

------------------------------------------------------------------------

## ⚠️ Limitations

-   Basic rules may generate false positives\
-   Requires threshold tuning for production use

------------------------------------------------------------------------

## 🚀 Future Improvements

-   Implement threshold-based detection\
-   Add advanced attack signatures\
-   Integrate alerts with SIEM platforms\
-   Automate alert analysis

------------------------------------------------------------------------

## 📸 Suggested Screenshots

-   Snort running terminal\
-   Alert log output\
-   hping3 test traffic

------------------------------------------------------------------------

## 📚 References

-   Snort Official Documentation\
    https://docs.snort.org/

-   Snort Rule Writing Guide\
    https://docs.snort.org/rules/

------------------------------------------------------------------------

## 👨‍💻 Author

Kripal PV\
Cybersecurity Student \| SOC & Blue Team Enthusiast
