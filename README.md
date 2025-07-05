# 🛡️ Unauthorized-VPN-Client-Usage

## 📌 Reason for the Threat Hunt

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- ProtonVPN

## Scenario:  
This hunt was initiated following a management directive and a recent cybersecurity advisory highlighting the risk of unauthorized VPN usage. Such behavior can:
- 🕵️‍♂️ Obscure user traffic from security monitoring tools
- 📤 Enable unauthorized exfiltration of sensitive data
- 📉 Violate compliance requirements or internal policies

---
## 🔍 Observed TTPs Steps 

- 1. Downloaded ProtonVPN installer: https://protonvpn.com/download
- 2. Silently installed using: `ProtonVPN_v4.2.0_x64.exe /S`
- 3. Launched ProtonVPN from disk
- 4. Established outbound connection over encrypted channel `(port 443)`
- 5. Masked traffic through external VPN server
 
---
### 🗂️ Tables Used

- `DeviceFileEvents`    :  Detected VPN file downloads
- `DeviceProcessEvents` :  Monitored installation and app launch
- `DeviceNetworkEvents` :  Identified encrypted traffic to VPN servers

---
## 🧪 Threat Hunt Steps
## Step 1: VPN download detection

Searched the DeviceFileEvents table for any file containing the string `"VPN"` in its name. The investigation revealed that the user "LabUserTest" appears to have downloaded a  ProtonVPN installer. These events began at: `2025-07-05T08:54:04.8698922Z`

```kusto
DeviceFileEvents
| where DeviceName == "windows-target-"
| where InitiatingProcessAccountName == "labusertest"
| where FileName has_any ("VPN")
| where TimeGenerated >= datetime(2025-07-05T08:54:04.8698922Z)
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![VPN download detected](https://github.com/user-attachments/assets/429b26b2-01de-48a8-bb5c-545bc5bf5dbd)


---
## Step 2: Silent Execution of Installer

Searched the DeviceProcessEvents for any ProcessCommandLine that contained the string `"ProtonVPN_v4.2.0_x64.exe  /S"`. Based on the logs returned: On `July 05, 2025` at `08:55:42.AM`, the device `"windows-target-"` logged that the user `“labusertest”` launched a `ProtonVPN` installer from their Downloads folder—specifically `"ProtonVPN_v4.2.0_x64.exe"` (SHA 256: 297edcc81aec28324f45e2587d6dade9bf16a02f8c939ed4f45ca8e43ad35ada), running it silently with the `/S` flag.

```kusto
DeviceProcessEvents
| where DeviceName == "windows-target-"
| where ProcessCommandLine contains "ProtonVPN_v4.2.0_x64.exe  /S"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![ProtonVPN installation detected](https://github.com/user-attachments/assets/eba20fca-3fbb-435e-ad96-7de9a5944e5e)


---

## Step 3: VPN App Execution

I searched the `DeviceProcessEvents` table for any indication that the user `“labusertest”` actually launched the ProtonVPN application. The findings show that it was indeed launched at: `2025-07-05T08:57:31.5430293Z`. Followed by an Instance of `ProtonVPN Client` running at: `2025-07-05T08:57:32.2064081Z`.

```kusto
DeviceProcessEvents
| where DeviceName == "windows-target-"
| where FileName has_any ("ProtonVPN")
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![VPN Client execution](https://github.com/user-attachments/assets/e0eda5a5-0292-4de9-b442-223ff1db1d76)


---
## Step 4: VPN Tunnel Established

Query the `DeviceNetworkEvents` table for signs that ProtonVPN may have been used to initiate a connection over any known VPN-related ports. At `08:57:53.AM` On `July 05, 2025`, an employee on the device `"windows-target-"` successfully established a connection to the IP address `185.159.159.148` over port `443`, using VPN — indicating that the VPN was actively communicating over the network. 

```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ProtonVPN.exe"
    or InitiatingProcessCommandLine has "ProtonVPN"
| where RemotePort in (1194, 443, 500, 4500, 1701) 
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
![VPN connection established](https://github.com/user-attachments/assets/c691f044-1d7e-4935-bf6e-7b3ee2295353)


---
**📅 Timeline of Events**

| Time (UTC) | Activity                        |
|------------|---------------------------------|
| 08:54:04Z  | ProtonVPN installer dropped     |
| 08:55:42Z  | Installer executed with `/S`   |
| 08:57:31Z  | VPN application started         |
| 08:57:53Z  | Encrypted VPN traffic initiated |

---
**🧾 Summary**

The user on device windows-target- downloaded and silently installed ProtonVPN `(ProtonVPN_v4.2.0_x64.exe)`. Within minutes, the ProtonVPN process was launched, and a secure connection was established to an external IP on port `443`, indicating active VPN usage. These actions were carried out without authorization and suggest an attempt to bypass corporate network monitoring.

These findings confirm:
- ✅ Unauthorized software installation
- ✅ Execution of anonymous browsing tools
- ✅ Encrypted outbound connections bypassing controls

---

**🛡️ Response Actions**

- 🛑 Isolated the device from corporate network
- 👨‍💼 Notified direct manager 
- 🧹 Marked VPN application and artifacts for removal
- 🔁 Recommended implementation of AppLocker and endpoint VPN detection scripts

---
## 📌 Revision History

| Version | Change                  | Date         | Author      |
|---------|-------------------------|--------------|-------------|
| 1.0     | Initial GitHub-ready draft | July 5, 2025 | Tinan Makadjibeye |
