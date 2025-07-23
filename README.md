<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MohamadHamad17/Tor-Browser-Detection-and-Threat-Hunting-Investigation/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- MDE EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- TOR Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any files containing the string "tor" and found that the user "employee" had downloaded a Tor installer. This action appears to have triggered the copying of several Tor-related files to the desktop, including the creation of a file named "tor-shopping-list.txt" at 2025-07-22T00:43:54.3988281Z. The activity began at 2025-07-22T00:26:48.3746158Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "desktop-jdoe-vm"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2025-07-22T00:26:48.3746158Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1262" height="464" alt="Screenshot 2025-07-22 at 9 04 33 PM" src="https://github.com/user-attachments/assets/5d4cb7c7-e639-4ca5-8483-29c887c4f96e" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any process involving the Tor installer tor-browser-windows-x86_64-portable-14.5.4.exe on device desktop-jdoe-vm. Found that the installer was executed by the employee at the company, with events starting at 2025-07-22T00:29:44Z. Queried for timestamp, device, account, action, file name, path, SHA256, and command line used. Events were sorted by time.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "desktop-jdoe-vm"
| where ProcessCommandLine startswith "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1262" height="231" alt="Screenshot 2025-07-22 at 9 08 19 PM" src="https://github.com/user-attachments/assets/b0f8ec75-6c3b-4464-8d7f-91e434f0caf5" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user "employee" actually opened the Tor browser. Found evidence that it was launched at 2025-07-22T00:31:53Z. There were several other instances of firefox.exe (Tor) as well as Tor.exe spawned after

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "desktop-jdoe-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe", "torbrowser-install-win64.exe", "torbrowser-install-win32.exe", "tor-browser-windows-x86_64-portable.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1262" height="465" alt="Screenshot 2025-07-22 at 9 09 39 PM" src="https://github.com/user-attachments/assets/8363507c-cab3-4349-b848-3103fb137348" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table on device desktop-jdoe-vm, filtering out system-level activity. Focused on known Tor-related ports (9001, 9030, 9040, 9050, 9051, 9150) to detect potential Tor network traffic. Queried for timestamp, device name, user account, connection details (IP and port), URL, and the process that initiated the connection. Results were sorted by most recent activity. Confirmed that the Tor browser made a successful connection from desktop-jdoe-vm under the user "employee" on July 21, 2025, at 8:34:07 PM. The connection was made to 127.0.0.1 on port 9150, using the process firefox.exe, indicating Tor was likely running on this computer.indicating use outside the the browser There were a couple of other connections to sites over port `443` indicating use outside the the browser.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "desktop-jdoe-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1262" height="465" alt="Screenshot 2025-07-22 at 9 11 16 PM" src="https://github.com/user-attachments/assets/e680da59-4460-4f7b-be79-08406e25aa89" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
