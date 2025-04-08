# Learning Objectives

![image](https://github.com/user-attachments/assets/6e5d1c12-71ed-4f6a-9ece-d028ef7b3129)

- Setting up and rolling out various Azure components including Virtual Machines (VMs), Log Analytics Workspaces, and Azure Sentinel 
- Competence and experience with Microsoft Azure Sentinel, a SIEM (Security Information and Event Management) Log Management Tool
- Third-party API Calls
- Using KQL to query logs
- Learn how to read the Security Event Logs in Windows
- Utilize Workbooks (World Map) to make an interactive map showing attack statistics

---


# Part 1. Setup Azure Subscription

- **Create Free Azure Subscription**:  
  [https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)

- If Azure doesn’t let you create a free account, you can create a paid subscription and be mindful of shutting down/deleting your resources when you are done.

- Azure Portal: [https://portal.azure.com](https://portal.azure.com)

---


# Part 2. Create the Honey Pot (Azure Virtual Machine)

- Go to: [https://portal.azure.com](https://portal.azure.com) and search for **Virtual Machines**.
- Create a new **Windows 10** virtual machine (choose an appropriate size).

![image](https://github.com/user-attachments/assets/22ea26b2-e25d-4ce2-ad28-ec92c3bdbeac)

- Remember the **username and password**.
- Go to the **Network Security Group** for your virtual machine and create a rule that allows **all traffic inbound**.

![image](https://github.com/user-attachments/assets/86e80e85-3bd0-4ac0-bd05-718efb010291)

- Log into your virtual machine and **turn off the Windows firewall**:  
  `Start -> wf.msc -> Properties -> All Off`

![image](https://github.com/user-attachments/assets/1de21488-48ec-44b7-adb5-903252dc0293)

- To test whether the firewall and NSG have been disabled or not, use ICMP protocol and ping the public ip address

![image](https://github.com/user-attachments/assets/858aea86-4551-4af6-825a-f76097b66a11)


---


# Part 3. Logging into the VM and Inspecting Logs

- **Fail 3 logins** as “employee123” (or some other username).

![image](https://github.com/user-attachments/assets/35a757aa-7d68-4e28-b5bc-ea7aafdc54b1)

- Login to your virtual machine.
- Open up **Event Viewer** and inspect the **Security Logs**.
  - Look for failed logins as “employee123”, Event ID: `4625`.

![image](https://github.com/user-attachments/assets/fe103016-b2de-427d-a59d-625c3db37886)


---


# Part 4. Log Forwarding and KQL

- Create **Log Analytics Workspace** (a central log repository).
![image](https://github.com/user-attachments/assets/0e40c72b-1b2d-4dee-bde1-2cc6d4c0773a)

- Create a **Sentinel Instance** and connect it to **Log Analytics**.
![image](https://github.com/user-attachments/assets/8d6336bb-fec6-43b0-b5a1-3152b6565ce8)

- Configure the “**Windows Security Events via AMA**” connector.
![image](https://github.com/user-attachments/assets/85628aaf-d32e-44b2-8a50-8cb2025ae4cc)

- Create the **DCR** within Sentinel, watch for extension creation.
![image](https://github.com/user-attachments/assets/24f20339-7734-483c-819f-43d05a926e4c)

- Query for logs within the **LAW**.

```kusto
SecurityEvent
| where EventId == 4625
```

---


# Part 5. Log Enrichment and Finding Location Data

When observing the `SecurityEvent` logs in the **Log Analytics Workspace**, you'll notice there is **no location data**, only IP addresses. We can derive the location using external data.

## Step 1: Import a GeoIP Watchlist

Import a spreadsheet as a **Sentinel Watchlist** containing geographic info for each IP block.

**Download**: `geoip-summarized.csv`

### Create the Watchlist in Microsoft Sentinel

- **Name/Alias**: `geoip`
- **Source type**: `Local File`
- **Number of lines before row**: `0`
- **Search Key**: `network`

Wait for the watchlist to fully import. It should contain around **55,000 rows**.
![image](https://github.com/user-attachments/assets/cbe6c3a5-4595-48d8-8f34-86da78cc882b)


> In real-world scenarios, this kind of location data would typically be pulled live or updated automatically by the service provider.

## Step 2: Use the Watchlist to Enrich Security Logs

We now join the watchlist data with the `SecurityEvent` logs to add geographic information:

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

---


# Part 6. Attack Map Creation

We will now create a live **Attack Map** in Microsoft Sentinel to visualize login attempts based on geographic data.

---

## Step 1: Create a New Workbook

1. Go to **Microsoft Sentinel**.
2. Navigate to the **Workbooks** section.
3. Click **+ New** to create a new workbook.
4. Delete all the prepopulated visual elements.

---

## Step 2: Add a Query Element

1. Click **Add Query**.
2. Go to the **Advanced Editor** tab.
3. Paste the contents of the pre-configured JSON.

> **Workbook (Attack Map) JSON**:  
> `windows-rdp-auth-fail.json`
> `linux-ssh-auth-fail.json`

---

## Step 3: Analyze the Attack Map


![image](https://github.com/user-attachments/assets/9153e2b3-aa74-4f0c-aff2-8dcc522eae11)

- **Observation**:  
  - The **largest concentration** of attacks originated from **South America (Argentina)**.
  - **Western and Central Europe** (Netherlands, Poland, Belgium) had significant hostile activity.
  - A **small but notable number** of attempts originated from **Asia**, **Africa**, and **North America**.
  - These patterns help illustrate how brute-force login attempts on cloud VMs are **globally distributed** and **automated**.

- **This visualization helps:**
  - Identify **hot zones of malicious activity**
  - Understand attacker **geographic distribution**
  - Justify the use of **geo-fencing**, **IP-based restrictions**, and **region-aware alerting**

---

**Done!**  
Successfully visualized cyber-attack activity in real-time using Azure Sentinel’s Workbook feature and your enriched logs.
