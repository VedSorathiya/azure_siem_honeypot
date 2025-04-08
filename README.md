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
- Log into your virtual machine and **turn off the Windows firewall**:  
  `Start -> wf.msc -> Properties -> All Off`

---

# Part 3. Logging into the VM and Inspecting Logs

- **Fail 3 logins** as “employee” (or some other username).
- Login to your virtual machine.
- Open up **Event Viewer** and inspect the **Security Logs**.
  - Look for 3 failed logins as “employee”, Event ID: `4625`.
- Next, we are going to create a **central log repository** called a **Log Analytics Workspace (LAW)**.

---

# Part 4. Log Forwarding and KQL

- Create **Log Analytics Workspace**.
- Create a **Sentinel Instance** and connect it to **Log Analytics**.
  - (Observe architecture)
- Configure the “**Windows Security Events via AMA**” connector.
- Create the **DCR** within Sentinel, watch for extension creation.
- Query for logs within the **LAW**.

```kusto
SecurityEvent
| where EventId == 4625
```

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

Wait for the watchlist to fully import. It should contain around **54,000 rows**.

> 🔎 In real-world scenarios, this kind of location data would typically be pulled live or updated automatically by the service provider.

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

# Part 6. Attack Map Creation

We will now create a live **Attack Map** in Microsoft Sentinel to visualize login attempts based on geographic data.

---

## 🛠 Step 1: Create a New Workbook

1. Go to **Microsoft Sentinel**.
2. Navigate to the **Workbooks** section.
3. Click **+ New** to create a new workbook.
4. Delete all the prepopulated visual elements.

---

## 🔍 Step 2: Add a Query Element

1. Click **Add Query**.
2. Go to the **Advanced Editor** tab.
3. Paste the contents of the pre-configured JSON.

> 📁 **Workbook (Attack Map) JSON**:  
> `map.json` (should be provided/downloaded separately)

---

## 🧠 Step 3: Analyze the Attack Map

- **Observe the Query**:  
  Understand how the query pulls enriched log data and matches it with the geoIP watchlist.

- **Observe the Map Settings**:  
  Includes coordinates, display options, pin styles, etc.

- **Observe the Map Visualization**:  
  It will show failed login attempts (e.g., Event ID 4625) with geolocation plotted based on IP address.

---

✅ **Finished!**  
You’ve successfully visualized cyber-attack activity in real-time using Azure Sentinel’s Workbook feature and your enriched logs.
