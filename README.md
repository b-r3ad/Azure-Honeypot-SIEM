# Overview
This repository contains a step-by-step honeypot lab designed to simulate attacker behavior and collect real-world security logs using Azure VM's Log Analytics Workspace and Microsoft Sentinel.

By exposing a vulnerable system to the Internet, this lab captures actual attack attempts, including failed login attempts and geographic data of the attackers. The collected logs are then analyzed using KQL queries, enriched with GeoIP data, and visualized in Sentinel Workbooks to create an interactive attack map.

This lab provides a practical way to observe live attack patterns, analyze security events, and gain insights into attacker behavior using real-world data.


# Prerequisites:
- This can be completed 100% free if it's your first time making a Azure account, sign up [here](https://azure.microsoft.com/en-in/pricing/purchase-options/azure-account).
- Tip! I used a temporary card from privacy.com to avoid any accidental charges, as you do need to link a debit/credit card. However, when creating your first account you will receive a $200 credit (*expires in 30 days*).
- The account creation is a fairly simple process, you will just need a Microsoft and or Google account.

# Step 1: Create the Lab Environment:
1. **Create a Resource Group** - Named 'SOC-Lab' for this setup.
2. **Create a Virtual Network** - Ensures connectivity for the lab.
3. **Deploy a Virtual Machine (VM)** - Using Windows 10 for the target system; however, feel free to choose whichever setup you'd like.

### Initial Environment:
![Initial Environment](images/initialenvironment.png)



# Step 2: Configuring the Honeypot (*Removing Security Controls*)
1. **Modify Network Security Group (NSG):**
   - By default, RDP (Remote Desktop Protocol) is the only allowed inbound connection.
   - Delete the default RDP rule and allow all inbound traffic to attract attackers.
2. **Disable Windows Firewall:**
   - Use RDP to access the VM.
   - Open `wf.msc`, and set all firewall properties to Off.
3. **Verify External Reachability:**
   - Ping the VM from your local machine to confirm it's reachable.


### Initial Connection Using RDP:
![RDP](images/initialRDP.png)


### Firewall Status ON:
![FirewallsOn](images/firewallson.png)


### Disabling Each Part of Windows Firewall:
![FirewallOff1](images/firewallsoff1.png)
---
![FirewallOff2](images/firewallsoff2.png)
---
![FirewallOff3](images/firewallsoff3.png)
---
![FirewallOff4](images/firewallsoff4.png)
---




# Step 3: Enable Logging & Forwarding Data
1. **Verify Local Logging:**
   - Attempt incorrect login credentials to generate failed login logs.
   - Open Event Viewer - Navigate to Security events.
   - Locate Event ID 4625 (*failed login attempts*)
2. **Create LAW (Log Analytics Workspace):**
   - This serves as the central repository for security logs.


### Event Viewer for Failed Login Attempts:
![Eventviewerimage](images/eventviewermyfailedlogin.png)


### Event Viewer 4625:
![4625](images/myfailedlogindetail.png)



### LAW Creation
![LAW](images/LAWcreation.png)


# Step 4: Deploying Microsoft Sentinel (SIEM)
1. **Create a Sentinel Instance** - Azure's Security Information and Event Management (SIEM) tool.
2. **Install Windows Security Events Connector:**
   - Select Windows Security Events via AMA (Azure Monitoring Agent).
   - Create a Data Collection Rule (DCR) to forward logs.
3. **Wait for Log Collection:**
   - Logs may take 1–2 hours to populate.

### Initial Failed Login Attempts via Microsoft Sentinel
![logs1](images/attacklogs1.png)
![logs2](images/attacklogs2.png)
![logs3](images/attacklogs3.png)





# Step 5: Observing Real Attacks
1. **Analyze Failed Login Attempts:**
   - Multiple failed login attempts observed from different usernames (`Admin`, `Administrator`, `usuario`, `Cuentas`)
   - All the initial login attempts originated from the same IP address, indicating a brute force attack, likely from an automated script.
2. **Querying Security Events for Failed Logins:**
   - To identify failed login attempts (*Event ID 4625*) use the following KQL query in Microsoft Sentinel:
   - `kql
SecurityEvent
| where EventID == 4625`


# Step 6: Enriching Logs with Geolocation Data
1. **Create a Watchlist in Microsoft Sentinel:**
   - Upload a GeoIP file to map attacker IP addresses to geographic locations.
   - File used: [geoip-summarized.csv](https://github.com/user-attachments/files/20694215/geoip-summarized.csv)
2. **Query Logs using KQL with Geolocation Data:**
   - `let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventId == 4625
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents`


### Watchlist Creation:
![watchlist](images/watchlistcreation.png)



# Step 7: Attack Map Visualization
1. **Create a Sentinel Workbook to visualize attack locations.**
2. **Add a Query Element and paste the following JSON data:**
   - `{
    "type": 3,
    "content": {
        "version": "KqlItem/1.0",
        "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
        "size": 3,
        "timeContext": {
            "durationMs": 2592000000
        },
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "map",
        "mapSettings": {
            "locInfo": "LatLong",
            "locInfoColumn": "countryname",
            "latitude": "latitude",
            "longitude": "longitude",
            "sizeSettings": "FailureCount",
            "sizeAggregation": "Sum",
            "opacity": 0.8,
            "labelSettings": "friendly_location",
            "legendMetric": "FailureCount",
            "legendAggregation": "Sum",
            "itemColorSettings": {
                "nodeColorField": "FailureCount",
                "colorAggregation": "Sum",
                "type": "heatmap",
                "heatmapPalette": "greenRed"
            }
        }
    },
    "name": "query - 0"
}
`
3. **Observe the attack map, showing where login attempts originate.**



### Initial Attack Map ~2 Hours:
![Attack Map](images/mapdataog.png)


### Attack Map After ~24 Hours:
![Attack Map 24h](images/mapdataovernight.png)



# Real-World Application
   - **Threat Intelligence** – Observe live attack attempts from real-world adversaries
   - **Log Analysis Practice** – Gain hands-on experience with KQL queries and SIEM operations



# **Lab Teardown** (*Optional, but Highly Recommended*):
- Azure resources don't delete themselves, to avoid any unnecessary charges be sure to properly shutdown/delete the resources.
1. **Delete the VM:**
   - Navigate to the Virtual Machines section and select your VM, then click delete.
   - Be sure to delete the associated resources like the OS disk and public IP address.
2. **Delete Resource Group:** 
   - If all lab resources are contained within a single group, then deleting the group will remove everything else.
   - From Azure Portal, go to Resource Groups, select it, and click **Delete Resource Group**
3. **Remove Log Analytics Workspace:**
   - Same steps as before, go to your LAW, select it, and delete it
4. **Delete Microsoft Sentinel:**
   - Finally, ensure that Sentinel is deleted; deleting the workspace should remove the Sentinel instance but it's always good to check there's no lingering connections.


### Last Note:
- Final note, if you would like to setup a way to automate this process in the future, consider checking out my [ARM Folder](https://github.com/b-r3ad/Azure-Honeypot-SIEM/blob/main/Creating-ARM-template.md)


# Resources used:
- [Josh Madakor - Cyber Home Lab from Zero and Catch Attackers.](https://youtu.be/g5JL2RIbThM?si=lBckMrzOO6zGOXun)


