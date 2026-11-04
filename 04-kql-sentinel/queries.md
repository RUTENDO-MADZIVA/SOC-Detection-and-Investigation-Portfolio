# KQL Queries (Microsoft Sentinel / Log Analytics)

Run in the Log Analytics demo environment or an Azure free trial. Table names can differ by workspace, so adjust as needed. Add a screenshot of each result under `screenshots/`.

## 1. Failed sign-ins by user and IP
```kql
SigninLogs
| where ResultType != 0
| summarize failures = count() by UserPrincipalName, IPAddress
| order by failures desc
```
**Analyst use:** many failures from one IP may indicate password spraying or brute force (T1110).

## 2. Failed Windows logons per hour
```kql
SecurityEvent
| where EventID == 4625
| summarize attempts = count() by Account, IpAddress, bin(TimeGenerated, 1h)
| order by attempts desc
```
**Analyst use:** spikes show brute-force timing; compare against normal business hours.

## 3. Successful sign-in after many failures
```kql
let failed = SigninLogs | where ResultType != 0 | summarize fails = count() by UserPrincipalName, IPAddress | where fails > 5;
SigninLogs
| where ResultType == 0
| join kind=inner failed on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, fails
```
**Analyst use:** a success after repeated failures can mean a compromised account.

## 4. [Add your own query]
## 5. [Add your own query]
