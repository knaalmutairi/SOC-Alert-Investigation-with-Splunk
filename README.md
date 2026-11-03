# SOC Investigation: Windows Security Log Analysis Using Splunk

## Objective

The goal of this investigation was to analyze Windows Security logs in Splunk and review authentication events to check for any suspicious activity.

## Tools and Data Sources

- Splunk Cloud
- Splunk Universal Forwarder
- Windows Security Event Logs
- Windows PowerShell

## Investigation

I collected Windows Security logs and forwarded them to Splunk. I then focused on Event ID 4624 (successful logon) and Event ID 4625 (failed logon), looking at the logon types and the account information in each event.

### SPL Queries

#### 1. Identify available indexes and event sources

```spl
index=*
| stats count by index, sourcetype
```

#### 2. Extract Windows Event IDs

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

#### 3. Analyze successful logon types

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="4624"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>\d+)</Data>"
| stats count by LogonType
| sort - count
```

#### 4. Investigate usernames and logon types

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="4624"
| rex field=_raw "<Data Name='TargetUserName'>(?<Username>[^<]+)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>\d+)</Data>"
| stats count by Username, LogonType
| sort - count
```

#### 5. Investigate failed logon events

```spl
index=main sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="4625"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>\d+)</Data>"
| rex field=_raw "<Data Name='Status'>(?<Status>[^<]+)</Data>"
| rex field=_raw "<Data Name='SubStatus'>(?<SubStatus>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]*)</Data>"
| table _time EventID LogonType TargetUserName IpAddress Status SubStatus
```

## Findings

The analysis was performed using the Windows Security logs available in Splunk, with the search time range set to All time. The results reflect the data available in Splunk at the time of the investigation, so the counts may change if the search is repeated later and new logs have arrived.

### Event Analysis

- Event ID 4624: 788 successful logon events.
- Event ID 4625: 1 failed logon event.

### Successful Logon Events (4624)

- Some account names appeared in GUID format. These events used Logon Type 5 (service logon). A GUID-style name on its own does not mean the account is suspicious.
- The inspected events included the domain `NT VIRTUAL MACHINE`.
- In the inspected event, the associated process was `C:\Windows\System32\vmcompute.exe`.
- PowerShell `Get-AuthenticodeSignature` returned a Valid signature status for `vmcompute.exe`.

The observed activity is consistent with Windows virtualization services and was assessed as likely benign based on the available evidence. That said, a valid signature only means the file passed signature verification. It does not prove that everything the file does is safe, so this conclusion is not final.

## Failed Logon Investigation

### Failed Logon Details

The single failed logon event (Event ID 4625) was examined in detail.

| Field | Finding |
|---|---|
| Event ID | 4625 |
| Date | October 27, 2026 |
| Time | 2:42:27.743 PM |
| Logon Type | 2 – Interactive |
| Status | 0xC000006D |
| SubStatus | 0xC000006A |
| Failure Meaning | Incorrect password |
| Target User Name | `-` (not provided) |
| Target Domain Name | `-` (not provided) |
| IP Address | `-` (not provided) |
| Workstation Name | `-` (not provided) |

The Status and SubStatus values indicate a logon failure caused by an incorrect password.

### Related Successful Logon Review

A successful logon event (Event ID 4624) was also observed:

- Date: October 27, 2026
- Time: 2:50:07.897 PM
- Logon Type: 5 – Service

This event happened about 7 minutes and 40 seconds after the failed logon. However, the successful event had Logon Type 5, while the failed event had Logon Type 2. The available evidence does not show a relationship between the two events.

## Overall Investigation Conclusion

The investigation found two things worth noting.

First, several successful service logons involved GUID-style account names. The inspected events included the `NT VIRTUAL MACHINE` domain. In one inspected event, the associated process was `C:\Windows\System32\vmcompute.exe`. This activity was assessed as likely benign based on the available evidence.

Second, there was one failed interactive logon caused by an incorrect password. The target username, target domain, IP address, and workstation name were shown as `-` in the event, so the available information was not enough to identify the account or the source of the attempt. I also did not treat the later successful service logon as a login after the failed attempt, because the two events had different logon types.

**Preliminary Assessment:** There is not enough evidence to classify the failed logon as malicious or to confirm a security incident.

## Limitations

- This was an initial investigation based only on the Windows Security events available.
- Only one failed logon event was found in the search (All time).
- The target account and source information were shown as `-` in the failed logon event.
- The available logs were not enough to connect the failed and successful logon events.
- Additional log sources and further investigation would be needed for a complete security assessment.

## Skills Practiced

- Windows Security log analysis
- Splunk Search Processing Language (SPL)
- Event ID investigation (4624 and 4625)
- Logon type analysis
- Authentication failure investigation
- Basic security event triage
- Basic digital signature verification
