SOC Investigation: Windows Security Log Analysis Using Splunk
1. Objective

The goal of this investigation was to analyze Windows Security logs in Splunk and review authentication events to check for any suspicious activity.

2. Tools and Data Sources
Splunk Cloud
Splunk Universal Forwarder
Windows Security Event Logs
Windows PowerShell
3. Investigation

I collected Windows Security logs and forwarded them to Splunk. I then focused on Event ID 4624 (successful logon), looking at the logon types and the account information in each event.

4. Findings
I found several successful logon events (Event ID 4624).
Some account names looked unfamiliar because they were GUID-style names. These events used Logon Type 5 (service logon).
The domain in these events was NT VIRTUAL MACHINE.
The process linked to the events was C:\Windows\System32\vmcompute.exe.
The digital signature of the executable was valid.
5. Preliminary Assessment

The activity matches normal Windows virtualization services. Based on the evidence I had, I assessed it as likely benign.

That said, a valid digital signature does not prove that everything it does is safe, so this conclusion is not final.

6. Limitations

This was an initial investigation based only on the Windows Security events I had available. More analysis would be needed for a complete security assessment.

7. Skills Practiced
Windows Security log analysis
Splunk Search Processing Language (SPL)
Event ID investigation
Logon type analysis
Basic digital signature verification
