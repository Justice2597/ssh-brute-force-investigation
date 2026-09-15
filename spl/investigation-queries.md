# Splunk Investigation Queries

These SPL searches were used during the SSH brute-force investigation.

## Review available sourcetypes
```spl
source="tutorialdata.zip:*"
| stats count by sourcetype
```

## Failed SSH authentication events
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password"
```

## Top attacking source IP addresses
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password"
| rex "from (?<source_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by source_ip
| sort - count
| head 10
```

## Investigate highest-volume source IP
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password" "87.194.216.51"
```

## Targeted usernames for the highest-volume source
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password" "87.194.216.51"
| rex "Failed password for (?:invalid user )?(?<username>\S+)"
| stats count by username
| sort - count
```

## Failed-login activity over time
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password" "87.194.216.51"
| timechart span=1h count
```

## Top targeted usernames across failed logins
```spl
source="tutorialdata.zip:*" sourcetype="secure-2" "Failed password"
| rex "Failed password for (?:invalid user )?(?<username>\S+)"
| stats count by username
| sort - count
| head 10
```

## Detection Logic
A production detection can build on these searches by establishing a threshold for repeated authentication failures from a source IP or against a single account within a defined time window. Thresholds should be tuned to the organization's normal authentication behavior to reduce false positives.
