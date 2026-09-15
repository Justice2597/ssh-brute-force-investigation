# Investigation Findings

## Scenario
SSH authentication logs were analyzed in Splunk Cloud to identify patterns associated with password-guessing and brute-force activity in a training dataset.

## Investigation Process
The investigation began by validating the imported tutorial data and identifying the `secure-2` sourcetype. Failed SSH authentication events were isolated using the phrase `Failed password`. Regular expressions were then used to extract source IP addresses and attempted usernames from the raw events.

The extracted fields were aggregated with `stats`, ranked by event count, and used to identify high-volume sources and commonly targeted accounts. The highest-volume source was investigated further, and a timechart was created to visualize its failed authentication activity over time. The results were then incorporated into a Splunk dashboard.

## Observations
The failed-password search returned **33,253 events**. The highest-volume source IP was **87.194.216.51**, with **948 failed attempts**. Other high-volume sources included **211.166.11.101 (743)** and **128.241.220.82 (622)**.

The most frequently targeted account name was **root (1,493 attempts)**, followed by **administrator (1,020)**, **admin (938)**, and **operator (923)**. These are common administrative or privileged account names and therefore useful indicators when reviewing password-guessing activity.

## Assessment
The combination of repeated authentication failures, high event counts from individual sources, and repeated targeting of common privileged usernames is consistent with brute-force/password-spraying style behavior in the lab dataset. Event counts alone do not prove compromise, so a production investigation would require additional correlation.

## Recommended Follow-Up
A SOC analyst should correlate suspicious sources with successful authentication events, review affected account privileges, examine endpoint/network telemetry, enrich source addresses with approved threat-intelligence sources, and determine whether any defensive controls or account protections were triggered. Repeated failed authentication activity can also be converted into a tuned Splunk alert or correlation search.

## Outcome
The project produced an analyst-facing Splunk dashboard that summarizes attack activity and demonstrates an investigation workflow from raw logs through field extraction, aggregation, analysis, visualization, and documented findings.
