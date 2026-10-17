# Mini SOC Log Analyzer

A beginner cybersecurity project built with Python to analyze login logs and identify potentially suspicious authentication activity.

## Features

- Reads login events from a text file.
- Counts successful and failed login attempts.
- Groups failed attempts by IP address.
- Detects at least three failed logins from the same IP within a five-minute window.
- Reports suspicious patterns with timestamps.
- Exports an analysis report to a text file.
- Handles malformed log entries and missing log files.

## Technologies

- Python
- Datetime processing
- Log analysis
- Basic security monitoring

## How It Works

The analyzer reads each log entry, extracts its timestamp, IP address, and login status, then examines failed attempts. If three or more failures from the same IP occur within five minutes, the tool generates a warning.

## Project Status

Working prototype. Tested with sample logs covering suspicious activity, attempts spread over a longer period, and the exact five-minute boundary.

## Limitations

This is an educational prototype, not a production security monitoring system. A suspicious pattern does not prove malicious activity, and the tool uses sample text logs rather than live system events.