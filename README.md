# Infosec Live X bot

This bot posts each new [Infosec Live](https://t.me/s/infoseclive) security
alert to X as one line, on [@infoseclivebot](https://x.com/infoseclivebot).

![How the bot works](docs/how-it-works.svg)

GitHub Actions runs `bot.py` every 5 minutes. The script reads the RSS feed,
skips the alerts that it has already sent, and sends each new alert to an
IFTTT Applet. The Applet posts it to X.

A post looks like this:

```text
🔴 CRITICAL 9/10: Two memory-safety bugs in NGINX HTTP/2 handling (a connection use-after-free and a send_window integer underflow) allow unauthenticated remote code execution (CVE-2026-123633, CVE-2026-123007).
```

The bot copies the sentence from the alert. It posts alerts with a score of 7
or higher: 9 and 10 are CRITICAL, 7 and 8 are HIGH.

To set up the bot or run it yourself, see [SETUP.md](SETUP.md).
