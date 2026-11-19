# Infosec Live X bot

This bot posts each new Infosec Live alert to X. It reads the RSS feed at
`https://feed.mpcvault.com/feed.xml`, builds the post, and sends it to IFTTT.
An IFTTT Applet posts it to X. The bot does not use the X API.

## What it posts

```text
🔴 CRITICAL 9/10: <one sentence that says what happened> (<CVE IDs>).
```

Example:

```text
🔴 CRITICAL 9/10: Two memory-safety bugs in NGINX HTTP/2 handling (a connection use-after-free and a send_window integer underflow) allow unauthenticated remote code execution (CVE-2026-123633, CVE-2026-123007).
```

- 9 and 10 are CRITICAL, 7 and 8 are HIGH. An alert with a score below 7, or
  with no score, is not posted. To change the lowest score, add the repository
  variable `MIN_SCORE`.
- The post is one line of at most 280 characters. The X account does not need
  X Premium.
- The post has no links, no AFFECTED line and no ACTION line. The bot writes
  domains as `example[.]com`.

The bot copies the sentence from the feed. It does not write text of its own.

1. The sentence is the first sentence of the alert summary.
2. If the post is then longer than 280 characters, the sentence is cut at a
   semicolon, where a complete clause ends.
3. If the post is still too long, the sentence is the alert title.
4. The sentence is also the alert title when the summary sentence has none of
   the names in the title (for example the product name). Such a sentence
   does not say what is affected.

The CVE IDs come from the alert title and go at the end of the post.

## Set up IFTTT (free plan)

1. Sign in to IFTTT and connect the X account that will post the alerts.
2. Create an Applet:
   - If This: **Webhooks** > **Receive a web request**. Event name: `infosec_alert`.
   - Then That: **X (Twitter)** > **Post a tweet**. Tweet text: `{{Value1}}` and nothing more.
3. Open https://ifttt.com/maker_webhooks and select **Documentation**. Copy the key.

## Run on GitHub Actions

The workflow is `.github/workflows/post-alerts.yml`.

1. Add the repository secret `IFTTT_WEBHOOK_KEY` with the key from IFTTT
   (Settings > Secrets and variables > Actions).
2. Start the workflow by hand (Actions > Post alerts to X > Run workflow) with
   mode `dry-run`. It prints the posts for the three newest alerts.
3. Start it again with mode `post` and backfill `1`. It sends the newest alert.
   Check the post on X.
4. To start the schedule, add the repository variable `POSTING_ENABLED` with the
   value `true` (Settings > Secrets and variables > Actions > Variables).
   A scheduled run starts every 5 minutes and checks the feed 3 times, 2 minutes
   apart. GitHub can start a run late. To stop the schedule, delete the variable.

To send one alert again, run the workflow with mode `post` and a part of the
alert title in `resend`, for example `LUKSO`. The run sends only the alerts
that match.

The first live run records the alerts that are already in the feed and sends
none of them, unless you set a backfill number.

The workflow saves `state.json` to the repo after each run. This file is the
record of sent alerts. Do not delete it: without it, the next run is a first
run again.

## Run on your computer

```bash
python3 bot.py
```

This is a dry run. It sends nothing. To send, copy `.env.example` to `.env`,
add the key, and run `python3 bot.py --post`.

## When a post fails

- IFTTT answers when it has the request and posts to X after that. The bot
  cannot see if the post reached X. The Applet's activity log in IFTTT shows it.
- If the key is wrong or IFTTT does not answer, the bot stops the run and tries
  again in the next run. A failed run shows as failed in the Actions tab.
- When the IFTTT credits for the month are used, IFTTT pauses the Applet and
  does not post what it gets while it is paused.

## Cost

The IFTTT free plan gives 1,000 credits each month. Each post uses credits.
GitHub Actions is free for this schedule only while the repo is public.
In a private repo the same schedule costs about $247 a month.
