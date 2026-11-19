# Infosec Live X bot

This bot posts each new Infosec Live alert to X. It reads the RSS feed at
`https://feed.mpcvault.com/feed.xml`, builds the post, and sends it to IFTTT.
An IFTTT Applet posts it to X. The bot does not use the X API.

## What it posts

```text
🔴 CRITICAL 9/10: <alert title>.

<start of the alert summary>

AFFECTED: <affected versions>

ACTION: <what to do>
```

- 9 and 10 are CRITICAL, 7 and 8 are HIGH, 4 to 6 are MEDIUM, 1 to 3 are LOW.
- The label, the title and the start of the summary stay within the first 280
  characters. X shows that part in the timeline.
- The full post is longer than 280 characters, so the X account needs X Premium.
  Without Premium, add the repository variable `MAX_POST_CHARS` with the value
  `280`. The bot then leaves out AFFECTED and ACTION.
- The post has no links. The bot writes domains as `example[.]com`.

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
   The schedule runs every 30 minutes. To stop it, delete the variable.

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
GitHub Actions is in the free allowance at one run every 30 minutes.
