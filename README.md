# Infosec Live X bot

This bot posts each new Infosec Live alert to X. It reads the RSS feed at
`https://feed.mpcvault.com/feed.xml`.

## What it posts

Each alert is a main post and one reply.

```text
MAIN POST
🔴 CRITICAL 9/10: <alert title>.

<start of the alert summary>

REPLY
AFFECTED: <affected versions>

ACTION: <what to do>
```

- 9 and 10 are CRITICAL, 7 and 8 are HIGH, 4 to 6 are MEDIUM, 1 to 3 are LOW.
- The main post stays within 280 characters.
- The reply is longer than 280 characters, so the bot account needs X Premium.
  Without Premium, set `MAX_REPLY_CHARS` to `280` and the bot splits the reply.
- The posts have no links. The bot writes domains as `example[.]com`.

## Run on GitHub Actions

The workflow is `.github/workflows/post-alerts.yml`.

1. Add four repository secrets (Settings > Secrets and variables > Actions):
   `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET`.
2. Start the workflow by hand (Actions > Post alerts to X > Run workflow) with
   mode `dry-run`. It prints the posts for the three newest alerts.
3. Start it again with mode `post` and backfill `1`. It posts the newest alert.
4. To start the schedule, add the repository variable `POSTING_ENABLED` with the
   value `true` (Settings > Secrets and variables > Actions > Variables).
   The schedule runs every 30 minutes. To stop it, delete the variable.

The first live run records the alerts that are already in the feed and posts
none of them, unless you set a backfill number.

The workflow saves `state.json` to the repo after each run. This file is the
record of posted alerts. Do not delete it: without it, the next run is a first
run again.

## Run on your computer

```bash
python3 bot.py
```

This is a dry run. It posts nothing. To post, copy `.env.example` to `.env`,
add the four keys, and run `python3 bot.py --post`.

## When a post fails

- If X refuses one alert, the bot goes on to the next alert. It tries the
  refused alert again in the next two runs, and then stops trying.
- If the cause is not the alert (network, keys, credits, rate limit), the bot
  stops the run and tries again in the next run.
- A failed run shows as failed in the Actions tab.

## Cost

X bills $0.015 for each post. An alert is two posts, so $0.03. At 150 alerts a
month, that is about $4.50. Set a spending limit in the X Developer Console.
