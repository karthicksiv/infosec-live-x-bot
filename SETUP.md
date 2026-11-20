# Infosec Live X bot: setup

This bot posts each new Infosec Live alert to X. It reads the RSS feed at
`https://feed.mpcvault.com/feed.xml`, builds the post, and sends it to IFTTT.
An IFTTT Applet posts it to X. The bot does not use the X API.

## What it posts

```text
🚨 CRITICAL 9/10: <ALERT TITLE IN CAPITAL LETTERS>

<description>

<source link>
```

Example:

```text
🟠 HIGH 8/10: HYPERLIQUID XMR1 DEPLOYER WALLET SUSPECTED COMPROMISE, ~$13.3M DUMPED

The XMR1 (wrapped Monero) deployer wallet on Hyperliquid sent 5.2M XMR1 to a fresh address (0x1464dAcaCeB0d511f9964cDac5ebA50ea42220Bf), which sold it into the order book for ~13.3M USDC, crashing XMR1 from ~$494 to ~$1 in about 35 minutes, then bought ~7,467 ETH and bridged most of it to Ethereum. Flagged by Scam Sniffer and Lookonchain; no official issuer statement yet.

www.lookonchain.com/feeds/83263
```

- 9 and 10 are CRITICAL (🚨), 7 and 8 are HIGH (🟠). An alert with a score
  below 7, or with no score, is not posted. To change the lowest score, add
  the repository variable `MIN_SCORE`.
- The headline is the alert title in capital letters.
- The description is the summary paragraph of the feed item. The bot does not
  rewrite it. The post has no AFFECTED line and no ACTION line.
- The link is the source link of the feed item, with no `https://` in front.
  IFTTT replaces a link that starts with `https://` with its own `ift.tt`
  short link. X makes a link from the address alone and shows a preview of
  the page.
- In the headline and the description, the bot writes domains as
  `example[.]com`, so that X does not make them links.
- The post is longer than 280 characters, so the X account needs X Premium.

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
4. To start the bot, add the repository variable `POSTING_ENABLED` with the
   value `true` (Settings > Secrets and variables > Actions > Variables). Then
   start the workflow by hand with mode `watch`.
   A watch run checks the feed 3 times, 2 minutes apart, and then starts the
   next watch run. Thus a new run starts about every 5 minutes.
5. To stop the bot, delete the variable `POSTING_ENABLED`. The next run then
   does nothing and starts no other run. To stop it at once, also cancel the
   run that is in progress.

The workflow also has a schedule (every 5 minutes). In November 2026 GitHub did
not start these scheduled runs for this repo. For that reason each run starts
the next run. If a run stops before it starts the next run, the bot stops:
the Actions tab then shows no new run. Start the workflow with mode `watch`
again.

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
