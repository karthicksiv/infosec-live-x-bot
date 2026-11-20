#!/usr/bin/env python3
"""Infosec Live X bot.

Reads the Infosec Live RSS feed, builds one X post for each new alert, and
sends the post to IFTTT. An IFTTT Applet then posts it to X.

    🚨 CRITICAL 9/10: <ALERT TITLE IN CAPITAL LETTERS>

    <description from the feed>

    <source link>

9 and 10 are CRITICAL (🚨), 7 and 8 are HIGH (🟠). An alert with a score below
7, or with no score, is not posted. The description is the summary paragraph
of the feed item, with no AFFECTED line and no ACTION line. The post is longer
than 280 characters, so the X account needs X Premium.

  python3 bot.py                      Dry run. Prints the posts. Sends nothing.
  python3 bot.py --post               Sends the new alerts to IFTTT.
  python3 bot.py --post --backfill 2  On the first live run, also sends the 2 newest alerts.
  python3 bot.py --post --resend LUKSO
                                      Sends again the alerts with LUKSO in the title.

On the first live run the bot records the alerts that are already in the feed
and sends none of them. Without this rule it would post 50 old alerts at once.

Settings come from the environment, or from a .env file next to this script.
See .env.example. The script uses only the Python standard library.
"""

import argparse
import html
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
USER_AGENT = "infosec-live-x-bot/1.0"

# The bot stops trying an alert that IFTTT refused this many times.
MAX_ATTEMPTS = 3

# The longest post, as X counts it (see xlen). X Premium allows more. This
# limit keeps a broken feed item from making a very long post.
POST_CHARS = 4000

SIREN = "\U0001F6A8"
ORANGE = "\U0001F7E0"
YELLOW = "\U0001F7E1"
GREEN = "\U0001F7E2"
ELLIPSIS = "\u2026"


# ---------------------------------------------------------------- settings

def load_env_file(path):
    """Read KEY=VALUE lines. A value already in the environment wins."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def setting(name, default):
    return os.environ.get(name) or default


# ---------------------------------------------------------------- text

EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF☀-➿⬀-⯿️‍⃣]"
)
TAG = re.compile(r"<[^>]+>")
URL = re.compile(r"https?://\S+")
DOTTED = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SCHEME = re.compile(r"\bhttp(s?)://", re.I)
MENTION = re.compile(r"(?<![A-Za-z0-9_])[@＠](?=[A-Za-z0-9_])")
HASHTAG = re.compile(r"(?<![A-Za-z0-9_&])[#＃](?=[A-Za-z_])")


def load_tlds():
    lines = (HERE / "tlds.txt").read_text(encoding="utf-8").splitlines()
    return {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}


TLDS = load_tlds()


def clean(text):
    """HTML to plain text. Removes the emoji that the feed adds; the bot adds its own."""
    text = html.unescape(TAG.sub("", text))
    text = EMOJI.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def defang(text):
    """Write domains as example[.]com so that X does not make them links.

    An alert can name a domain that an attacker controls, and the bot must not
    link to it.
    A dotted word is a domain when one of its later parts is a real domain
    ending (tlds.txt). Version numbers and names such as Node.js do not change.
    """
    def fix(match):
        token = match.group(0)
        later_parts = token.lower().split(".")[1:]
        if any(part.isalpha() and part in TLDS for part in later_parts):
            return token.replace(".", "[.]")
        return token

    return SCHEME.sub(r"hxxp\1://", DOTTED.sub(fix, text))


def sanitize(text):
    """Make feed text safe to post: no links, no @mentions, no hashtags."""
    text = defang(text)
    text = MENTION.sub("", text)   # X rule: no unsolicited @mentions
    text = HASHTAG.sub("", text)
    return text


def xlen(text):
    """Length of a post as X counts it. A link counts as 23, an emoji as 2."""
    text = URL.sub("x" * 23, unicodedata.normalize("NFC", text))
    total = 0
    for ch in text:
        cp = ord(ch)
        single = cp <= 4351 or 8192 <= cp <= 8205 or 8208 <= cp <= 8223 or 8242 <= cp <= 8247
        total += 1 if single else 2
    return total


def with_full_stop(text):
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else text + "."


# ---------------------------------------------------------------- feed

class Alert:
    def __init__(self, guid, title, score, summary, link, published):
        self.guid = guid
        self.title = title
        self.score = score          # 1 to 10, or None
        self.summary = summary
        self.link = link
        self.published = published


def fetch_feed(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def parse_feed(xml_bytes):
    """Return the alerts in the feed, oldest first."""
    root = ET.fromstring(xml_bytes)
    alerts = []
    for item in root.findall("./channel/item"):
        raw_title = clean(item.findtext("title") or "")
        link = (item.findtext("link") or "").strip()
        guid = (item.findtext("guid") or "").strip() or link or raw_title
        if not raw_title or not guid:
            continue

        score = None
        in_title = re.search(r"\(\s*Score\s+(\d+)\s*/\s*10\s*\)\s*$", raw_title)
        if in_title:
            score = int(in_title.group(1))
            raw_title = raw_title[: in_title.start()].strip()

        description = item.findtext("description") or ""
        paragraphs = [clean(p) for p in re.findall(r"<p>(.*?)</p>", description, flags=re.S)]
        if not paragraphs:
            paragraphs = [clean(description)]

        summary = []
        for para in paragraphs:
            low = para.lower()
            if not para:
                continue
            if low.startswith("score:"):
                in_line = re.search(r"(\d+)\s*/\s*10", para)
                if in_line:
                    score = int(in_line.group(1))
            elif low.startswith(("affected:", "action:")):
                continue   # the post does not use these lines
            elif low.startswith("http") or "share the channel" in low or low.startswith("untrusted data"):
                continue   # source link, share line and reader notice
            else:
                summary.append(para)

        alerts.append(Alert(
            guid=guid,
            title=sanitize(raw_title),
            score=score if score is not None and 1 <= score <= 10 else None,
            summary=sanitize(" ".join(summary)),
            link=link if link.startswith("https://") else "",
            published=(item.findtext("pubDate") or "").strip(),
        ))
    alerts.reverse()   # the feed lists the newest alert first
    return alerts


# ---------------------------------------------------------------- posts

def severity_label(score):
    """The first words of the post: a mark, a severity word and the score.

    9 and 10 are CRITICAL, 7 and 8 are HIGH, 4 to 6 are MEDIUM, 1 to 3 are LOW.
    The bot posts only scores of MIN_SCORE (7) or higher, so the last two
    appear only if MIN_SCORE is set lower.
    """
    if score is None:
        return "ALERT"
    if score >= 9:
        mark, word = SIREN, "CRITICAL"
    elif score >= 7:
        mark, word = ORANGE, "HIGH"
    elif score >= 4:
        mark, word = YELLOW, "MEDIUM"
    else:
        mark, word = GREEN, "LOW"
    return "%s %s %d/10" % (mark, word, score)


def shorten(text, room):
    """Cut text at a word so that it fits in `room` characters. The cut ends with an ellipsis."""
    cut = ""
    for word in text.split(" "):
        candidate = word if not cut else cut + " " + word
        if xlen(candidate) + 2 > room:   # keep room for the ellipsis
            break
        cut = candidate
    return cut.rstrip(",:;") + ELLIPSIS


def build_post(alert):
    """The post: the headline in capital letters, the description, the source link.

        🚨 CRITICAL 9/10: <ALERT TITLE IN CAPITAL LETTERS>

        <description>

        <source link>

    The description is the summary paragraph of the feed item. The bot does
    not rewrite it. The post is longer than 280 characters, so the X account
    needs X Premium. If the post is longer than POST_CHARS, the description
    is cut at a word.
    """
    head = "%s: %s" % (severity_label(alert.score), alert.title.upper())
    # The link goes out with no "https://". IFTTT replaces a link that starts
    # with "https://" with its own ift.tt short link. X makes a link from the
    # address alone and shows it in the same way.
    link = re.sub(r"^https://", "", alert.link)
    tail = "\n\n" + link if link else ""
    body = alert.summary
    room = POST_CHARS - xlen(head + tail) - 2
    if body and xlen(body) > room:
        body = shorten(body, room)
    return head + ("\n\n" + body if body else "") + tail


# ---------------------------------------------------------------- IFTTT

class PostError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status   # HTTP status, or None when there was no reply

    def stops_the_run(self):
        """True when the cause is not this alert: network, key, rate limit, IFTTT itself."""
        return self.status is None or self.status in (401, 403, 429) or self.status >= 500


def send_to_ifttt(text, key, event, api_base):
    """Send one post to the IFTTT Webhooks trigger. The Applet posts {{Value1}} to X.

    IFTTT answers when it has the request and posts to X after that. This call
    cannot tell if the post reached X. The Applet's activity log in IFTTT shows it.
    """
    url = "%s/trigger/%s/with/key/%s" % (
        api_base.rstrip("/"), urllib.parse.quote(event, safe=""), urllib.parse.quote(key, safe=""))
    request = urllib.request.Request(
        url,
        data=json.dumps({"value1": text}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise PostError("IFTTT returned HTTP %s: %s" % (error.code, detail), status=error.code)
    except urllib.error.URLError as error:
        raise PostError("IFTTT request failed: %s" % error.reason)


def load_key():
    key = os.environ.get("IFTTT_WEBHOOK_KEY", "")
    if not key:
        sys.exit("Missing setting: IFTTT_WEBHOOK_KEY. Add it to .env (see .env.example).")
    return key


# ---------------------------------------------------------------- state

def load_state(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"initialized": False, "alerts": {}}


def save_state(path, state):
    if len(state["alerts"]) > 1000:   # keep the file small; the feed holds 50 alerts
        for guid in list(state["alerts"])[:-1000]:
            del state["alerts"][guid]
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=1), encoding="utf-8")
    os.replace(temp, path)


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description="Post Infosec Live alerts to X through IFTTT.")
    parser.add_argument("--post", action="store_true", help="send to IFTTT (default: dry run)")
    parser.add_argument("--backfill", type=int, default=0, metavar="N",
                        help="on the first live run, send the N newest alerts")
    parser.add_argument("--resend", default="", metavar="TEXT",
                        help="send again the alerts whose title contains TEXT, and nothing else")
    parser.add_argument("--preview", type=int, default=3, metavar="N",
                        help="dry run with no state file: show the N newest alerts")
    args = parser.parse_args()

    load_env_file(HERE / ".env")
    feed_url = setting("FEED_URL", "https://feed.mpcvault.com/feed.xml")
    api_base = setting("IFTTT_API_BASE", "https://maker.ifttt.com")
    event = setting("IFTTT_EVENT", "infosec_alert")
    max_alerts = int(setting("MAX_ALERTS_PER_RUN", "3"))
    min_score = int(setting("MIN_SCORE", "7"))
    state_path = Path(setting("STATE_FILE", str(HERE / "state.json")))

    key = load_key() if args.post else None
    alerts = parse_feed(fetch_feed(feed_url))
    state = load_state(state_path)
    known = state["alerts"]

    if not state["initialized"]:
        keep = args.backfill if args.post else args.preview
        old = alerts[: len(alerts) - keep] if keep > 0 else alerts
        if args.post:
            for alert in old:
                known[alert.guid] = {"done": True, "skipped": "in feed before first run"}
            state["initialized"] = True
            save_state(state_path, state)
            print("First live run: recorded %d alerts as already in the feed." % len(old))
        else:
            alerts = alerts[len(old):]

    pending = [a for a in alerts if not known.get(a.guid, {}).get("done")]
    if args.resend:
        # Only the named alerts, also when the record says they were sent.
        pending = [a for a in alerts if args.resend.lower() in a.title.lower()]
    batch = pending[:max_alerts]
    mode = "Live run." if args.post else "Dry run. Nothing is sent."
    print("%s New alerts: %d. In this run: %d." % (mode, len(pending), len(batch)))

    failed = 0
    for alert in batch:
        post = build_post(alert)
        print("\n=== %s  [%s]" % (alert.title, alert.published))

        too_low = alert.score is None or alert.score < min_score
        if too_low:
            print("Not posted: the score is below %d or there is no score." % min_score)
        if not args.post:
            if not too_low:
                print("--- post (%d/%d)" % (xlen(post), POST_CHARS))
                print(post)
            continue

        record = known.setdefault(alert.guid, {"done": False})
        record["title"] = alert.title
        if too_low:
            record["done"] = True
            record["skipped"] = "score below %d" % min_score
            save_state(state_path, state)
            continue
        try:
            send_to_ifttt(post, key, event, api_base)
            time.sleep(1)
        except PostError as error:
            failed += 1
            print("FAILED: %s" % error)
            if error.stops_the_run():
                print("The cause is not this alert. Stopping this run.")
                sys.exit(1)
            # The cause is this alert. Go on to the next one, so that one bad
            # alert does not block newer alerts. Try this one again next run.
            record["attempts"] = record.get("attempts", 0) + 1
            if record["attempts"] >= MAX_ATTEMPTS:
                record["done"] = True
                record["gave_up"] = True
                print("Gave up on this alert after %d tries." % MAX_ATTEMPTS)
            save_state(state_path, state)
            continue
        record["done"] = True
        record["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(state_path, state)
        print("Sent to IFTTT.")

    if failed:
        sys.exit(1)   # a failed run shows as failed in GitHub Actions


if __name__ == "__main__":
    main()
