#!/usr/bin/env python3
"""Infosec Live X bot.

Reads the Infosec Live RSS feed and posts each new alert to X as a main post
with one reply under it:

    Main post   severity word with the score, the title, the start of the summary
    Reply       AFFECTED and ACTION

The posts have no links. X bills a post with a link at a much higher price.

The reply is longer than 280 characters, so the bot account needs X Premium.
Without it, set MAX_REPLY_CHARS=280 and the bot splits the reply.

  python3 bot.py                      Dry run. Prints the posts. Posts nothing.
  python3 bot.py --post               Posts the new alerts to X.
  python3 bot.py --post --backfill 2  On the first live run, also posts the 2 newest alerts.

On the first live run the bot records the alerts that are already in the feed
and posts none of them. Without this rule it would post 50 old alerts at once.

Settings come from the environment, or from a .env file next to this script.
See .env.example. The script uses only the Python standard library.
"""

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
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

# X API prices in USD for each request (docs.x.com pricing page, read 2026-11-18).
COST_POST = 0.015
COST_POST_WITH_URL = 0.200

# The bot stops trying an alert that X refused this many times.
MAX_ATTEMPTS = 3

# X shows a post of this length in full in the timeline. The main post never
# goes over it, also when the account can write longer posts.
MAIN_POST_CHARS = 280

SIREN = "\U0001F6A8"
RED = "\U0001F534"
ORANGE = "\U0001F7E0"
YELLOW = "\U0001F7E1"
GREEN = "\U0001F7E2"
ELLIPSIS = "…"


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

    Two reasons. An alert can name a domain that an attacker controls, and the
    bot must not link to it. X also bills a post with a link at a higher price.
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
    def __init__(self, guid, title, score, summary, affected, action, link, published):
        self.guid = guid
        self.title = title
        self.score = score          # 1 to 10, or None
        self.summary = summary
        self.affected = affected
        self.action = action
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

        summary, affected, action = [], "", ""
        for para in paragraphs:
            low = para.lower()
            if not para:
                continue
            if low.startswith("score:"):
                in_line = re.search(r"(\d+)\s*/\s*10", para)
                if in_line:
                    score = int(in_line.group(1))
            elif low.startswith("affected:"):
                affected = para.split(":", 1)[1].strip()
            elif low.startswith("action:"):
                action = para.split(":", 1)[1].strip()
            elif low.startswith("http") or "share the channel" in low or low.startswith("untrusted data"):
                continue   # source link, share line and reader notice
            else:
                summary.append(para)

        alerts.append(Alert(
            guid=guid,
            title=sanitize(raw_title),
            score=score if score is not None and 1 <= score <= 10 else None,
            summary=sanitize(" ".join(summary)),
            affected=sanitize(affected),
            action=sanitize(action),
            link=link if link.startswith("https://") else "",
            published=(item.findtext("pubDate") or "").strip(),
        ))
    alerts.reverse()   # the feed lists the newest alert first
    return alerts


# ---------------------------------------------------------------- posts

SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")
CLAUSE_END = re.compile(r"(?<=[;,:])\s+")


def pack(parts, limit):
    """Join parts with spaces into pieces of at most `limit` length."""
    pieces, current = [], ""
    for part in parts:
        candidate = part if not current else current + " " + part
        if xlen(candidate) <= limit:
            current = candidate
            continue
        if current:
            pieces.append(current)
        current = part
    if current:
        pieces.append(current)
    return pieces


def hard_cut(word, limit):
    out, current = [], ""
    for ch in word:
        if xlen(current + ch) > limit:
            out.append(current)
            current = ""
        current += ch
    return out + [current]


def pieces_of(text, limit):
    """Split text into pieces that each fit in one post.

    Split at sentence ends first. Split a sentence that is too long at
    clause marks, and a clause that is too long at spaces.
    """
    if xlen(text) <= limit:
        return [text]
    pieces = []
    for sentence in SENTENCE_END.split(text):
        if xlen(sentence) <= limit:
            pieces.append(sentence)
            continue
        clauses = []
        for clause in CLAUSE_END.split(sentence):
            if xlen(clause) <= limit:
                clauses.append(clause)
                continue
            words = []
            for word in clause.split(" "):
                words.extend(hard_cut(word, limit) if xlen(word) > limit else [word])
            clauses.extend(pack(words, limit))
        pieces.extend(pack(clauses, limit))
    return pieces


def severity_label(score):
    """The first words of the main post: a color mark, a severity word and the score.

    9 and 10 are CRITICAL, 7 and 8 are HIGH, 4 to 6 are MEDIUM, 1 to 3 are LOW.
    The feed publishes only scores of 8 or higher, so the last two are rare.
    """
    if score is None:
        return "%s ALERT" % SIREN
    if score >= 9:
        mark, word = RED, "CRITICAL"
    elif score >= 7:
        mark, word = ORANGE, "HIGH"
    elif score >= 4:
        mark, word = YELLOW, "MEDIUM"
    else:
        mark, word = GREEN, "LOW"
    return "%s %s %d/10" % (mark, word, score)


def summary_lead(summary, room):
    """Return the start of the summary that fits in `room` characters.

    Whole sentences are used while they fit. If the first sentence is too
    long, it is cut at a clause mark (; , :) and, if that leaves less than
    half of the room used, at a word. A cut ends with an ellipsis, except a
    cut at a semicolon, which is a complete clause and ends with a full stop.
    """
    if not summary or room < 40:
        return ""
    sentences = SENTENCE_END.split(summary)
    lead = ""
    for sentence in sentences:
        candidate = sentence if not lead else lead + " " + sentence
        if xlen(candidate) > room:
            break
        lead = candidate
    if lead:
        return lead

    by_clause = CLAUSE_END.split(sentences[0])
    by_word = sentences[0].split(" ")
    for parts, minimum in ((by_clause, room // 2), (by_word, 1)):
        cut = ""
        for part in parts:
            candidate = part if not cut else cut + " " + part
            if xlen(candidate) + 2 > room:   # keep room for the ellipsis
                break
            cut = candidate
        if xlen(cut) >= minimum:
            if cut.endswith(";"):
                return cut[:-1] + "."
            return cut.rstrip(",:;") + ELLIPSIS
    return ""


def build_main_post(alert):
    """Severity label with the score and the title, then the start of the summary."""
    limit = MAIN_POST_CHARS
    post = with_full_stop("%s: %s" % (severity_label(alert.score), alert.title))
    if xlen(post) > limit:
        post = pieces_of(post, limit)[0]
    lead = summary_lead(alert.summary, limit - xlen(post) - 2)
    return post + "\n\n" + lead if lead else post


def build_replies(alert, limit):
    """AFFECTED and ACTION, in as few replies as fit."""
    blocks = []
    if alert.affected:
        blocks.append("AFFECTED: " + alert.affected)
    if alert.action:
        blocks.append("ACTION: " + alert.action)

    replies, current = [], ""
    for block in blocks:
        for index, piece in enumerate(pieces_of(block, limit)):
            joiner = "\n\n" if index == 0 else " "
            candidate = piece if not current else current + joiner + piece
            if xlen(candidate) <= limit:
                current = candidate
            else:
                replies.append(current)
                current = piece
    if current:
        replies.append(current)
    return replies


def build_posts(alert, reply_limit):
    """Return the main post followed by its replies."""
    return [build_main_post(alert)] + build_replies(alert, reply_limit)


def thread_cost(posts):
    return sum(COST_POST_WITH_URL if URL.search(p) else COST_POST for p in posts)


# ---------------------------------------------------------------- X API

class XError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status   # HTTP status, or None when there was no reply

    def stops_the_run(self):
        """True when the cause is not this alert: network, keys, credits, rate limit, X itself.

        The two word checks are a best guess at X's error text for an app with
        the wrong permission and for an account with no credits.
        """
        if self.status is None or self.status in (401, 402, 429) or self.status >= 500:
            return True
        text = str(self).lower()
        return "permission" in text or "credit" in text


def percent(value):
    return urllib.parse.quote(str(value), safe="-._~")


def oauth_header(method, url, keys, extra_params=None, nonce=None, timestamp=None):
    """OAuth 1.0a header (HMAC-SHA1). A JSON body is not part of the signature."""
    oauth = {
        "oauth_consumer_key": keys["api_key"],
        "oauth_nonce": nonce or secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(timestamp or int(time.time())),
        "oauth_token": keys["access_token"],
        "oauth_version": "1.0",
    }
    signed = dict(oauth)
    signed.update(extra_params or {})
    param_string = "&".join(
        "%s=%s" % (k, v) for k, v in sorted((percent(k), percent(v)) for k, v in signed.items())
    )
    base = "&".join([method.upper(), percent(url), percent(param_string)])
    signing_key = percent(keys["api_secret"]) + "&" + percent(keys["access_token_secret"])
    digest = hmac.new(signing_key.encode(), base.encode(), hashlib.sha1).digest()
    oauth["oauth_signature"] = base64.b64encode(digest).decode()
    return "OAuth " + ", ".join('%s="%s"' % (percent(k), percent(v)) for k, v in sorted(oauth.items()))


def create_post(text, reply_to, keys, api_base):
    """Create one post. Return its id."""
    url = api_base.rstrip("/") + "/2/tweets"
    body = {"text": text}
    if reply_to:
        body["reply"] = {"in_reply_to_tweet_id": reply_to}
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": oauth_header("POST", url, keys),
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:500]
        raise XError("X API returned HTTP %s: %s" % (error.code, detail), status=error.code)
    except urllib.error.URLError as error:
        raise XError("X API request failed: %s" % error.reason)
    post_id = (data.get("data") or {}).get("id")
    if not post_id:
        raise XError("X API reply has no post id: %s" % json.dumps(data)[:300])
    return post_id


def load_keys():
    names = {
        "api_key": "X_API_KEY",
        "api_secret": "X_API_SECRET",
        "access_token": "X_ACCESS_TOKEN",
        "access_token_secret": "X_ACCESS_TOKEN_SECRET",
    }
    keys = {field: os.environ.get(env, "") for field, env in names.items()}
    missing = [names[field] for field, value in keys.items() if not value]
    if missing:
        sys.exit("Missing settings: %s. Add them to .env (see .env.example)." % ", ".join(missing))
    return keys


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
    parser = argparse.ArgumentParser(description="Post Infosec Live alerts to X.")
    parser.add_argument("--post", action="store_true", help="post to X (default: dry run)")
    parser.add_argument("--backfill", type=int, default=0, metavar="N",
                        help="on the first live run, post the N newest alerts")
    parser.add_argument("--preview", type=int, default=3, metavar="N",
                        help="dry run with no state file: show the N newest alerts")
    args = parser.parse_args()

    load_env_file(HERE / ".env")
    feed_url = setting("FEED_URL", "https://feed.mpcvault.com/feed.xml")
    api_base = setting("X_API_BASE", "https://api.x.com")
    reply_limit = int(setting("MAX_REPLY_CHARS", "4000"))
    max_alerts = int(setting("MAX_ALERTS_PER_RUN", "3"))
    state_path = Path(setting("STATE_FILE", str(HERE / "state.json")))

    keys = load_keys() if args.post else None
    alerts = parse_feed(fetch_feed(feed_url))
    state = load_state(state_path)
    known = state["alerts"]

    if not state["initialized"]:
        keep = args.backfill if args.post else args.preview
        old = alerts[: len(alerts) - keep] if keep > 0 else alerts
        if args.post:
            for alert in old:
                known[alert.guid] = {"done": True, "ids": [], "skipped": "in feed before first run"}
            state["initialized"] = True
            save_state(state_path, state)
            print("First live run: recorded %d alerts as already in the feed." % len(old))
        else:
            alerts = alerts[len(old):]

    pending = [a for a in alerts if not known.get(a.guid, {}).get("done")]
    batch = pending[:max_alerts]
    mode = "Live run." if args.post else "Dry run. Nothing is posted."
    print("%s New alerts: %d. In this run: %d." % (mode, len(pending), len(batch)))

    total_cost = 0.0
    failed = 0
    for alert in batch:
        posts = build_posts(alert, reply_limit)
        total_cost += thread_cost(posts)
        print("\n=== %s  [%s]" % (alert.title, alert.published))

        if not args.post:
            for number, text in enumerate(posts):
                name = "main post" if number == 0 else "reply %d" % number
                cap = MAIN_POST_CHARS if number == 0 else reply_limit
                print("--- %s (%d/%d)" % (name, xlen(text), cap))
                print(text)
            print("Cost of this alert: $%.3f" % thread_cost(posts))
            continue

        record = known.setdefault(alert.guid, {"done": False, "ids": []})
        record["title"] = alert.title
        try:
            # Continue an alert that stopped part way in an earlier run.
            for text in posts[len(record["ids"]):]:
                reply_to = record["ids"][-1] if record["ids"] else None
                record["ids"].append(create_post(text, reply_to, keys, api_base))
                save_state(state_path, state)
                time.sleep(1)
        except XError as error:
            failed += 1
            print("FAILED after %d of %d posts: %s" % (len(record["ids"]), len(posts), error))
            if error.stops_the_run():
                save_state(state_path, state)
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
        print("Posted %d posts. Main post id: %s" % (len(posts), record["ids"][0]))

    print("\nCost of this run: $%.3f" % total_cost)
    if failed:
        sys.exit(1)   # a failed run shows as failed in GitHub Actions


if __name__ == "__main__":
    main()
