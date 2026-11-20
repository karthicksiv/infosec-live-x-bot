"""Check the Telegram page reader. Run: python3 test_bot.py"""
import bot

PAGE = b'''
<div class="tgme_widget_message" data-post="infoseclive/7">
<div class="tgme_widget_message_text js-message_text" dir="auto"><i class="emoji"><b>\xf0\x9f\x9f\xa0</b></i> Acme VPN root RCE exploited<br/>Attackers at evil.com used it &amp; got root.<br/><br/>Score: 8/10 (exploited)<br/>Affected: Acme VPN 1.2<br/>Action: Upgrade to 1.3<br/><a href="https://example.org/a?b=1&amp;c=2">https://example.org/a?b=1&amp;c=2</a><br/><br/>Know someone? Share the channel: t.me/infoseclive</div>
<time datetime="2026-11-20T11:18:05+00:00">11:18</time></div>
<div class="tgme_widget_message" data-post="infoseclive/8">
<div class="tgme_widget_message_text js-message_text" dir="auto">The RSS feed is live.</div>
<time datetime="2026-11-20T12:00:00+00:00">12:00</time></div>
'''

alert, note = bot.parse_channel(PAGE)
assert alert.guid == "telegram:7" and alert.score == 8
assert alert.title == "Acme VPN root RCE exploited"
assert alert.summary == "Attackers at evil[.]com used it & got root."   # no live link to a named domain
assert alert.link == "https://example.org/a?b=1&c=2"
assert bot.build_post(alert).endswith("\n\nexample.org/a?b=1&c=2")
assert note.guid == "telegram:8" and note.score is None                # no score: the bot does not post it
print("ok")
