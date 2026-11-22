# SiteGuard Analytics

SiteGuard Analytics is a WordPress plugin that treats the site like a network
endpoint. Each request is attributed to a subject (an account, an address, or a
first-party browser id), classified by what it is asking for, and checked
against that class's policy **before** the page is rendered. A client that
crosses a line gets a temporary block from an escalating ladder, an incident is
written with the evidence that caused it, and light first-party analytics run
alongside without ever deciding access. It needs no CDN, no Redis, no root
access, no background worker, and no paid service. It runs on ordinary shared
hosting with PHP 8.1+ and MySQL.

Version 0.1.13. Tested on WordPress 7.0.2 / PHP 8.5.

## How one request is judged

The engine is deterministic — no model, no score, no randomness — so a block
can always be explained by the row it wrote.

1. **Attribute.** An authenticated user is an account subject; anyone else is an
   address subject (IPv6 collapsed to /64), with a first-party visitor id
   checked as a secondary subject.
2. **Classify.** The request becomes one of ten endpoint classes: page, search,
   feed, REST, admin-ajax, API, login, cart, checkout, download.
3. **Count.** Three windows are incremented at once: 10 seconds, 60 seconds,
   one hour.
4. **Test breadth.** Page and search traffic also counts distinct paths in ten
   minutes; more than 150 is a scan, whatever the raw request rate.
5. **Escalate.** A crossed limit chooses a rung on the block ladder (300 s, 15
   min, 1 h, 6 h, 24 h) from the subject's block count in the previous week.
   The last rung is a ceiling, never a permaban.
6. **Record.** The incident stores the rule, class, window, count, limit, and
   subject. Every block expires and can be lifted by hand.

Front-end checks run at `parse_request` priority 1, REST at
`rest_pre_dispatch`, `admin-ajax.php` at `init`, and the login form at
`login_init`.

## What it protects, and what it cannot

The plugin enforces at four WordPress entry points. Anything that does not run
through PHP cannot be protected by a plugin, and the dashboard says so instead
of implying full coverage.

| Surface | Protected | How |
|---|---|---|
| Front-end pages, search, feeds, downloads | Yes | `parse_request` at priority 1, before the main query |
| REST API | Yes, JSON errors | `rest_pre_dispatch` filter |
| `admin-ajax.php` | Yes, plain-text error | `init`, only when `wp_doing_ajax()` |
| `wp-login.php` and login paths | Yes, plain-text error | `login_init` |
| `wp-admin` | No — excluded on purpose | An administrator can always recover |
| Cached pages served by a page cache | No | The cache answers without PHP |
| Static files served by the web server | No | Never reaches WordPress |
| `wp-cron.php` | No | Not visitor traffic |
| Edge / CDN / WAF | No | Requires configuration outside WordPress |

The Operations section of the SiteGuard page shows this table with a
per-install status (verified / partial / unavailable / untested). Statuses
other than `unavailable` mean the install recorded something; they are not a
promise that a cache is correctly configured.

## Install

1. Upload `siteguard-analytics.zip` in **Plugins → Add New → Upload Plugin**,
   or copy the `siteguard-analytics` folder into `wp-content/plugins/`.
2. Activate. Activation checks PHP, MySQL and the `wpdb` object, creates the
   ten `wp_sg_*` tables through `dbDelta`, grants the seven `sg_*`
   capabilities to administrators, and schedules two cron events.
3. The shipped profile is **Balanced** with enforcement on. Everything the
   plugin does lives on the single **SiteGuard** page, in the Operations
   section — open it to see the current state before changing anything.

If activation cannot create the tables it deactivates itself and shows the
reason instead of leaving the site half-installed.

## Defaults

Limits are `[window seconds, allowed requests]` triples per endpoint class.
Balanced is the default; Strict multiplies every limit by `strict_factor`
(default 0.5); Observe records but never denies.

| Class | 10 s | 60 s | 1 h |
|---|---|---|---|
| html | 20 | 60 | 600 |
| search / feed | 10 | 30 | 200 |
| rest / ajax | 30 | 120 | 1200 |
| api | 20 | 60 | 600 |
| login | 5 | 10 | 60 |
| cart | 20 | 60 | 600 |
| checkout | 10 | 30 | 300 |
| download | 10 | 20 | 100 |

Signed-in accounts get `account_multiplier` (default 2×) so a busy editor is
not treated like a script. The breadth rule blocks a client that requests more
than 150 **distinct** paths inside 10 minutes; set the limit to 0 to disable it.
The block ladder defaults to 300 s, 15 min, 1 h, 6 h, 24 h — the last rung is a
ceiling, not a permanent ban. Every block expires and can be lifted manually.

## Privacy and fingerprinting

Subjects are keyed HMACs, not raw values: `ip4:…`, `ip6:…` (collapsed to /64),
`a:<user id>`, and `v:<first-party visitor id>`. The default `ip_storage` is
`hashed`; `full` keeps the address, `none` omits it.

**The fingerprint is a correlation layer, not a decision key.** Each pageview
records a keyed, versioned hash (`fp1:…`) of the signals the browser
volunteers: language and languages, timezone and its offset, screen size and
viewport, device pixel ratio and colour depth, touch support, CPU cores,
device memory, platform, user-agent client hints, WebGL vendor and renderer
strings, and one-way hashes of a canvas render and an audio graph. The signals
are lowercased, sorted, and HMAC-SHA256 hashed with a site-scoped salt; the
version prefix means rotating the salt makes old hashes stop matching rather
than silently compare across rotations. Canvas and audio are stored only as
hashes, and font enumeration or plugin lists are not read. Enforcement never
consults the fingerprint: it keys on the account, the address, and the visitor
id. The fingerprint exists so two visits that share a hash can be recognised
as one browser when the cookie has been cleared or the address has changed.

The collector is first-party, uses random first-party ids, and never
resurrects cookies or tracks across sites.

**Browser telemetry is untrusted.** A visitor id from the browser can select a
counter, but it can never create a persistent block: a forged id would
otherwise let an attacker ban its victim. Visitor-scope violations receive a
short quota denial and nothing is stored.

## Recovery

Three independent stops, in order of speed:

1. **Emergency stop** in the Operations section of the SiteGuard page — one
   click, audited.
2. `add_filter('siteguard_emergency_disabled', '__return_true');` in a theme or
   mu-plugin.
3. `define('SITEGUARD_DISABLED', true);` in `wp-config.php` — stops enforcement
   and collection before the plugin boots.

`wp-admin` is never rate limited and administrators bypass the enforcer, so a
bad rule cannot lock you out. Uninstalling drops the tables and options only
when `SITEGUARD_REMOVE_DATA` is true; otherwise the data survives a
deactivate/reactivate cycle.

## Analytics

`assets/tracker.js` sends `pageview` and `leave` events with `navigator.sendBeacon`
to `POST /wp-json/siteguard/v1/collect`. The endpoint returns 204 for every
accepted or rejected payload, accepts only 32-hex ids, the two event types, and
paths starting with `/`, and dedupes to one row per visitor/session/type/path
per minute through a unique index. Events are stored with `source='browser'`;
`source='server'` rows come from enforcement and never depend on JavaScript.

`consent_mode` is `none` (collect without asking), `optional` (host page
decides), or `required`. In `optional` and `required` modes the tracker also
honours Do Not Track and waits for `localStorage.sg_consent === '1'`; in `none`
mode it does neither, because the site has declared collection the default.

The pageview payload also carries a fingerprint object. The server whitelists
its keys (`Beacon::SIGNALS`), keeps strings under 160 characters, and stores the
result as JSON on the event and visitor rows. Unknown keys are ignored, which is
what keeps a future tracker change from silently widening what is stored.

## Visitor records and exports

Each pageview row keeps the address the server saw, the user-agent header, and
a JSON profile of the signals the browser reported: screen and viewport, device
pixel ratio and colour depth, time zone and offset, languages, CPU cores, device
memory, platform, client hints (brands, platform, mobile, model, architecture),
WebGL vendor and renderer, and one-way hashes of a canvas render and an audio
graph. The visitor row keeps the latest values of each so the list is readable
without a join.

Address storage is `full` by default, with `hashed` and `none` available in
Settings. The fingerprint is collected in every mode.

There is no assistant and no provider configuration. Analysis happens outside
WordPress: Operations offers per-table CSVs and a single JSON bundle (2,000 rows
per table, newest first, with true counts) that the owner downloads and hands to
whatever tool they choose. The plugin makes no outbound call.

## Capabilities

| Capability | Grants |
|---|---|
| `sg_view_analytics` | Overview and visitor analytics |
| `sg_view_security` | Active blocks and incidents |
| `sg_manage_blocks` | Manual block, lift |
| `sg_manage_rules` | Limits and profiles (reserved) |
| `sg_manage_settings` | Settings and emergency stop |
| `sg_export_data` | CSV exports and the JSON bundle |
| `sg_view_audit` | Audit log |

Only administrators receive them at activation. Every `admin_post_*` handler
checks its capability and its nonce, then writes an audit row.

## WP-CLI

```
wp siteguard status
wp siteguard blocks [--limit=100]
wp siteguard lift <subject>
wp siteguard prune
wp siteguard coverage [--class=html]
```

The CLI loads the same Core classes; it does not bypass the audit log.

## Layout

```
siteguard-analytics.php     bootstrap, constants, activation hooks
uninstall.php               opt-in data removal
src/Core/                   WordPress-free engine (settings, IP, crypto,
                            classifier, policy, enforcer, AI)
src/Wp/                     WordPress adapters (hooks, stores, admin, REST)
assets/tracker.js           first-party collector
assets/admin.css            dashboard styles
docs/                       this file, test results, unfinished list
```
