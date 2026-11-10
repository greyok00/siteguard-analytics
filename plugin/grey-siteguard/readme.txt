=== Grey SiteGuard ===
Contributors: 00greyok00
Tags: security, analytics, rate limiting, incidents, privacy
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.12
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Rate limits, temporary blocks, content-attack rules, a fingerprint watchlist, incident records, and light first-party analytics, with no CDN or external service.

== Description ==

SiteGuard Analytics treats the site like a network endpoint. Each request is
attributed to a subject — an account, an address, or a first-party browser id —
classified by what it asks for, and checked against that class's limits before
the page is rendered. A client that crosses a line gets a temporary block from
an escalating ladder, and an incident is written with the evidence that caused
it. Light first-party analytics run alongside and never decide access.

The engine is deterministic: no model, no score, no randomness. Every block can
be explained by the row it wrote.

* **Ten endpoint classes.** Page, search, feed, REST, admin-ajax, API, login,
  cart, checkout, and download each carry their own limits.
* **Three windows at once.** Every request counts in a 10-second, a 60-second,
  and an hourly window.
* **Scan detection.** Page and search traffic also counts distinct paths in ten
  minutes; a client asking for too many different pages is a scan whatever its
  raw request rate.
* **Temporary blocks.** A crossed limit picks a rung on a 5-minute to 24-hour
  ladder from the client's recent block count. The last rung is a ceiling, not
  a permaban, and any block can be lifted by hand.
* **Incident records.** Each block stores the rule, class, window, count, limit,
  and subject, so nothing is blocked without a reason on file.
* **Content-attack rules.** Request rules score probes, traversal and encoding
  tricks, structural shape anomalies, and device-hint impossibles in the same
  ledger, with a live self-test page that runs the shipped corpus.
* **Fingerprint watchlist.** Save a tampered browser's profile and matching
  visitors score it with graded severity; every incident names the saved
  profile. Candidate profiles are drafted from recent tampering signals, and
  the list imports and exports as JSON.
* **Analytics that never decide access.** Pageviews, sessions, landing and exit
  paths, referrers, device class, and browser are counted for the dashboard.
* **Bounded retention.** Old rows are deleted on a schedule; exports are
  generated on demand and never stored.

The overview page shows a single request matrix: which WordPress entry point is
protected, which is only partly covered, and which never reaches PHP (a page
served from a cache, or a file served by the web server, cannot be rate-limited
by any plugin). The dashboard says so instead of implying full coverage.

Administrators bypass every rule, so the owner cannot lock themselves out. The
last-resort switch is a constant in `wp-config.php`:

    define('SITEGUARD_DISABLED', true);

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`, or install the zip from
   Plugins > Add New > Upload Plugin.
2. Activate the plugin through the Plugins screen.
3. Open SiteGuard in the admin menu. Tables are created on activation.

== Frequently Asked Questions ==

= Does this plugin contact any external service? =

No. It makes no outbound request, runs no model, and sends no telemetry. All
data stays in this site's own WordPress tables.

The Visitors screen offers one-click address lookups that open ipinfo,
AbuseIPDB, Shodan, or RDAP in a new tab. Those are ordinary links: nothing is
sent until you click one, and the lookup then goes from your browser to that
service under that service's own terms.

= What visitor data is stored? =

A pageview can store the address the server saw, the user-agent header, and a
profile of the browser's reported signals (screen size, time zone, languages,
platform, WebGL renderer, and canvas and audio hashes) so the Visitors screen
can identify a row. Settings can switch address storage to a keyed hash or turn
the profile off; retention deletes old rows on a schedule.

= Does a block lock me out? =

No. Administrators bypass every rule. Blocks expire, the ladder ends at a
ceiling, and the Security screen lifts any block immediately.

= Why does the matrix say some request types are unavailable? =

A response served from a cache, or a static file served directly by the web
server, never reaches WordPress. No plugin can rate-limit what it never sees.

= Is this legal advice? =

No. The plugin offers a first-party visitor identifier and an optional consent
requirement; whether you also need a cookie banner depends on your
jurisdiction. Consult your own counsel.

== Changelog ==

= 0.1.12 =
* Renamed the plugin to **Grey SiteGuard**: the WAF is the product and
  analytics is one of its features, so the name no longer leads with it. The
  plugin folder is `grey-siteguard/`, the bootstrap is
  `grey-siteguard.php`, and the text domain is `grey-siteguard`. Existing
  options, tables, capabilities, and blocks carry over untouched; the old
  folder can be removed after the new one is active.
* The plugin header and the version constant now move in sync (0.1.11
  shipped with both still reading 0.1.9).

= 0.1.11 =
* Fingerprint watchlist: save a visitor's tampering profile (name, notes,
  anchors) and it scores on the same WAF ladder with graded severity; every
  incident names the saved profile.
* The Profiles screen carries the watchlist card (create, edit, delete,
  import, export), a candidates card drafted from recent tampering signals
  behind the stored-address mode, and a save-as-profile flow on visitor
  detail.
* Enforcement follows the WAF profile: balanced keeps a single anchor under
  the block line, strict lets one anchor block, and the toggle lives in
  Settings with observe-first advice.
* The visitors table stores the keyed address hash beside the address (added
  through the table-version bump), so candidate matching works on upgraded
  installs too.
* 42 new tests; the suite is at 162.

= 0.1.10 =
* WAF request-inspection rules grew from 12 to 46: header and token
  anomalies, path traversal, encoded-URL families, method misuse, and the
  structural impossibles.
* Layered encodings are unwound before evaluation and the decode steps are
  written as evidence rows with each block.
* Device-hint impossibles: header combinations that cannot honestly co-occur,
  stated as evidence rather than scored.
* WAF enforcement modes (off, observe, balanced, strict) with a self-test
  page that re-runs the shipped corpus as fixtures.

= 0.1.9 =
* Renamed Grey SiteGuard + Analytics, so the directory slug names this plugin
  and is not confused with the existing SiteGuard plugins.
* Plugin Check reports no warnings; the remaining direct-database notices are
  annotated with the reason each statement needs the plugin's own table.
* REST detection parses the query string instead of reading `$_GET`.
* The coverage seed uses `$wpdb->insert()` rather than a raw `INSERT IGNORE`.

= 0.1.8 =
* Notice and visitor-detail links carry a nonce, and the handlers verify it.
* Request fields are unslashed and sanitized before use.
* The coverage seed and uninstall queries use `%i` identifier placeholders.
* The CSV export selects whole rows, so one prepared statement covers the
  page query.
* A failed install or a storage fault is recorded in the plugin's own error
  option instead of writing to the PHP error log.

= 0.1.7 =
* Added the readme required for distribution and declared the plugin under
  GPL-2.0-or-later.
* Hardened every admin output path, switched URL parsing to `wp_parse_url()`,
  and parameterised export queries with `%i` identifiers.
* Added direct-access guards and replaced a PHP 8.1-only call with an
  equivalent that runs on the declared WordPress minimum.
* The plugin archive now ships the readable sources for its minified scripts.

= 0.1.6 =
* Visitors store address, user-agent, and browser fingerprint; detail view and
  CSV/JSON exports added.
* Built-in assistant removed; exports are handed to a tool by the owner.

= 0.1.5 =
* Single-page dashboard, request coverage matrix, and operations checks.

== Upgrade Notice ==

= 0.1.12 =
The plugin is renamed Grey SiteGuard (folder `grey-siteguard/` main file
`grey-siteguard.php`); settings, tables, and blocks carry over. Deactivate
the old copy, install the new zip, and the rename is done.

= 0.1.11 =
The visitors table gains one column through the scheduled table-version
bump; no action is required.

= 0.1.9 =
Plugin Check clean: no warnings. No schema or behaviour change.

= 0.1.8 =
Nonce, sanitizing, and query-placeholder hardening. No schema or behaviour
change.

= 0.1.7 =
Directory-compliance release: readme, GPL-2.0-or-later, escaping and query
hardening. No schema or behaviour change.
