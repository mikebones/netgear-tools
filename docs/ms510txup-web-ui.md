# MS510TXUP web UI: how to find a setting's payload

Some settings on this switch cannot be configured through `cgi/set.cgi` with
a payload derived from the matching `get.cgi` response. Writes that miss a
required field are **accepted and silently discarded** — the reply still says
`save_success` — so the only reliable source is what the web UI itself sends.

This page records how to get at that, because it took a long time to work out.

## URLs are signed

Every page and asset needs an md5 signature over its own query string:

```
login.html?aj4=<value>&bj4=<md5("aj4=<value>")>
```

`internal/ms510txup.sign()` already does this (using `dummy=` rather than
`aj4=`, which the device accepts equally), so `Client.GetPage` can fetch any
page or JS file through the authenticated session. Without the signature
everything returns **404**, which reads as "no such page" and is why a long
list of plausible page names all appeared not to exist.

## The pages are not where the legacy JS suggests

`js/xui_enhancements.js` references `DhcpQueueMapping.html` and
`qos802QueueMapping.html`. Neither exists on this firmware — that file is
shared across many NETGEAR switches and those are other models' pages.
Guessing page names from it does not work, and neither does deriving them
from the `url_get_*` / `url_set_*` variable names in `js/url.js`.

## Use the UI's own search box

The fastest route by far. The header has a search field; typing part of a
feature name lists the matching page with its menu path, and clicking it
navigates there. "loop" finds **Security → L2 Loop Protection**; "storm"
finds **Security → Traffic Control → Storm Control**. There is also a full
site **Index** page in the sidebar listing every page in the product.

## Two shapes of settings page

Both of the pages above follow the same pattern, and getting the order wrong
loses your edits:

1. A **global** block at the top with its own Apply.
2. A **per-port table** with checkboxes and an Edit button that opens a modal.

**Apply the global block first.** Opening the per-port modal re-reads the
table and discards unsaved global edits.

The modal's dropdowns are custom elements, not `<select>`, so they are not in
the accessibility tree and form tooling cannot set them. Click to open, then
**arrow keys plus Enter** — clicking an option often lands on the control
underneath as the list closes.

## Storm control is per-mode, and this is a real trap

`storm_cfg` returns a *mode-specific* configuration, and the API always
answers for mode `0` (Disabled) — appending `&mode=N` does not change it. So
after configuring broadcast storm control, a plain `get storm_cfg` returns
all zeros and looks like the write failed.

It has not. The page defaults to mode Disabled on load too; selecting
**Broadcast** re-reads and shows the real configuration. Verify this setting
through the UI with the mode selected, or by a full navigate-away-and-back,
not by reading `storm_cfg` directly.

Loop protection has no such wrinkle: `loop_protect` reads back honestly, and
its per-port `state` field is the "Keep Alive" column.
