# Vendored frontend assets

The dashboard has no build step and no CDN dependency at runtime. These files
are pinned copies, served from `/static/vendor/`.

| File | Project | Version | SHA-256 |
|------|---------|---------|---------|
| `htmx-2.0.4.min.js` | [htmx](https://htmx.org) | 2.0.4 | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| `pico-2.0.6.min.css` | [Pico CSS](https://picocss.com) | 2.0.6 | `dd5fd5591afd81ee21dcc117ad85c014dc3f1f19dc2d7b7d101ea0acc29274c2` |

Licences: htmx is BSD-2-Clause; Pico CSS is MIT.

Updating: download the new pinned file, record its digest above, and adjust the
`<link>`/`<script>` references in `gateway/dashboard/templates/base.html`.
