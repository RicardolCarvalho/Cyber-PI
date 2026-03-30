const KNOWN_TRACKERS = new Set([
  // Google Analytics / Ads
  "google-analytics.com",
  "googleadservices.com",
  "googlesyndication.com",
  "googletagmanager.com",
  "googletagservices.com",
  "doubleclick.net",
  "google.com/ads",
  "pagead2.googlesyndication.com",
  "adservice.google.com",
  "analytics.google.com",

  // Facebook
  "facebook.net",
  "facebook.com/tr",
  "connect.facebook.net",
  "pixel.facebook.com",
  "fbcdn.net",

  // Amazon Ads
  "amazon-adsystem.com",
  "assoc-amazon.com",

  // Microsoft / LinkedIn
  "bat.bing.com",
  "ads.linkedin.com",
  "snap.licdn.com",
  "linkedin.com/px",

  // Twitter / X
  "ads-twitter.com",
  "analytics.twitter.com",
  "t.co",
  "ads-api.twitter.com",

  // Ad Networks
  "adnxs.com",
  "adsrvr.org",
  "adroll.com",
  "criteo.com",
  "criteo.net",
  "outbrain.com",
  "taboola.com",
  "pubmatic.com",
  "rubiconproject.com",
  "openx.net",
  "casalemedia.com",
  "indexww.com",
  "bidswitch.net",
  "sharethrough.com",
  "smartadserver.com",
  "media.net",
  "yieldmo.com",
  "triplelift.com",
  "33across.com",
  "sovrn.com",

  // Analytics & Tracking
  "hotjar.com",
  "hotjar.io",
  "mixpanel.com",
  "segment.io",
  "segment.com",
  "amplitude.com",
  "heapanalytics.com",
  "fullstory.com",
  "mouseflow.com",
  "crazyegg.com",
  "luckyorange.com",
  "clarity.ms",
  "newrelic.com",
  "nr-data.net",
  "sentry.io",
  "bugsnag.com",

  // Social Tracking
  "addthis.com",
  "sharethis.com",
  "addtoany.com",
  "disqus.com",
  "disquscdn.com",

  // Fingerprinting / ID
  "id5-sync.com",
  "rlcdn.com",
  "bluekai.com",
  "exelator.com",
  "krxd.net",
  "demdex.net",
  "everesttech.net",
  "contextweb.com",
  "liadm.com",
  "intentmedia.net",
  "tapad.com",
  "liveramp.com",
  "adsymptotic.com",
  "quantserve.com",
  "quantcast.com",
  "scorecardresearch.com",
  "comscore.com",
  "imrworldwide.com",

  // Data Management Platforms
  "crwdcntrl.net",
  "lotame.com",
  "moatads.com",
  "doubleverify.com",

  // Retargeting
  "perfectaudience.com",
  "steelhouse.com",
  "fetchback.com",
  "adform.net",
  "eyeota.net",
  "mathtag.com",

  // Brazilian trackers
  "newtail.com.br",
  "tail.digital",
  "neemu.com",
  "chaordicsystems.com",
  "pmweb.com.br",
  "dp6.com.br",

  // Cookie sync / ID sync
  "sync.outbrain.com",
  "pixel.rubiconproject.com",
  "eus.rubiconproject.com",
  "match.adsrvr.org",
  "cm.g.doubleclick.net",
  "ids.ad.gt",
  "cookie.adsafeprotected.com",

  // Misc tracking
  "chartbeat.com",
  "chartbeat.net",
  "optimizely.com",
  "adobedtm.com",
  "omtrdc.net",
  "2o7.net",
  "sc.omtrdc.net",
  "tiqcdn.com",
  "ensighten.com",
  "bounceexchange.com",
  "bouncex.net"
]);

// Padrões de sincronismo de cookies (Cookie Sync)
const COOKIE_SYNC_PATTERNS = [
  /[?&](uid|uuid|user_id|userid|visitor_id|device_id)=/i,
  /[?&](sync|pixel|match|cm|cookie_match|id_sync)=/i,
  /\/sync[\/?]/i,
  /\/cookie[-_]?sync/i,
  /\/match[\/?]/i,
  /\/pixel[\/?].*id=/i,
  /\/cm[\/?]/i,
  /\/id[-_]?match/i,
  /[?&]redirect.*[?&](uid|id)=/i,
  /bounce.*[?&](r|url|redirect)=/i
];

// Padrões de scripts BeEF / XSS hook para detecção de hijacking
const HIJACKING_PATTERNS = [
  "hook.js",
  "beef.js",
  "BeEF",
  "browser_exploitation",
  "evercookie",
  "zombiejs"
];
