'use strict';

function normalizeUrl(u) {
  if (!u || typeof u !== 'string') return null;
  return u.replace(/\\u0026/g, '&').replace(/\\//g, '/');
}

function isHongguoFullCdnUrl(u) {
  const url = normalizeUrl(u);
  if (!url) return false;
  const lower = url.toLowerCase();
  if (lower.indexOf('qznovelvod.com') === -1) return false;
  if (lower.indexOf('reading-video') === -1) return false;
  if (lower.indexOf('http://') !== -1 || lower.indexOf('https://') !== -1) return true;
  return false;
}

function isCandidateMediaUrl(u) {
  const url = normalizeUrl(u);
  if (!url) return false;
  const lower = url.toLowerCase();
  if (lower.indexOf('qznovelvod.com') !== -1) return true;
  if (lower.indexOf('qznovel.com') !== -1) return false;
  if (lower.indexOf('tos-cn-v-6fcc8e') !== -1) return true;
  return false;
}

const seen = {};
function emitUrl(url, kind) {
  const u = normalizeUrl(url);
  if (!u) return;
  if (seen[u]) return;
  seen[u] = true;
  send({ type: 'hongguo_url', kind: kind || 'unknown', url: u, full_cdn: isHongguoFullCdnUrl(u) });
}

Java.perform(function () {
  try {
    const URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (s) {
      const ret = this.$init(s);
      try {
        if (isCandidateMediaUrl(s)) emitUrl(s, 'java.net.URL');
      } catch (_) {}
      return ret;
    };
  } catch (_) {}

  try {
    const Uri = Java.use('android.net.Uri');
    Uri.parse.overload('java.lang.String').implementation = function (s) {
      const ret = this.parse(s);
      try {
        if (isCandidateMediaUrl(s)) emitUrl(s, 'android.net.Uri.parse');
      } catch (_) {}
      return ret;
    };
  } catch (_) {}

  try {
    const Builder = Java.use('okhttp3.Request$Builder');
    Builder.url.overload('java.lang.String').implementation = function (s) {
      const ret = this.url(s);
      try {
        if (isCandidateMediaUrl(s)) emitUrl(s, 'okhttp3.Request$Builder.url');
      } catch (_) {}
      return ret;
    };
  } catch (_) {}

  try {
    const HttpUrl = Java.use('okhttp3.HttpUrl');
    HttpUrl.parse.overload('java.lang.String').implementation = function (s) {
      const ret = this.parse(s);
      try {
        if (isCandidateMediaUrl(s)) emitUrl(s, 'okhttp3.HttpUrl.parse');
      } catch (_) {}
      return ret;
    };
  } catch (_) {}
});

