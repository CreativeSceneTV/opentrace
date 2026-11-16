// Server-side proxy: only the tools listed below can be called, keys stay in Netlify env vars.
const net = require("net");
const E = process.env, enc = encodeURIComponent;
const UA = { "User-Agent": "OpenTrace/1.0" };
const form = (o) => new URLSearchParams(o).toString();
const FORM = { "Content-Type": "application/x-www-form-urlencoded" };
const ab = (k) => ({ "Auth-Key": E[k] || "" });

// id: [env var required (or null), (q) => {u, h, m, b}]
const T = {
  ipinfo: [null, q => ({ u: `https://ipinfo.io/${enc(q)}/json${E.IPINFO_TOKEN ? "?token=" + E.IPINFO_TOKEN : ""}` })],
  ipapi: [null, q => ({ u: `http://ip-api.com/json/${enc(q)}?fields=66846719` })],
  ripestat: [null, q => ({ u: `https://stat.ripe.net/data/prefix-overview/data.json?resource=${enc(q)}` })],
  rdap: [null, q => ({ u: `https://rdap.org/${net.isIP(q) ? "ip" : "domain"}/${enc(q)}` })],
  dns: [null, q => { const [n, t = "A"] = q.split(/\s+/); return { u: `https://dns.google/resolve?name=${enc(n)}&type=${enc(t)}` }; }],
  hackertarget: [null, q => ({ u: `https://api.hackertarget.com/hostsearch/?q=${enc(q)}` })],
  abuseipdb: ["ABUSEIPDB_KEY", q => ({ u: `https://api.abuseipdb.com/api/v2/check?ipAddress=${enc(q)}&maxAgeInDays=90`, h: { Key: E.ABUSEIPDB_KEY, Accept: "application/json" } })],
  greynoise: [null, q => ({ u: `https://api.greynoise.io/v3/community/${enc(q)}`, h: E.GREYNOISE_KEY ? { key: E.GREYNOISE_KEY } : {} })],
  crtsh: [null, q => ({ u: `https://crt.sh/?q=%25.${enc(q)}&output=json` })],
  urlhaus: ["ABUSECH_KEY", q => ({ u: "https://urlhaus-api.abuse.ch/v1/host/", m: "POST", h: { ...FORM, ...ab("ABUSECH_KEY") }, b: form({ host: q }) })],
  urlscan: [null, q => ({ u: `https://urlscan.io/api/v1/search/?q=domain:${enc(q)}&size=15`, h: E.URLSCAN_KEY ? { "API-Key": E.URLSCAN_KEY } : {} })],
  safebrowsing: ["GSB_KEY", q => ({ u: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${E.GSB_KEY}`, m: "POST", h: { "Content-Type": "application/json" }, b: JSON.stringify({ client: { clientId: "opentrace", clientVersion: "1.0" }, threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url: q }] } }) })],
  commoncrawl: [null, q => ({ u: `https://index.commoncrawl.org/CC-MAIN-2024-33-index?url=${enc(q)}&output=json&limit=20` })],
  wayback: [null, q => ({ u: `https://web.archive.org/cdx/search/cdx?url=${enc(q)}&output=json&limit=20&fl=timestamp,original,statuscode&collapse=digest` })],
  dnsdumpster: ["DNSDUMPSTER_KEY", q => ({ u: `https://api.dnsdumpster.com/domain/${enc(q)}`, h: { "X-API-Key": E.DNSDUMPSTER_KEY } })],
  securitytrails: ["SECURITYTRAILS_KEY", q => ({ u: `https://api.securitytrails.com/v1/domain/${enc(q)}/subdomains`, h: { APIKEY: E.SECURITYTRAILS_KEY } })],
  hibp: ["HIBP_KEY", q => ({ u: `https://haveibeenpwned.com/api/v3/breachedaccount/${enc(q)}?truncateResponse=false`, h: { "hibp-api-key": E.HIBP_KEY } })],
  hunter: ["HUNTER_KEY", q => ({ u: `https://api.hunter.io/v2/domain-search?domain=${enc(q)}&api_key=${E.HUNTER_KEY}` })],
  emailrep: [null, q => ({ u: `https://emailrep.io/${enc(q)}`, h: E.EMAILREP_KEY ? { Key: E.EMAILREP_KEY } : {} })],
  numverify: ["NUMVERIFY_KEY", q => ({ u: `http://apilayer.net/api/validate?access_key=${E.NUMVERIFY_KEY}&number=${enc(q)}` })],
  abstractphone: ["ABSTRACT_KEY", q => ({ u: `https://phonevalidation.abstractapi.com/v1/?api_key=${E.ABSTRACT_KEY}&phone=${enc(q)}` })],
  nvd: [null, q => ({ u: `https://services.nvd.nist.gov/rest/json/cves/2.0?${/^CVE-/i.test(q) ? "cveId=" + enc(q.toUpperCase()) : "resultsPerPage=10&keywordSearch=" + enc(q)}` })],
  kev: [null, () => ({ u: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" })],
  otx: [null, q => ({ u: `https://otx.alienvault.com/api/v1/indicators/${net.isIPv4(q) ? "IPv4" : net.isIPv6(q) ? "IPv6" : /^[a-f0-9]{32,64}$/i.test(q) ? "file" : "domain"}/${enc(q)}/general`, h: E.OTX_KEY ? { "X-OTX-API-KEY": E.OTX_KEY } : {} })],
  malwarebazaar: ["ABUSECH_KEY", q => ({ u: "https://mb-api.abuse.ch/api/v1/", m: "POST", h: { ...FORM, ...ab("ABUSECH_KEY") }, b: form({ query: "get_info", hash: q }) })],
  threatfox: ["ABUSECH_KEY", q => ({ u: "https://threatfox-api.abuse.ch/api/v1/", m: "POST", h: { "Content-Type": "application/json", ...ab("ABUSECH_KEY") }, b: JSON.stringify({ query: "search_ioc", search_term: q }) })],
  phishtank: ["PHISHTANK_KEY", q => ({ u: "https://checkurl.phishtank.com/checkurl/", m: "POST", h: FORM, b: form({ url: Buffer.from(q).toString("base64"), format: "json", app_key: E.PHISHTANK_KEY }) })],
  opencorporates: ["OPENCORPORATES_KEY", q => ({ u: `https://api.opencorporates.com/v0.4/companies/search?q=${enc(q)}&api_token=${E.OPENCORPORATES_KEY}` })],
  wikidata: [null, q => ({ u: `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${enc(q)}&language=en&format=json&limit=10` })],
  gdelt: [null, q => ({ u: `https://api.gdeltproject.org/api/v2/doc/doc?query=${enc(q)}&mode=artlist&maxrecords=15&format=json` })],
  archive: [null, q => ({ u: `https://archive.org/advancedsearch.php?q=${enc(q)}&fl[]=identifier&fl[]=title&rows=15&output=json` })],
  nominatim: [null, q => ({ u: `https://nominatim.openstreetmap.org/search?q=${enc(q)}&format=json&limit=5&addressdetails=1` })],
  geonames: ["GEONAMES_USER", q => ({ u: `http://api.geonames.org/searchJSON?q=${enc(q)}&maxRows=10&username=${E.GEONAMES_USER}` })],
};

const json = (c, o) => ({ statusCode: c, headers: { "Content-Type": "application/json" }, body: typeof o === "string" ? o : JSON.stringify(o) });
const tmo = (ms) => AbortSignal.timeout(ms);

// Username check using the WhatsMyName dataset
async function wmn(user) {
  const d = await (await fetch("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", { signal: tmo(5000) })).json();
  const sites = d.sites.filter(s => s.uri_check && s.uri_check.includes("{account}") && !s.post_body && s.e_code).slice(0, 90);
  const out = await Promise.all(sites.map(async s => {
    try {
      const r = await fetch(s.uri_check.replace("{account}", enc(user)), { headers: UA, redirect: "manual", signal: tmo(5500) });
      const t = await r.text();
      if (r.status === s.e_code && (!s.e_string || t.includes(s.e_string)) && (!s.m_string || !t.includes(s.m_string)))
        return { site: s.name, url: (s.uri_pretty || s.uri_check).replace("{account}", user) };
    } catch (e) {}
  }));
  return { checked: sites.length, found: out.filter(Boolean) };
}

exports.handler = async (ev) => {
  const { t, q = "" } = ev.queryStringParameters || {};
  const query = q.trim().slice(0, 300);
  if (!query) return json(400, { error: "Enter a value first." });
  try {
    if (t === "wmn") return json(200, await wmn(query));
    const tool = T[t];
    if (!tool) return json(404, { error: "Unknown tool." });
    if (tool[0] && !E[tool[0]]) return json(400, { error: `Add the environment variable ${tool[0]} in Netlify (Site settings → Environment variables), then redeploy.` });
    const { u, h = {}, m = "GET", b } = tool[1](query);
    const r = await fetch(u, { method: m, headers: { ...UA, ...h }, body: b, signal: tmo(9000) });
    let text = await r.text();
    if (t === "kev") {
      const k = JSON.parse(text), n = query.toLowerCase();
      text = JSON.stringify({ catalogVersion: k.catalogVersion, matches: k.vulnerabilities.filter(v => JSON.stringify(v).toLowerCase().includes(n)).slice(0, 25) });
    }
    return json(r.status >= 400 ? 502 : 200, text.length > 400000 ? text.slice(0, 400000) : text);
  } catch (e) {
    return json(502, { error: "Upstream request failed: " + e.message });
  }
};
