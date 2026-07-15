require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const puppeteer = require("puppeteer");

const app = express();

const config = {
  port: Number(process.env.PORT || 3000),
  appSecret: String(process.env.APP_SECRET || ""),
  browserHeadless: String(process.env.BROWSER_HEADLESS || "true") !== "false",
  browserTimeoutMs: Number(process.env.BROWSER_TIMEOUT_MS || 45000),
  browserConcurrency: Math.max(1, Number(process.env.BROWSER_CONCURRENCY || 1)),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS || 1000 * 60 * 30),
  saveScreenshots: String(process.env.SAVE_SCREENSHOTS || "false") === "true",
  maxResponseTextLength: Number(process.env.MAX_RESPONSE_TEXT_LENGTH || 5000)
};

const cache = new Map();
const browserQueue = [];

let browserPromise = null;
let activeBrowserJobs = 0;

app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
}));

function verifySecret(req, res, next) {
  if (!config.appSecret) {
    return next();
  }

  const received = String(req.header("x-app-secret") || "");

  if (received !== config.appSecret) {
    return res.status(401).json({
      ok: false,
      error: "unauthorized"
    });
  }

  return next();
}

function normalizeMla(value) {
  const text = String(value || "").trim().toUpperCase();
  const match = text.match(/MLA[-\s]?(\d{6,})/i);

  if (!match) {
    return "";
  }

  return `MLA${match[1]}`;
}

function extractMlaFromUrl(url) {
  return normalizeMla(url);
}

function buildItemUrl(mla) {
  const numericId = String(mla || "").replace(/^MLA/i, "");
  return `https://articulo.mercadolibre.com.ar/MLA-${numericId}-_JM`;
}

function validateTargetUrl(value) {
  try {
    const parsed = new URL(String(value || "").trim());
    const hostname = parsed.hostname.toLowerCase();

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return {
        ok: false,
        error: "invalid_protocol"
      };
    }

    const allowed =
      hostname === "mercadolibre.com.ar" ||
      hostname.endsWith(".mercadolibre.com.ar");

    if (!allowed) {
      return {
        ok: false,
        error: "host_not_allowed"
      };
    }

    return {
      ok: true,
      url: parsed.toString(),
      hostname
    };
  } catch {
    return {
      ok: false,
      error: "invalid_url"
    };
  }
}

function cacheGet(key) {
  const entry = cache.get(key);

  if (!entry) {
    return null;
  }

  if (Date.now() >= entry.expiresAt) {
    cache.delete(key);
    return null;
  }

  return entry.value;
}

function cacheSet(key, value) {
  cache.set(key, {
    value,
    expiresAt: Date.now() + config.cacheTtlMs
  });
}

function cleanText(value) {
  return String(value || "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseSoldNumber(displayText) {
  const normalized = cleanText(displayText)
    .toLowerCase()
    .replace(/\+/g, "")
    .replace(/^más de\s+/, "")
    .replace(/^mas de\s+/, "")
    .replace(/\s+vendidos?.*$/i, "")
    .trim();

  const numericMatch = normalized.match(/[\d.,]+/);

  if (!numericMatch) {
    return null;
  }

  let numericText = numericMatch[0];
  const usesMillion = /\bmill[oó]n(?:es)?\b/i.test(normalized);
  const usesThousand = /\bmil\b/i.test(normalized);

  if (usesMillion || usesThousand) {
    numericText = numericText.replace(",", ".");

    const parsed = Number(numericText);

    if (!Number.isFinite(parsed)) {
      return null;
    }

    return Math.round(parsed * (usesMillion ? 1000000 : 1000));
  }

  numericText = numericText.replace(/[.,](?=\d{3}(?:\D|$))/g, "");
  numericText = numericText.replace(",", ".");

  const parsed = Number(numericText);

  if (!Number.isFinite(parsed)) {
    return null;
  }

  return Math.round(parsed);
}

function classifySoldDisplay(displayText) {
  const text = cleanText(displayText).toLowerCase();

  return {
    value: parseSoldNumber(displayText),
    approximate:
      text.includes("+") ||
      text.includes("más de") ||
      text.includes("mas de") ||
      /\bmil\b/.test(text) ||
      /\bmill[oó]n/.test(text),
    lowerBound:
      text.includes("+") ||
      text.includes("más de") ||
      text.includes("mas de")
  };
}

function findSoldCandidates(text) {
  const normalized = cleanText(text);

  const patterns = [
    /(?:más de|mas de)\s+[\d.,]+\s*(?:mil|mill[oó]n(?:es)?)?\s+vendidos?/gi,
    /\+[\d.,]+\s*(?:mil|mill[oó]n(?:es)?)?\s+vendidos?/gi,
    /\b[\d.,]+\s*(?:mil|mill[oó]n(?:es)?)\s+vendidos?/gi,
    /\b[\d.,]+\s+vendidos?/gi
  ];

  const candidates = [];

  for (const pattern of patterns) {
    const matches = normalized.match(pattern) || [];

    for (const match of matches) {
      const candidate = cleanText(match);

      if (candidate && !candidates.includes(candidate)) {
        candidates.push(candidate);
      }
    }
  }

  return candidates;
}

function detectBlockedPage(text, title, url) {
  const combined = `${title}\n${text}\n${url}`.toLowerCase();

  const indicators = [
    "account-verification",
    "para continuar, ingresa a",
    "para continuar, ingresá a",
    "ya tengo cuenta",
    "soy nuevo",
    "captcha",
    "verifica que eres humano",
    "verificá que sos humano",
    "validación de seguridad",
    "validacion de seguridad",
    "security check",
    "access denied",
    "acceso denegado",
    "demasiadas solicitudes",
    "too many requests",
    "no pudimos procesar tu solicitud"
  ];

  return indicators.filter(indicator => combined.includes(indicator));
}

function detectAuthenticationRequired(text, url) {
  const combined = `${text}\n${url}`.toLowerCase();

  return [
    "account-verification",
    "para continuar, ingresa a",
    "para continuar, ingresá a",
    "ya tengo cuenta",
    "soy nuevo"
  ].some(indicator => combined.includes(indicator));
}

async function waitForBrowserSlot() {
  if (activeBrowserJobs < config.browserConcurrency) {
    activeBrowserJobs += 1;
    return;
  }

  await new Promise(resolve => {
    browserQueue.push(resolve);
  });

  activeBrowserJobs += 1;
}

function releaseBrowserSlot() {
  activeBrowserJobs = Math.max(0, activeBrowserJobs - 1);

  const next = browserQueue.shift();

  if (next) {
    next();
  }
}

async function getBrowser() {
  if (browserPromise) {
    return browserPromise;
  }

  const launchOptions = {
    headless: config.browserHeadless,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-default-apps",
      "--disable-sync",
      "--metrics-recording-only",
      "--no-first-run",
      "--no-zygote"
    ]
  };

  if (process.env.PUPPETEER_EXECUTABLE_PATH) {
    launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  }

  browserPromise = puppeteer.launch(launchOptions);

  try {
    const browser = await browserPromise;

    browser.on("disconnected", () => {
      browserPromise = null;
    });

    return browser;
  } catch (error) {
    browserPromise = null;
    throw error;
  }
}

async function inspectPage(page) {
  return page.evaluate(() => {
    const selectors = [
      ".ui-pdp-subtitle",
      ".ui-pdp-header__subtitle",
      ".ui-pdp-header",
      ".ui-pdp-container",
      "[class*='subtitle']",
      "[class*='sold']",
      "main",
      "body"
    ];

    const selectedTexts = [];

    for (const selector of selectors) {
      const elements = Array.from(document.querySelectorAll(selector)).slice(0, 30);

      for (const element of elements) {
        const text = String(element.innerText || element.textContent || "").trim();

        if (text && !selectedTexts.includes(text)) {
          selectedTexts.push(text);
        }
      }
    }

    const scripts = Array.from(document.scripts)
      .map(script => script.textContent || "")
      .filter(text => /sold|vendidos|sold_quantity/i.test(text))
      .slice(0, 20)
      .map(text => text.slice(0, 20000));

    return {
      bodyText: document.body ? document.body.innerText || "" : "",
      selectedTexts,
      scripts,
      htmlLength: document.documentElement
        ? document.documentElement.outerHTML.length
        : 0
    };
  });
}

async function scrapeUrl(targetUrl, options = {}) {
  const startedAt = Date.now();

  await waitForBrowserSlot();

  let page = null;

  try {
    const browser = await getBrowser();
    page = await browser.newPage();

    await page.setViewport({
      width: 1365,
      height: 900,
      deviceScaleFactor: 1
    });

    await page.setUserAgent(
      process.env.BROWSER_USER_AGENT ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    );

    await page.setExtraHTTPHeaders({
      "Accept-Language": "es-AR,es;q=0.9,en;q=0.7"
    });

    page.setDefaultNavigationTimeout(config.browserTimeoutMs);
    page.setDefaultTimeout(config.browserTimeoutMs);

    const networkErrors = [];
    const relevantResponses = [];

    page.on("requestfailed", request => {
      networkErrors.push({
        url: request.url().slice(0, 500),
        error: request.failure()?.errorText || "request_failed"
      });
    });

    page.on("response", response => {
      const responseUrl = response.url();
      const resourceType = response.request().resourceType();

      if (
        resourceType === "document" ||
        /item|product|catalog|sold|review/i.test(responseUrl)
      ) {
        relevantResponses.push({
          status: response.status(),
          url: responseUrl.slice(0, 500),
          resource_type: resourceType
        });
      }
    });

    const response = await page.goto(targetUrl, {
      waitUntil: "domcontentloaded",
      timeout: config.browserTimeoutMs
    });

    await Promise.race([
      page.waitForFunction(
        () => /vendidos?|account-verification|captcha|ingresa a|ingresá a/i.test(
          document.body?.innerText || location.href
        ),
        { timeout: Math.min(config.browserTimeoutMs, 15000) }
      ).catch(() => null),
      new Promise(resolve => setTimeout(resolve, 5000))
    ]);

    const pageData = await inspectPage(page);
    const title = await page.title();
    const finalUrl = page.url();
    const bodyText = cleanText(pageData.bodyText);
    const selectedText = cleanText(pageData.selectedTexts.join("\n"));
    const scriptText = cleanText(pageData.scripts.join("\n"));

    const visibleCandidates = findSoldCandidates(
      `${selectedText}\n${bodyText}`
    );

    const scriptCandidates = findSoldCandidates(scriptText);
    const soldCandidates = [...visibleCandidates];

    for (const candidate of scriptCandidates) {
      if (!soldCandidates.includes(candidate)) {
        soldCandidates.push(candidate);
      }
    }

    const soldDisplay = visibleCandidates[0] || scriptCandidates[0] || null;

    const soldData = soldDisplay
      ? classifySoldDisplay(soldDisplay)
      : {
          value: null,
          approximate: null,
          lowerBound: null
        };

    const blockedIndicators = detectBlockedPage(bodyText, title, finalUrl);
    const authenticationRequired = detectAuthenticationRequired(bodyText, finalUrl);
    const screenshotEnabled = options.screenshot || config.saveScreenshots;

    let screenshotBase64 = null;

    if (screenshotEnabled) {
      screenshotBase64 = await page.screenshot({
        type: "jpeg",
        quality: 65,
        fullPage: false,
        encoding: "base64"
      });
    }

    const result = {
      ok: true,
      requested_url: targetUrl,
      final_url: finalUrl,
      redirected: finalUrl !== targetUrl,
      item_id: extractMlaFromUrl(finalUrl) || extractMlaFromUrl(targetUrl) || null,
      authenticated: false,
      authentication_required: authenticationRequired,
      http_status: response ? response.status() : null,
      page_title: title,
      blocked: blockedIndicators.length > 0,
      blocked_indicators: blockedIndicators,
      sold_found: Boolean(soldDisplay),
      sold: soldData.value,
      sold_display: soldDisplay,
      sold_approximate: soldData.approximate,
      sold_lower_bound: soldData.lowerBound,
      sold_scope: extractMlaFromUrl(targetUrl) ? "unknown_meli_entity" : "unknown",
      sold_source: soldDisplay
        ? visibleCandidates.includes(soldDisplay)
          ? "visible_page_text"
          : "embedded_script"
        : "not_found",
      sold_candidates: soldCandidates.slice(0, 20),
      diagnostics: {
        html_length: pageData.htmlLength,
        body_text_sample: bodyText.slice(0, config.maxResponseTextLength),
        network_errors: networkErrors.slice(0, 20),
        relevant_responses: relevantResponses.slice(-30),
        duration_ms: Date.now() - startedAt
      }
    };

    if (screenshotBase64) {
      result.diagnostics.screenshot_base64 = screenshotBase64;
    }

    return result;
  } finally {
    if (page) {
      await page.close().catch(() => null);
    }

    releaseBrowserSlot();
  }
}

async function handleScrape(req, res) {
  const suppliedUrl = String(
    req.body?.url ||
    req.query?.url ||
    ""
  ).trim();

  const suppliedMla = normalizeMla(
    req.params?.mla ||
    req.body?.mla ||
    req.query?.mla ||
    ""
  );

  const force = String(
    req.body?.force ||
    req.query?.force ||
    "false"
  ) === "true";

  const screenshot = String(
    req.body?.screenshot ||
    req.query?.screenshot ||
    "false"
  ) === "true";

  let targetUrl = "";

  if (suppliedUrl) {
    const validation = validateTargetUrl(suppliedUrl);

    if (!validation.ok) {
      return res.status(400).json({
        ok: false,
        error: validation.error,
        message: "La URL debe pertenecer a mercadolibre.com.ar"
      });
    }

    targetUrl = validation.url;
  } else if (suppliedMla) {
    targetUrl = buildItemUrl(suppliedMla);
  } else {
    return res.status(400).json({
      ok: false,
      error: "missing_target",
      message: "Enviá una URL de Mercado Libre en url o un MLA en mla"
    });
  }

  const cacheKey = `anonymous:${targetUrl}`;

  if (!force) {
    const cached = cacheGet(cacheKey);

    if (cached) {
      return res.json({
        ...cached,
        cached: true
      });
    }
  }

  try {
    const result = await scrapeUrl(targetUrl, {
      screenshot
    });

    if (!screenshot) {
      cacheSet(cacheKey, result);
    }

    return res.json({
      ...result,
      cached: false
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "scrape_failed",
      message: error.message,
      requested_url: targetUrl,
      authenticated: false,
      chromium_path: process.env.PUPPETEER_EXECUTABLE_PATH || null
    });
  }
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "mercadolibre-browser-scraper-test",
    authenticated: false,
    endpoints: {
      health: "GET /health",
      scrape_post: "POST /scrape",
      scrape_url: "GET /scrape?url=URL_CODIFICADA",
      scrape_mla: "GET /scrape/MLA63233625"
    }
  });
});

app.get("/health", async (req, res) => {
  let browserConnected = false;
  let browserError = null;

  try {
    const browser = await getBrowser();
    browserConnected = Boolean(browser.connected);
  } catch (error) {
    browserError = error.message;
  }

  return res.status(browserConnected ? 200 : 503).json({
    ok: browserConnected,
    browser_connected: browserConnected,
    browser_error: browserError,
    active_browser_jobs: activeBrowserJobs,
    queued_browser_jobs: browserQueue.length,
    cache_entries: cache.size,
    authenticated: false
  });
});

app.post("/scrape", verifySecret, handleScrape);
app.get("/scrape", verifySecret, handleScrape);
app.get("/scrape/:mla", verifySecret, handleScrape);

app.use((error, req, res, next) => {
  return res.status(500).json({
    ok: false,
    error: "internal_error",
    message: error.message
  });
});

const server = app.listen(config.port, "0.0.0.0", () => {
  console.log(`Servidor iniciado en el puerto ${config.port}`);
});

async function shutdown(signal) {
  console.log(`Cerrando servicio por ${signal}`);

  server.close(async () => {
    try {
      if (browserPromise) {
        const browser = await browserPromise;
        await browser.close();
      }
    } catch {
    }

    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));