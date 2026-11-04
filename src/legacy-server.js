const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const seedCars = require("./car-catalog");

const scrypt = promisify(crypto.scrypt);
const catalogSeedVersion = 1;
const backendRoot = path.resolve(__dirname, "..");
const localEnvPath = [
  path.join(backendRoot, ".env"),
  path.resolve(backendRoot, "..", ".env"),
].find((candidate) => fsSync.existsSync(candidate));
if (localEnvPath && process.loadEnvFile) {
  process.loadEnvFile(localEnvPath);
}
const workspaceRoot = path.resolve(backendRoot, "..");
const root = fsSync.existsSync(path.join(workspaceRoot, "frontend", "public"))
  ? workspaceRoot
  : backendRoot;
const staticRoot = path.join(root, "frontend", "public");
const dataDir = process.env.KCR_DATA_DIR || path.join(root, "data");
const storePath = path.join(dataDir, "store.json");
const port = Number(process.env.PORT || 3000);
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const adminEmail =
  process.env.ADMIN_EMAIL?.trim().toLowerCase() ||
  (process.env.NODE_ENV === "production" ? "" : "admin@example.com");
const adminPassword =
  process.env.ADMIN_PASSWORD ||
  (process.env.NODE_ENV === "production" ? "" : "admin-kigali-2026");
let store;
let writeQueue = Promise.resolve();
let databaseClient = null;
let databasePool = null;
let vercelRequestQueue = Promise.resolve();
const providerTokens = new Map();

function assertAdminPassword() {
  if (!adminPassword || adminPassword.length < 12) {
    throw new Error("Set ADMIN_PASSWORD to a secret of at least 12 characters.");
  }
  if (!adminEmail) {
    throw new Error("Set ADMIN_EMAIL to the administrator email address.");
  }
}

function json(res, status, value, headers) {
  res.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  res.end(JSON.stringify(value));
}

function error(res, status, message) {
  json(res, status, { error: message });
}

function cookieOptions(maxAge) {
  return [
    "kcr_session=" + (maxAge ? maxAge.token : ""),
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=" + (maxAge ? Math.floor(sessionLifetime / 1000) : 0),
    process.env.NODE_ENV === "production" ? "Secure" : "",
  ]
    .filter(Boolean)
    .join("; ");
}

async function getSession(req) {
  const raw = req.headers.cookie || "";
  const token = raw
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("kcr_session="))
    ?.slice("kcr_session=".length);
  const session = token && store.sessions[token];
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    delete store.sessions[token];
    await saveStore();
    return null;
  }
  return { ...session, token };
}

function createSession(res, role, phone) {
  const token = crypto.randomBytes(32).toString("base64url");
  store.sessions[token] = {
    role,
    phone: phone || null,
    expiresAt: Date.now() + sessionLifetime,
  };
  res.setHeader("Set-Cookie", cookieOptions({ token }));
  return saveStore();
}

function normalizePhone(value) {
  return String(value || "")
    .replace(/[\s+-]/g, "")
    .replace(/^250/, "0");
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function isEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isPhone(value) {
  return /^07\d{8}$/.test(value);
}

function publicUser(identifier, user) {
  return {
    id: identifier,
    name: user.name,
    phone: user.phone || (isPhone(identifier) ? identifier : null),
    email: user.email || (isEmail(identifier) ? identifier : null),
    joinedAt: user.createdAt,
  };
}

function logEvent(action, identifier) {
  store.authEvents.push({
    action,
    phone: identifier ? String(identifier).slice(0, 254) : null,
    ts: Date.now(),
  });
  if (store.authEvents.length > 5000) {
    store.authEvents = store.authEvents.slice(-5000);
  }
  return saveStore();
}

function saveStore() {
  if (databaseClient) {
    return databaseClient.query(
      "UPDATE kcr_app_state SET data = $1::jsonb WHERE id = 1",
      [JSON.stringify(store)],
    );
  }
  writeQueue = writeQueue.then(async () => {
    const temporaryPath = storePath + ".tmp";
    await fs.writeFile(temporaryPath, JSON.stringify(store, null, 2), {
      mode: 0o600,
    });
    await fs.rename(temporaryPath, storePath);
  });
  return writeQueue;
}

async function readJson(req, maxLength = 8192) {
  if (!String(req.headers["content-type"] || "").includes("application/json")) {
    throw Object.assign(new Error("Send a JSON request body."), {
      status: 415,
    });
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxLength) {
      throw Object.assign(new Error("Request body is too large."), {
        status: 413,
      });
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("Invalid JSON request body."), {
      status: 400,
    });
  }
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const originHost = new URL(origin).host;
    const reqHost = req.headers["x-forwarded-host"] || req.headers.host;
    return originHost === reqHost || originHost === req.headers.host;
  } catch {
    return false;
  }
}

function clientAddress(req) {
  return req.ip || req.socket.remoteAddress || "unknown";
}

async function allowAttempt(req, route) {
  const key = route + ":" + clientAddress(req);
  const now = Date.now();
  for (const [attemptKey, attempt] of Object.entries(store.loginAttempts)) {
    if (now - attempt.startedAt > 15 * 60 * 1000) {
      delete store.loginAttempts[attemptKey];
    }
  }
  const attempt = store.loginAttempts[key];
  if (!attempt || now - attempt.startedAt > 15 * 60 * 1000) {
    store.loginAttempts[key] = { startedAt: now, count: 1 };
    await saveStore();
    return true;
  }
  attempt.count += 1;
  await saveStore();
  return attempt.count <= 10;
}

async function resetAttempts(req, route) {
  delete store.loginAttempts[route + ":" + clientAddress(req)];
  await saveStore();
}

async function passwordHash(password, salt) {
  return scrypt(password, salt, 64);
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validAdminCredentials(email, password) {
  const suppliedHash = crypto.createHash("sha256").update(password).digest();
  const configuredHash = crypto
    .createHash("sha256")
    .update(adminPassword)
    .digest();
  const suppliedEmailHash = crypto
    .createHash("sha256")
    .update(email)
    .digest();
  const configuredEmailHash = crypto
    .createHash("sha256")
    .update(adminEmail)
    .digest();
  return (
    crypto.timingSafeEqual(suppliedEmailHash, configuredEmailHash) &&
    crypto.timingSafeEqual(suppliedHash, configuredHash)
  );
}

function paymentPublic(payment) {
  return {
    id: payment.id,
    provider: payment.provider,
    amount: payment.amount,
    currency: payment.currency,
    status: payment.status,
    createdAt: payment.createdAt,
    confirmedAt: payment.confirmedAt || null,
  };
}

function adminPayment(payment) {
  return {
    ...paymentPublic(payment),
    name: payment.name,
    phone: payment.phone,
    accountId: payment.accountId || null,
  };
}

function paymentProviderConfig(provider) {
  if (provider === "mtn") {
    const config = {
      baseUrl: "https://sandbox.momodeveloper.mtn.com",
      subscriptionKey: process.env.MTN_MOMO_SUBSCRIPTION_KEY,
      apiUser: process.env.MTN_MOMO_API_USER,
      apiKey: process.env.MTN_MOMO_API_KEY,
      targetEnvironment: "sandbox",
    };
    if (!config.subscriptionKey || !config.apiUser || !config.apiKey) {
      throw Object.assign(
        new Error("MTN sandbox payment is not configured on the server."),
        {
          status: 503,
        },
      );
    }
    return config;
  }
  if (provider === "airtel") {
    const config = {
      baseUrl: "https://openapiuat.airtel.africa",
      clientId: process.env.AIRTEL_MONEY_CLIENT_ID,
      clientSecret: process.env.AIRTEL_MONEY_CLIENT_SECRET,
    };
    if (!config.clientId || !config.clientSecret) {
      throw Object.assign(
        new Error("Airtel sandbox payment is not configured on the server."),
        {
          status: 503,
        },
      );
    }
    return config;
  }
  throw Object.assign(new Error("Choose MTN or Airtel Mobile Money."), {
    status: 400,
  });
}

async function providerJson(url, options) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(15000),
  });
  let payload;
  try {
    payload = response.status === 204 ? {} : await response.json();
  } catch {
    payload = {};
  }
  if (!response.ok) {
    const e = new Error("The mobile-money provider rejected the request.");
    e.providerStatus = response.status;
    throw e;
  }
  return payload;
}

async function mtnToken(config) {
  const cached = providerTokens.get("mtn");
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const auth = Buffer.from(config.apiUser + ":" + config.apiKey).toString(
    "base64",
  );
  const payload = await providerJson(config.baseUrl + "/collection/token/", {
    method: "POST",
    headers: {
      Authorization: "Basic " + auth,
      "Ocp-Apim-Subscription-Key": config.subscriptionKey,
    },
  });
  if (!payload.access_token)
    throw new Error("MTN did not return an access token.");
  providerTokens.set("mtn", {
    value: payload.access_token,
    expiresAt:
      Date.now() + Math.max(30, Number(payload.expires_in || 3600) - 60) * 1000,
  });
  return payload.access_token;
}

async function airtelToken(config) {
  const cached = providerTokens.get("airtel");
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const payload = await providerJson(config.baseUrl + "/auth/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "*/*" },
    body: JSON.stringify({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: "client_credentials",
    }),
  });
  if (!payload.access_token) {
    throw new Error("Airtel did not return an access token.");
  }
  providerTokens.set("airtel", {
    value: payload.access_token,
    expiresAt:
      Date.now() + Math.max(30, Number(payload.expires_in || 3600) - 60) * 1000,
  });
  return payload.access_token;
}

async function requestProviderPayment(payment) {
  const config = paymentProviderConfig(payment.provider);
  if (payment.provider === "mtn") {
    const token = await mtnToken(config);
    await providerJson(config.baseUrl + "/collection/v1_0/requesttopay", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": config.subscriptionKey,
        "X-Reference-Id": payment.id,
        "X-Target-Environment": config.targetEnvironment,
      },
      body: JSON.stringify({
        amount: String(payment.amount),
        currency: payment.currency,
        externalId: payment.id,
        payer: {
          partyIdType: "MSISDN",
          partyId: "250" + payment.phone.slice(1),
        },
        payerMessage: "Kigali Car Rent payment",
        payeeNote: "Kigali Car Rent",
      }),
    });
    return;
  }
  const token = await airtelToken(config);
  await providerJson(config.baseUrl + "/merchant/v1/payments/", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      Accept: "*/*",
      "X-Country": "RW",
      "X-Currency": payment.currency,
    },
    body: JSON.stringify({
      reference: "Kigali Car Rent " + payment.id,
      subscriber: {
        country: "RW",
        currency: payment.currency,
        msisdn: payment.phone.slice(1),
      },
      transaction: {
        amount: String(payment.amount),
        country: "RW",
        currency: payment.currency,
        id: payment.id,
      },
    }),
  });
}

function providerPaymentStatus(provider, payload) {
  const raw =
    provider === "mtn"
      ? payload.status
      : payload?.data?.transaction?.status ||
        payload?.status?.code ||
        payload?.status;
  const status = String(raw || "").toUpperCase();
  if (["SUCCESSFUL", "SUCCESS", "TS"].includes(status)) return "successful";
  if (["FAILED", "FAILURE", "TF", "EXPIRED", "CANCELLED"].includes(status)) {
    return "failed";
  }
  return "pending";
}

async function readProviderPaymentStatus(payment) {
  const config = paymentProviderConfig(payment.provider);
  if (payment.provider === "mtn") {
    const token = await mtnToken(config);
    const payload = await providerJson(
      config.baseUrl +
        "/collection/v1_0/requesttopay/" +
        encodeURIComponent(payment.id),
      {
        method: "GET",
        headers: {
          Authorization: "Bearer " + token,
          "Ocp-Apim-Subscription-Key": config.subscriptionKey,
          "X-Target-Environment": config.targetEnvironment,
        },
      },
    );
    return providerPaymentStatus("mtn", payload);
  }
  const token = await airtelToken(config);
  const payload = await providerJson(
    config.baseUrl + "/standard/v1/payments/" + encodeURIComponent(payment.id),
    {
      method: "GET",
      headers: {
        Authorization: "Bearer " + token,
        Accept: "*/*",
        "X-Country": "RW",
        "X-Currency": payment.currency,
      },
    },
  );
  return providerPaymentStatus("airtel", payload);
}

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/api/health") {
    return json(res, 200, { ok: true });
  }

  if (req.method === "GET" && url.pathname === "/api/cars") {
    return json(res, 200, { cars: store.cars });
  }

  if (req.method === "GET" && url.pathname === "/api/bookings") {
    const session = await getSession(req);
    if (!session) return json(res, 200, { bookings: [] });
    if (session.role === "admin") {
      return json(res, 200, { bookings: store.bookings });
    }
    const user = store.users[session.phone];
    return json(res, 200, {
      bookings: store.bookings.filter(
        (booking) =>
          booking.accountId === session.phone ||
          (user?.phone && booking.phone === user.phone),
      ),
    });
  }

  if (req.method === "GET" && url.pathname === "/api/me") {
    const session = await getSession(req);
    if (!session) return json(res, 200, { user: null });
    if (session.role === "admin") {
      return json(res, 200, { user: { role: "admin" } });
    }
    const user = store.users[session.phone];
    if (!user) return json(res, 200, { user: null });
    return json(res, 200, {
      user: { ...publicUser(session.phone, user), role: "customer" },
    });
  }

  if (req.method === "POST" && url.pathname === "/api/me") {
    if (!sameOrigin(req)) {
      return error(res, 403, "Request origin is not allowed.");
    }
    let body;
    try {
      body = await readJson(req);
    } catch (e) {
      return error(res, e.status || 400, e.message);
    }
    const session = await getSession(req);
    if (!session || session.role !== "customer") {
      return error(res, 401, "Customer login is required.");
    }
    const user = store.users[session.phone];
    if (!user) {
      return error(res, 401, "Customer account was not found.");
    }
    const name = String(body.name || "").trim();
    if (!name || name.length > 100) {
      return error(res, 400, "Enter a name of at most 100 characters.");
    }
    user.name = name;
    await logEvent("Account name updated", session.phone);
    return json(res, 200, {
      user: { ...publicUser(session.phone, user), role: "customer" },
    });
  }

  if (req.method === "DELETE" && url.pathname === "/api/me") {
    if (!sameOrigin(req)) {
      return error(res, 403, "Request origin is not allowed.");
    }
    const session = await getSession(req);
    if (!session || session.role !== "customer") {
      return error(res, 401, "Customer login is required.");
    }
    const identifier = session.phone;
    if (!store.users[identifier]) {
      return error(res, 404, "Customer account was not found.");
    }
    delete store.users[identifier];
    for (const [token, accountSession] of Object.entries(store.sessions)) {
      if (
        accountSession.role === "customer" &&
        accountSession.phone === identifier
      ) {
        delete store.sessions[token];
      }
    }
    await saveStore();
    res.setHeader("Set-Cookie", cookieOptions(null));
    return json(res, 200, { ok: true });
  }

  if (req.method === "POST") {
    if (!sameOrigin(req))
      return error(res, 403, "Request origin is not allowed.");
    let body;
    try {
      body = await readJson(
        req,
        url.pathname === "/api/admin/cars" ? 128 * 1024 : undefined,
      );
    } catch (e) {
      return error(res, e.status || 400, e.message);
    }

    if (url.pathname === "/api/register") {
      if (!(await allowAttempt(req, "register"))) {
        return error(res, 429, "Too many attempts. Try again later.");
      }
      const name = String(body.name || "").trim();
      const suppliedIdentifier =
        body.identifier !== undefined ? body.identifier : body.phone;
      const rawIdentifier = String(suppliedIdentifier || "").trim();
      const email = rawIdentifier.includes("@")
        ? normalizeEmail(rawIdentifier)
        : "";
      const phone = email ? "" : normalizePhone(rawIdentifier);
      const identifier = email || phone;
      const password = String(body.password || "");
      if (!name || name.length > 100) {
        return error(res, 400, "Enter a name of at most 100 characters.");
      }
      if (!isEmail(email) && !isPhone(phone)) {
        return error(
          res,
          400,
          "Enter a valid email address or Rwanda mobile number.",
        );
      }
      if (email && email === adminEmail) {
        return error(
          res,
          409,
          "This email address is reserved for the administrator.",
        );
      }
      if (password.length < 8 || password.length > 128) {
        return error(
          res,
          400,
          "Password must be between 8 and 128 characters.",
        );
      }
      if (
        !/[a-z]/.test(password) ||
        !/[A-Z]/.test(password) ||
        !/[0-9]/.test(password)
      ) {
        return error(
          res,
          400,
          "Include at least one uppercase letter, one lowercase letter, and one number.",
        );
      }
      if (store.users[identifier]) {
        await logEvent("Registration failed", identifier);
        return error(
          res,
          409,
          "This email address or number already has an account. Please log in.",
        );
      }
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = (await passwordHash(password, salt)).toString("hex");
      if (store.users[identifier]) {
        await logEvent("Registration failed", identifier);
        return error(
          res,
          409,
          "This email address or number already has an account. Please log in.",
        );
      }
      const user = {
        name,
        phone: phone || null,
        email: email || null,
        salt,
        hash,
        createdAt: Date.now(),
      };
      store.users[identifier] = user;
      await logEvent("Registration succeeded", identifier);
      await resetAttempts(req, "register");
      await createSession(res, "customer", identifier);
      return json(res, 201, {
        user: {
          ...publicUser(identifier, store.users[identifier]),
          role: "customer",
        },
      });
    }

    if (url.pathname === "/api/login") {
      const suppliedIdentifier =
        body.identifier !== undefined ? body.identifier : body.phone;
      const rawIdentifier = String(suppliedIdentifier || "").trim();
      const identifier = rawIdentifier.includes("@")
        ? normalizeEmail(rawIdentifier)
        : normalizePhone(rawIdentifier);
      const password = String(body.password || "");
      const adminLogin = isEmail(identifier) && identifier === adminEmail;
      const attemptRoute = adminLogin ? "admin-login" : "login";
      if (!(await allowAttempt(req, attemptRoute))) {
        return error(res, 429, "Too many attempts. Try again later.");
      }
      if (adminLogin) {
        if (!validAdminCredentials(identifier, password)) {
          await logEvent("Admin login failed");
          return error(res, 401, "Wrong email or phone number and password.");
        }
        await resetAttempts(req, attemptRoute);
        await logEvent("Admin login succeeded");
        await createSession(res, "admin");
        return json(res, 200, { user: { role: "admin" } });
      }
      if (
        (!isPhone(identifier) && !isEmail(identifier)) ||
        password.length > 1024
      ) {
        await logEvent("Customer login failed", identifier);
        return error(res, 401, "Wrong email or phone number and password.");
      }
      const user = store.users[identifier];
      const calculatedHash = await passwordHash(
        password,
        user ? user.salt : "kcr-invalid-account-salt",
      );
      const valid =
        user && secureEqual(calculatedHash, Buffer.from(user.hash, "hex"));
      if (!valid) {
        await logEvent("Customer login failed", identifier);
        return error(res, 401, "Wrong email or phone number and password.");
      }
      await resetAttempts(req, "login");
      await logEvent("Customer login succeeded", identifier);
      await createSession(res, "customer", identifier);
      return json(res, 200, {
        user: { ...publicUser(identifier, user), role: "customer" },
      });
    }

    if (url.pathname === "/api/admin/login") {
      if (!(await allowAttempt(req, "admin-login"))) {
        return error(res, 429, "Too many attempts. Try again later.");
      }
      const email = normalizeEmail(body.email);
      const password = String(body.password || "");
      if (!validAdminCredentials(email, password)) {
        await logEvent("Admin login failed");
        return error(res, 401, "Wrong admin email or password.");
      }
      await resetAttempts(req, "admin-login");
      await logEvent("Admin login succeeded");
      await createSession(res, "admin");
      return json(res, 200, { user: { role: "admin" } });
    }

    if (url.pathname === "/api/payments/request") {
      if (!(await allowAttempt(req, "payment-request"))) {
        return error(res, 429, "Too many payment attempts. Try again later.");
      }
      const provider = String(body.provider || "").toLowerCase();
      const phone = normalizePhone(body.phone);
      const name = String(body.name || "").trim();
      const amount = Number(body.amount);
      if (!["mtn", "airtel"].includes(provider)) {
        return error(res, 400, "Choose MTN or Airtel Mobile Money.");
      }
      if (!/^07\d{8}$/.test(phone)) {
        return error(res, 400, "Enter a valid Rwanda mobile number.");
      }
      if (!name || name.length > 100) {
        return error(res, 400, "Enter your name.");
      }
      if (!Number.isSafeInteger(amount) || amount < 1 || amount > 50000000) {
        return error(res, 400, "Enter a valid payment amount in RWF.");
      }
      let config;
      try {
        config = paymentProviderConfig(provider);
      } catch (e) {
        return error(res, e.status || 503, e.message);
      }
      const payment = {
        id: crypto.randomUUID(),
        provider,
        phone,
        name,
        amount,
        currency: "RWF",
        status: "initiating",
        createdAt: Date.now(),
        confirmedAt: null,
      };
      const session = await getSession(req);
      if (session?.role === "customer" && store.users[session.phone]) {
        payment.accountId = session.phone;
      }
      store.payments.push(payment);
      await saveStore();
      try {
        await requestProviderPayment(payment, config);
        payment.status = "pending";
        await saveStore();
        return json(res, 202, {
          payment: paymentPublic(payment),
          message: "Approve the payment request in your mobile-money prompt.",
        });
      } catch (e) {
        payment.status = "failed";
        await saveStore();
        console.error(
          "Mobile-money request failed for " +
            provider +
            " (HTTP " +
            (e.providerStatus || "network error") +
            ").",
        );
        return error(
          res,
          502,
          "The provider could not start this payment. Check the number and try again.",
        );
      }
    }

    if (url.pathname === "/api/bookings") {
      const car = String(body.car || "")
        .slice(0, 100)
        .trim();
      const name = String(body.name || "")
        .slice(0, 100)
        .trim();
      const phone = normalizePhone(body.phone);
      const d1 = String(body.d1 || "").slice(0, 20);
      const d2 = String(body.d2 || "").slice(0, 20);
      const days = Number(body.days) || 1;
      const driver = Boolean(body.driver);
      const total = Number(body.total) || 0;
      const paid = Number(body.paid) || 0;
      const loc = String(body.loc || "Kigali").slice(0, 100);
      const nid = String(body.nid || "").slice(0, 50);
      const status = String(body.status || "Booked").slice(0, 30);

      if (!car || !name || !phone) {
        return error(
          res,
          400,
          "Please provide car, customer name, and phone number.",
        );
      }

      const ref =
        body.ref && /^KCR-[A-Z0-9-]{3,24}$/i.test(body.ref)
          ? String(body.ref).toUpperCase()
          : "KCR-" +
            Date.now().toString(36).toUpperCase() +
            "-" +
            crypto.randomBytes(2).toString("hex").toUpperCase();

      const booking = {
        ref,
        car,
        name,
        phone,
        d1,
        d2,
        days,
        driver,
        total,
        paid,
        loc,
        nid,
        status,
        createdAt: Date.now(),
      };
      const session = await getSession(req);
      if (session?.role === "customer" && store.users[session.phone]) {
        booking.accountId = session.phone;
      }
      store.bookings.unshift(booking);
      await logEvent("New booking " + ref, phone);
      await saveStore();
      return json(res, 201, { booking });
    }

    if (url.pathname === "/api/admin/cars") {
      const session = await getSession(req);
      if (!session || session.role !== "admin") {
        return error(res, 401, "Admin login is required.");
      }
      const id = Number(body.id) || Date.now();
      const name = String(body.name || body.n || "")
        .slice(0, 100)
        .trim();
      const cat = String(body.category || body.cat || "economy").toLowerCase();
      const price = Number(body.price || body.p || 0);
      const transmission = String(body.transmission || body.tr || "Automatic");
      const seats = Number(body.seats || body.s || 5);
      const fuel = String(body.fuel || body.f || "Petrol");
      const status = String(body.status || "Available");
      const img = String(body.img || "images/car-1.jpg");

      if (!name) return error(res, 400, "Provide a car name.");
      const carIndex = store.cars.findIndex((c) => c.id === id);
      const carData = {
        id,
        name,
        cat,
        price,
        transmission,
        seats,
        fuel,
        status,
        img,
      };
      if (carIndex > -1) {
        store.cars[carIndex] = { ...store.cars[carIndex], ...carData };
      } else {
        store.cars.push(carData);
      }
      await logEvent("Car fleet updated: " + name);
      await saveStore();
      return json(res, 200, { cars: store.cars, car: carData });
    }

    if (url.pathname === "/api/contact") {
      const name = String(body.name || "")
        .slice(0, 100)
        .trim();
      const phone = normalizePhone(body.phone);
      const message = String(body.message || "")
        .slice(0, 2000)
        .trim();
      if (!name || !message) {
        return error(res, 400, "Enter your name and message.");
      }
      const msg = {
        id: crypto.randomUUID(),
        name,
        phone,
        message,
        createdAt: Date.now(),
        status: "unread",
      };
      store.messages.unshift(msg);
      await logEvent("Inquiry received from " + name, phone);
      await saveStore();
      return json(res, 201, { ok: true, message: msg });
    }

    if (url.pathname === "/api/logout") {
      const session = await getSession(req);
      if (session) {
        await logEvent(
          session.role === "admin" ? "Admin logout" : "Customer logout",
          session.phone,
        );
        delete store.sessions[session.token];
        await saveStore();
      }
      res.setHeader("Set-Cookie", cookieOptions(null));
      return json(res, 200, { ok: true });
    }
  }

  const paymentMatch = url.pathname.match(
    /^\/api\/payments\/([0-9a-f-]{36})$/i,
  );
  if (req.method === "GET" && paymentMatch) {
    const payment = store.payments.find((item) => item.id === paymentMatch[1]);
    if (!payment) return error(res, 404, "Payment request not found.");
    if (payment.status === "pending") {
      try {
        const status = await readProviderPaymentStatus(payment);
        if (status !== payment.status) {
          payment.status = status;
          if (status === "successful") payment.confirmedAt = Date.now();
          await saveStore();
        }
      } catch (e) {
        console.error(
          "Mobile-money status check failed for " +
            payment.provider +
            " (HTTP " +
            (e.providerStatus || "network error") +
            ").",
        );
        return error(
          res,
          503,
          "Could not check the payment status. Retry shortly.",
        );
      }
    }
    return json(res, 200, { payment: paymentPublic(payment) });
  }

  const adminBookingMatch = url.pathname.match(
    /^\/api\/admin\/bookings\/([A-Za-z0-9_-]+)$/,
  );
  if (adminBookingMatch) {
    const session = await getSession(req);
    if (!session || session.role !== "admin") {
      return error(res, 401, "Admin login is required.");
    }
    if (!sameOrigin(req)) {
      return error(res, 403, "Request origin is not allowed.");
    }
    const ref = adminBookingMatch[1].toUpperCase();
    const booking = store.bookings.find(
      (b) => String(b.ref).toUpperCase() === ref,
    );
    if (!booking) {
      return error(res, 404, "Booking not found.");
    }

    if (req.method === "PATCH") {
      let body;
      try {
        body = await readJson(req);
      } catch (e) {
        return error(res, e.status || 400, e.message);
      }
      if (body.status !== undefined) {
        booking.status = String(body.status).slice(0, 30);
      }
      if (body.paid !== undefined && Number.isSafeInteger(Number(body.paid))) {
        booking.paid = Number(body.paid);
      }
      await logEvent("Booking " + ref + " status: " + booking.status);
      await saveStore();
      return json(res, 200, { booking });
    }

    if (req.method === "DELETE") {
      store.bookings = store.bookings.filter(
        (b) => String(b.ref).toUpperCase() !== ref,
      );
      await logEvent("Booking " + ref + " deleted");
      await saveStore();
      return json(res, 200, { ok: true });
    }
  }

  if (req.method === "GET" && url.pathname === "/api/admin/data") {
    const session = await getSession(req);
    if (!session || session.role !== "admin") {
      return error(res, 401, "Admin login is required.");
    }
    return json(res, 200, {
      users: Object.keys(store.users).map((identifier) =>
        publicUser(identifier, store.users[identifier]),
      ),
      authEvents: store.authEvents,
      payments: store.payments.map(adminPayment),
      bookings: store.bookings,
      cars: store.cars,
      messages: store.messages,
    });
  }

  return error(res, 404, "API route not found.");
}

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

async function serveStatic(req, res, url) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return error(res, 405, "Method not allowed.");
  }
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return error(res, 400, "Invalid URL path.");
  }
  if (pathname === "/" || pathname === "/admin" || pathname === "/admin/")
    pathname = "/index.html";
  if (
    !/^\/(?:index\.html|(?:css|js|images)\/[a-zA-Z0-9._-]+)$/.test(pathname)
  ) {
    return error(res, 404, "File not found.");
  }
  const filePath = path.resolve(staticRoot, "." + pathname);
  try {
    const content = await fs.readFile(filePath);
    res.writeHead(200, {
      "Cache-Control": "no-cache",
      "Content-Type":
        contentTypes[path.extname(filePath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(req.method === "HEAD" ? undefined : content);
  } catch (e) {
    if (e.code === "ENOENT") return error(res, 404, "File not found.");
    throw e;
  }
}

function emptyStore() {
  return {
    users: {},
    authEvents: [],
    payments: [],
    bookings: [],
    cars: seedCars.map((car) => ({ ...car })),
    messages: [],
    sessions: {},
    loginAttempts: {},
    catalogSeedVersion,
  };
}

function seedCatalog(value) {
  if (Number(value.catalogSeedVersion) >= catalogSeedVersion) return false;
  if (value.cars.length === 0) {
    value.cars = seedCars.map((car) => ({ ...car }));
  }
  value.catalogSeedVersion = catalogSeedVersion;
  return true;
}

function normalizeStore(value, source) {
  if (
    !value ||
    !value.users ||
    typeof value.users !== "object" ||
    Array.isArray(value.users) ||
    !Array.isArray(value.authEvents)
  ) {
    throw new Error("The data store has an invalid format: " + source);
  }
  for (const key of ["payments", "bookings", "cars", "messages"]) {
    if (!Array.isArray(value[key])) value[key] = [];
  }
  if (!value.sessions || typeof value.sessions !== "object") {
    value.sessions = {};
  }
  if (!value.loginAttempts || typeof value.loginAttempts !== "object") {
    value.loginAttempts = {};
  }
  return value;
}

async function loadFileStore() {
  await fs.mkdir(dataDir, { recursive: true, mode: 0o700 });
  try {
    store = normalizeStore(
      JSON.parse(await fs.readFile(storePath, "utf8")),
      storePath,
    );
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    store = emptyStore();
  }
}

function getDatabasePool() {
  if (!databasePool) {
    const { Pool } = require("@neondatabase/serverless");
    databasePool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 1,
    });
  }
  return databasePool;
}

async function dispatchRequest(req, res) {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url);
  } else {
    await serveStatic(req, res, url);
  }
}

async function handleVercelRequest(req, res) {
  if (!process.env.DATABASE_URL) {
    console.error("Set DATABASE_URL to the Neon PostgreSQL connection string.");
    return error(res, 503, "The server is not configured.");
  }
  try {
    assertAdminPassword();
  } catch (e) {
    console.error(e);
    return error(res, 503, "The server is not configured.");
  }

  const request = vercelRequestQueue.then(async () => {
    const client = await getDatabasePool().connect();
    let transactionStarted = false;
    try {
      await client.query("BEGIN");
      transactionStarted = true;
      await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [
        "1350846783",
      ]);
      await client.query(
        "CREATE TABLE IF NOT EXISTS kcr_app_state (id SMALLINT PRIMARY KEY CHECK (id = 1), data JSONB NOT NULL)",
      );
      await client.query(
        "INSERT INTO kcr_app_state (id, data) VALUES (1, $1::jsonb) ON CONFLICT (id) DO NOTHING",
        [JSON.stringify(emptyStore())],
      );
      const result = await client.query(
        "SELECT data FROM kcr_app_state WHERE id = 1",
      );
      store = normalizeStore(result.rows[0].data, "Neon PostgreSQL");
      if (seedCatalog(store)) {
        await client.query(
          "UPDATE kcr_app_state SET data = $1::jsonb WHERE id = 1",
          [JSON.stringify(store)],
        );
      }
      databaseClient = client;
      await dispatchRequest(req, res);
      await client.query("COMMIT");
      transactionStarted = false;
    } catch (e) {
      if (transactionStarted) await client.query("ROLLBACK");
      throw e;
    } finally {
      databaseClient = null;
      client.release();
    }
  });
  vercelRequestQueue = request.catch(() => {});
  try {
    await request;
  } catch (e) {
    console.error(e);
    if (!res.headersSent) {
      error(res, 500, "The server could not complete the request.");
    } else {
      res.destroy();
    }
  }
}

async function start() {
  assertAdminPassword();
  if (!process.env.ADMIN_PASSWORD && process.env.NODE_ENV !== "test") {
    console.log(
      "Notice: using default development ADMIN_PASSWORD: admin-kigali-2026",
    );
  }
  await loadFileStore();

  const server = http.createServer((req, res) => {
    dispatchRequest(req, res).catch((e) => {
      console.error(e);
      if (!res.headersSent)
        error(res, 500, "The server could not complete the request.");
      else res.destroy();
    });
  });
  const host = process.env.HOST || "0.0.0.0";
  server.listen(port, host, () => {
    console.log(
      "Kigali Car Rent server listening on port " +
        server.address().port +
        " (host " +
        host +
        ")",
    );
  });
}

if (require.main === module) {
  start().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { clientAddress, handleVercelRequest };
