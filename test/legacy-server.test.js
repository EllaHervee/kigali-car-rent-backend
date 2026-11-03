const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const test = require("node:test");

test("server persists accounts and protects admin records", async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "kcr-backend-"));
  const server = spawn(
    process.execPath,
    [path.join(__dirname, "../src/legacy-server.js")],
    {
    env: {
      ...process.env,
      ADMIN_EMAIL: "admin@example.com",
      ADMIN_PASSWORD: "test-admin-password-2026",
      MTN_MOMO_SUBSCRIPTION_KEY: "",
      MTN_MOMO_API_USER: "",
      MTN_MOMO_API_KEY: "",
      AIRTEL_MONEY_CLIENT_ID: "",
      AIRTEL_MONEY_CLIENT_SECRET: "",
      KCR_DATA_DIR: dataDir,
      PORT: "0",
      NODE_ENV: "test",
    },
    stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  server.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  server.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  t.after(async () => {
    server.kill();
    await once(server, "exit").catch(() => {});
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  const startedAt = Date.now();
  while (!output.includes("listening on port")) {
    if (Date.now() - startedAt > 5000) {
      throw new Error("Backend did not start: " + output);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  const port = Number(output.match(/port (\d+)/)[1]);
  const base = "http://127.0.0.1:" + port;
  const request = (route, options) =>
    fetch(base + route, {
      ...options,
      headers: {
        ...(options && options.headers),
        ...(options && options.body ? { "Content-Type": "application/json" } : {}),
      },
    });
  const body = (value) => JSON.stringify(value);
  const cookieFrom = (response) =>
    response.headers.get("set-cookie").split(";")[0];

  const unauthenticated = await request("/api/admin/data");
  assert.equal(unauthenticated.status, 401);

  const noMtnConfig = await request("/api/payments/request", {
    method: "POST",
    body: body({
      provider: "mtn",
      phone: "0783553434",
      name: "Test Customer",
      amount: 1000,
    }),
  });
  assert.equal(noMtnConfig.status, 503);
  const noAirtelConfig = await request("/api/payments/request", {
    method: "POST",
    body: body({
      provider: "airtel",
      phone: "0783553434",
      name: "Test Customer",
      amount: 1000,
    }),
  });
  assert.equal(noAirtelConfig.status, 503);

  const weakPassword = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Test Customer",
      phone: "0783553434",
      password: "password",
    }),
  });
  assert.equal(weakPassword.status, 400);

  const registered = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Test Customer",
      phone: "0783553434",
      password: "Customer123",
    }),
  });
  assert.equal(registered.status, 201);
  const customerCookie = cookieFrom(registered);
  assert.equal(
    (
      await (
        await request("/api/me", { headers: { Cookie: customerCookie } })
      ).json()
    ).user.role,
    "customer",
  );
  const loggedOut = await request("/api/logout", {
    method: "POST",
    headers: { Cookie: customerCookie },
    body: "{}",
  });
  assert.equal(loggedOut.status, 200);
  const afterLogout = await request("/api/me", {
    headers: { Cookie: customerCookie },
  });
  assert.equal((await afterLogout.json()).user, null);

  const failedLogin = await request("/api/login", {
    method: "POST",
    body: body({ phone: "0783553434", password: "WrongCustomer123" }),
  });
  assert.equal(failedLogin.status, 401);

  const loggedIn = await request("/api/login", {
    method: "POST",
    body: body({ phone: "0783553434", password: "Customer123" }),
  });
  assert.equal(loggedIn.status, 200);

  const adminLogin = await request("/api/admin/login", {
    method: "POST",
    body: body({
      email: "ADMIN@example.com",
      password: "test-admin-password-2026",
    }),
  });
  assert.equal(adminLogin.status, 200);
  const wrongAdminEmail = await request("/api/admin/login", {
    method: "POST",
    body: body({
      email: "wrong@example.com",
      password: "test-admin-password-2026",
    }),
  });
  assert.equal(wrongAdminEmail.status, 401);
  const dashboard = await request("/api/admin/data", {
    headers: { Cookie: cookieFrom(adminLogin) },
  });
  assert.equal(dashboard.status, 200);
  const records = await dashboard.json();
  assert.equal(records.users[0].phone, "0783553434");
  assert.deepEqual(records.payments, []);
  assert.deepEqual(records.bookings, []);
  assert.deepEqual(records.cars, []);
  assert.ok(records.authEvents.some((event) => event.action === "Registration succeeded"));
  assert.ok(records.authEvents.some((event) => event.action === "Customer login failed"));

  // Test booking creation and admin management
  const createdBookingRes = await request("/api/bookings", {
    method: "POST",
    body: body({
      car: "Toyota Land Cruiser V8",
      name: "Test Customer",
      phone: "0783553434",
      d1: "2026-11-10",
      d2: "2026-11-15",
      days: 5,
      total: 900000,
      paid: 270000,
      loc: "Kigali Airport",
    }),
  });
  assert.equal(createdBookingRes.status, 201);
  const createdBooking = (await createdBookingRes.json()).booking;
  assert.ok(createdBooking.ref.startsWith("KCR-"));

  const adminCookie = cookieFrom(adminLogin);
  const patchBookingRes = await request("/api/admin/bookings/" + createdBooking.ref, {
    method: "PATCH",
    headers: { Cookie: adminCookie },
    body: body({ status: "Picked up" }),
  });
  assert.equal(patchBookingRes.status, 200);
  const patched = (await patchBookingRes.json()).booking;
  assert.equal(patched.status, "Picked up");

  const adminCarsRes = await request("/api/admin/cars", {
    method: "POST",
    headers: { Cookie: adminCookie },
    body: body({
      id: 1,
      name: "Toyota Land Cruiser V8",
      status: "Rented",
      price: 195000,
    }),
  });
  assert.equal(adminCarsRes.status, 200);

  const updatedDashboard = await (
    await request("/api/admin/data", { headers: { Cookie: adminCookie } })
  ).json();
  assert.equal(updatedDashboard.bookings.length, 1);
  assert.equal(updatedDashboard.bookings[0].status, "Picked up");
  assert.equal(updatedDashboard.cars[0].status, "Rented");
  const stored = await fs.readFile(path.join(dataDir, "store.json"), "utf8");
  assert.equal(stored.includes("Customer123"), false);
  assert.equal((await request("/data/store.json")).status, 404);
  assert.equal(JSON.stringify(records).includes("salt"), false);
  assert.equal(JSON.stringify(records).includes("hash"), false);

  const staticPage = await request("/");
  assert.equal(staticPage.status, 200);
  assert.match(await staticPage.text(), /Kigali Car Rent/);

  const adminPage = await request("/admin");
  assert.equal(adminPage.status, 200);
  assert.match(await adminPage.text(), /Kigali Car Rent/);
});

test("Vercel handler reports missing Neon configuration", async () => {
  const previousDatabaseUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    const handler = require("../src/legacy-server.js").handleVercelRequest;
    const response = {
      headersSent: false,
      writeHead(status, headers) {
        this.statusCode = status;
        this.headers = headers;
        this.headersSent = true;
      },
      end(body) {
        this.body = body;
      },
    };
    await handler({ headers: {}, url: "/api/health" }, response);
    assert.equal(response.statusCode, 503);
    assert.deepEqual(JSON.parse(response.body), {
      error: "The server is not configured.",
    });
  } finally {
    if (previousDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = previousDatabaseUrl;
    }
  }
});
