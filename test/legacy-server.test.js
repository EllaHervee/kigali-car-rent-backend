const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const test = require("node:test");

test("login attempt keys use the trusted client IP when available", () => {
  const { clientAddress } = require("../src/legacy-server.js");
  assert.equal(
    clientAddress({
      ip: "198.51.100.10",
      socket: { remoteAddress: "10.0.0.2" },
    }),
    "198.51.100.10",
  );
  assert.equal(
    clientAddress({ socket: { remoteAddress: "127.0.0.1" } }),
    "127.0.0.1",
  );
});

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
        ...(options && options.body
          ? { "Content-Type": "application/json" }
          : {}),
      },
    });
  const body = (value) => JSON.stringify(value);
  const cookieFrom = (response) =>
    response.headers.get("set-cookie").split(";")[0];

  const unauthenticated = await request("/api/admin/data");
  assert.equal(unauthenticated.status, 401);
  const unauthenticatedProfileUpdate = await request("/api/me", {
    method: "POST",
    body: body({ name: "Iradukunda Ella Herve" }),
  });
  assert.equal(unauthenticatedProfileUpdate.status, 401);
  const unauthenticatedAccountDeletion = await request("/api/me", {
    method: "DELETE",
  });
  assert.equal(unauthenticatedAccountDeletion.status, 401);

  const catalogResponse = await request("/api/cars");
  assert.equal(catalogResponse.status, 200);
  const catalog = (await catalogResponse.json()).cars;
  assert.equal(catalog.length, 30);
  assert.equal(catalog[0].name, "Toyota Land Cruiser V8");
  assert.equal(catalog[29].name, "Kia Niro Hybrid");

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
  const customerLoginCookie = cookieFrom(loggedIn);
  const profileUpdated = await request("/api/me", {
    method: "POST",
    headers: { Cookie: customerLoginCookie },
    body: body({ name: "  Iradukunda Ella Herve  " }),
  });
  assert.equal(profileUpdated.status, 200);
  assert.equal((await profileUpdated.json()).user.name, "Iradukunda Ella Herve");
  const updatedProfile = await request("/api/me", {
    headers: { Cookie: customerLoginCookie },
  });
  assert.equal((await updatedProfile.json()).user.name, "Iradukunda Ella Herve");

  const emailRegistered = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Email Customer",
      identifier: "Test.Customer@example.com",
      password: "Customer123",
    }),
  });
  assert.equal(emailRegistered.status, 201);
  const emailLoggedIn = await request("/api/login", {
    method: "POST",
    body: body({
      identifier: "TEST.CUSTOMER@example.com",
      password: "Customer123",
    }),
  });
  assert.equal(emailLoggedIn.status, 200);

  const adminLogin = await request("/api/login", {
    method: "POST",
    body: body({
      identifier: "ADMIN@example.com",
      password: "test-admin-password-2026",
    }),
  });
  assert.equal(adminLogin.status, 200);
  assert.equal((await adminLogin.json()).user.role, "admin");
  const adminProfileUpdate = await request("/api/me", {
    method: "POST",
    headers: { Cookie: cookieFrom(adminLogin) },
    body: body({ name: "Unauthorized Change" }),
  });
  assert.equal(adminProfileUpdate.status, 401);
  const adminAccountDeletion = await request("/api/me", {
    method: "DELETE",
    headers: { Cookie: cookieFrom(adminLogin) },
  });
  assert.equal(adminAccountDeletion.status, 401);
  const adminEmailRegistration = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Admin Account",
      identifier: "ADMIN@example.com",
      password: "Customer123",
    }),
  });
  assert.equal(adminEmailRegistration.status, 409);
  const legacyAdminLogin = await request("/api/admin/login", {
    method: "POST",
    body: body({
      email: "ADMIN@example.com",
      password: "test-admin-password-2026",
    }),
  });
  assert.equal(legacyAdminLogin.status, 200);
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
  assert.equal(records.cars.length, 30);
  assert.equal(records.cars[0].name, "Toyota Land Cruiser V8");
  assert.ok(
    records.authEvents.some(
      (event) => event.action === "Registration succeeded",
    ),
  );
  assert.ok(
    records.authEvents.some(
      (event) => event.action === "Customer login failed",
    ),
  );

  const emailRegistration = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Email Customer",
      identifier: "New.Customer@Example.com",
      password: "Customer123",
    }),
  });
  assert.equal(emailRegistration.status, 201);
  const emailAccount = (await emailRegistration.json()).user;
  assert.equal(emailAccount.id, "new.customer@example.com");
  assert.equal(emailAccount.email, "new.customer@example.com");
  assert.equal(emailAccount.phone, null);
  assert.ok(cookieFrom(emailRegistration).startsWith("kcr_session="));
  const restoredEmailAccount = await request("/api/me", {
    headers: { Cookie: cookieFrom(emailRegistration) },
  });
  assert.equal(
    (await restoredEmailAccount.json()).user.email,
    "new.customer@example.com",
  );
  const emailLogin = await request("/api/login", {
    method: "POST",
    body: body({
      identifier: "new.customer@example.com",
      password: "Customer123",
    }),
  });
  assert.equal(emailLogin.status, 200);
  const duplicateEmail = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Email Customer",
      identifier: "NEW.CUSTOMER@example.com",
      password: "Customer123",
    }),
  });
  assert.equal(duplicateEmail.status, 409);

  const invalidIdentifier = await request("/api/register", {
    method: "POST",
    body: body({
      name: "Invalid Customer",
      identifier: "not-an-email",
      password: "Customer123",
    }),
  });
  assert.equal(invalidIdentifier.status, 400);

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

  const emailBookingRes = await request("/api/bookings", {
    method: "POST",
    headers: { Cookie: cookieFrom(emailLogin) },
    body: body({
      car: "Toyota RAV4 Hybrid",
      name: "Email Customer",
      phone: "0783999999",
      d1: "2026-11-12",
      d2: "2026-11-14",
      days: 2,
      total: 180000,
      paid: 0,
      loc: "Kigali",
    }),
  });
  assert.equal(emailBookingRes.status, 201);
  const emailBooking = (await emailBookingRes.json()).booking;
  assert.equal(emailBooking.accountId, emailAccount.id);
  const emailBookings = await request("/api/bookings", {
    headers: { Cookie: cookieFrom(emailLogin) },
  });
  assert.deepEqual(
    (await emailBookings.json()).bookings.map((booking) => booking.ref),
    [emailBooking.ref],
  );
  const phoneBookings = await request("/api/bookings", {
    headers: { Cookie: cookieFrom(loggedIn) },
  });
  assert.deepEqual(
    (await phoneBookings.json()).bookings.map((booking) => booking.ref),
    [createdBooking.ref],
  );

  const adminCookie = cookieFrom(adminLogin);
  const patchBookingRes = await request(
    "/api/admin/bookings/" + createdBooking.ref,
    {
      method: "PATCH",
      headers: { Cookie: adminCookie },
      body: body({ status: "Picked up" }),
    },
  );
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
  const emailCustomer = updatedDashboard.users.find(
    (user) => user.id === emailAccount.id,
  );
  assert.equal(emailCustomer.email, "new.customer@example.com");
  assert.equal(emailCustomer.phone, null);
  assert.equal(updatedDashboard.bookings.length, 2);
  assert.equal(
    updatedDashboard.bookings.find(
      (booking) => booking.ref === createdBooking.ref,
    ).status,
    "Picked up",
  );
  assert.equal(updatedDashboard.cars[0].status, "Rented");
  const stored = await fs.readFile(path.join(dataDir, "store.json"), "utf8");
  assert.equal(stored.includes("Customer123"), false);
  assert.equal((await request("/data/store.json")).status, 404);
  assert.equal(JSON.stringify(records).includes("salt"), false);
  assert.equal(JSON.stringify(records).includes("hash"), false);

  const staticPage = await request("/");
  assert.equal(staticPage.status, 200);
  assert.match(await staticPage.text(), /Kigali Car Rent/);

  const secondPhoneLogin = await request("/api/login", {
    method: "POST",
    body: body({ phone: "0783553434", password: "Customer123" }),
  });
  assert.equal(secondPhoneLogin.status, 200);
  const accountDeletion = await request("/api/me", {
    method: "DELETE",
    headers: { Cookie: customerLoginCookie },
  });
  assert.equal(accountDeletion.status, 200);
  assert.deepEqual(await accountDeletion.json(), { ok: true });
  assert.match(accountDeletion.headers.get("set-cookie"), /Max-Age=0/);
  assert.equal(
    (await (
      await request("/api/me", { headers: { Cookie: customerLoginCookie } })
    ).json()).user,
    null,
  );
  assert.equal(
    (await (
      await request("/api/me", {
        headers: { Cookie: cookieFrom(secondPhoneLogin) },
      })
    ).json()).user,
    null,
  );
  const afterAccountDeletion = await (
    await request("/api/admin/data", { headers: { Cookie: adminCookie } })
  ).json();
  assert.equal(
    afterAccountDeletion.users.some((user) => user.phone === "0783553434"),
    false,
  );
  assert.equal(afterAccountDeletion.bookings.length, 2);

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
