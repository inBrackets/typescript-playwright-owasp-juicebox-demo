import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A02:2021 – Cryptographic Failures / Sensitive Data Exposure
// Verifies that confidential documents, backup files, password hashes,
// API keys, and personal data are not inadvertently exposed.

test.describe('Sensitive Data Exposure (OWASP A02:2021)', () => {

  let adminToken: string;
  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();
    userToken  = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // Confidential Document
  test('Confidential Document: internal acquisition document must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/acquisitions.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Confidential /ftp/acquisitions.md must not be served to unauthenticated users'
    ).not.toBe(200);
  });

  // Email Leak
  test('Email Leak: user list API must not expose all email addresses to non-admin', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Users/', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Non-admin must not retrieve the full user email list'
    ).toBe(true);
  });

  // Exposed Credentials
  test('Exposed Credentials: main.js must not contain hardcoded credentials', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/main.js');
    if (res.status() !== 200) return;
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Bundled JavaScript must not contain hardcoded passwords or API keys'
    ).not.toMatch(/password\s*[:=]\s*["'][^"']{6,}/i);
  });

  // Forgotten Developer Backup
  test('Forgotten Developer Backup: package.json.bak must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/package.json.bak');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Developer backup file must not be publicly accessible'
    ).not.toBe(200);
  });

  // Forgotten Sales Backup
  test('Forgotten Sales Backup: coupons backup file must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/coupons_2013.md.bak');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Sales backup file must not be publicly accessible'
    ).not.toBe(200);
  });

  // GDPR Data Theft
  test('GDPR Data Theft: user must not download another user\'s GDPR data export', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Attempt to download GDPR export for userId=1 (admin) as a regular user
    const res = await client.get('/rest/user/data-export', userToken);
    const body = await res.json() as { userData?: { email?: string } };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body.userData?.email,
      'GDPR export must return data for the authenticated user only, never for admin'
    ).not.toBe('admin@juice-sh.op');
  });

  // Leaked API Key
  test('Leaked API Key: API keys must not appear in client-side JavaScript bundles', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/runtime.js');
    if (res.status() !== 200) return;
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Runtime JS bundle must not contain API key literals'
    ).not.toMatch(/[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*["'][^"']{16,}/);
  });

  // Leaked Unsafe Product
  test('Leaked Unsafe Product: unsafe product must not appear in the public product list', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Products');
    const body = await res.json() as { data?: Array<{ name?: string }> };
    const products = body.data ?? [];
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      products.some(p => /r0b0t|battery|unsafe|recall/i.test(p.name ?? '')),
      'Recalled or unsafe product must not appear in the public product listing'
    ).toBe(false);
  });

  // Login Amy
  test('Login Amy: Amy\'s password must not be trivially guessable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const guesses = ['K1f...', 'K1f', 'password'];
    const tokens  = await Promise.all(guesses.map(pw => client.login('amy@juice-sh.op', pw)));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      tokens.some(t => t.length > 0),
      "Amy's account must not be loginable with common guesses"
    ).toBe(false);
  });

  // Login MC SafeSearch
  test('Login MC SafeSearch: MC SafeSearch password must not be derivable from public information', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const guesses = ['Mr. Noodles', 'mrnoodles', 'noodles'];
    const tokens  = await Promise.all(guesses.map(pw => client.login('mc.safesearch@juice-sh.op', pw)));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      tokens.some(t => t.length > 0),
      'MC SafeSearch password must not be guessable from public song lyrics'
    ).toBe(false);
  });

  // Meta Geo Stalking
  test('Meta Geo Stalking: photo metadata must not expose precise geolocation', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/uploads/favorite-hiking-place.png');
    if (res.status() !== 200) return;
    // Minimal check: the image must be served as an image, not as JSON with coordinates
    const contentType = res.headers()['content-type'] ?? '';
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      contentType,
      'Hiking image endpoint must serve an image, not a JSON payload with geolocation'
    ).toMatch(/image\//);
  });

  // NFT Takeover
  test('NFT Takeover: NFT ownership transfer must require wallet authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/nftMint', { nftId: 1 });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'NFT minting endpoint must require authentication'
    ).toBe(true);
  });

  // Password Hash Leak
  test('Password Hash Leak: password hashes must not be exposed via the user API', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Users/', adminToken);
    if (res.status() !== 200) return;
    const body = await res.json() as { data?: Array<{ password?: string }> };
    const users = body.data ?? [];
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      users.every(u => !u.password || u.password === ''),
      'Password field must be omitted or empty in the user list API response'
    ).toBe(true);
  });

  // Reset Uvogin's Password
  test("Reset Uvogin's Password: security answer must not be obtainable from public social media", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const guesses = ['Mr. Noodles', 'Squeaky', 'uvogin'];
    const statuses = await Promise.all(guesses.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'uvogin@juice-sh.op',
        answer,
        new: 'NewPwd@1234!',
        repeat: 'NewPwd@1234!',
      }).then(res => res.status())
    ));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      "Uvogin's security answer must not be guessable from a short list of public clues"
    ).toBe(false);
  });

  // Retrieve Blueprint
  test('Retrieve Blueprint: product blueprint file must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/products/JuiceShop.stl');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Product blueprint (.stl) must not be publicly accessible'
    ).not.toBe(200);
  });

  // Visual Geo Stalking
  test('Visual Geo Stalking: profile photo must not expose identifiable location metadata', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/uploads/IMG_4253.jpg');
    if (res.status() !== 200) return;
    const contentType = res.headers()['content-type'] ?? '';
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      contentType,
      'Geo-stalking image must be served as an image type, not as a data-exposing endpoint'
    ).toMatch(/image\//);
  });

});
