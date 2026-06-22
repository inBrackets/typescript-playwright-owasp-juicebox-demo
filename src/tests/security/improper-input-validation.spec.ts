import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A03:2021 – Injection / Input Validation
// Verifies that all user-supplied inputs are validated server-side:
// role escalation, quantity limits, file upload restrictions, coupon
// expiry, and rating boundaries.

const BASE = 'http://localhost:3000';

test.describe('Improper Input Validation (OWASP A03:2021)', () => {

  let userToken: string;
  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // Admin Registration
  test('Admin Registration: role field in registration payload must be ignored', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const email = AuthHelper.uniqueEmail();
    const res = await client.register(email, 'Test@1234!', { role: 'admin' });
    const body = await res.json() as { data?: { role?: string } };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body.data?.role,
      'Self-assigned role "admin" must be ignored during registration'
    ).not.toBe('admin');
  });

  // Deluxe Fraud
  test('Deluxe Fraud: deluxe membership must not be obtainable without payment', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/deluxe-membership', {
      paymentMode: 'credit card',
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Deluxe membership must require a valid payment, not just a POST request'
    ).not.toBe(200);
  });

  // Empty User Registration
  test('Empty User Registration: blank email must be rejected during registration', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.register('', 'Test@1234!');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 422].includes(res.status()),
      'Registration with empty email must be rejected'
    ).toBe(true);
  });

  // Expired Coupon
  test('Expired Coupon: expired coupon codes must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // This is a known expired coupon from Juice Shop
    const res = await client.post('/rest/basket/1/coupon/apply', { coupon: 'WMNSDY2019' }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 401, 404, 422].includes(res.status()),
      'Expired coupon must be rejected'
    ).toBe(true);
  });

  // Mint the Honey Pot
  test('Mint the Honey Pot: NFT minting must require valid authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/nftMint', { nftId: 1 });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'NFT mint endpoint must require authentication'
    ).toBe(true);
  });

  // Missing Encoding
  test('Missing Encoding: URL with unencoded emoji must not crash the application', async ({ page }) => {
    await page.goto(`${BASE}/#/search?q=😼`);
    await page.waitForLoadState('networkidle');
    const title = await page.title();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      title,
      'Application must handle emoji in search without crashing or showing an error page'
    ).toContain('OWASP Juice Shop');
  });

  // Payback Time
  test('Payback Time: negative quantity order must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/api/BasketItems', {
      BasketId: 1,
      ProductId: 1,
      quantity: -100,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 422].includes(res.status()),
      'Negative product quantity must be rejected'
    ).toBe(true);
  });

  // Poison Null Byte
  test('Poison Null Byte: null-byte-encoded path must not bypass FTP extension filter', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/eastere.gg%00.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Null-byte path traversal must not bypass FTP file type restriction'
    ).not.toBe(200);
  });

  // Repetitive Registration
  test('Repetitive Registration: duplicate email registration must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const email = AuthHelper.uniqueEmail();
    await client.register(email, 'Test@1234!');
    const secondRes = await client.register(email, 'Test@1234!');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 409, 422].includes(secondRes.status()),
      'Registering the same email twice must be rejected'
    ).toBe(true);
  });

  // Upload Size
  test('Upload Size: oversized file upload must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Create an in-memory 110 kB buffer (exceeds typical 100 kB limit)
    const bigContent = Buffer.alloc(110 * 1024, 'A');

    const res = await request.post(`${BASE}/file-upload`, {
      headers: { Authorization: `Bearer ${userToken}` },
      multipart: { file: { name: 'oversized.pdf', mimeType: 'application/pdf', buffer: bigContent } },
    });

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 413, 422, 500].includes(res.status()),
      'Upload exceeding the size limit must be rejected'
    ).toBe(true);
  });

  // Upload Type
  test('Upload Type: executable file upload must be rejected', async ({ request }) => {
    const exeContent = Buffer.from('MZ'); // PE header magic bytes
    const res = await request.post(`${BASE}/file-upload`, {
      headers: { Authorization: `Bearer ${userToken}` },
      multipart: { file: { name: 'malware.exe', mimeType: 'application/octet-stream', buffer: exeContent } },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 415, 422, 500].includes(res.status()),
      'Executable file upload must be rejected'
    ).toBe(true);
  });

  // Zero Stars
  test('Zero Stars: zero-star feedback rating must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // First get a valid CAPTCHA
    const captchaRes = await client.get('/api/Captchas', userToken);
    const captchaBody = await captchaRes.json() as { data?: { answer: number; id: number } };
    const captchaId = captchaBody.data?.id ?? 1;
    const answer = captchaBody.data?.answer ?? 0;

    const res = await client.post('/api/Feedbacks', {
      comment: 'zero star test',
      rating: 0,
      captchaId,
      captcha: answer,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 422].includes(res.status()),
      'A zero-star rating must be rejected by the API'
    ).toBe(true);
  });

});
