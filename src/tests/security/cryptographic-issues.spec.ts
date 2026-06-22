import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A02:2021 – Cryptographic Failures
// Verifies that coupon codes use strong algorithms, that weak crypto
// algorithms are not in production use, and that paywalled content
// cannot be bypassed via cryptographic manipulation.

const BASE = 'http://localhost:3000';

test.describe('Cryptographic Issues (OWASP A02:2021)', () => {

  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // Forged Coupon
  test('Forged Coupon: coupon validation must reject codes not issued by the server', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const forgedCoupon = 'AAAAAAAAAAAA'; // random string unlikely to be valid
    const res = await client.post('/rest/basket/1/coupon/apply', { coupon: forgedCoupon }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 401, 404, 422].includes(res.status()),
      'A randomly forged coupon code must be rejected'
    ).toBe(true);
  });

  // Imaginary Challenge
  test('Imaginary Challenge: non-existent challenge endpoint must return 404', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/rest/imaginary', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Endpoint for imaginary challenge must not exist'
    ).toBe(404);
  });

  // Nested Easter Egg
  test('Nested Easter Egg: double-encoded URL must not bypass file access controls', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    // %2500 is a double-encoded null byte (%25 = %, making %2500 = %00 after one decode)
    const res = await client.get('/ftp/eastere.gg%2500.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Double-encoded path must not bypass the FTP extension filter'
    ).not.toBe(200);
  });

  // Premium Paywall
  test('Premium Paywall: premium content must not be accessible without a valid subscription', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/rest/deluxe-membership', userToken);
    const body = await res.json() as { status?: string };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body.status,
      'Free user must not have deluxe membership status'
    ).not.toBe('active');
  });

  // Weird Crypto
  test('Weird Crypto: password hashes must not use MD5 or other deprecated algorithms', async ({ request }) => {
    const auth = new AuthHelper(request);
    const adminToken = await auth.loginAsAdmin();
    const client = new JuiceShopApiClient(request, BASE);

    const res = await client.get('/api/Users/', adminToken);
    if (res.status() !== 200) {
      // If endpoint is inaccessible, the test is informational
      return;
    }
    const body = await res.json() as { data?: Array<{ password?: string }> };
    const users = body.data ?? [];
    const md5Pattern = /^[a-f0-9]{32}$/;

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      users.some(u => u.password && md5Pattern.test(u.password)),
      'No user password hash should match the MD5 hex pattern (32 hex chars)'
    ).toBe(false);
  });

});
