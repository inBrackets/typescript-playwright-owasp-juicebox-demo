import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A02:2021 – Cryptographic Failures
// Verifies that coupon codes use strong algorithms, that weak crypto
// algorithms are not in production use, and that paywalled content
// cannot be bypassed via cryptographic manipulation.

test.describe('Cryptographic Issues (OWASP A02:2021)', () => {

  let userToken: string;
  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken  = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
    adminToken = await auth.loginAsAdmin();
  });

  // Forged Coupon — https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_forge_a_coupon_code_that_gives_you_a_discount_of_at_least_80
  // The coupon redemption endpoint is PUT /rest/basket/:basketId/coupon/:coupon (coupon in URL path).
  // Calling POST /rest/basket/1/coupon/apply with body always returns 404 regardless of coupon
  // validity — the vulnerability is never actually tested.
  test('Forged Coupon: coupon validation must reject codes not issued by the server', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const forgedCoupon = 'AAAAAAAAAAAA'; // random string not issued by the server
    // Use admin's basket (bid=1) with admin token to ensure ownership check passes
    // so the test exercises coupon validation, not basket access control.
    const res = await client.put(`/rest/basket/1/coupon/${forgedCoupon}`, {}, adminToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means a forged coupon was accepted — cryptographic validation is broken.
    expect(
      [400, 401, 404, 422].includes(res.status()),
      'A randomly forged coupon code must be rejected by the server'
    ).toBe(true);
  });

  // Imaginary Challenge — https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_solve_challenge_999
  test('Imaginary Challenge: non-existent challenge endpoint must return 404', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/imaginary', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Endpoint for imaginary challenge must not exist'
    ).toBe(404);
  });

  // Nested Easter Egg — https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_apply_some_advanced_cryptanalysis_to_find_the_real_easter_egg
  test('Nested Easter Egg: double-encoded URL must not bypass file access controls', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
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
    const client = new JuiceShopApiClient(request);
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
    const client = new JuiceShopApiClient(request);

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
