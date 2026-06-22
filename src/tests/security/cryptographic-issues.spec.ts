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

  // Forged Coupon — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_forge_a_coupon_code_that_gives_you_a_discount_of_at_least_80
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_forge_a_coupon_code_that_gives_you_a_discount_of_at_least_80
  // The coupon redemption endpoint is PUT /rest/basket/:basketId/coupon/:coupon (coupon in URL path).
  // Calling POST /rest/basket/1/coupon/apply with body always returns 404 regardless of coupon
  // validity — the vulnerability is never actually tested.
  test('Forged Coupon: coupon validation must reject codes not issued by the server', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // n<5U!< is a z85-encoded forged coupon granting 80%+ discount that was never officially issued.
    // The coupon redemption endpoint is GET /rest/basket/:id/coupon/:coupon (not PUT).
    const forgedCoupon = 'n<5U!<';
    const res = await client.get(`/rest/basket/1/coupon/${forgedCoupon}`, adminToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means a forged coupon was accepted — cryptographic validation is broken.
    expect(
      [400, 401, 404, 422].includes(res.status()),
      'A forged z85-encoded coupon must be rejected — cryptographic coupon validation is broken'
    ).toBe(true);
  });

  // Imaginary Challenge — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_solve_challenge_999
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_solve_challenge_999
  test('Imaginary Challenge: non-existent challenge endpoint must return 404', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/imaginary', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Endpoint for imaginary challenge must not exist'
    ).toBe(404);
  });

  // Nested Easter Egg — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_apply_some_advanced_cryptanalysis_to_find_the_real_easter_egg
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_apply_some_advanced_cryptanalysis_to_find_the_real_easter_egg
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

  // Premium Paywall — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_unlock_premium_challenge_to_access_exclusive_content
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_unlock_premium_challenge_to_access_exclusive_content
  test('Premium Paywall: deluxe membership must not be obtainable without valid payment', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The bypass: submit an empty paymentMode — vulnerable server grants membership without charging.
    const res = await client.post('/rest/deluxe-membership', { paymentMode: '' }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A 200 response means deluxe membership was granted with no valid payment.
    expect(
      res.status(),
      'Deluxe membership must not be grantable with an empty or invalid payment mode'
    ).not.toBe(200);
  });

  // Weird Crypto — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/cryptographic-issues.html#_inform_the_shop_about_an_algorithm_or_library_it_should_definitely_not_use_the_way_it_does
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_shop_about_an_algorithm_or_library_it_should_definitely_not_use_the_way_it_does
  test('Weird Crypto: password hashes must not use MD5 or other deprecated algorithms', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // /api/Users/ strips the password field for privacy. Use SQLi to retrieve hashes directly.
    const res = await client.get(
      "/rest/products/search?q=qwert'))UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
    );
    const body = await res.json() as { data?: Array<{ description?: string }> };
    const rows = body.data ?? [];
    const md5Pattern = /^[a-f0-9]{32}$/;

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // The SQLi itself succeeding is already a vulnerability; additionally, MD5 hashes expose the algorithm.
    expect(
      rows.some(r => r.description && md5Pattern.test(r.description)),
      'Password hashes returned via SQLi must not be MD5 (32 hex chars) — a stronger algorithm must be used'
    ).toBe(false);
  });

});
