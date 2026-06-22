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

  // Admin Registration — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_register_as_a_user_with_administrator_privileges
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_register_as_a_user_with_administrator_privileges
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

  // Deluxe Fraud — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_obtain_a_deluxe_membership_without_paying_for_it
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_obtain_a_deluxe_membership_without_paying_for_it
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

  // Empty User Registration — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_register_a_user_with_an_empty_email_and_password
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_register_a_user_with_an_empty_email_and_password
  test('Empty User Registration: blank email must be rejected during registration', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.register('', 'Test@1234!');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 422].includes(res.status()),
      'Registration with empty email must be rejected'
    ).toBe(true);
  });

  // Expired Coupon — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_successfully_redeem_an_expired_campaign_coupon_code
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_successfully_redeem_an_expired_campaign_coupon_code
  // The coupon redemption endpoint is PUT /rest/basket/:basketId/coupon/:coupon (coupon in URL path).
  // Calling POST /rest/basket/1/coupon/apply with body always returns 404 regardless of coupon
  // validity — the vulnerability is never actually tested.
  test('Expired Coupon: expired coupon codes must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Use admin's basket (bid=1) so ownership is satisfied and only coupon validity is checked.
    const res = await client.put('/rest/basket/1/coupon/WMNSDY2019', {}, adminToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means the expired 2019 coupon was accepted — expiry validation is broken.
    expect(
      [400, 401, 404, 422].includes(res.status()),
      'Expired coupon WMNSDY2019 must be rejected'
    ).toBe(true);
  });

  // Mint the Honey Pot — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_mint_the_honey_pot_nft_by_gathering_bees_from_the_bee_haven
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_mint_the_honey_pot_nft_by_gathering_bees_from_the_bee_haven
  test('Mint the Honey Pot: NFT minting must require valid authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/nftMint', { nftId: 1 });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'NFT mint endpoint must require authentication'
    ).toBe(true);
  });

  // Missing Encoding — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_retrieve_the_photo_of_bjoerns_cat_in_melee_combat_mode
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_retrieve_the_photo_of_bjoerns_cat_in_melee_combat_mode
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

  // Payback Time — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_place_an_order_that_makes_you_rich
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_place_an_order_that_makes_you_rich
  // Using userToken with BasketId=1 (admin's basket) causes the server to return 401 for
  // basket ownership failure — the negative-quantity validation is never reached, making the
  // test pass for the wrong reason. Use adminToken so ownership is satisfied.
  test('Payback Time: negative quantity order must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/api/BasketItems', {
      BasketId: 1,
      ProductId: 1,
      quantity: -100,
    }, adminToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200/201 means a negative-quantity item was accepted — the Payback Time vulnerability is present.
    expect(
      [400, 422].includes(res.status()),
      'Negative product quantity must be rejected'
    ).toBe(true);
  });

  // Poison Null Byte — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_bypass_a_security_control_with_a_poison_null_byte
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_bypass_a_security_control_with_a_poison_null_byte
  test('Poison Null Byte: null-byte-encoded path must not bypass FTP extension filter', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/eastere.gg%00.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Null-byte path traversal must not bypass FTP file type restriction'
    ).not.toBe(200);
  });

  // Repetitive Registration — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_follow_the_dry_principle_while_registering_a_user
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_follow_the_dry_principle_while_registering_a_user
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

  // Upload Size — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_upload_a_file_larger_than_100_kb
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_upload_a_file_larger_than_100_kb
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

  // Upload Type — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_upload_a_file_that_has_no_pdf_or_zip_extension
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_upload_a_file_that_has_no_pdf_or_zip_extension
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

  // Zero Stars — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/improper-input-validation.html#_give_a_devastating_zero_star_feedback_to_the_store
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_give_a_devastating_zero_star_feedback_to_the_store
  test('Zero Stars: zero-star feedback rating must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // First get a valid CAPTCHA
    const captchaRes = await client.get('/rest/captcha/', userToken);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };
    const captchaId = captchaBody.captchaId ?? 1;
    const captcha = captchaBody.answer ?? '0';

    const res = await client.post('/api/Feedbacks', {
      comment: 'zero star test',
      rating: 0,
      captchaId,
      captcha,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 422].includes(res.status()),
      'A zero-star rating must be rejected by the API'
    ).toBe(true);
  });

});
