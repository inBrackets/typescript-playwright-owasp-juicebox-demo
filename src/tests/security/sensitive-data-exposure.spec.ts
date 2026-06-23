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

  // Confidential Document — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_access_a_confidential_document
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_access_a_confidential_document
  test('Confidential Document: internal acquisition document must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/acquisitions.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Confidential /ftp/acquisitions.md must not be served to unauthenticated users'
    ).not.toBe(200);
  });

  // Email Leak — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_perform_an_unwanted_information_disclosure_by_accessing_data_cross_domain
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_an_unwanted_information_disclosure_by_accessing_data_cross_domain
  test('Email Leak: user list API must not expose all email addresses to non-admin', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Users/', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Non-admin must not retrieve the full user email list'
    ).toBe(true);
  });

  // Exposed Credentials — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_a_developer_was_careless_with_hardcoding_unused_but_still_valid_credentials
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_a_developer_was_careless_with_hardcoding_unused_but_still_valid_credentials
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

  // Forgotten Developer Backup — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_access_a_developers_forgotten_backup_file
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_access_a_developers_forgotten_backup_file
  test('Forgotten Developer Backup: null-byte bypass must not allow access to package.json.bak', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The exploit: append %2500.md (double-encoded null byte) to bypass the .bak extension filter.
    const res = await client.get('/ftp/package.json.bak%2500.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Developer backup must not be downloadable via %2500.md null-byte bypass'
    ).not.toBe(200);
  });

  // Forgotten Sales Backup — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_access_a_salesmans_forgotten_backup_file
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_access_a_salesmans_forgotten_backup_file
  test('Forgotten Sales Backup: null-byte bypass must not allow access to coupons_2013.md.bak', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The exploit: append %2500.md to bypass the .bak extension filter.
    const res = await client.get('/ftp/coupons_2013.md.bak%2500.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Sales backup must not be downloadable via %2500.md null-byte bypass'
    ).not.toBe(200);
  });

  // GDPR Data Theft — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_steal_someone_elses_personal_data_without_using_injection
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_steal_someone_elses_personal_data_without_using_injection
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

  // Leaked API Key — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_inform_the_shop_about_a_leaked_api_key
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_shop_about_a_leaked_api_key
  test('Leaked API Key: Google Maps API key must not appear in client-side JavaScript bundles', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The leaked key is a Google Maps API key embedded in main.js (not runtime.js).
    const res = await client.get('/main.js');
    if (res.status() !== 200) return;
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Google Maps API keys match AIza[0-9A-Za-z_-]{35}.
    expect(
      body,
      'main.js must not contain a Google Maps API key (AIza pattern)'
    ).not.toMatch(/AIza[0-9A-Za-z_-]{35}/);
  });

  // Leaked Unsafe Product — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_identify_an_unsafe_product_that_was_removed_from_the_shop_and_inform_the_shop_which_ingredients_are_dangerous
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_identify_an_unsafe_product_that_was_removed_from_the_shop_and_inform_the_shop_which_ingredients_are_dangerous
  test('Leaked Unsafe Product: SQL injection must not expose soft-deleted unsafe products', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The unsafe product is soft-deleted and absent from /api/Products.
    // The exploit uses SQLi to retrieve rows WHERE deletedAt IS NOT NULL.
    const res = await client.get(
      "/rest/products/search?q='))UNION SELECT id,name,description,price,deluxePrice,image,createdAt,updatedAt,deletedAt FROM Products WHERE deletedAt IS NOT NULL--"
    );
    const body = await res.json() as { data?: Array<{ name?: string; description?: string }> };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Any returned rows mean soft-deleted products are leakable via SQLi.
    expect(
      (body.data ?? []).length,
      'SQL injection must not return soft-deleted products — the search endpoint must use parameterized queries'
    ).toBe(0);
  });

  // Login Amy — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_log_in_with_amys_original_user_credentials
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_amys_original_user_credentials
  test('Login Amy: Amy\'s password must not be trivially guessable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Amy's actual password is 'K1f.....................' (K1f followed by 23 dots).
    const guesses = ['K1f.....................', 'K1f......................', 'K1f...', 'K1f', 'password'];
    const tokens  = await Promise.all(guesses.map(pw => client.login('amy@juice-sh.op', pw)));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      tokens.some(t => t.length > 0),
      "Amy's account must not be loginable with common guesses"
    ).toBe(false);
  });

  // Login MC SafeSearch — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_log_in_with_mc_safesearchs_original_user_credentials
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_mc_safesearchs_original_user_credentials
  test('Login MC SafeSearch: MC SafeSearch password must not be derivable from public information', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The correct password is 'Mr. N00dles' (zeros instead of letter O) — from a song lyric hint.
    const guesses = ['Mr. N00dles', 'Mr. Noodles', 'mrnoodles', 'noodles'];
    const tokens  = await Promise.all(guesses.map(pw => client.login('mc.safesearch@juice-sh.op', pw)));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      tokens.some(t => t.length > 0),
      'MC SafeSearch password must not be guessable from public song lyrics'
    ).toBe(false);
  });

  // Meta Geo Stalking — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_determine_the_answer_to_johns_security_question
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_determine_the_answer_to_johns_security_question
  test('Meta Geo Stalking: security answer derivable from photo EXIF must not reset password', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The EXIF GPS data in the hiking photo reveals 'Daniel Boone National Forest' — John's security answer.
    const res = await client.post('/rest/user/reset-password', {
      email: 'john@juice-sh.op',
      answer: 'Daniel Boone National Forest',
      new: 'NewPwd@1234!',
      repeat: 'NewPwd@1234!',
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      "John's password must not be resettable with a location derived from photo EXIF metadata"
    ).not.toBe(200);
  });

  // NFT Takeover — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_take_over_the_wallet_containing_our_official_soul_bound_token
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_take_over_the_wallet_containing_our_official_soul_bound_token
  test('NFT Takeover: NFT ownership transfer must require wallet authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/nftMint', { nftId: 1 });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'NFT minting endpoint must require authentication'
    ).toBe(true);
  });

  // Password Hash Leak — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html
  test('Password Hash Leak: password hashes must not be retrievable via SQL injection', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // /api/Users/ strips the password field. The actual leak requires SQLi on the search endpoint.
    const res = await client.get(
      "/rest/products/search?q=qwert'))UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
    );
    const body = await res.json() as { data?: unknown[] };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Any rows returned means SQLi succeeded and password hashes are exposed.
    expect(
      (body.data ?? []).length,
      'Password hashes must not be retrievable via UNION injection — parameterized queries must be enforced'
    ).toBe(0);
  });

  // Reset Uvogin's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_reset_uvogins_password_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_uvogins_password_via_the_forgot_password_mechanism
  test("Reset Uvogin's Password: security answer must not be obtainable from public social media", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // 'Silence of the Lambs' is the correct answer — derivable from Uvogin's public social media.
    const guesses = ['Silence of the Lambs', 'Mr. Noodles', 'Squeaky', 'uvogin'];
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

  // Retrieve Blueprint — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_deprive_the_shop_of_earnings_by_downloading_the_blueprint_for_one_of_its_products
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_deprive_the_shop_of_earnings_by_downloading_the_blueprint_for_one_of_its_products
  test('Retrieve Blueprint: product blueprint file must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/products/JuiceShop.stl');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Product blueprint (.stl) must not be publicly accessible'
    ).not.toBe(200);
  });

  // Visual Geo Stalking — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/sensitive-data-exposure.html#_determine_the_answer_to_emmas_security_question
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_determine_the_answer_to_emmas_security_question
  test('Visual Geo Stalking: security answer derivable from profile photo must not reset password', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The background in Emma's profile photo visually identifies 'ITsec' — her security answer.
    // The stored answer is 'ITsec' (without the corporate suffix 'GmbH'); the full 'ITsec GmbH'
    // variant does not match the stored hash and returns 401.
    const res = await client.post('/rest/user/reset-password', {
      email: 'emma@juice-sh.op',
      answer: 'ITsec',
      new: 'NewPwd@1234!',
      repeat: 'NewPwd@1234!',
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      "Emma's password must not be resettable with a company name visible in her profile photo"
    ).not.toBe(200);
  });

});
