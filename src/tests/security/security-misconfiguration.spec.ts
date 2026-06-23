import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A05:2021 – Security Misconfiguration
// Verifies that the application does not expose internal error details,
// deprecated interfaces, or admin accounts with known credentials.

test.describe('Security Misconfiguration (OWASP A05:2021)', () => {

  let adminToken: string;
  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    [adminToken, userToken] = await Promise.all([
      auth.loginAsAdmin(),
      auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!'),
    ]);
  });

  // Cross-Site Imaging — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_stick_cute_cross_domain_kittens_all_over_our_delivery_boxes
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_stick_cute_cross_domain_kittens_all_over_our_delivery_boxes
  test('Cross-Site Imaging: product image update must not accept untrusted cross-origin URLs', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Save original image to restore it after the test.
    const originalRes = await client.get('/api/Products/1');
    const originalBody = await originalRes.json() as { data?: { image?: string } };
    const originalImage = originalBody.data?.image ?? '';

    // The exploit: update a product image to a cross-origin URL — server must reject it.
    const res = await client.put('/api/Products/1', { image: 'https://placekitten.com/400/400' }, adminToken);

    // Restore regardless of outcome.
    await client.put('/api/Products/1', { image: originalImage }, adminToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A 200 means a cross-origin URL was accepted — SSRF / cross-site imaging vulnerability is present.
    expect(
      res.status(),
      'Product image must not accept a cross-origin URL — server-side URL validation is missing'
    ).not.toBe(200);
  });

  // Deprecated Interface — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_use_a_deprecated_b2b_interface_that_was_not_properly_shut_down
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_use_a_deprecated_b2b_interface_that_was_not_properly_shut_down
  test('Deprecated Interface: legacy B2B API endpoint must be disabled even for authenticated users', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Without auth the endpoint returns 401 which doesn't test decommissioning — use userToken.
    const res = await client.get('/b2b/v2/orders', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A 200 means the deprecated interface is still active and accepting requests.
    expect(
      [404, 410].includes(res.status()),
      'Deprecated B2B v2 interface must return 404 or 410 — a 200 means it is still active'
    ).toBe(true);
  });

  // Error Handling — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_provoke_an_error_that_is_neither_very_gracefully_nor_consistently_handled
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_provoke_an_error_that_is_neither_very_gracefully_nor_consistently_handled
  test('Error Handling: invalid routes must not expose stack traces', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/this-does-not-exist-at-all');
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Error responses must not contain stack traces or internal file paths'
    ).not.toMatch(/at\s+\w+\s+\(.*\.js:\d+:\d+\)|Error:\s+Cannot/);
  });

  // Login Support Team — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_log_in_with_the_support_teams_original_user_credentials
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_the_support_teams_original_user_credentials
  test('Login Support Team: support team account must not use easily guessable credentials', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const weakPasswords = ['support', 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'];
    const tokens: string[] = [];

    for (const pw of weakPasswords) {
      const token = await client.login('support@juice-sh.op', pw);
      tokens.push(token);
    }
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      tokens.some(t => t.length > 0),
      'Support team account must not accept any of the guessed passwords'
    ).toBe(false);
  });

});
