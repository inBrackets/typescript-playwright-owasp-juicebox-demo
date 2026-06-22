import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A05:2021 – Security Misconfiguration
// Verifies that the application does not expose internal error details,
// deprecated interfaces, or admin accounts with known credentials.

test.describe('Security Misconfiguration (OWASP A05:2021)', () => {

  // Cross-Site Imaging — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_stick_cute_cross_domain_kittens_all_over_our_delivery_boxes
  test('Cross-Site Imaging: product images must not be served from untrusted cross-origin sources', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Products');
    const body = await res.json() as { data?: Array<{ image?: string }> };
    const products = body.data ?? [];

    const crossOriginImages = products.filter(p =>
      p.image && p.image.startsWith('http') && !p.image.startsWith('http://localhost:3000')
    );
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      crossOriginImages.length,
      'No product should load images from untrusted cross-origin URLs'
    ).toBe(0);
  });

  // Deprecated Interface — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_use_a_deprecated_b2b_interface_that_was_not_properly_shut_down
  test('Deprecated Interface: legacy B2B API endpoint must be disabled', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/b2b/v2/orders');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Deprecated B2B v2 interface must return 404 or 410 if decommissioned'
    ).not.toBe(200);
  });

  // Error Handling — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html#_provoke_an_error_that_is_neither_very_gracefully_nor_consistently_handled
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

  // Login Support Team
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
