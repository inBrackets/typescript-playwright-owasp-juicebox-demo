import { test, expect } from '@playwright/test';

// OWASP A01:2021 – Broken Access Control (Open Redirect)
// Verifies that the redirect endpoint enforces a strict allowlist and
// does not forward users to arbitrary external URLs.

const BASE = 'http://localhost:3000';

test.describe('Unvalidated Redirects (OWASP A01:2021)', () => {

  // Allowlist Bypass — https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html#_enforce_a_redirect_to_a_page_you_are_not_supposed_to_redirect_to
  test('Allowlist Bypass: redirect endpoint must not forward to non-allowlisted domains', async ({ page }) => {
    await page.goto(`${BASE}/redirect?to=https://evil.com`);
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      currentUrl,
      'Redirect endpoint must not forward to arbitrary external domains'
    ).not.toContain('evil.com');
  });

  // Outdated Allowlist — https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html#_let_us_redirect_you_to_one_of_our_crypto_currency_addresses
  test('Outdated Allowlist: deprecated allowlisted domain must no longer be a valid redirect target', async ({ page }) => {
    // Juice Shop previously allowlisted github.com for redirect; it should now reject all external domains
    await page.goto(`${BASE}/redirect?to=https://github.com/bkimminich/juice-shop`);
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      currentUrl,
      'Outdated allowlisted redirect target must not bypass the current redirect policy'
    ).not.toContain('github.com');
  });

});
