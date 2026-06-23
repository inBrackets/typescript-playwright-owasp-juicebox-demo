import { test, expect } from '@playwright/test';

// OWASP A01:2021 – Broken Access Control (Open Redirect)
// Verifies that the redirect endpoint enforces a strict allowlist and
// does not forward users to arbitrary external URLs.

const BASE = 'http://localhost:3000';

test.describe('Unvalidated Redirects (OWASP A01:2021)', () => {

  // Allowlist Bypass — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html#_enforce_a_redirect_to_a_page_you_are_not_supposed_to_redirect_to
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_enforce_a_redirect_to_a_page_you_are_not_supposed_to_redirect_to
  test('Allowlist Bypass: redirect endpoint must not be bypassable by embedding an allowlisted URL', async ({ page }) => {
    // The vulnerability: the allowlist check uses String.includes() rather than exact matching,
    // so appending an allowlisted URL in the fragment bypasses the check.
    // to=https://evil.com#https://github.com/bkimminich/juice-shop passes the allowlist
    // but the browser navigates to evil.com (fragment is ignored for routing).
    const bypassUrl = encodeURIComponent(
      'https://evil.com#https://github.com/bkimminich/juice-shop'
    );
    await page.goto(`${BASE}/redirect?to=${bypassUrl}`);
    await page.waitForLoadState('networkidle');
    const currentUrl = page.url();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      currentUrl,
      'Allowlist bypass via URL fragment must not redirect to evil.com'
    ).not.toContain('evil.com');
  });

  // Outdated Allowlist — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html#_let_us_redirect_you_to_one_of_our_crypto_currency_addresses
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_let_us_redirect_you_to_one_of_our_crypto_currency_addresses
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
