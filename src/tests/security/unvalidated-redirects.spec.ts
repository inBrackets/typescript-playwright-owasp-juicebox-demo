import { test, expect } from '@playwright/test';

// OWASP A01:2021 – Broken Access Control (Open Redirect)
// Verifies that the redirect endpoint enforces a strict allowlist and
// does not forward users to arbitrary external URLs.

const BASE = 'http://localhost:3000';

test.describe('Unvalidated Redirects (OWASP A01:2021)', () => {

  // Allowlist Bypass
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

  // Outdated Allowlist
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
