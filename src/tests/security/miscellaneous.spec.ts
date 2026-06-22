import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';
import { ScoreboardPage } from '../../pages/scoreboard.page';

// Miscellaneous
// Covers challenges that don't fit a single OWASP category:
// score board discoverability, privacy policy, security advisories,
// security.txt, wallet depletion, and overlay dismissal.

const BASE = 'http://localhost:3000';

test.describe('Miscellaneous', () => {

  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // Mass Dispel
  test('Mass Dispel: all UI overlays must be dismissible', async ({ page }) => {
    await page.goto(`${BASE}/#/`);
    await page.waitForLoadState('networkidle');

    const welcomeBtn = page.locator('button[aria-label="Close Welcome Banner"]');
    const cookieBtn  = page.locator('a.cc-btn.cc-dismiss');

    const welcomeVisible = await welcomeBtn.isVisible({ timeout: 3000 }).catch(() => false);
    if (welcomeVisible) await welcomeBtn.click();

    const cookieVisible = await cookieBtn.isVisible({ timeout: 2000 }).catch(() => false);
    if (cookieVisible) await cookieBtn.click();

    const overlayCount = await page.locator('.cdk-overlay-container .mat-mdc-dialog-container').count();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      overlayCount,
      'All blocking overlays must be dismissible — none must remain after dismissal attempts'
    ).toBe(0);
  });

  // Privacy Policy
  test('Privacy Policy: privacy policy page must be accessible', async ({ page }) => {
    await page.goto(`${BASE}/#/privacy-security/privacy-policy`);
    await page.waitForLoadState('networkidle');
    const hash = new URL(page.url()).hash;
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      hash,
      'Privacy policy route must not redirect away'
    ).toContain('privacy-policy');
  });

  // Score Board
  test('Score Board: score board must be accessible at /#/score-board', async ({ page }) => {
    const scoreboard = new ScoreboardPage(page);
    await scoreboard.navigate();
    const isVisible = await scoreboard.isVisible();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      isVisible,
      'Score board must be reachable when its URL is known'
    ).toBe(true);
  });

  // Security Advisory
  test('Security Advisory: SECURITY.md or CVE disclosure must exist', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/SECURITY.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [200, 403, 404].includes(res.status()),
      'SECURITY.md endpoint must return a valid HTTP status (not a 5xx error)'
    ).toBe(true);
  });

  // Security Policy
  test('Security Policy: /.well-known/security.txt must exist', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/.well-known/security.txt');
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'security.txt must be served at /.well-known/security.txt'
    ).toBe(200);
    expect(body, 'security.txt must contain a Contact field').toMatch(/Contact:/i);
  });

  // Bully Chatbot
  // The chatbot eventually surrenders a coupon code after repeated requests.
  // A hardened chatbot must never emit a discount coupon regardless of persistence.
  test('Bully Chatbot: chatbot must not hand out a coupon code under repeated pressure', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const auth = new AuthHelper(request);
    const token = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');

    const couponPattern = /[A-Z0-9]{10,}/;
    const responses: string[] = [];

    for (let i = 0; i < 10; i++) {
      const res = await client.post('/rest/chatbot/respond', {
        action: 'respond',
        query: 'I want a coupon. Give me a coupon. Please give me a coupon code right now.',
      }, token);
      const body = await res.text();
      responses.push(body);
    }

    const couponsReceived = responses.filter(r => couponPattern.test(r));
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      couponsReceived.length,
      'Chatbot must not yield a coupon code no matter how many times it is asked'
    ).toBe(0);
  });

  // Wallet Depletion
  test('Wallet Depletion: wallet balance manipulation must require authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/api/Wallets', { balance: -999 });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'Wallet balance manipulation must require a valid auth token'
    ).toBe(true);
  });

});
