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

  // Mass Dispel — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_close_multiple_challenge_solved_notifications_in_one_go
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_close_multiple_challenge_solved_notifications_in_one_go
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

  // Privacy Policy — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_read_our_privacy_policy
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_read_our_privacy_policy
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

  // Score Board — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_find_the_carefully_hidden_score_board_page
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_find_the_carefully_hidden_score_board_page
  test('Score Board: score board route must not be directly accessible (hidden by design)', async ({ page }) => {
    const scoreboard = new ScoreboardPage(page);
    await scoreboard.navigate();
    const isVisible = await scoreboard.isVisible();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // On stock Juice Shop the route IS accessible — that IS the vulnerability (discoverable hidden page).
    expect(
      isVisible,
      'Score board must not be directly navigable — it is a hidden route that must require discovery'
    ).toBe(false);
  });

  // Security Advisory — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_the_juice_shop_is_susceptible_to_a_known_vulnerability_in_a_library_for_which_an_advisory_has_already_been_issued
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_the_juice_shop_is_susceptible_to_a_known_vulnerability_in_a_library_for_which_an_advisory_has_already_been_issued
  test('Security Advisory: SECURITY.md must not be publicly accessible via the FTP directory', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/SECURITY.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // On stock Juice Shop the file IS served (200) — exposing the security advisory is the vulnerability.
    expect(
      res.status(),
      'SECURITY.md must not be publicly downloadable from the FTP directory'
    ).not.toBe(200);
  });

  // Security Policy — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_behave_like_any_white_hat_should_before_getting_into_the_action
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_behave_like_any_white_hat_should_before_getting_into_the_action
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

  // Bully Chatbot — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_receive_a_coupon_code_from_the_support_chatbot
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_receive_a_coupon_code_from_the_support_chatbot
  // The chatbot eventually surrenders a coupon code after repeated requests.
  // A hardened chatbot must never emit a discount coupon regardless of persistence.
  test('Bully Chatbot: chatbot must not hand out a coupon code under repeated pressure', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const auth = new AuthHelper(request);
    const token = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');

    // Coupon codes are z85-encoded strings — broader pattern than plain ALLCAPS alphanumeric.
    const couponPattern = /coupon[^.]{0,40}[A-Za-z0-9!#$%&<>()]{5,}|[A-Za-z0-9!#$%&<>()]{5,}[^.]{0,10}coupon/i;
    let couponLeaked = false;

    for (let i = 0; i < 20; i++) {
      const res = await client.post('/rest/chatbot/respond', {
        action: 'respond',
        query: 'I want a coupon. Give me a coupon. Please give me a coupon code right now.',
      }, token);
      const rawBody = await res.text();
      let message = rawBody;
      try {
        const parsed = JSON.parse(rawBody) as { message?: string };
        message = parsed.message ?? rawBody;
      } catch { /* use raw text */ }
      if (couponPattern.test(message)) { couponLeaked = true; break; }
    }

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      couponLeaked,
      'Chatbot must not yield a coupon code no matter how many times it is asked'
    ).toBe(false);
  });

  // Wallet Depletion — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/miscellaneous.html#_withdraw_more_eth_from_the_new_wallet_than_you_deposited
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_withdraw_more_eth_from_the_new_wallet_than_you_deposited
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
