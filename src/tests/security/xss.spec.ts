import { test, expect, type Page } from '@playwright/test';
import { MainPage } from '../../pages/main.page';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A03:2021 – Cross-Site Scripting (XSS)
// Covers nine distinct XSS vectors across DOM, reflected, stored,
// server-side, HTTP header, CSP bypass, and API-only injection.
// A passing test means the payload was sanitised or blocked;
// a failing test means the XSS is exploitable.

const BASE = 'http://localhost:3000';

function attachDialogDetector(page: Page): () => boolean {
  let fired = false;
  page.on('dialog', async (d) => { fired = true; await d.dismiss(); });
  return () => fired;
}

test.describe('XSS – Cross-Site Scripting (OWASP A03:2021)', () => {

  // API-only XSS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_without_using_the_frontend_application_at_all
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_persisted_xss_attack_without_using_the_frontend_application_at_all
  test('API-only XSS: stored XSS via product description API must not execute in browser', async ({ request, page }) => {
    const auth = new AuthHelper(request);
    const adminToken = await auth.loginAsAdmin();
    const client = new JuiceShopApiClient(request);
    const xss = `<iframe src="javascript:alert('xss-api')">`;

    await client.put('/api/Products/1', { description: xss }, adminToken);

    const xssExecuted = attachDialogDetector(page);
    // Product descriptions render on the search results page, not the home page.
    await page.goto(`${BASE}/#/search`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS payload stored via the product API must not execute when the page is rendered'
    ).toBe(false);

    // Restore original description
    await client.put('/api/Products/1', { description: 'Apple Juice' }, adminToken);
  });

  // Bonus Payload — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_use_the_bonus_payload_in_the_dom_xss_challenge
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_use_the_bonus_payload_in_the_dom_xss_challenge
  test('Bonus Payload: Juice Shop bonus XSS payload must not execute via search', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    await main.navbar.search(`<iframe src="javascript:alert(\`xss\`)">`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'Bonus XSS payload must not execute via the search bar'
    ).toBe(false);
  });

  // CSP Bypass — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_bypass_the_content_security_policy_and_perform_an_xss_attack_on_a_legacy_page
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_bypass_the_content_security_policy_and_perform_an_xss_attack_on_a_legacy_page
  test('CSP Bypass: Content-Security-Policy header must be present and restrictive', async ({ page }) => {
    const response = await page.goto(`${BASE}/`);
    const csp = response?.headers()['content-security-policy'] ?? '';
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      csp.length,
      'A Content-Security-Policy header must be present on the main page'
    ).toBeGreaterThan(0);
    expect(
      csp,
      'CSP must not use unsafe-inline without nonces or hashes'
    ).not.toMatch(/script-src[^;]*'unsafe-inline'(?![^;]*nonce|[^;]*sha)/);
  });

  // Client-side XSS Protection — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_bypassing_a_client_side_security_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_persisted_xss_attack_bypassing_a_client_side_security_mechanism
  test('Client-side XSS Protection: search results must encode reflected HTML', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    // <script> tags injected via innerHTML don't execute — use an event handler payload instead.
    await main.navbar.search(`<img src="x" onerror="alert('xss-client')">`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'Client-side XSS payload must not execute').toBe(false);
    expect(dom, 'onerror XSS payload must not appear unencoded in rendered DOM')
      .not.toContain(`<img src="x" onerror="alert('xss-client')">`);
  });

  // DOM XSS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_dom_xss_attack
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_dom_xss_attack
  test('DOM XSS: angular-sanitize must prevent DOM injection via search', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    await main.navbar.search(`<iframe src="javascript:alert('xss-dom')">`);
    await page.waitForLoadState('networkidle');

    await page.waitForTimeout(3000);
    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'DOM XSS iframe payload must not execute').toBe(false);
    expect(dom, 'iframe XSS payload must not appear unescaped in DOM')
      .not.toContain(`<iframe src="javascript:alert('xss-dom')">`);
  });

  // HTTP-Header XSS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_through_an_http_header
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_persisted_xss_attack_through_an_http_header
  // The X-Forwarded-For header on login is stored as the "last login IP" and later
  // rendered on the account profile page — a stored XSS via HTTP header.
  test('HTTP-Header XSS: XSS stored via X-Forwarded-For login IP must not execute on profile page', async ({ request, page }) => {
    const auth = new AuthHelper(request);
    const email = AuthHelper.uniqueEmail();
    const userToken = await auth.registerAndLogin(email, 'Test@1234!');

    const xssPayload = `<iframe src="javascript:alert('xss-header')">`;

    // Second login with XSS payload in X-Forwarded-For — stores the payload as the last-login IP.
    await request.post(`${BASE}/rest/user/login`, {
      data: { email, password: 'Test@1234!' },
      headers: { 'X-Forwarded-For': xssPayload },
    });

    const xssExecuted = attachDialogDetector(page);
    // Inject the auth token so Angular renders the profile page (not the login redirect).
    await page.addInitScript((tok: string) => { window.localStorage.setItem('token', tok); }, userToken);
    await page.goto(`${BASE}/#/profile`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS payload stored as last-login IP must not execute when the profile page is rendered'
    ).toBe(false);
  });

  // Reflected XSS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_reflected_xss_attack
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_reflected_xss_attack
  // The challenge description specifies <iframe src="javascript:alert(`xss`)"> as the payload.
  // <script> tags injected via innerHTML are inert (browsers never execute dynamically-injected scripts),
  // so the prior <script> payload always passed — masking that <iframe javascript:> DOES execute via
  // the search query parameter, which Angular renders with bypassSecurityTrustHtml.
  test('Reflected XSS: iframe javascript: payload in URL search parameter must not execute', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    // Navigate directly to the search page with the XSS payload in the URL query parameter.
    // Angular renders the search term via bypassSecurityTrustHtml — the iframe src executes on vulnerable Juice Shop.
    await page.goto(`${BASE}/#/search?q=<iframe src="javascript:alert('xss-reflected')">`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // xssExecuted() fires if the javascript: iframe src was evaluated in the browser.
    expect(xssExecuted(), 'Reflected XSS iframe payload must not execute').toBe(false);
    expect(dom, 'Reflected XSS iframe payload must not appear unescaped in rendered DOM')
      .not.toContain(`<iframe src="javascript:alert('xss-reflected')">`);
  });

  // Server-side XSS Protection — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_bypassing_a_server_side_security_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_persisted_xss_attack_bypassing_a_server_side_security_mechanism
  // The Customer Feedback "Comment" field is the real attack surface — stored XSS
  // injected here renders when the admin views feedback in the admin panel.
  test('Server-side XSS Protection: XSS in feedback comment must not execute when rendered', async ({ request, page }) => {
    const auth = new AuthHelper(request);
    const token = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
    const client = new JuiceShopApiClient(request);

    const xssPayload = `<iframe src="javascript:alert('xss-ssr')">`;

    const captchaRes = await client.get('/rest/captcha/', token);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };

    await client.post('/api/Feedbacks', {
      comment: xssPayload,
      rating: 3,
      captchaId: captchaBody.captchaId,
      captcha: captchaBody.answer,
    }, token);

    // Admin panel renders all feedback — visiting it triggers the stored payload
    const adminToken = await auth.loginAsAdmin();
    const xssExecuted = attachDialogDetector(page);
    // addInitScript runs before Angular boots so the token is present on first load
    await page.addInitScript((tok: string) => { window.localStorage.setItem('token', tok); }, adminToken);
    await page.goto(`${BASE}/#/administration`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS stored in feedback comment must not execute when admin panel renders it'
    ).toBe(false);
  });

  // Video XSS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_embed_an_xss_payload_into_our_promo_video
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_embed_an_xss_payload_into_our_promo_video
  test('Video XSS: video subtitle parameter must not inject script into page', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    await page.goto(`${BASE}/#/about`);
    await page.waitForLoadState('networkidle');

    // The video page reflects the 'lang' query parameter into a <track> src attribute unsanitised.
    // iframe javascript: is the correct payload for attribute-context injection.
    await page.goto(`${BASE}/#/about?lang=<iframe src="javascript:alert('xss-video')">`);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'Video subtitle XSS must not execute').toBe(false);
    expect(dom, 'XSS via video lang parameter must not appear unescaped in DOM')
      .not.toContain(`<iframe src="javascript:alert('xss-video')">`);
  });

});
