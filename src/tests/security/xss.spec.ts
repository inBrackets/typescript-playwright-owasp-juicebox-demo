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

  // API-only XSS — https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_without_using_the_frontend_application_at_all
  test('API-only XSS: stored XSS via product description API must not execute in browser', async ({ request, page }) => {
    const auth = new AuthHelper(request);
    const adminToken = await auth.loginAsAdmin();
    const client = new JuiceShopApiClient(request);
    const xss = `<iframe src="javascript:alert('xss-api')">`;

    await client.put('/api/Products/1', { description: xss }, adminToken);

    const xssExecuted = attachDialogDetector(page);
    await page.goto(`${BASE}/#/`);
    await page.waitForLoadState('networkidle');

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS payload stored via the product API must not execute when the page is rendered'
    ).toBe(false);

    // Restore original description
    await client.put('/api/Products/1', { description: 'Apple Juice' }, adminToken);
  });

  // Bonus Payload — https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_use_the_bonus_payload_in_the_dom_xss_challenge
  test('Bonus Payload: Juice Shop bonus XSS payload must not execute via search', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    await main.navbar.search(`<iframe src="javascript:alert(\`xss\`)">`);
    await page.waitForLoadState('networkidle');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'Bonus XSS payload must not execute via the search bar'
    ).toBe(false);
  });

  // CSP Bypass — https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_bypass_the_content_security_policy_and_perform_an_xss_attack_on_a_legacy_page
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

  // Client-side XSS Protection — https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html#_perform_a_persisted_xss_attack_bypassing_a_client_side_security_mechanism
  test('Client-side XSS Protection: search results must encode reflected HTML', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    await main.navbar.search(`<script>alert('xss-client')</script>`);
    await page.waitForLoadState('networkidle');

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'Client-side XSS payload must not execute').toBe(false);
    expect(dom, 'Raw <script> tag must not appear unencoded in rendered DOM')
      .not.toContain(`<script>alert('xss-client')</script>`);
  });

  // DOM XSS
  test('DOM XSS: angular-sanitize must prevent DOM injection via search', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    const main = new MainPage(page);
    await main.navigate();
    await main.navbar.search(`<iframe src="javascript:alert('xss-dom')">`);
    await page.waitForLoadState('networkidle');

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'DOM XSS iframe payload must not execute').toBe(false);
    expect(dom, 'iframe XSS payload must not appear unescaped in DOM')
      .not.toContain(`<iframe src="javascript:alert('xss-dom')">`);
  });

  // HTTP-Header XSS
  // The X-Forwarded-For header on login is stored as the "last login IP" and later
  // rendered on the account profile page — a stored XSS via HTTP header.
  test('HTTP-Header XSS: XSS stored via X-Forwarded-For login IP must not execute on profile page', async ({ request, page }) => {
    const auth = new AuthHelper(request);
    const email = AuthHelper.uniqueEmail();
    await auth.registerAndLogin(email, 'Test@1234!');

    const xssPayload = `<iframe src="javascript:alert('xss-header')">`;

    // Login a second time with the XSS payload as the apparent IP
    await request.post(`${BASE}/rest/user/login`, {
      data: { email, password: 'Test@1234!' },
      headers: { 'X-Forwarded-For': xssPayload },
    });

    const xssExecuted = attachDialogDetector(page);
    // Navigating to profile triggers rendering of the stored last-login IP
    await page.goto(`${BASE}/#/profile`);
    await page.waitForLoadState('networkidle');

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS payload stored as last-login IP must not execute when the profile page is rendered'
    ).toBe(false);
  });

  // Reflected XSS
  test('Reflected XSS: URL parameter must not reflect unencoded script into the page', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    await page.goto(`${BASE}/#/search?q=<script>alert('xss-reflected')</script>`);
    await page.waitForLoadState('networkidle');

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'Reflected XSS payload must not execute').toBe(false);
    expect(dom, 'Reflected XSS must be encoded in the DOM')
      .not.toContain(`<script>alert('xss-reflected')</script>`);
  });

  // Server-side XSS Protection
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

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      xssExecuted(),
      'XSS stored in feedback comment must not execute when admin panel renders it'
    ).toBe(false);
  });

  // Video XSS
  test('Video XSS: video subtitle parameter must not inject script into page', async ({ page }) => {
    const xssExecuted = attachDialogDetector(page);
    await page.goto(`${BASE}/#/about`);
    await page.waitForLoadState('networkidle');

    // Attempt to inject via the video subtitle track parameter if present
    await page.goto(`${BASE}/#/about?subtitles=<script>alert('xss-video')</script>`);
    await page.waitForLoadState('networkidle');

    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(xssExecuted(), 'Video subtitle XSS must not execute').toBe(false);
    expect(dom, 'XSS via video subtitle parameter must not appear unescaped in DOM')
      .not.toContain(`<script>alert('xss-video')</script>`);
  });

});
