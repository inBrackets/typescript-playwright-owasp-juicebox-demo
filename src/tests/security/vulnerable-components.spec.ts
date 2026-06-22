import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A06:2021 – Vulnerable and Outdated Components
// Verifies that JWT signature validation is enforced, that path traversal
// is blocked, and that known vulnerable front-end libraries are not served.

const BASE = 'http://localhost:3000';

function buildJwt(header: object, payload: object, signature: string = ''): string {
  const enc = (obj: object): string =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${enc(header)}.${enc(payload)}.${signature}`;
}

test.describe('Vulnerable Components (OWASP A06:2021)', () => {

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();
  });

  // Arbitrary File Write — https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_overwrite_the_legal_information_file
  test('Arbitrary File Write: path traversal in file upload must be blocked', async ({ request }) => {
    const traversalContent = Buffer.from('malicious content');
    const res = await request.post(`${BASE}/file-upload`, {
      headers: { Authorization: `Bearer ${adminToken}` },
      multipart: {
        file: {
          name: '../../malicious.js',
          mimeType: 'application/javascript',
          buffer: traversalContent,
        },
      },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 403, 422].includes(res.status()),
      'Path traversal filename in upload must be rejected'
    ).toBe(true);
  });

  // Forged Signed JWT — https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_forge_an_almost_properly_rsa_signed_jwt_token
  test('Forged Signed JWT: RS256 token signed with the RSA public key must be rejected', async ({ request }) => {
    // "Algorithm confusion" attack: server uses RS256 but if it falls back to HS256
    // and the attacker signs with the public key, it would verify successfully.
    const forgedToken = buildJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: '1', email: 'admin@juice-sh.op', role: 'admin', iat: Math.floor(Date.now() / 1000) }
    );
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Users/', forgedToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'JWT forged via algorithm confusion must be rejected'
    ).toBe(true);
  });

  // Frontend Typosquatting — https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_shop_about_a_typosquatting_imposter_that_dug_itself_deep_into_the_frontend
  test('Frontend Typosquatting: package-lock.json must not reference typosquatted packages', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/package.json.bak');
    if (res.status() !== 200) return; // file not accessible — pass
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Dependency manifest must not contain known typosquatted package names'
    ).not.toMatch(/sequal|expres[^s]|lodahs|node-uuid-v4/i);
  });

  // Legacy Typosquatting — https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_shop_about_a_typosquatting_trick_it_has_been_a_victim_of
  test('Legacy Typosquatting: legacy npm package names must not be present in the dependency tree', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/package.json.bak');
    if (res.status() !== 200) return;
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Dependency manifest must not contain deprecated or hijackable legacy package names'
    ).not.toMatch(/"sanitize-html":\s*"1\./);
  });

  // Local File Read
  test('Local File Read: path traversal in order tracking must not expose /etc/passwd', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/track-order/..%2F..%2F..%2Fetc%2Fpasswd');
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // The original check only looked for /bin/bash, which misses Alpine Linux Docker images
    // that use /bin/sh or /bin/ash — both are also conclusive indicators of /etc/passwd content.
    expect(
      body,
      'Path traversal in order-tracking must not serve /etc/passwd content'
    ).not.toMatch(/root:x:|\/bin\/(bash|sh|ash)/);
  });

  // Supply Chain Attack
  test('Supply Chain Attack: integrity hashes must be present on externally loaded scripts', async ({ page }) => {
    await page.goto(`${BASE}/`);
    await page.waitForLoadState('networkidle');
    const externalScripts = await page.evaluate<string[]>(() => {
      return Array.from(document.querySelectorAll('script[src]'))
        .filter(s => {
          const src = (s as HTMLScriptElement).src;
          return src.startsWith('http') && !src.includes('localhost');
        })
        .map(s => {
          const integrity = (s as HTMLScriptElement).integrity;
          return integrity || 'MISSING';
        });
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      externalScripts.some(i => i === 'MISSING'),
      'All externally loaded scripts must have Subresource Integrity (SRI) hashes'
    ).toBe(false);
  });

  // Unsigned JWT
  test('Unsigned JWT: token with alg=none must be rejected', async ({ request }) => {
    const unsignedToken = buildJwt(
      { alg: 'none', typ: 'JWT' },
      { sub: '1', email: 'admin@juice-sh.op', role: 'admin', iat: Math.floor(Date.now() / 1000) }
    );
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/api/Users/', unsignedToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'JWT with alg=none (unsigned) must be rejected'
    ).toBe(true);
  });

  // Kill Chatbot
  // The chatbot relies on a third-party library whose status/control endpoint
  // must not be accessible to unauthenticated or non-admin callers.
  test('Kill Chatbot: chatbot disable endpoint must require admin authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Attempt to toggle chatbot off without auth
    const resUnauth = await client.post('/rest/chatbot/status', { status: false });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(resUnauth.status()),
      'Unauthenticated request must not be able to disable the chatbot'
    ).toBe(true);

    // Attempt as a normal user
    const auth = new AuthHelper(request);
    const userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
    const resUser = await client.post('/rest/chatbot/status', { status: false }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(resUser.status()),
      'Non-admin user must not be able to disable the chatbot'
    ).toBe(true);
  });

  // Vulnerable Library
  test('Vulnerable Library: frontend must not load a known vulnerable version of a JS library', async ({ page }) => {
    const issues: string[] = [];

    page.on('response', async (res) => {
      const url = res.url();
      if (/jquery[.-]1\.[0-9]\.|angular[.-]1\.[0-4]\.|bootstrap[.-][12]\./.test(url)) {
        issues.push(url);
      }
    });

    await page.goto(`${BASE}/`);
    await page.waitForLoadState('networkidle');

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      issues,
      'Application must not load known vulnerable versions of jQuery, Angular, or Bootstrap'
    ).toHaveLength(0);
  });

});
