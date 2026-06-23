import { test, expect } from '@playwright/test';
import { createHmac, createPublicKey } from 'crypto';
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

  // Arbitrary File Write — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_overwrite_the_legal_information_file
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_overwrite_the_legal_information_file
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

  // Forged Signed JWT — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_forge_an_almost_properly_rsa_signed_jwt_token
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_forge_an_almost_properly_rsa_signed_jwt_token
  test('Forged Signed JWT: RS256 token signed with the RSA public key must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Fetch the RSA public key from the JWKS endpoint.
    const jwksRes = await client.get('/.well-known/jwks.json');
    const jwks = await jwksRes.json() as { keys?: Array<{ kty: string; n: string; e: string }> };
    const jwk = jwks.keys?.[0];
    expect(jwk, 'JWKS endpoint must return at least one RSA public key').toBeDefined();

    // Convert the JWK to PEM — this is the PUBLIC key the attacker can obtain.
    const publicKeyPem = createPublicKey({ key: { kty: jwk!.kty, n: jwk!.n, e: jwk!.e }, format: 'jwk' })
      .export({ type: 'pkcs1', format: 'pem' }) as string;

    // Build HS256 header + payload (same as a real admin token).
    const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      sub: '1', email: 'admin@juice-sh.op', role: 'admin', iat: Math.floor(Date.now() / 1000),
    })).toString('base64url');
    const signingInput = `${header}.${payload}`;

    // Sign with HMAC-SHA256 using the RSA public key as the HMAC secret (algorithm confusion).
    const signature = createHmac('sha256', publicKeyPem).update(signingInput).digest('base64url');
    const forgedToken = `${signingInput}.${signature}`;

    const res = await client.get('/api/Users/', forgedToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'JWT forged via RS256→HS256 algorithm confusion (signed with public key) must be rejected'
    ).toBe(true);
  });

  // Frontend Typosquatting — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_shop_about_a_typosquatting_imposter_that_dug_itself_deep_into_the_frontend
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_shop_about_a_typosquatting_imposter_that_dug_itself_deep_into_the_frontend
  test('Frontend Typosquatting: package.json.bak must not contain typosquatted frontend packages', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The null-byte bypass is required to access .bak files from the FTP directory.
    const res = await client.get('/ftp/package.json.bak%2500.md');
    // FAILURE CONDITION: Accessible backup file with typosquatted packages means the vulnerability is present.
    expect(
      res.status(),
      'Developer backup must not be downloadable via %2500.md null-byte bypass'
    ).not.toBe(200);
    if (res.status() !== 200) return;
    const body = await res.text();
    expect(
      body,
      'Dependency manifest must not contain known typosquatted frontend package names (freexml++, etc.)'
    ).not.toMatch(/freexml\+\+|sequal|expres[^s]|lodahs|node-uuid-v4/i);
  });

  // Legacy Typosquatting — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_shop_about_a_typosquatting_trick_it_has_been_a_victim_of
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_shop_about_a_typosquatting_trick_it_has_been_a_victim_of
  test('Legacy Typosquatting: package.json.bak must not contain the hijacked epilogue-js package', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Access the backup via null-byte bypass; epilogue-js is the legacy typosquatted package.
    const res = await client.get('/ftp/package.json.bak%2500.md');
    // FAILURE CONDITION: Accessible backup containing epilogue-js means the vulnerability is present.
    expect(
      res.status(),
      'Developer backup must not be downloadable via %2500.md null-byte bypass'
    ).not.toBe(200);
    if (res.status() !== 200) return;
    const body = await res.text();
    expect(
      body,
      'Dependency manifest must not reference the hijacked legacy package epilogue-js'
    ).not.toMatch(/"epilogue-js"|"sanitize-html":\s*"1\./);
  });

  // Local File Read — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_gain_read_access_to_an_arbitrary_local_file_on_the_web_server
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_gain_read_access_to_an_arbitrary_local_file_on_the_web_server
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

  // Supply Chain Attack — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_development_team_about_a_danger_to_some_of_their_credentials
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_development_team_about_a_danger_to_some_of_their_credentials
  test('Supply Chain Attack: package.json.bak must not reference a known compromised dependency', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Access the backup via null-byte bypass; event-stream@3.3.6 was a known malicious package.
    const res = await client.get('/ftp/package.json.bak%2500.md');
    // FAILURE CONDITION: Accessible backup containing a compromised package is the vulnerability.
    expect(
      res.status(),
      'Developer backup must not be downloadable via %2500.md null-byte bypass'
    ).not.toBe(200);
    if (res.status() !== 200) return;
    const body = await res.text();
    expect(
      body,
      'Dependency manifest must not reference the known compromised package event-stream@3.3.6'
    ).not.toMatch(/"event-stream":\s*"3\.3\.6"|"event-stream":\s*"\^3\.3/);
  });

  // Unsigned JWT — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_forge_an_essentially_unsigned_jwt_token
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_forge_an_essentially_unsigned_jwt_token
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

  // Kill Chatbot — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_permanently_disable_the_support_chatbot
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_permanently_disable_the_support_chatbot
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

  // Vulnerable Library — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html#_inform_the_shop_about_a_high_severity_vulnerability
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_inform_the_shop_about_a_high_severity_vulnerability
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
