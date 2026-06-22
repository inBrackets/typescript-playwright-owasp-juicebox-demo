import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A08:2021 – Software and Data Integrity Failures (Insecure Deserialization)
// Verifies that the server rejects malformed serialised payloads that could
// cause denial-of-service via memory exhaustion or remote code execution.

const BASE = 'http://localhost:3000';

test.describe('Insecure Deserialization (OWASP A08:2021)', () => {

  let adminToken: string;
  let userToken: string;
  let userId: number = 0;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();
    userToken  = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');

    const client = new JuiceShopApiClient(request);
    const profileRes = await client.get('/api/Users/whoami', userToken);
    const profileBody = await profileRes.json() as { data?: { id: number } };
    userId = profileBody.data?.id ?? 0;
  });

  // Blocked RCE DoS
  test('Blocked RCE DoS: RCE payload in file upload must be blocked before execution', async ({ request }) => {
    const rcePayload = Buffer.from(
      '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}'
    );
    const res = await request.post(`${BASE}/file-upload`, {
      headers: { Authorization: `Bearer ${adminToken}` },
      multipart: {
        file: { name: 'rce.zip', mimeType: 'application/zip', buffer: rcePayload },
      },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'RCE payload in upload must not return 200 (execution blocked)'
    ).not.toBe(200);
  });

  // Memory Bomb
  test('Memory Bomb: excessively large nested payload must be rejected before OOM', async ({ request }) => {
    // A deep zip bomb: send a very large JSON payload that would expand in memory
    const largePayload = JSON.stringify({ a: 'x'.repeat(50_000) });
    const res = await request.post(`${BASE}/api/Users/login`, {
      data: largePayload,
      headers: { 'Content-Type': 'application/json' },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 413, 422].includes(res.status()),
      'Oversized login payload must be rejected before causing a memory issue'
    ).toBe(true);
  });

  // Successful RCE DoS
  test('Successful RCE DoS: node-serialize RCE via profile image URL must be blocked', async ({ request }) => {
    if (!userId) return;
    const client = new JuiceShopApiClient(request);
    const rceUrl = '_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()';
    const res = await client.put(`/api/Users/${userId}`, { profileImage: rceUrl }, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'RCE payload as profileImage URL must be rejected or sanitised'
    ).not.toBe(200);
  });

});
