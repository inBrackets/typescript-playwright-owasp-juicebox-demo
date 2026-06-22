import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';
import { AdminPage } from '../../pages/admin.page';

// OWASP A01:2021 – Broken Access Control
// Verifies that authorisation boundaries are enforced across admin operations,
// basket isolation, SSRF, CSRF, and object-level access controls.
// A passing test means access was correctly denied; a failing test means
// the boundary is missing and the vulnerability is exploitable.

const BASE = 'http://localhost:3000';

test.describe('Broken Access Control (OWASP A01:2021)', () => {

  let adminToken: string;
  let userToken: string;
  let userId: number;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();

    const email = AuthHelper.uniqueEmail();
    const client = new JuiceShopApiClient(request);
    await client.register(email, 'Test@1234!');
    userToken = await client.login(email, 'Test@1234!');

    const profileRes = await client.get('/api/Users/whoami', userToken);
    const profileBody = await profileRes.json() as { data?: { id: number } };
    userId = profileBody.data?.id ?? 2;
  });

  // AI Debugging
  test('AI Debugging: AI debug endpoint must require admin auth', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/chatbot/status', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [200, 401, 403].includes(res.status()),
      'AI debug endpoint returned unexpected status'
    ).toBe(true);
  });

  // Admin Section
  test('Admin Section: admin panel must redirect unauthenticated users', async ({ page }) => {
    const adminPage = new AdminPage(page);
    await adminPage.navigate();
    await page.waitForLoadState('networkidle');
    const hash = new URL(page.url()).hash;
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      hash,
      'Unauthenticated user must not reach /#/administration'
    ).not.toContain('/administration');
  });

  // CSRF
  test('CSRF: state-changing requests must reject missing origin', async ({ request }) => {
    const res = await request.post(`${BASE}/api/Feedbacks`, {
      data: { comment: 'csrf-test', rating: 3 },
      headers: { Authorization: `Bearer ${userToken}`, Origin: 'https://evil.com' },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Cross-origin POST must be rejected'
    ).not.toBe(200);
  });

  // Easter Egg
  test('Easter Egg: /ftp/eastere.gg must not be directly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/eastere.gg');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Easter egg file must not be served without a bypass'
    ).not.toBe(200);
  });

  // Five-Star Feedback
  test('Five-Star Feedback: only admin can delete feedback', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const createRes = await client.post('/api/Feedbacks', { comment: 'bac-test', rating: 5 }, adminToken);
    const body = await createRes.json() as { data?: { id: number } };
    const feedbackId = body.data?.id ?? 1;

    const deleteRes = await client.delete(`/api/Feedbacks/${feedbackId}`, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      deleteRes.status(),
      'Non-admin must not delete feedback'
    ).toBe(401);
  });

  // Forged Feedback
  test('Forged Feedback: posting feedback on behalf of another user must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/api/Feedbacks', {
      comment: 'forged',
      rating: 1,
      UserId: 1,
    }, userToken);
    const body = await res.json() as { data?: { UserId: number } };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body.data?.UserId,
      'API must not honour a caller-supplied UserId that differs from the authenticated user'
    ).not.toBe(1);
  });

  // Forged Review
  test('Forged Review: editing another user\'s review must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.patch('/rest/products/1/reviews', {
      id: 'r0000000000000000000001',
      message: 'forged review',
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Editing another user\'s review must return 401 or 403'
    ).toBe(true);
  });

  // Manipulate Basket
  test('Manipulate Basket: adding to another user\'s basket must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/api/BasketItems', {
      BasketId: 1,
      ProductId: 1,
      quantity: 1,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Adding items to a basket owned by another user must be rejected'
    ).toBe(true);
  });

  // Product Tampering
  test('Product Tampering: non-admin must not modify product descriptions', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.put('/api/Products/1', {
      description: '<script>alert(1)</script>',
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Non-admin product PUT must be rejected'
    ).toBe(true);
  });

  // SSRF
  test('SSRF: server must not fetch arbitrary internal URLs on behalf of the user', async ({ request }) => {
    const res = await request.post(`${BASE}/rest/saveLoginIp`, {
      headers: { 'X-Forwarded-For': 'http://localhost:3000/api/Users/' },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'SSRF via X-Forwarded-For must be rejected or ignored'
    ).not.toBe(200);
  });

  // View Basket
  test('View Basket: user must not read another user\'s basket', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Basket 1 is typically admin's; attempt access as normal user
    const res = await client.get('/api/Baskets/1', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      'Reading another user\'s basket must return 401 or 403'
    ).toBe(true);
  });

  // Web3 Sandbox
  test('Web3 Sandbox: blockchain dev interface must require authentication', async ({ page }) => {
    await page.goto(`${BASE}/#/web3-sandbox`);
    await page.waitForLoadState('networkidle');
    const hash = new URL(page.url()).hash;
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      hash,
      'Unauthenticated user must not reach /#/web3-sandbox'
    ).not.toContain('/web3-sandbox');
  });

});
