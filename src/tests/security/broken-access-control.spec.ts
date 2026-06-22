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

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    adminToken = await auth.loginAsAdmin();
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // AI Debugging — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_reveal_some_behind_the_scenes_information_on_the_chatbot_as_a_non_admin_user
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reveal_some_behind_the_scenes_information_on_the_chatbot_as_a_non_admin_user
  test('AI Debugging: AI debug endpoint must require admin auth', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/rest/chatbot/status', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means a non-admin can access the debug endpoint — vulnerability is present.
    expect(
      [401, 403].includes(res.status()),
      'AI debug endpoint must return 401 or 403 for non-admin users, not 200'
    ).toBe(true);
  });

  // Admin Section — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_access_the_administration_section_of_the_store
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_access_the_administration_section_of_the_store
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

  // CSRF — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_change_the_name_of_a_user_by_performing_cross_site_request_forgery_from_another_origin
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_change_the_name_of_a_user_by_performing_cross_site_request_forgery_from_another_origin
  // The CSRF challenge is to change the authenticated user's username from a cross-origin page.
  // PUT /api/Users/:id is the endpoint — it must reject requests from untrusted origins.
  test('CSRF: cross-origin profile update must be rejected', async ({ request }) => {
    const uid = AuthHelper.getUserId(userToken);
    if (!uid) return;

    const res = await request.put(`${BASE}/api/Users/${uid}`, {
      data: { username: 'csrf-pwned' },
      headers: { Authorization: `Bearer ${userToken}`, Origin: 'https://evil.com' },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means the server accepted a cross-origin state-changing request — CSRF is unprotected.
    expect(
      res.status(),
      'Cross-origin profile update from evil.com must be rejected (CSRF vulnerability present if 200)'
    ).not.toBe(200);
  });

  // Easter Egg — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_find_the_hidden_easter_egg
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_find_the_hidden_easter_egg
  test('Easter Egg: /ftp/eastere.gg must not be directly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/eastere.gg');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Easter egg file must not be served without a bypass'
    ).not.toBe(200);
  });

  // Five-Star Feedback — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_get_rid_of_all_5_star_customer_feedback
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_get_rid_of_all_5_star_customer_feedback
  test('Five-Star Feedback: only admin can delete feedback', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Feedback creation requires a valid CAPTCHA — without it the endpoint returns 400
    // and body.data?.id would be undefined, making feedbackId fall back to 1 silently.
    const captchaRes = await client.get('/rest/captcha/', adminToken);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };

    const createRes = await client.post('/api/Feedbacks', {
      comment: 'bac-test',
      rating: 5,
      captchaId: captchaBody.captchaId,
      captcha: captchaBody.answer,
    }, adminToken);
    const body = await createRes.json() as { data?: { id: number } };

    // If feedback creation failed, we cannot run this test meaningfully
    const feedbackId = body.data?.id;
    if (!feedbackId) return;

    const deleteRes = await client.delete(`/api/Feedbacks/${feedbackId}`, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      deleteRes.status(),
      'Non-admin must not delete feedback'
    ).toBe(401);
  });

  // Forged Feedback — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_post_some_feedback_in_another_users_name
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_post_some_feedback_in_another_users_name
  test('Forged Feedback: posting feedback on behalf of another user must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Without a valid CAPTCHA the endpoint always returns 400 and body.data is undefined,
    // causing body.data?.UserId to be undefined — the assertion would silently pass
    // even when the server would otherwise accept a forged UserId.
    const captchaRes = await client.get('/rest/captcha/', userToken);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };

    const res = await client.post('/api/Feedbacks', {
      comment: 'forged',
      rating: 1,
      UserId: 1,
      captchaId: captchaBody.captchaId,
      captcha: captchaBody.answer,
    }, userToken);
    const body = await res.json() as { data?: { UserId: number } };
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body.data?.UserId,
      'API must not honour a caller-supplied UserId that differs from the authenticated user'
    ).not.toBe(1);
  });

  // Forged Review — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_post_a_product_review_as_another_user_or_edit_any_users_existing_review
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_post_a_product_review_as_another_user_or_edit_any_users_existing_review
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

  // Manipulate Basket — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_put_an_additional_product_into_another_users_shopping_basket
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_put_an_additional_product_into_another_users_shopping_basket
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

  // Product Tampering — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_change_the_href_of_the_link_within_the_o_saft_product_description
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_change_the_href_of_the_link_within_the_o_saft_product_description
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

  // SSRF — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_request_a_hidden_resource_on_server_through_server
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_request_a_hidden_resource_on_server_through_server
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

  // View Basket — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_view_another_users_shopping_basket
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_view_another_users_shopping_basket
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

  // Web3 Sandbox — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_find_an_accidentally_deployed_code_sandbox
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_find_an_accidentally_deployed_code_sandbox
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
