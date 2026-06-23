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
    [adminToken, userToken] = await Promise.all([
      auth.loginAsAdmin(),
      auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!'),
    ]);
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
  // The CSRF challenge: a state-changing request from a cross-origin page must be rejected.
  // PUT /rest/products/:productId/reviews with Origin: evil.com demonstrates the missing CORS check.
  test('CSRF: cross-origin state-changing request must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const reviewsRes = await client.get('/rest/products/1/reviews');
    const reviewsBody = await reviewsRes.json() as { data?: Array<{ _id: string }> };
    const reviews = reviewsBody.data ?? [];
    expect(reviews.length, 'Product 1 must have at least one seeded review to test CSRF').toBeGreaterThan(0);
    const reviewId = reviews[0]._id;

    const res = await request.put(`${BASE}/rest/products/1/reviews`, {
      data: { id: reviewId },
      headers: { Authorization: `Bearer ${userToken}`, Origin: 'https://evil.com' },
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 201 means the server accepted a cross-origin state-changing request — CSRF is unprotected.
    expect(
      res.status(),
      'Cross-origin state-changing PUT from evil.com must be rejected (CSRF vulnerability present if 201)'
    ).not.toBe(201);
  });

  // Easter Egg — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html#_find_the_hidden_easter_egg
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_find_the_hidden_easter_egg
  test('Easter Egg: null-byte bypass must not allow access to /ftp/eastere.gg', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The exploit: append %2500.md (double-encoded null byte) to bypass the .gg extension filter.
    const res = await client.get('/ftp/eastere.gg%2500.md');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Easter egg file must not be downloadable via %2500.md null-byte bypass'
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

    const feedbackId = body.data?.id;
    expect(feedbackId, 'Feedback creation must succeed before testing delete authorization').toBeDefined();

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
    // Compound check: either the request was rejected (non-201), or the accepted response must not
    // contain the forged UserId. This avoids a false pass when body.data is undefined on error responses.
    expect(
      res.status() !== 201 || body.data?.UserId !== 1,
      'Forged UserId=1 must not be accepted: server must reject or sanitize the caller-supplied field'
    ).toBe(true);
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
  // The attack: PUT /api/BasketItems/:id has no ownership check — any authenticated user can modify
  // any basket item by its NeDB ID, regardless of which user's basket it belongs to.
  test('Manipulate Basket: modifying another user\'s basket item must be rejected', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Admin adds an item to their own basket to create a known basket item ID
    const addRes = await client.post('/api/BasketItems', {
      BasketId: 1,
      ProductId: 2,
      quantity: 1,
    }, adminToken);
    const addBody = await addRes.json() as { data?: { id?: number } };
    const basketItemId = addBody.data?.id;
    expect(basketItemId, 'Admin must be able to create a basket item for Manipulate Basket test').toBeDefined();

    // A different user tries to modify admin's basket item — must be rejected
    const res = await client.put(`/api/BasketItems/${basketItemId!}`, { quantity: 2 }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 200 means the user modified another user's basket item — Manipulate Basket is present.
    expect(
      [401, 403].includes(res.status()),
      'Modifying another user\'s basket item must return 401 or 403 (vulnerability present if 200)'
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
  // The attack: POST /profile with profileImage set to an internal URL causes the server to fetch it
  // (SSRF). A hardened server should reject internal URLs with 400/422; a vulnerable server attempts
  // the fetch and may return 500 when it fails or gets blocked.
  test('SSRF: server must not fetch arbitrary internal URLs on behalf of the user', async ({ request }) => {
    const boundary = 'ssrf-test-boundary';
    const body = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="profileImage"',
      '',
      'http://localhost:3000/api/Users/',
      `--${boundary}--`,
    ].join('\r\n');

    const res = await request.post(`${BASE}/profile`, {
      headers: {
        Authorization: `Bearer ${userToken}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      },
      data: body,
    });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Status 500 means the server attempted to fetch the URL (SSRF in progress) and failed internally.
    // A hardened server must return 400 or 422 to reject the internal URL before any fetch attempt.
    expect(
      [400, 422].includes(res.status()),
      'Internal URL in profileImage must be rejected before fetch (SSRF vulnerability present if 500)'
    ).toBe(true);
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
