import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A07:2021 – Identification and Authentication Failures (Anti-Automation)
// Verifies that rate-limiting, CAPTCHA enforcement, and abuse controls
// prevent scripted abuse of feedback, likes, and account recovery flows.

const BASE = 'http://localhost:3000';

test.describe('Broken Anti Automation (OWASP A07:2021)', () => {

  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // CAPTCHA Bypass — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_submit_10_or_more_customer_feedbacks_within_20_seconds
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_submit_10_or_more_customer_feedbacks_within_20_seconds
  test('CAPTCHA Bypass: feedback endpoint must reject captchaId reuse across multiple submissions', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // Solve CAPTCHA once with a correct answer, then reuse the same captchaId 10 times.
    // Vulnerability: the server never invalidates captchaId after first use, allowing automation.
    const captchaRes = await client.get('/rest/captcha/', userToken);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };
    expect(captchaBody.captchaId, 'CAPTCHA endpoint must return a valid captchaId').toBeDefined();
    const captchaId = captchaBody.captchaId!;
    const correctAnswer = captchaBody.answer!;

    const SUBMISSIONS = 10;
    const statuses = await Promise.all(
      Array.from({ length: SUBMISSIONS }, (_, i) =>
        client.post('/api/Feedbacks', {
          comment: `captcha-reuse-test-${i}`,
          rating: 3,
          captchaId,
          captcha: correctAnswer,
        }, userToken).then(res => res.status())
      )
    );

    const acceptedCount = statuses.filter(s => s === 201).length;
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // On a hardened server captchaId is invalidated after first use — only 1 can succeed.
    // More than 1 success means CAPTCHA bypass is possible.
    expect(
      acceptedCount <= 1,
      `CAPTCHA bypass detected: ${acceptedCount} of ${SUBMISSIONS} submissions accepted with the same captchaId`
    ).toBe(true);
  });

  // Extra Language — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_retrieve_the_language_file_that_never_made_it_into_production
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_retrieve_the_language_file_that_never_made_it_into_production
  test('Extra Language: non-standard Accept-Language must not unlock extra translations', async ({ request }) => {
    const res = await request.get(`${BASE}/i18n/tlh_AA.json`);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Klingon or other extra language file must not be served to unauthenticated requests'
    ).not.toBe(200);
  });

  // Multiple Likes — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_like_any_review_at_least_three_times_as_the_same_user
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_like_any_review_at_least_three_times_as_the_same_user
  // The like endpoint is PUT /rest/products/:productId/reviews with body { id: reviewId }.
  // Sending three consecutive likes from the same user must be rejected after the first.
  test('Multiple Likes: same user must not like a review more than once', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Fetch existing reviews for product 1 to obtain a real NeDB review _id
    const reviewsRes = await client.get('/rest/products/1/reviews');
    const reviewsBody = await reviewsRes.json() as { data?: Array<{ _id: string }> };
    const reviews = reviewsBody.data ?? [];

    expect(reviews.length, 'Product 1 must have at least one seeded review to test Multiple Likes').toBeGreaterThan(0);

    const reviewId = reviews[0]._id;
    await client.put('/rest/products/1/reviews', { id: reviewId }, userToken);
    const secondLike = await client.put('/rest/products/1/reviews', { id: reviewId }, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // Both likes returning 201 means the same user can like the same review multiple times —
    // anti-automation is broken.
    expect(
      secondLike.status(),
      'A second like on the same review by the same user must be rejected (Multiple Likes vulnerability present if 201)'
    ).not.toBe(201);
  });

  // Reset Morty's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_reset_mortys_password_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_mortys_password_via_the_forgot_password_mechanism
  // The vulnerability: no rate limiting on the forgot-password endpoint allows unlimited brute force.
  // A hardened server must return 429 after repeated wrong answers.
  test("Reset Morty's Password: security question brute-force must be rate-limited", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const ATTEMPTS = 20;
    const statuses = await Promise.all(
      Array.from({ length: ATTEMPTS }, (_, i) =>
        client.post('/rest/user/reset-password', {
          email: 'morty@juice-sh.op',
          answer: `brute${i}`,
          new: 'NewPwd@1234!',
          repeat: 'NewPwd@1234!',
        }).then(res => res.status())
      )
    );

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // If zero requests return 429, the endpoint has no rate limiting — brute force is unrestricted.
    expect(
      statuses.some(s => s === 429),
      'Forgot-password endpoint must return 429 after repeated wrong answers (Broken Anti-Automation if never 429)'
    ).toBe(true);
  });

});
