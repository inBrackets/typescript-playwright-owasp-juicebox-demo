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
  // The like endpoint is POST /rest/products/reviews/:reviewId/like — the review ID is
  // a NeDB _id string. Calling /rest/products/1/reviews/like (wrong path) always returns
  // 404 and never tests the actual rate-limiting vulnerability.
  test('Multiple Likes: same user must not like a review more than once', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Fetch existing reviews for product 1 to obtain a real review ID
    const reviewsRes = await client.get('/rest/products/1/reviews');
    const reviewsBody = await reviewsRes.json() as { data?: Array<{ _id: string }> };
    const reviews = reviewsBody.data ?? [];

    expect(reviews.length, 'Product 1 must have at least one seeded review to test Multiple Likes').toBeGreaterThan(0);

    const reviewId = reviews[0]._id;
    const firstLike  = await client.post(`/rest/products/reviews/${reviewId}/like`, {}, userToken);
    const secondLike = await client.post(`/rest/products/reviews/${reviewId}/like`, {}, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // If the same user can like the same review twice (200 on second call), anti-automation is broken.
    expect(
      secondLike.status(),
      'A second like on the same review from the same user must be rejected (Multiple Likes vulnerability)'
    ).not.toBe(200);
  });

  // Reset Morty's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_reset_mortys_password_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_mortys_password_via_the_forgot_password_mechanism
  test("Reset Morty's Password: security question brute-force must be rate-limited", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // '5N0wb4ll' is Morty's cat's name — the correct answer per the companion guide.
    const attempts = ['5N0wb4ll', 'Snowball', 'cat', 'dog', 'hamster'];
    const statuses = await Promise.all(attempts.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'morty@juice-sh.op',
        answer,
        new: 'NewPwd@1234!',
        repeat: 'NewPwd@1234!',
      }).then(res => res.status())
    ));

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      'None of the brute-forced answers should succeed; Morty\'s answer must not be trivially guessable'
    ).toBe(false);
  });

});
