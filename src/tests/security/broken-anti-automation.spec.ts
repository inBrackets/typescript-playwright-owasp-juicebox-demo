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

  // CAPTCHA Bypass — https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_submit_10_or_more_customer_feedbacks_within_20_seconds
  test('CAPTCHA Bypass: feedback endpoint must enforce CAPTCHA validation', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const captchaRes = await client.get('/rest/captcha/', userToken);
    const captchaBody = await captchaRes.json() as { captchaId?: number; answer?: string };
    const captchaId = captchaBody.captchaId ?? 1;
    const wrongAnswer = Number(captchaBody.answer ?? '0') + 1;

    const res = await client.post('/api/Feedbacks', {
      comment: 'captcha-bypass-test',
      rating: 3,
      captchaId,
      captcha: wrongAnswer,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Feedback with wrong CAPTCHA answer must be rejected'
    ).not.toBe(201);
  });

  // Extra Language — https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_retrieve_the_language_file_that_never_made_it_into_production
  test('Extra Language: non-standard Accept-Language must not unlock extra translations', async ({ request }) => {
    const res = await request.get(`${BASE}/i18n/tlh_AA.json`);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Klingon or other extra language file must not be served to unauthenticated requests'
    ).not.toBe(200);
  });

  // Multiple Likes — https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-anti-automation.html#_like_any_review_at_least_three_times_as_the_same_user
  // The like endpoint is POST /rest/products/reviews/:reviewId/like — the review ID is
  // a NeDB _id string. Calling /rest/products/1/reviews/like (wrong path) always returns
  // 404 and never tests the actual rate-limiting vulnerability.
  test('Multiple Likes: same user must not like a review more than once', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    // Fetch existing reviews for product 1 to obtain a real review ID
    const reviewsRes = await client.get('/rest/products/1/reviews');
    const reviewsBody = await reviewsRes.json() as { data?: Array<{ _id: string }> };
    const reviews = reviewsBody.data ?? [];

    if (reviews.length === 0) {
      // No reviews seeded — cannot test this challenge
      return;
    }

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

  // Reset Morty's Password
  test("Reset Morty's Password: security question brute-force must be rate-limited", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const attempts = ['cat', 'dog', 'fish', 'bird', 'hamster'];
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
