# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: xss.spec.ts >> Cross-Site Scripting (XSS) – Reflected/DOM via Search (OWASP A03:2021) >> search results page must encode all reflected query output
- Location: src\tests\xss.spec.ts:63:7

# Error details

```
Error: locator.fill: Error: Element is not an <input>, <textarea>, <select> or [contenteditable] and does not have a role allowing [aria-readonly]
Call log:
  - waiting for locator('#searchQuery')
    - locator resolved to <app-mat-search-bar id="searchQuery" class="search-expanded" _nghost-ng-c1668053465="" _ngcontent-ng-c1731522247="" aria-label="Click to search">…</app-mat-search-bar>
    - fill("<b>probe</b>")
  - attempting fill action
    - waiting for element to be visible, enabled and editable

```

# Page snapshot

```yaml
- generic [ref=e4]:
  - generic [ref=e7]:
    - button "Open Sidenav" [ref=e8] [cursor=pointer]:
      - img [ref=e9]: menu
    - button "Back to homepage" [ref=e12]:
      - generic [ref=e14]:
        - img "OWASP Juice Shop" [ref=e15]
        - generic [ref=e16]: OWASP Juice Shop
    - generic "Click to search" [ref=e20]:
      - generic [ref=e21]:
        - img [ref=e22]: search
        - textbox [active] [ref=e23]
        - button "Close search" [ref=e24] [cursor=pointer]:
          - img [ref=e25]: close
    - generic [ref=e28]:
      - button "Show/hide account menu" [ref=e29]:
        - img [ref=e30]: account_circle
        - generic [ref=e31]: Account
      - button "Show the shopping cart" [ref=e34]:
        - img [ref=e35]: shopping_cart
        - generic [ref=e36]:
          - text: Your Basket
          - generic [ref=e37]: "0"
      - button "Language selection menu" [ref=e40]:
        - img [ref=e41]: language
        - generic [ref=e42]: EN
  - main [ref=e46]:
    - generic [ref=e48]: All Products
    - generic [ref=e49]:
      - article [ref=e52]:
        - button "Click for more information about the product" [ref=e53]:
          - img "Apple Juice (1000ml)" [ref=e55] [cursor=pointer]
          - generic [ref=e57] [cursor=pointer]: Apple Juice (1000ml)
        - generic [ref=e58]:
          - generic [ref=e59]: 1.99¤
          - button "Add to Basket" [ref=e60]:
            - img [ref=e61]: add_shopping_cart
            - generic [ref=e62]: Add to Basket
      - article [ref=e67]:
        - button "Click for more information about the product" [ref=e68]:
          - img "Apple Pomace" [ref=e70] [cursor=pointer]
          - generic [ref=e72] [cursor=pointer]: Apple Pomace
        - generic [ref=e73]:
          - generic [ref=e74]: 0.89¤
          - button "Add to Basket" [ref=e75]:
            - img [ref=e76]: add_shopping_cart
            - generic [ref=e77]: Add to Basket
      - article [ref=e82]:
        - button "Click for more information about the product" [ref=e83]:
          - img "Banana Juice (1000ml)" [ref=e85] [cursor=pointer]
          - generic [ref=e87] [cursor=pointer]: Banana Juice (1000ml)
        - generic [ref=e88]:
          - generic [ref=e89]: 1.99¤
          - button "Add to Basket" [ref=e90]:
            - img [ref=e91]: add_shopping_cart
            - generic [ref=e92]: Add to Basket
      - article [ref=e97]:
        - button "Click for more information about the product" [ref=e98]:
          - img "Basil Smoothie" [ref=e100] [cursor=pointer]
          - generic [ref=e102] [cursor=pointer]: Basil Smoothie
        - generic [ref=e103]:
          - generic [ref=e104]: 2.99¤
          - button "Add to Basket" [ref=e105]:
            - img [ref=e106]: add_shopping_cart
            - generic [ref=e107]: Add to Basket
      - article [ref=e112]:
        - button "Click for more information about the product" [ref=e113]:
          - img "Berry Juice (1000ml)" [ref=e115] [cursor=pointer]
          - generic [ref=e117] [cursor=pointer]: Berry Juice (1000ml)
        - generic [ref=e118]:
          - generic [ref=e119]: 3.49¤
          - button "Add to Basket" [ref=e120]:
            - img [ref=e121]: add_shopping_cart
            - generic [ref=e122]: Add to Basket
      - article [ref=e127]:
        - complementary [ref=e128]: Only 1 left
        - button "Click for more information about the product" [ref=e129]:
          - img "Best Juice Shop Salesman Artwork" [ref=e131] [cursor=pointer]
          - generic [ref=e133] [cursor=pointer]: Best Juice Shop Salesman Artwork
        - generic [ref=e134]:
          - generic [ref=e135]: 5000¤
          - button "Add to Basket" [ref=e136]:
            - img [ref=e137]: add_shopping_cart
            - generic [ref=e138]: Add to Basket
      - article [ref=e143]:
        - button "Click for more information about the product" [ref=e144]:
          - img "Bragă (500ml)" [ref=e146] [cursor=pointer]
          - generic [ref=e148] [cursor=pointer]: Bragă (500ml)
        - generic [ref=e149]:
          - generic [ref=e150]: 2.49¤
          - button "Add to Basket" [ref=e151]:
            - img [ref=e152]: add_shopping_cart
            - generic [ref=e153]: Add to Basket
      - article [ref=e158]:
        - button "Click for more information about the product" [ref=e159]:
          - img "Carrot Juice (1000ml)" [ref=e161] [cursor=pointer]
          - generic [ref=e163] [cursor=pointer]: Carrot Juice (1000ml)
        - generic [ref=e164]:
          - generic [ref=e165]: 2.99¤
          - button "Add to Basket" [ref=e166]:
            - img [ref=e167]: add_shopping_cart
            - generic [ref=e168]: Add to Basket
      - article [ref=e173]:
        - button "Click for more information about the product" [ref=e174]:
          - img "Dragonfruit Juice (500ml)" [ref=e176] [cursor=pointer]
          - generic [ref=e178] [cursor=pointer]: Dragonfruit Juice (500ml)
        - generic [ref=e179]:
          - generic [ref=e180]: 3.99¤
          - button "Add to Basket" [ref=e181]:
            - img [ref=e182]: add_shopping_cart
            - generic [ref=e183]: Add to Basket
      - article [ref=e188]:
        - button "Click for more information about the product" [ref=e189]:
          - img "Eggfruit Juice (500ml)" [ref=e191] [cursor=pointer]
          - generic [ref=e193] [cursor=pointer]: Eggfruit Juice (500ml)
        - generic [ref=e194]:
          - generic [ref=e195]: 8.99¤
          - button "Add to Basket" [ref=e196]:
            - img [ref=e197]: add_shopping_cart
            - generic [ref=e198]: Add to Basket
      - article [ref=e203]:
        - button "Click for more information about the product" [ref=e204]:
          - img "Elderflower Cordial (500ml)" [ref=e206] [cursor=pointer]
          - generic [ref=e208] [cursor=pointer]: Elderflower Cordial (500ml)
        - generic [ref=e209]:
          - generic [ref=e210]: 3.29¤
          - button "Add to Basket" [ref=e211]:
            - img [ref=e212]: add_shopping_cart
            - generic [ref=e213]: Add to Basket
      - article [ref=e218]:
        - button "Click for more information about the product" [ref=e219]:
          - img "Fruit Press" [ref=e221] [cursor=pointer]
          - generic [ref=e223] [cursor=pointer]: Fruit Press
        - generic [ref=e224]:
          - generic [ref=e225]: 89.99¤
          - button "Add to Basket" [ref=e226]:
            - img [ref=e227]: add_shopping_cart
            - generic [ref=e228]: Add to Basket
      - article [ref=e233]:
        - button "Click for more information about the product" [ref=e234]:
          - img "Grape Juice (1000ml)" [ref=e236] [cursor=pointer]
          - generic [ref=e238] [cursor=pointer]: Grape Juice (1000ml)
        - generic [ref=e239]:
          - generic [ref=e240]: 2.99¤
          - button "Add to Basket" [ref=e241]:
            - img [ref=e242]: add_shopping_cart
            - generic [ref=e243]: Add to Basket
      - article [ref=e248]:
        - button "Click for more information about the product" [ref=e249]:
          - img "Green Smoothie" [ref=e251] [cursor=pointer]
          - generic [ref=e253] [cursor=pointer]: Green Smoothie
        - generic [ref=e254]:
          - generic [ref=e255]: 1.99¤
          - button "Add to Basket" [ref=e256]:
            - img [ref=e257]: add_shopping_cart
            - generic [ref=e258]: Add to Basket
      - article [ref=e263]:
        - complementary [ref=e264]: Only 1 left
        - button "Click for more information about the product" [ref=e265]:
          - img "Juice Shop \"Permafrost\" 2020 Edition" [ref=e267] [cursor=pointer]
          - generic [ref=e269] [cursor=pointer]: Juice Shop "Permafrost" 2020 Edition
        - generic [ref=e270]:
          - generic [ref=e271]: 9999.99¤
          - button "Add to Basket" [ref=e272]:
            - img [ref=e273]: add_shopping_cart
            - generic [ref=e274]: Add to Basket
    - group [ref=e277]:
      - generic [ref=e279]:
        - generic [ref=e280]:
          - generic [ref=e281]: "Items per page:"
          - combobox "Items per page:" [ref=e286] [cursor=pointer]:
            - generic [ref=e287]:
              - generic [ref=e289]: "15"
              - img [ref=e292]
        - generic [ref=e295]:
          - status [ref=e296]: 1 – 15 of 46
          - button "Previous page" [disabled] [ref=e297]:
            - img [ref=e298]
          - button "Next page" [ref=e302] [cursor=pointer]:
            - img [ref=e303]
```

# Test source

```ts
  1  | import { Page, Locator } from '@playwright/test';
  2  | 
  3  | /**
  4  |  * Maps the Juice Shop top navigation bar (mat-toolbar).
  5  |  * Scoped to interactions that are available globally regardless of auth state.
  6  |  */
  7  | export class NavbarComponent {
  8  |   private readonly logoLink: Locator;
  9  |   private readonly searchToggleButton: Locator;
  10 |   private readonly searchInput: Locator;
  11 |   private readonly accountMenuButton: Locator;
  12 |   private readonly loginMenuItem: Locator;
  13 |   private readonly basketButton: Locator;
  14 | 
  15 |   constructor(page: Page) {
  16 |     this.logoLink           = page.locator('#navbarBrandLink');
  17 |     // aria-label is localised in some Juice Shop builds; match by icon content instead.
  18 |     this.searchToggleButton = page.locator('button').filter({ has: page.locator('mat-icon', { hasText: 'search' }) });
  19 |     this.searchInput        = page.locator('#searchQuery');
  20 |     this.accountMenuButton  = page.locator('#navbarAccount');
  21 |     this.loginMenuItem      = page.locator('#navbarLoginButton');
  22 |     this.basketButton       = page.locator('button[aria-label="Show the shopping cart"]');
  23 |   }
  24 | 
  25 |   public async goHome(): Promise<void> {
  26 |     await this.logoLink.click();
  27 |   }
  28 | 
  29 |   public async search(query: string): Promise<void> {
  30 |     await this.searchToggleButton.click();
> 31 |     await this.searchInput.fill(query);
     |                            ^ Error: locator.fill: Error: Element is not an <input>, <textarea>, <select> or [contenteditable] and does not have a role allowing [aria-readonly]
  32 |     await this.searchInput.press('Enter');
  33 |   }
  34 | 
  35 |   public async openAccountMenu(): Promise<void> {
  36 |     await this.accountMenuButton.click();
  37 |   }
  38 | 
  39 |   public async navigateToLogin(): Promise<void> {
  40 |     await this.openAccountMenu();
  41 |     await this.loginMenuItem.click();
  42 |   }
  43 | 
  44 |   public async openBasket(): Promise<void> {
  45 |     await this.basketButton.click();
  46 |   }
  47 | 
  48 |   /** Returns the visible text of the account button — useful for asserting login state. */
  49 |   public async getAccountButtonLabel(): Promise<string> {
  50 |     return this.accountMenuButton.innerText();
  51 |   }
  52 | }
  53 | 
```