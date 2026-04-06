---
layout: training-page
title: "Business Logic Errors — Red Team Academy"
module: "Web Hacking"
tags:
  - business-logic
  - logic-flaws
  - price-manipulation
  - race-condition
  - idor
page_key: "web-business-logic"
render_with_liquid: false
---

# Business Logic Errors

Business logic vulnerabilities are flaws in the design or implementation of an application's
  business rules. Unlike SQL injection or XSS, they do not exploit broken code — they abuse
  intended functionality in ways the developer did not anticipate. An attacker might apply
  discounts multiple times, submit negative quantities, access premium features without paying,
  or generate profit through rounding errors.

These bugs are particularly dangerous because automated scanners rarely detect them. They require
  manual testing and an understanding of how the application is supposed to work.

## Testing Methodology

### Review Feature Testing

- Post a product review as a verified reviewer without having purchased the item
- Submit a rating outside the valid scale (e.g., 0, 6, or -1 on a 1-5 scale) by modifying the request parameter
- Post multiple ratings for the same product from one user — check for race conditions
- Test file upload fields on review endpoints — developers often skip extension restrictions on these
- Post reviews impersonating other users by modifying user ID parameters
- Attempt CSRF on the review endpoint — it is frequently left unprotected

### Discount Code Feature Testing

- Apply the same discount code multiple times — check if the server tracks usage per code or per session
- For single-use codes: apply simultaneously from two accounts to find race conditions
- Test for Mass Assignment: add multiple discount code fields (`discount[]=CODE1&discount[]=CODE2`) when the app expects only one
- Test HTTP Parameter Pollution: `discount=CODE1&discount=CODE2`
- Apply discount codes to non-discounted items by modifying the item ID in the request
- Test for injection vulnerabilities (XSS, SQLi) in the coupon code field

### Delivery Fee Manipulation

- Submit negative values for delivery charges to reduce the order total
- Modify the `delivery_fee` parameter to 0 or negative
- Change the delivery method parameter to see if free delivery can be forced

```
# Intercept checkout POST and modify delivery charge:
POST /checkout HTTP/1.1
...
item_total=50.00&delivery_fee=-50.00&total=0.00
```

### Currency Arbitrage

- Pay for a purchase in one currency (e.g., USD)
- Request a refund in a different currency (e.g., EUR or GBP)
- Exchange rate fluctuations or fixed conversion rates may result in receiving more than paid

### Premium Feature Exploitation

- Access premium-only API endpoints or pages directly without a valid subscription
- Purchase a premium feature, use it, cancel, and check if access persists after refund
- Use Burp's Match & Replace to flip `premium: false` to `premium: true` in API responses
- Check cookies and localStorage for variables that gate premium features — modify them client-side
- Look for authorization checks performed only on the front end

```
# Example: API response with premium flag
GET /api/user/profile
Response: {"username":"alice","premium":false,"features":["basic"]}

# Burp Match & Replace rule:
Match:   "premium":false
Replace: "premium":true
```

### Refund Feature Exploitation

- Purchase a product, request a refund, and check if you still have access to the product
- Submit multiple cancellation requests for the same subscription simultaneously (race condition)
- Request a refund in a different currency for arbitrage profit

### Cart and Wishlist Exploitation

- Add items with negative quantities alongside real items to make the cart total negative or zero
- Add more quantity than the available stock by manipulating the quantity parameter
- Move items from one user's cart or wishlist to another user's cart via IDOR

```
# Negative quantity attack:
POST /cart/add HTTP/1.1
...
item_id=EXPENSIVE_ITEM&quantity=-1&item_id=CHEAP_ITEM&quantity=1
# Result: cart total may become zero or negative
```

### Thread and Comment Testing

- Check if there is a comment limit on threads — try to bypass it
- If users can only comment once, test race conditions to post multiple comments simultaneously
- Mimic parameters of verified/privileged users to post as them
- Post comments with other users' IDs via IDOR

## Rounding Error Exploitation

A real-world example (HackerOne #176461): a cryptocurrency platform using XBT/Bitcoin had a rounding
  flaw in its internal transfer system. An attacker could transfer 0.000000005 XBT (0.5 satoshi —
  below the minimum 1 satoshi precision).

- Sender balance: unchanged (transfer rounded down to 0 satoshi)
- Receiver balance: +0.00000001 XBT (rounded up to 1 satoshi)

Result: the attacker creates value from nothing. With no rate limiting or fraud detection,
  automating this in a loop generates unlimited funds.

```
# Automated rounding exploit (pseudocode):
for i in range(1000000):
    transfer(from=attacker, to=attacker_alt, amount=0.000000005)
    # Each iteration: attacker_alt gains 0.00000001 XBT for free
```

## Race Condition Testing

Many business logic flaws only appear when requests are sent simultaneously. Use Burp Suite's
  Turbo Intruder or the Last-Byte Synchronization technique to send parallel requests.

```
# Burp Turbo Intruder — parallel requests example (Python script)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

## Resources

- PayloadsAllTheThings Business Logic Errors — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors`
- PortSwigger Business Logic Vulnerabilities — `portswigger.net/web-security/logic-flaws`
- OWASP Business Logic Vulnerability — `owasp.org/www-community/vulnerabilities/Business_logic_vulnerability`
- CWE-840: Business Logic Errors — `cwe.mitre.org/data/definitions/840.html`
- HackerOne #176461 — rounding error money generation bug
- PortSwigger Examples of Business Logic Vulnerabilities — `portswigger.net/web-security/logic-flaws/examples`
