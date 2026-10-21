// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// One helper for the pages: an element with its text and attributes set, never its markup.
// Text from the SDK, from a node and from a file is only ever set as text.

/** An element with `props` assigned and `children` (strings or elements) appended. */
export function el(doc, tag, props = {}, ...children) {
  const node = doc.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

/** How a thrown value is shown: an SDK refusal with its stable code, anything else as text. */
export function describe(e) {
  const code = e && typeof e.code === "string" ? e.code : "";
  const message = e && e.message ? e.message : String(e);
  return { code, message };
}

/** A long value shortened in the middle: `head` and `tail` characters kept, the whole in the title. */
export function shorten(value, head = 10, tail = 8) {
  return value.length > head + tail + 3 ? `${value.slice(0, head)}...${value.slice(value.length - tail)}` : value;
}

/**
 * A code element showing `shown` (a shortened form) whose full value is in its title. A click shows
 * the full value, selected, so it can be copied. Display only: nothing is hidden from a reader of
 * the title or of the click.
 */
export function shortCode(doc, cls, full, shown = shorten(full)) {
  const node = el(doc, "code", { class: `${cls} short`, text: shown, title: full, tabindex: "0", "data-full": full });
  const expand = () => {
    node.textContent = full;
    const range = doc.createRange();
    range.selectNodeContents(node);
    const selection = doc.defaultView.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  };
  node.addEventListener("click", expand);
  node.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      expand();
    }
  });
  return node;
}
