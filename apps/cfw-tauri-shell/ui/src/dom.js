export function node(tagName, options = {}, children = []) {
  const element = document.createElement(tagName);
  if (options.className) element.className = options.className;
  if (options.text !== undefined) element.textContent = String(options.text);
  if (options.title) element.title = String(options.title);
  if (options.type) element.type = options.type;
  if (options.value !== undefined) element.value = String(options.value);
  if (options.placeholder) element.placeholder = String(options.placeholder);
  if (options.disabled) element.disabled = true;
  if (options.checked !== undefined) element.checked = Boolean(options.checked);
  if (options.accept) element.accept = options.accept;
  if (options.dataset) {
    for (const [key, value] of Object.entries(options.dataset)) {
      element.dataset[key] = String(value);
    }
  }
  if (options.attributes) {
    for (const [key, value] of Object.entries(options.attributes)) {
      element.setAttribute(key, String(value));
    }
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child instanceof Node) element.append(child);
  }
  return element;
}

export function button(label, action, options = {}) {
  return node("button", {
    className: options.className ?? "button",
    text: label,
    type: "button",
    disabled: options.disabled,
    dataset: { action, ...(options.dataset ?? {}) },
  });
}

export function heading(kicker, title, description = null) {
  const children = [
    node("p", { className: "label", text: kicker }),
    node("h3", { text: title }),
  ];
  if (description) children.push(node("p", { className: "muted", text: description }));
  return node("div", {}, children);
}

export function statusPill(text, tone = "neutral") {
  return node("span", { className: `status-pill ${tone}`, text });
}

export function settingRow(label, hint, control) {
  return node("div", { className: "setting-row" }, [
    node("span", {}, [node("b", { text: label }), node("small", { text: hint })]),
    control,
  ]);
}

export function replaceChildren(target, children) {
  target.replaceChildren(...children.filter((child) => child instanceof Node));
}
