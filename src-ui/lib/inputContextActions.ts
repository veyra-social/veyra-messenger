export type TextRange = {
  start: number;
  end: number;
};

export type TextEditResult = {
  value: string;
  caret: number;
};

export type InputMenuState = {
  canPaste: boolean;
  canCopy: boolean;
  canCut: boolean;
  canClear: boolean;
  showCopyCut: boolean;
};

type TextInputElement = HTMLInputElement | HTMLTextAreaElement;

function clampIndex(value: string, index: number): number {
  return Math.max(0, Math.min(index, value.length));
}

export function normalizeRange(value: string, start: number | null, end: number | null): TextRange {
  const normalizedStart = clampIndex(value, start ?? value.length);
  const normalizedEnd = clampIndex(value, end ?? normalizedStart);
  return normalizedStart <= normalizedEnd
    ? { start: normalizedStart, end: normalizedEnd }
    : { start: normalizedEnd, end: normalizedStart };
}

export function selectedOrAllText(value: string, range: TextRange): string {
  return range.start !== range.end ? value.slice(range.start, range.end) : value;
}

export function pasteText(value: string, range: TextRange, pasted: string): TextEditResult {
  const nextValue = value.slice(0, range.start) + pasted + value.slice(range.end);
  return {
    value: nextValue,
    caret: range.start + pasted.length,
  };
}

export function cutText(value: string, range: TextRange): TextEditResult {
  if (range.start === range.end) {
    return { value: "", caret: 0 };
  }
  return {
    value: value.slice(0, range.start) + value.slice(range.end),
    caret: range.start,
  };
}

export function getInputMenuState(input: {
  value: string;
  readOnly?: boolean;
  disabled?: boolean;
  type?: string;
}, isPassword = false): InputMenuState {
  const readOnly = !!input.readOnly || !!input.disabled;
  const password = isPassword || input.type === "password";
  const hasText = input.value.length > 0;
  return {
    canPaste: !readOnly,
    canCopy: !password && hasText,
    canCut: !password && !readOnly && hasText,
    canClear: !readOnly && hasText,
    showCopyCut: !password,
  };
}

export function applyInputValue(el: TextInputElement, nextValue: string, caret: number): void {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const valueSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;

  if (valueSetter) {
    valueSetter.call(el, nextValue);
  } else {
    el.value = nextValue;
  }

  const nextCaret = clampIndex(nextValue, caret);
  try {
    el.setSelectionRange(nextCaret, nextCaret);
  } catch {
    // Some input types do not support text selection. Connected fields are text-like.
  }

  const event =
    typeof InputEvent === "function"
      ? new InputEvent("input", { bubbles: true, inputType: "insertText", data: null })
      : new Event("input", { bubbles: true });
  el.dispatchEvent(event);
  el.focus();
}
