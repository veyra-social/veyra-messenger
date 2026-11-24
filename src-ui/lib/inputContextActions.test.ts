import { describe, expect, it } from "vitest";
import {
  cutText,
  getInputMenuState,
  normalizeRange,
  pasteText,
  selectedOrAllText,
} from "./inputContextActions";

describe("input context menu text operations", () => {
  it("pastes text at the caret", () => {
    const range = normalizeRange("hello", 2, 2);

    expect(pasteText("hello", range, "YY")).toEqual({
      value: "heYYllo",
      caret: 4,
    });
  });

  it("pastes text over a selection", () => {
    const range = normalizeRange("hello", 1, 4);

    expect(pasteText("hello", range, "a")).toEqual({
      value: "hao",
      caret: 2,
    });
  });

  it("copies the selection or the full value when nothing is selected", () => {
    expect(selectedOrAllText("abcdef", normalizeRange("abcdef", 2, 5))).toBe("cde");
    expect(selectedOrAllText("abcdef", normalizeRange("abcdef", 3, 3))).toBe("abcdef");
  });

  it("cuts the selection or the full value when nothing is selected", () => {
    expect(cutText("abcdef", normalizeRange("abcdef", 2, 5))).toEqual({
      value: "abf",
      caret: 2,
    });
    expect(cutText("abcdef", normalizeRange("abcdef", 3, 3))).toEqual({
      value: "",
      caret: 0,
    });
  });

  it("enables clear only for writable fields with text", () => {
    expect(getInputMenuState({ value: "x" }).canClear).toBe(true);
    expect(getInputMenuState({ value: "" }).canClear).toBe(false);
    expect(getInputMenuState({ value: "x", readOnly: true }).canClear).toBe(false);
  });

  it("hides copy and cut for password fields", () => {
    const state = getInputMenuState({ value: "secret", type: "password" });

    expect(state.showCopyCut).toBe(false);
    expect(state.canCopy).toBe(false);
    expect(state.canCut).toBe(false);
    expect(state.canPaste).toBe(true);
    expect(state.canClear).toBe(true);
  });
});
