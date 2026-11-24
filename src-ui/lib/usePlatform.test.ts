import { describe, expect, it } from "vitest";
import { isAndroidUserAgent, isIosUserAgent } from "./usePlatform";

describe("platform user-agent helpers", () => {
  it("detects Android WebView user agents", () => {
    expect(
      isAndroidUserAgent(
        "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 Chrome/125 Mobile Safari/537.36",
      ),
    ).toBe(true);
    expect(isIosUserAgent("Mozilla/5.0 (Linux; Android 15; SM-S928B)")).toBe(false);
  });

  it("detects iPhone and iPad WebView user agents", () => {
    expect(
      isIosUserAgent(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
      ),
    ).toBe(true);
    expect(
      isIosUserAgent(
        "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
      ),
    ).toBe(true);
    expect(isAndroidUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X)")).toBe(false);
  });
});
