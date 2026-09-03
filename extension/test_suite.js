const assert = require("assert");

// 1. Mock DOM Environment
global.window = {
  location: { href: "http://localhost:5000/login" },
  innerWidth: 1920,
  innerHeight: 1080,
  getComputedStyle: () => ({ width: "100px", height: "50px", opacity: "1", display: "block", visibility: "visible" })
};
global.document = {
  title: "Test Page",
  body: { innerText: "Benvenuto" },
  querySelectorAll: () => [],
  getElementById: () => null,
  createElement: () => ({ style: {}, setAttribute: () => {} }),
  addEventListener: () => {}
};
global.chrome = {
  runtime: {
    onMessage: { addListener: () => {} },
    sendMessage: () => {}
  }
};

require("./content/triage.js");

console.log("=== Running BitM Sentinel Extension Test Suite ===");

// Test 1: Typosquatting (Levenshtein)
{
  global.window.location.href = "http://paypa1.com/login";
  const triage = window.BitMTriage.runFastTriage();
  assert(triage.triageScore >= 30, "Typosquatting must produce score >= 30");
  console.log("✓ Test 1 Passed: Typosquatting flagged accurately");
}

// Test 2: Evilginx Subdomain (paypal.evil-domain.com)
{
  global.window.location.href = "http://paypal.evil-domain.com/login";
  const triage = window.BitMTriage.runFastTriage();
  assert(triage.triageScore >= 45, "Evilginx subdomain must produce score >= 45");
  console.log("✓ Test 2 Passed: Evilginx subdomain flagged accurately");
}

// Test 3: Legitimate ccTLD (support.apple.com.cn / amazon.co.uk)
{
  global.window.location.href = "https://support.apple.com.cn/contact";
  const triage = window.BitMTriage.runFastTriage();
  assert.strictEqual(triage.triageScore, 0, "Legitimate ccTLD should NOT be flagged");
  console.log("✓ Test 3 Passed: Legitimate ccTLD not falsely flagged");
}

// Test 4: YouTube/Twitch Video False Positive Check
{
  global.window.location.href = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
  global.document.title = "Rick Astley - Never Gonna Give You Up";
  global.window.getComputedStyle = () => ({ width: "1920px", height: "1080px" });
  global.document.querySelectorAll = (selector) => {
    if (selector.includes("video")) return [{ style: { width: "100%", height: "100%" } }];
    return [];
  };
  const triage = window.BitMTriage.runFastTriage();
  assert.strictEqual(triage.triageScore, 0, "Normal video platforms must produce score 0");
  assert.strictEqual(triage.hasSensitiveInput, false);
  console.log("✓ Test 4 Passed: Normal video platforms do not trigger false positive");
}

// Test 5: Cuddlephish WebRTC Streaming Attack (Altoro Mutual on Raw IP)
{
  global.window.location.href = "http://192.168.122.201/";
  global.document.title = "Altoro Mutual Online Banking";
  global.document.querySelectorAll = (selector) => {
    if (selector.includes("video")) return [{ style: { width: "100vw", height: "100vh" } }];
    return [];
  };
  const triage = window.BitMTriage.runFastTriage();
  assert(triage.triageScore >= 65, "Streaming attack on sensitive title/IP must trigger score >= 65");
  assert.strictEqual(triage.hasSensitiveInput, true);
  console.log("✓ Test 5 Passed: Cuddlephish Streaming attack correctly flagged");
}

console.log("\nALL EXTENSION TESTS PASSED! (5/5) 🎉");
