'use strict';

// Innocent-looking stub — no install scripts, no obfuscation, no network calls.
// Layer 0 catches this via typosquatting: "expres" is distance-1 from "express".
// Layer 1 should PASS (no suspicious static patterns).

module.exports = function createApp() {
  return {
    listen: function(port, cb) {
      if (typeof cb === 'function') cb();
    }
  };
};
