// Layer 3 D3 fuzz harness: enumerate a package's exported API surface and
// invoke each callable with a dummy-arg matrix, to trigger trigger-on-use
// (API-call-gated) payloads that stay dormant at plain `require()` time.
//
// Usage: node fuzz_exports.js <package-dir>
// Best-effort: every property access / call is guarded by try/catch so a
// throwing getter or constructor never crashes the harness; it is only
// meant to observe side effects (network/file/process), not to validate
// the exported API.

const target = process.argv[2] || '/work';

const ARG_MATRIX = [[], [''], ['test'], [0], [1], [{}], [null], [undefined], [[]], [true]];

function safeCall(fn, thisArg, args) {
    try {
        const r = fn.apply(thisArg, args);
        // Wrap in case the call returns a promise/thenable — swallow async
        // rejections so they don't crash the process, while still letting
        // any async DNS/network side effect happen and flush.
        Promise.resolve(r).catch(() => {});
    } catch (e) {
        // Swallow — we only care about observed side effects, not correctness.
    }
}

function tryConstruct(fn, args) {
    try {
        new fn(...args);
    } catch (e) {
        // ignore
    }
}

function invokeWithMatrix(fn, thisArg, name) {
    for (const args of ARG_MATRIX) {
        safeCall(fn, thisArg, args);
    }
    // Constructor attempt for PascalCase-looking exports.
    if (/^[A-Z]/.test(name)) {
        for (const args of ARG_MATRIX) {
            tryConstruct(fn, args);
        }
    }
}

function fuzz(mod) {
    // The module itself, if callable.
    if (typeof mod === 'function') {
        invokeWithMatrix(mod, undefined, mod.name || 'default');
    }

    if (mod === null || (typeof mod !== 'object' && typeof mod !== 'function')) {
        return;
    }

    let keys = [];
    try {
        keys = Object.keys(mod);
    } catch (e) {
        return;
    }

    for (const key of keys) {
        let value;
        try {
            value = mod[key];
        } catch (e) {
            // Getter threw — skip this property.
            continue;
        }

        if (typeof value === 'function') {
            invokeWithMatrix(value, mod, key);
        } else if (value !== null && typeof value === 'object') {
            // One level of nesting into object-valued keys.
            let nestedKeys = [];
            try {
                nestedKeys = Object.keys(value);
            } catch (e) {
                continue;
            }
            for (const nk of nestedKeys) {
                let nested;
                try {
                    nested = value[nk];
                } catch (e) {
                    continue;
                }
                if (typeof nested === 'function') {
                    invokeWithMatrix(nested, value, nk);
                }
            }
        }
    }
}

try {
    const mod = require(target);
    fuzz(mod);
} catch (e) {
    process.stderr.write('fuzz_exports require error: ' + e.message + '\n');
}

// Let async side effects (DNS lookups, network callbacks) flush before exit.
setTimeout(() => {}, 3000);
