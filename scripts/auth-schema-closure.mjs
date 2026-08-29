//
//  auth-schema-closure.mjs
//  wxyc-swift-auth
//
//  Prints, one per line, the transitive `$ref` closure of every schema
//  reachable from wxyc-shared api.yaml's non-device `/auth/*` operations.
//
//  This is the input to regenerate-api-types.sh's AUTH_MODELS_KEEP tripwire.
//  The script vendors a *subset* of the generator's Models/ output rather than
//  the whole tree (see the repo CLAUDE.md's "Code generation" section for why),
//  and an allow-list that subsets silently DROPS anything nobody classified —
//  so the allow-list cannot be its own guard. This closure can be, because it
//  is derived from api.yaml rather than from the list it checks: a schema
//  added upstream and `$ref`'d from an auth operation appears here and fails
//  the comparison, and a list entry that stops being reachable fails it too.
//
//  Usage: node auth-schema-closure.mjs <wxyc-shared-clone-dir>
//
//  Resolves its YAML parser out of the clone's own node_modules (populated by
//  the `npm ci` regenerate-api-types.sh already runs), so this repo carries no
//  package.json of its own for one build-time parse.
//

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const cloneDir = process.argv[2];
if (!cloneDir) {
    console.error('usage: auth-schema-closure.mjs <wxyc-shared-clone-dir>');
    process.exit(2);
}

const require = createRequire(join(resolve(cloneDir), 'package.json'));
const YAML = require('yaml');

const doc = YAML.parse(readFileSync(join(cloneDir, 'api.yaml'), 'utf8'));

// The device-authorization (QR) surface is a documented non-goal for this
// package: wxyc-dj-ios is its sole consumer, and its own vendored
// WXYCAPIModels tree already carries the DeviceAuth* types. Including them
// here would put a second public copy of each into that app's dependency
// graph — the collision this subsetting exists to avoid.
const isAuthOperationPath = (path) => path.startsWith('/auth/') && !path.startsWith('/auth/device');

const schemaRefsIn = (node, found) => {
    if (node === null || typeof node !== 'object') return found;
    if (Array.isArray(node)) {
        for (const child of node) schemaRefsIn(child, found);
        return found;
    }
    for (const [key, value] of Object.entries(node)) {
        if (key === '$ref' && typeof value === 'string') {
            const match = /^#\/components\/schemas\/(.+)$/.exec(value);
            if (!match) {
                // Every `$ref` in this document's auth section is a local
                // component-schema reference. A `$ref` shaped any other way
                // (an external file, a `#/components/responses/...` indirection)
                // would silently contribute nothing to the closure, so the
                // allow-list comparison downstream would pass while the staged
                // tree is missing a type. Refuse rather than under-report.
                console.error(`ERROR: unsupported $ref form in the auth surface: ${value}`);
                process.exit(1);
            }
            found.add(match[1]);
        } else {
            schemaRefsIn(value, found);
        }
    }
    return found;
};

const seeds = new Set();
for (const [path, operations] of Object.entries(doc.paths ?? {})) {
    if (isAuthOperationPath(path)) schemaRefsIn(operations, seeds);
}
if (seeds.size === 0) {
    console.error('ERROR: no schemas are reachable from any non-device /auth/* operation — did the auth section move or get renamed?');
    process.exit(1);
}

const schemas = doc.components?.schemas ?? {};
const closure = new Set();
const pending = [...seeds];
while (pending.length > 0) {
    const name = pending.pop();
    if (closure.has(name)) continue;
    closure.add(name);
    const schema = schemas[name];
    if (schema === undefined) {
        console.error(`ERROR: auth operation references '#/components/schemas/${name}', which the document does not define`);
        process.exit(1);
    }
    for (const ref of schemaRefsIn(schema, new Set())) {
        if (!closure.has(ref)) pending.push(ref);
    }
}

for (const name of [...closure].sort()) console.log(name);
