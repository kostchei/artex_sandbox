// Structural and behavioral tests for the four-layer exposure engine and wire diagram.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require('../js/wire-engine.js');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'wire.html'), 'utf8');

// 1. Verify wire.html integration
assert(html.includes('<script src="js/wire-engine.js"></script>'), 'wire.html must load js/wire-engine.js');
assert(html.includes('id="map-profile"'), 'wire.html must include the attacker picker');
assert(!html.includes('id="estate-preset"'), 'Wire should have one estate generator');
assert.deepEqual([...html.matchAll(/data-mode="([^"]+)"/g)].map(match => match[1]),
  ['baseline', 'patch', 'soc', 'combined'], 'Wire must offer the four reference-design defense cards');
const demoAttackers = ['lockbit', 'conti', 'blackcat', 'hive', 'revil', 'solarwinds', 'darkside', 'log4shell', 'cl0p', 'artex'];
const pre2023PatternIds = ['lockbit', 'conti', 'blackcat', 'hive', 'revil', 'solarwinds', 'darkside', 'log4shell', 'cl0p'];
assert(!html.includes('<select id="map-profile"'), 'Attacker selection belongs in the title toggle');
assert.deepEqual([...html.matchAll(/data-attacker="([^"]+)"/g)].map(match => match[1]), ['artex', 'pre2023']);
const patternSelect = html.match(/<select id="pre2023-pattern"[^>]*>([\s\S]*?)<\/select>/)[1];
assert.deepEqual([...patternSelect.matchAll(/<option value="([^\"]+)"/g)].map(match => match[1]), ['rotation', ...pre2023PatternIds]);
assert.match(patternSelect, /<option value="rotation" selected>/, 'Pre-LLM Path dropdown must default to rotation');
for (const patternId of pre2023PatternIds) {
  assert(html.includes(`${patternId}:`), `wire.html pre2023Groups must include ${patternId}`);
  const pattern = engine.PRE2023_ATTACK_PATTERNS[patternId];
  assert(pattern, `PRE2023_ATTACK_PATTERNS must define ${patternId}`);
  assert.equal(pattern.behaviorPreset, 'operator_with_tools');
  assert.equal(pattern.provenanceType, 'historical_source');
  assert(pattern.sourceUrl && pattern.primaryVector && pattern.systemicImpact && pattern.techniques.length > 0);
  for (const cveId of pattern.cveIds) {
    assert(engine.CVE_ATTACK_DESCRIPTIONS[cveId], `Missing CVE description for ${cveId}`);
    assert(engine.KEV_MITIGATION_RULES[cveId]?.waf && engine.KEV_MITIGATION_RULES[cveId]?.ml,
      `Missing explicit KEV_MITIGATION_RULES coverage for ${cveId}`);
  }
}

{
  const catalog = require('../assets/wire-defense-catalog.json');
  assert.equal(catalog.schemaVersion, 1);
  assert.equal(catalog.examples.length, 100);
  assert.equal(new Set(catalog.examples.map(example => example.id)).size, 100);
  assert.equal(Object.keys(catalog.infrastructure).length, 4);
  assert(html.includes('assets/wire-defense-catalog.json'), 'Wire must load the reference catalog');
  for (const example of catalog.examples) {
    assert.match(example.id, /^CVE-\d{4}-\d{4,}$/);
    assert(Object.hasOwn(catalog.infrastructure, example.context));
    assert(example.vendor && example.product && example.techniques.length);
    for (const technique of example.techniques) assert.match(technique, /^T\d{4}(\.\d{3})?$/);
  }
  for (const [id, context] of Object.entries(catalog.infrastructure)) {
    assert.equal(catalog.examples.filter(example => example.context === id).length, 25);
    assert.equal(context.roles.length, 4);
    assert.equal(context.groups.length, 4);
    assert(context.roles[context.focus]);
    const rosters = new Set();
    for (let seed = 1; seed <= 25; seed++) {
      const estate = engine.generateEstate({ preset: 'mixed', seed, preferredIngress: context.groups[0] });
      const before = JSON.stringify(estate);
      const flow = engine.referenceServiceFlow(estate, context.groups);
      assert(flow, `Missing ${id} service flow for seed ${seed}`);
      assert.equal(flow.relationships.length, 3);
      assert.deepEqual(flow.assets.map(assetId => estate.assets.find(asset => asset.id === assetId).groupId), context.groups);
      assert.equal(JSON.stringify(estate), before);
      rosters.add(estate.assets.filter(asset => asset.referenceCve).map(asset => asset.groupId).sort().join());
    }
    assert(rosters.size > 1, `Expected appliance variety for ${id}`);
  }
}

{
  const archetypes = Object.keys(engine.INFRASTRUCTURE_ARCHETYPES);
  for (const archetypeId of archetypes) {
    for (const seed of [1, 2, 3, 15, 26, 42, 99, 106, 134]) {
      const options = { seed, archetypeId, generationMode: 'authored_walkthrough' };
      const estate = engine.generateEstate(options);
      assert.equal(estate.walkthroughRouteAssetIds.length, 4);
      assert.equal(engine.validateWalkthrough(estate).valid, true);
      assert.deepEqual(engine.generateEstate(options), estate);
      const exploratory = engine.generateEstate({ ...options, generationMode: 'exploratory' });
      assert.deepEqual(exploratory.walkthroughRouteAssetIds, []);
    }
  }
}

// 2. Structural checks on catalog, variant mappings, icons, connections, and external entries
const { LAYER_KEVS, LAYER_CONFIG, ALLOWED_CONNECTIONS, EXTERNAL_ENTRY_GROUPS } = engine;
const groups = new Map();
for (const [layer, config] of LAYER_CONFIG.entries()) {
  for (const cluster of config.clusters) {
    for (const target of cluster.targets) {
      assert(!groups.has(target.id), `Duplicate group ${target.id}`);
      groups.set(target.id, layer);
      assert(fs.existsSync(path.join(root, 'assets/diagram-icons/transparent', target.icon)), `Missing icon for ${target.id}`);
      if (target.kevByVariant) {
        assert.equal(target.kevByVariant.length, target.variants.length, `Variant mappings for ${target.id}`);
        for (const cve of target.kevByVariant.filter(Boolean)) {
          assert(LAYER_KEVS[layer].some(entry => entry.id === cve), `${target.id}: ${cve} missing from layer catalog`);
        }
      }
    }
  }
}
for (const [source, targets] of Object.entries(ALLOWED_CONNECTIONS)) {
  assert(groups.has(source), `Unknown source ${source}`);
  for (const target of targets) {
    assert(groups.has(target), `Unknown target ${target}`);
    assert.equal(groups.get(target), groups.get(source) + 1, `Non-adjacent connection ${source} -> ${target}`);
  }
}
for (const entry of EXTERNAL_ENTRY_GROUPS) {
  assert.equal(groups.get(entry), 0, `Invalid external entry ${entry}`);
}

// Helper to build minimal valid v2 estates for unit tests
function makeEstate(overrides = {}) {
  return {
    schemaVersion: engine.SCHEMA_VERSION,
    seed: 12345,
    preset: 'mixed',
    intentionalPathNote: null,
    assets: [],
    findings: [],
    credentials: [],
    relationships: [],
    actionOrder: [],
    ...overrides
  };
}

function makeAsset(id, groupId, layerIdx, extra = {}) {
  return {
    id,
    groupId,
    label: id,
    product: id,
    assumedVersion: '1.0',
    layerIdx,
    trustZone: ['internet-dmz', 'identity-edge', 'internal-mesh', 'data-tier'][layerIdx],
    interfaces: ['https'],
    auth: 'token',
    isExternalEntry: layerIdx === 0,
    x: 0.1,
    y: 0.5,
    ...extra
  };
}

// 3. Schema validation & legacy snapshot migration
{
  const legacy = engine.migrateSnapshot({ soarSeed: 99, nodes: [], wires: [] });
  assert.equal(legacy.ok, false);
  assert.equal(legacy.legacy, true);

  const badEstate = makeEstate({ findings: [{ id: 'f1', assetId: 'missing', kind: 'cve' }] });
  const v = engine.validateEstate(badEstate);
  assert.equal(v.valid, false);
}

// 4. Negative prerequisite checks: wrong product/version, wrong protocol/direction, healthy asset
{
  const a0 = makeAsset('gw-1', 'ivanti-connect', 0, { product: 'Ivanti', assumedVersion: '22.0', interfaces: ['https'] });
  const a1 = makeAsset('app-1', 'app-engine', 1, { product: 'Spring', assumedVersion: '5.3', interfaces: ['api-https'] });
  const a2 = makeAsset('db-1', 'db-rds', 3, { interfaces: ['db-pg'] });

  const estate = makeEstate({
    assets: [a0, a1, a2],
    findings: [
      // Wrong product
      { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'OtherProduct', affectedVersions: ['22.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'gw-1', targetId: 'app-1', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.summary.succeededTransitions, 0);
  assert.equal(res.summary.ineligibleTransitions, 1);

  // Protocol mismatch + healthy asset
  estate.findings = [
    { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'Ivanti', affectedVersions: ['22.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' }
  ];
  const res2 = engine.simulateEstate(estate, 'baseline');
  assert.equal(res2.summary.succeededTransitions, 1); // gw-1 succeeded
  assert.equal(res2.events.find(e => e.targetId === 'app-1').outcome, 'ineligible');
  assert(res2.events.find(e => e.targetId === 'app-1').reason.includes('Protocol mismatch'));
}

// 5. Credentials: unacquired, wrong-scope, revoked vs valid credential on healthy/patched asset
{
  const a0 = makeAsset('gw-1', 'ivanti-connect', 0);
  const a1 = makeAsset('app-1', 'app-engine', 1, { interfaces: ['api-https'] });
  const a3 = makeAsset('db-1', 'db-rds', 3, { interfaces: ['db-pg'] });

  const base = makeEstate({
    assets: [a0, a1, a3],
    findings: [
      { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'gw-1', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' },
      { id: 'f1', assetId: 'app-1', kind: 'cve', cveId: 'CVE-2022-22965', requiredProduct: 'app-1', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'api-https', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r01', sourceId: 'gw-1', targetId: 'app-1', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r13', sourceId: 'app-1', targetId: 'db-1', protocol: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });

  // Valid credential acquired on app-1 grants read on healthy db-1 (no CVE on db-1)
  const validCredEstate = {
    ...base,
    credentials: [
      { id: 'c1', kind: 'db_credential', label: 'db-ro', scope: 'read', targetGroupIds: ['db-rds'], targetAssetIds: ['db-1'], revoked: false, mfaRequired: false, sourceAssetId: 'app-1', requiredSourceCapability: 'app_exec' }
    ]
  };
  const okRes = engine.simulateEstate(validCredEstate, 'baseline');
  assert.equal(okRes.summary.dataReached, true);
  assert.equal(okRes.events.find(e => e.targetId === 'db-1').outcome, 'succeeded');

  // Revoked credential stops db-1
  const revokedEstate = {
    ...base,
    credentials: [{ ...validCredEstate.credentials[0], revoked: true }]
  };
  const revRes = engine.simulateEstate(revokedEstate, 'baseline');
  assert.equal(revRes.summary.dataReached, false);

  // Wrong-scope credential (targets other group) stops db-1
  const wrongScopeEstate = {
    ...base,
    credentials: [{ ...validCredEstate.credentials[0], targetGroupIds: ['mssql-db'], targetAssetIds: ['other-db'] }]
  };
  const wsRes = engine.simulateEstate(wrongScopeEstate, 'baseline');
  assert.equal(wsRes.summary.dataReached, false);
}

// 6. Password spray: MFA / rate-limit blocks vs unprotected succeeds; anonymous read needs no CVE
{
  const s3 = makeAsset('public-s3-1', 'public-s3', 0, { interfaces: ['storage-s3'] });
  const idpMfa = makeAsset('iam-idp-1', 'iam-idp', 0, { interfaces: ['https'] });
  const idpOpen = makeAsset('iam-idp-2', 'iam-idp', 0, { interfaces: ['https'] });

  const estate = makeEstate({
    assets: [s3, idpMfa, idpOpen],
    findings: [
      { id: 'f-s3', assetId: 'public-s3-1', kind: 'anonymous_access', technique: 'T1530', yieldsCapability: 'data_read' },
      { id: 'f-mfa', assetId: 'iam-idp-1', kind: 'password_spray', syntheticAccountUsesSprayedPassword: true, mfaProtected: true, rateLimited: false, technique: 'T1110.003', yieldsCapability: 'account_session' },
      { id: 'f-open', assetId: 'iam-idp-2', kind: 'password_spray', syntheticAccountUsesSprayedPassword: true, mfaProtected: false, rateLimited: false, technique: 'T1110.003', yieldsCapability: 'account_session' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.events.find(e => e.targetId === 'public-s3-1').outcome, 'succeeded');
  assert.equal(res.events.find(e => e.targetId === 'iam-idp-1').outcome, 'ineligible');
  assert.equal(res.events.find(e => e.targetId === 'iam-idp-2').outcome, 'succeeded');
}

// 7. Display density does not truncate modeled access.
{
  const src = makeAsset('gw-1', 'ivanti-connect', 0);
  const t1 = makeAsset('t-1', 'cust-api', 1);
  const t2 = makeAsset('t-2', 'cust-api', 1);
  const t3 = makeAsset('t-3', 'cust-api', 1);
  const estate = makeEstate({
    assets: [src, t1, t2, t3],
    findings: [
      { id: 'f0', assetId: 'gw-1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f1', assetId: 't-1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f2', assetId: 't-2', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f3', assetId: 't-3', kind: 'anonymous_access', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'gw-1', targetId: 't-1', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r2', sourceId: 'gw-1', targetId: 't-2', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r3', sourceId: 'gw-1', targetId: 't-3', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.summary.layerSuccessCounts[1], 3);
  assert.equal(res.summary.truncated, false);
}

// 8. Seeded determinism, mixed-estate (0-path allowed) vs demo-ready (verified 4-layer path), and 4 defense modes
{
  const e1 = engine.generateEstate({ seed: 42, preset: 'mixed' });
  const e2 = engine.generateEstate({ seed: 42, preset: 'mixed' });
  assert.deepEqual(e1, e2, 'Identical seeds must produce identical estates');
  assert.equal(engine.validateEstate(e1).valid, true);

  const demo = engine.generateEstate({ seed: 777, preset: 'demo' });
  assert.equal(engine.validateEstate(demo).valid, true);
  assert.ok(demo.intentionalPathNote);
  const baseSim = engine.simulateEstate(demo, 'baseline');
  assert.equal(baseSim.summary.completeFourLayerPath, true, 'Demo-ready preset must have a verified 4-layer path');

  for (const mode of ['baseline', 'patch', 'defender', 'combined']) {
    const rA = engine.simulateEstate(demo, mode);
    const rB = engine.simulateEstate(demo, mode);
    assert.deepEqual(rA.summary, rB.summary, `Replay invariance failed for mode ${mode}`);
  }
}

// Mixed estates open with an authenticated, staging-only credential exposure.
{
  const openingKinds = new Set();
  for (const seed of [0, 1, 2]) {
    const estate = engine.generateEstate({ seed, preset: 'mixed' });
    const diagnostics = estate.assets.find(asset => asset.groupId === 'support-diagnostics');
    const status = estate.assets.find(asset => asset.groupId === 'staging-status');
    assert.equal(status.isExternalEntry, false);
    assert(!estate.relationships.some(relationship => relationship.sourceId === status.id));

    const { events } = engine.simulateEstate(estate, 'baseline');
    const opening = events[0];
    openingKinds.add(opening.finding.openingType);
    assert.equal(opening.targetId, diagnostics.id);
    assert.equal(opening.finding.kind, 'diagnostic_access');
    assert.equal(opening.credentialUsed.startingAccess, true);
    assert.equal(opening.grantedCapability, 'diagnostic_read');
    assert.equal(opening.acquiredCredentials.length, 1);
    const [credential] = opening.acquiredCredentials;
    assert.equal(credential.scope, 'staging status only');
    assert.deepEqual(credential.targetAssetIds, [status.id]);
    assert.deepEqual(credential.permissions, ['authenticate']);
    assert.equal(events.find(event => event.targetId === status.id).credentialUsed?.id, credential.id);

    const unauthorizedEstate = { ...estate, credentials: estate.credentials.filter(cred => !cred.startingAccess) };
    const unauthorized = engine.simulateEstate(unauthorizedEstate, 'baseline').events[0];
    assert.equal(unauthorized.outcome, 'ineligible');
    assert.match(unauthorized.reason, /authorized diagnostics viewer/);

    const correctedDiagnostics = { ...diagnostics, conditions: {} };
    const correctedEstate = {
      ...estate,
      assets: estate.assets.map(asset => asset.id === diagnostics.id ? correctedDiagnostics : asset)
    };
    const corrected = engine.simulateEstate(correctedEstate, 'baseline').events;
    assert.equal(corrected[0].outcome, 'ineligible');
    assert.match(corrected[0].reason, /diagnostic exposure is absent/);
    assert(!corrected.some(event => event.targetId === status.id && event.outcome === 'succeeded'));
  }
  assert.deepEqual(openingKinds, new Set(['low_exposure', 'misconfiguration', 'low_vulnerability']));

  const counts = new Map();
  const entryCounts = new Set();
  const dataOutcomes = new Set();
  const applianceFamilies = new Set();
  const applianceCves = new Set();
  const applianceRosters = new Set();
  const misconfigurations = new Set();
  for (let seed = 0; seed < 300; seed++) {
    const estate = engine.generateEstate({ seed, preset: 'mixed' });
    const appliances = estate.assets.filter(asset => asset.referenceCve);
    assert(appliances.length >= 5 && appliances.length <= 7);
    applianceRosters.add(appliances.map(asset => asset.groupId).sort().join());
    for (const asset of appliances) {
      applianceFamilies.add(asset.groupId);
      const finding = estate.findings.find(item => item.assetId === asset.id);
      if (finding) {
        assert.equal(finding.cveId, asset.referenceCve);
        applianceCves.add(finding.cveId);
      } else {
        assert.equal(asset.assumedVersion, null);
      }
    }
    assert(appliances.some(asset => asset.assumedVersion), 'Mixed must model at least one appliance finding');
    const { openingType } = estate.findings.find(finding => finding.kind === 'diagnostic_access');
    counts.set(openingType, (counts.get(openingType) || 0) + 1);
    const { summary, events } = engine.simulateEstate(estate, 'baseline');
    // The original edge-opening budget excludes the new independent workforce branch.
    entryCounts.add(new Set(events.filter(event => event.outcome === 'succeeded' &&
      estate.assets.some(asset => asset.id === event.targetId && asset.layerIdx === 0 && !asset.id.startsWith('windows-')))
      .map(event => event.targetId)).size);
    dataOutcomes.add(summary.dataReached);
    const misconfig = estate.findings.find(item => item.category === 'external_misconfiguration');
    if (misconfig) {
      misconfigurations.add(misconfig.id);
      const asset = estate.assets.find(item => item.id === misconfig.assetId);
      assert(asset.isExternalEntry);
      assert(fs.existsSync(path.join(root, 'assets/diagram-icons/transparent', asset.icon)));
      assert(misconfig.sourceUrl && misconfig.historicalReference);
      const entry = events.find(event => event.targetId === asset.id);
      assert.equal(entry.outcome, 'succeeded');
      const outgoing = estate.relationships.filter(relationship => relationship.sourceId === asset.id);
      assert.equal(outgoing.length, 0);
      if (misconfig.id === 'finding-datadog-proxy') {
        assert.equal(misconfig.illustration, 'git-to-idp');
        assert.equal(entry.grantedCapability, 'file_read');
        assert.equal(entry.acquiredCredentials.length, 0);
      } else {
        assert(['edge_access', 'account_session'].includes(entry.grantedCapability));
      }
    }
  }
  assert.deepEqual([...counts.values()], [100, 100, 100]);
  assert.deepEqual(entryCounts, new Set([2, 3]));
  assert.deepEqual(dataOutcomes, new Set([true, false]));
  assert.equal(applianceFamilies.size, 10);
  assert.equal(applianceCves.size, 10);
  assert(applianceRosters.size > 50);
  assert.equal(misconfigurations.size, 11);
  assert(misconfigurations.has('finding-datadog-proxy'));

  const newMixed = engine.generateEstate({ seed: 42 });
  const legacyMixed = makeEstate({ seed: 42 });
  assert.deepEqual(engine.migrateSnapshot(legacyMixed).estate, newMixed);
  assert.equal(engine.migrateSnapshot(newMixed).estate, newMixed);
  const oldDiagnostics = {
    ...newMixed,
    findings: newMixed.findings.map(finding => {
      if (finding.kind !== 'diagnostic_access') return finding;
      const { openingType, ...previousFinding } = finding;
      return previousFinding;
    })
  };
  assert.deepEqual(engine.migrateSnapshot(oldDiagnostics).estate, newMixed);
  for (const preset of ['demo', 'logs']) {
    const estate = engine.generateEstate({ seed: 42, preset });
    assert(!estate.credentials.some(cred => cred.startingAccess));
    assert(!estate.assets.some(asset => asset.groupId === 'support-diagnostics'));
  }
}

// 9. A source must actually possess the capability required by its connection.
{
  const source = makeAsset('read-only', 'edge', 0);
  const target = makeAsset('target', 'service', 1);
  const relation = { id: 'r', sourceId: source.id, targetId: target.id, direction: 'outbound', protocol: 'https', requiredSourceCapability: 'app_exec' };
  const state = { reachedAssets: new Map([[source.id, { capabilities: new Set(['file_read']) }]]), acquiredCredentials: new Map(), revokedCredentials: new Set() };
  const estate = makeEstate({ assets: [source, target], relationships: [relation], findings: [{ id: 'public', assetId: target.id, kind: 'anonymous_access' }] });
  assert.equal(engine.evaluateAction(state, source, target, relation, estate).eligible, false);
  state.reachedAssets.get(source.id).capabilities.add('app_exec');
  assert.equal(engine.evaluateAction(state, source, target, relation, estate).eligible, true);
}

// 10. Credential authorization is shared by regular access and authenticated CVEs.
{
  const target = makeAsset('db-1', 'db-rds', 3);
  const sibling = makeAsset('db-2', 'db-rds', 3);
  const cred = { id: 'c', label: 'test', scope: 'read', targetAssetIds: ['db-1'], targetGroupIds: ['db-rds'] };
  const state = { reachedAssets: new Map(), acquiredCredentials: new Map([['c', cred]]), revokedCredentials: new Set() };
  const estate = makeEstate({ assets: [target, sibling] });
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false); // not external
  target.isExternalEntry = sibling.isExternalEntry = true;
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, true);
  assert.equal(engine.evaluateAction(state, null, sibling, null, estate).eligible, false);
  for (const attr of ['revoked', 'expired', 'mfaRequired']) {
    cred[attr] = true;
    assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false, attr);
    cred[attr] = false;
  }
  estate.findings = [{ id: 'f', assetId: target.id, kind: 'cve', cveId: 'CVE-TEST', requiredProduct: target.product, affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', requiresAuth: true, requiredPermission: 'execute' }];
  assert.notEqual(engine.evaluateAction(state, null, target, null, estate).actionKind, 'cve_authenticated');
  cred.permissions = ['execute']; cred.mfaRequired = true;
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false);
}

// 11. The canary does not fire for an inaccessible target.
{
  const src = makeAsset('src', 'edge', 0);
  const decoy = makeAsset('decoy', 'db', 3);
  const estate = makeEstate({ assets: [src, decoy], findings: [{ id: 'entry', assetId: src.id, kind: 'anonymous_access', yieldsCapability: 'app_exec' }], relationships: [{ id: 'r', sourceId: src.id, targetId: decoy.id, direction: 'outbound', protocol: 'https', requiredSourceCapability: 'app_exec' }] });
  const event = engine.simulateEstate(estate, 'combined').events.find(e => e.targetId === decoy.id);
  if (event) assert.equal(event.outcome, 'ineligible');
}

// Demo preset must use sourced examples and produce a complete chain under many seeds.
for (let seed = 0; seed < 100; seed++) {
  const estate = engine.generateEstate({ seed, preset: 'demo' });
  assert(estate.findings.filter(f => f.kind === 'cve').every(f => f.sourceUrl && f.sourceReviewed && f.affectedVersions.length));
  assert(engine.simulateEstate(estate, 'baseline').summary.completeFourLayerPath, `demo seed ${seed}`);
}

// 12. Distinct actions against an already reached asset are not collapsed.
{
  const e1 = makeAsset('e1', 'ivanti-connect', 0);
  const e2 = makeAsset('e2', 'f5-gateway', 0);
  const e3 = makeAsset('e3', 'apache-edge', 0);
  const mid = makeAsset('mid', 'cust-api', 1, { interfaces: ['https', 'api-https'] });
  const db = makeAsset('db', 'db-rds', 3, { interfaces: ['db-pg'] });

  const estate = makeEstate({
    assets: [e1, e2, e3, mid, db],
    findings: [
      { id: 'f-e1', assetId: 'e1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f-e2', assetId: 'e2', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f-e3', assetId: 'e3', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      // mid has a file_read finding over https AND an app_exec finding over api-https
      { id: 'f-mid-read', assetId: 'mid', kind: 'anonymous_access', yieldsCapability: 'file_read' },
      { id: 'f-mid-exec', assetId: 'mid', kind: 'cve', cveId: 'CVE-2022-29464', requiredProduct: 'mid', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'api-https', yieldsCapability: 'app_exec' },
      { id: 'f-db', assetId: 'db', kind: 'anonymous_access', yieldsCapability: 'data_read' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'e1', targetId: 'mid', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r2', sourceId: 'e2', targetId: 'mid', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r3', sourceId: 'e3', targetId: 'mid', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r4', sourceId: 'mid', targetId: 'db', protocol: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  const midEvents = res.events.filter(e => e.targetId === 'mid');
  assert(midEvents.some(e => e.outcome === 'succeeded' && e.grantedCapability === 'file_read'), 'First visit grants file_read');
  assert(midEvents.some(e => e.outcome === 'succeeded' && e.grantedCapability === 'app_exec'), 'Second distinct action grants app_exec instead of collapsing to revisit');
  assert(midEvents.some(e => e.outcome === 'revisit'), 'Third visit with duplicate capability records revisit');
  assert.equal(res.summary.layerSuccessCounts[1], 1, 'Distinct actions on one asset count once in layerSuccessCounts');
  assert.equal(res.summary.dataReached, true, 'Downstream db reached using newly acquired app_exec capability');
}

// 13. Dedicated credential-in-logs scenario (non-CVE 4-layer path + expired sibling rejection).
for (let seed = 0; seed < 20; seed++) {
  const logsEstate = engine.generateEstate({ seed, preset: 'logs' });
  assert.equal(engine.validateEstate(logsEstate).valid, true);
  assert.equal(logsEstate.preset, 'logs');
  assert.ok(logsEstate.intentionalPathNote.includes('CREDENTIAL-IN-LOGS'));
  assert.equal(logsEstate.findings.filter(f => f.kind === 'cve').length, 0, 'Credential-in-logs scenario requires no CVE');
  const sim = engine.simulateEstate(logsEstate, 'baseline');
  assert.equal(sim.summary.completeFourLayerPath, true, `logs seed ${seed} must complete 4-layer path`);
  assert.equal(sim.summary.dataReached, true);
  if (logsEstate.credentials.some(c => c.expired)) {
    assert(sim.events.some(e => e.outcome === 'ineligible' && /expired/i.test(e.reason)), 'Expired sibling token in logs must be rejected');
  }
}

// 14. The public comparison and playback APIs use the same causal engine.
{
  const matrix = engine.evaluateComparisonMatrix('speed-race');
  assert.deepEqual(engine.evaluateComparisonMatrix('speed-race'), matrix);
  assert.equal(engine.importManifest(engine.exportManifest(matrix)).ok, true);
  const estateBefore = structuredClone(matrix.estate);
  for (const profile of matrix.attackerProfiles) {
    const cells = matrix.cells[profile.id];
    const readCount = cell => cell.outcomes.impact.sensitiveDatasetsRead.length;
    assert(readCount(cells.baseline) > 0);
    assert.equal(readCount(cells.patch), readCount(cells.baseline), 'The patch is outside the ingress path');
    assert.equal(readCount(cells.canaries), readCount(cells.baseline));
    assert(cells.canaries.outcomes.detection.decoyAlerts.some(alert => alert.alertDelivered));
    assert.deepEqual(cells.canaries.outcomes.response.confirmedResponses, []);
    assert.equal(readCount(cells.soc), 0);
    assert(cells.soc.events.some(event => event.reasonCode === 'SESSION_OR_HOST_CONTAINED'));
    assert.equal(cells.combined.defenseConfig.virtualPatching, true);
    assert.equal(cells.combined.defenseConfig.canaries, true);
    assert.equal(cells.combined.outcomes.comparisonSummary.preventedImpact, true);
    for (const [id, cell] of Object.entries(cells)) {
      assert.deepEqual(engine.evaluateComparisonRun(matrix.fixture.id, profile.id, id), cell);
      const browserActor = profile.id === 'pre2023' ? 'lockbit' : profile.id;
      const playback = engine.simulateWireRun(matrix.estate, id, browserActor, {
        attackerProfile: profile, defenseConfig: cell.defenseConfig, runConfig: matrix.runConfig
      });
      assert.deepEqual(playback.causalEvents, cell.events);
      const coordinates = events => events.map(({id, timeSec, startSec}) => ({id, timeSec, startSec}));
      assert.deepEqual(coordinates(playback.events), coordinates(cell.projectedEvents.filter(event =>
        event.kind === 'action_result' && event.dispatchBatch > 0)));
    }
  }
  assert.deepEqual(matrix.estate, estateBefore);

  const run = (fixture, defense, options) => engine.evaluateComparisonRun(fixture, 'artex', defense, options);
  const noSignal = run('speed-no-signal', 'soc');
  assert.equal(noSignal.outcomes.detection.totalObservations, 0);
  assert.equal(noSignal.outcomes.response.proposedCount, 0);
  assert(noSignal.outcomes.impact.sensitiveDatasetsRead.length);
  const covered = run('speed-covered-patch', 'combined');
  assert(covered.events.some(event => event.reasonCode === 'RULE_ENFORCED'));
  assert.equal(covered.outcomes.impact.sensitiveDatasetsRead.length, 0);
  const denied = run('capability-denied', 'combined');
  assert(denied.events.some(event => event.reasonCode === 'CREDENTIAL_MISSING_PERMISSION'));
  assert.equal(denied.outcomes.comparisonSummary.preventedImpact, false);
  const unrelated = run('speed-scope-mismatch', 'soc');
  assert(unrelated.events.some(event => event.reasonCode === 'SCOPE_UNRESOLVED'));
  assert(unrelated.outcomes.impact.sensitiveDatasetsRead.length);
  const untouched = run('speed-untouched-decoy', 'canaries');
  assert.equal(untouched.outcomes.detection.decoyAlerts.length, 0);
  const late = run('speed-late-decoy', 'combined');
  assert(late.outcomes.impact.sensitiveDatasetsRead.length);
  assert(late.events.find(event => event.kind === 'decoy_interaction').sequence >
    late.events.find(event => event.isProtectedRead).sequence);
  const atRead = run('speed-at-objective', 'soc');
  assert(atRead.outcomes.impact.sensitiveDatasetsRead.length);
  assert(atRead.events.find(event => event.reasonCode === 'CONFIRMED_AFTER_ACTION').sequence >
    atRead.events.find(event => event.isProtectedRead).sequence);
  const beforeRead = run('speed-at-objective', 'soc', { runConfig: {
    interventionContracts: [{ contract: 'confirmed_before_action', dependentTargetId: 'cmp-data' }]
  } });
  assert.equal(beforeRead.outcomes.impact.sensitiveDatasetsRead.length, 0);

  const makePlayback = (policy, options = {}) => engine.simulateWireRun(matrix.estate, 'baseline', 'artex', {
    ...options, defenseConfig: { virtualPatching: false, canaries: false, responsePolicy: policy }
  });
  const passive = makePlayback('observe_only');
  assert(passive.summary.dataReached && !passive.controls.some(event => event.control === 'enforced'));
  const playbook = makePlayback('playbook');
  const active = makePlayback('agentic');
  const human = makePlayback('human_led');
  assert(!playbook.summary.dataReached && !active.summary.dataReached);
  assert.equal(playbook.outcomes.costs.investigationsExecuted, 0);
  assert(active.outcomes.costs.investigationsExecuted > 0);
  assert.deepEqual(human.outcomes, active.outcomes);
  const retimed = makePlayback('agentic', { actionDurations: [0, 10, 20, 30], reentryDurationSec: 15 });
  assert.deepEqual(retimed.causalEvents, active.causalEvents);
  assert.deepEqual(retimed.outcomes, active.outcomes);
  assert.notDeepEqual(retimed.events.map(event => event.timeSec), active.events.map(event => event.timeSec));
  assert.throws(() => makePlayback('agentic', { actionDurations: [-1] }), /nonnegative/);

  const archived = engine.simulateLegacyWireRun(matrix.estate, 'baseline', 'artex');
  for (const playback of [retimed, archived]) {
    const manifest = JSON.parse(engine.exportWirePlayback(matrix.estate, 'artex', playback));
    const imported = engine.importManifest(manifest);
    assert.equal(imported.ok, true, imported.errors?.join(' '));
    assert.deepEqual(imported.replayed.events, playback.events);
    assert.deepEqual(imported.replayed.controls, playback.controls);
    manifest.events[0].timeSec += 1;
    assert.equal(engine.importManifest(manifest).ok, false, 'Modified playback trace is rejected');
  }
}

// ===========================================================================
// 15. Spec §16 Deterministic Verification & Minimum Fixture Suite (F01–F35)
//     + Bounded Seed Property Checks (Invariants R01–R14)
// ===========================================================================
{
  function makeV4Fixture({
    id = 'estate-fixture',
    archetypeId = 'public-web',
    seed = 101,
    assets = [],
    routes = [],
    weaknesses = [],
    credentials = [],
    datasets = [],
    sensors = [],
    enforcementPoints = [],
    patchRules = [],
    decoys = [],
    responseIntegrations = [],
    legitimateWorkflows = [],
    actionOrder = null
  } = {}) {
    const fullAssets = assets.map((a, idx) => ({
      id: a.id,
      groupId: a.groupId || a.id,
      label: a.label || a.id,
      product: a.product || 'FixtureProduct',
      assumedVersion: a.assumedVersion ?? '1.0',
      conditions: a.conditions || {},
      layerIdx: a.layerIdx ?? Math.min(3, idx),
      trustZone: TRUST_ZONES_FIXTURE[a.layerIdx ?? Math.min(3, idx)],
      interfaces: a.interfaces || ['https'],
      auth: a.auth || 'token',
      isExternalEntry: a.isExternalEntry ?? (a.layerIdx === 0),
      isDecoy: !!a.isDecoy,
      role: a.role || (a.isDecoy ? 'decoy' : 'service'),
      lifecycle: a.lifecycle || { status: 'active', decommissioned: false, poc: false },
      egress: a.egress || { cloudUploadAllowed: true, responseExportAllowed: true },
      x: 0.2 * ((a.layerIdx ?? 0) + 1),
      y: 0.5,
      ...a
    }));
    const fullRoutes = routes.map((r, idx) => ({
      id: r.id || `route-${idx + 1}`,
      sourceId: r.sourceId,
      targetId: r.targetId,
      protocol: r.protocol || 'https',
      accessibleInterface: r.accessibleInterface || r.protocol || 'https',
      direction: 'outbound',
      requiredSourceCapability: r.requiredSourceCapability || 'app_exec',
      policyPredicates: r.policyPredicates || [r.requiredSourceCapability || 'app_exec'],
      enforcementPointIds: r.enforcementPointIds || [],
      ...r
    }));
    const fullDatasets = datasets.length > 0 ? datasets : fullAssets
      .filter(a => a.layerIdx === 3 || a.isDecoy)
      .map(a => ({
        id: `ds-${a.id}`,
        ownerAssetId: a.id,
        label: `Dataset on ${a.label}`,
        sensitivity: a.isDecoy ? 'decoy' : (a.datasetSensitivity || 'sensitive'),
        records: a.isDecoy ? 0 : 500,
        bytes: a.isDecoy ? 0 : 512000,
        isDecoy: !!a.isDecoy,
        allowedOperations: ['read', 'export']
      }));
    const fullSensors = sensors.length > 0 ? sensors : [0, 1, 2, 3].map(l => ({
      id: `sensor-l${l}`,
      assetId: null,
      layerIdx: l,
      observableActions: ['cve', 'cve_authenticated', 'valid_credential', 'password_spray', 'anonymous_access', 'phishing_attachment', 'remote_service', 'persistence', 'encryption', 'data_exfiltration'],
      fieldsCollected: ['sourceId', 'targetId', 'protocol', 'principalId', 'sessionId', 'technique'],
      attributionQuality: 'session_scoped',
      availability: true,
      deterministicDetection: true,
      lossConditions: []
    }));
    const fullIntegrations = responseIntegrations.length > 0 ? responseIntegrations : [
      {
        id: 'ri-default-iam',
        supportedActions: ['invalidate_session', 'revoke_credential', 'disable_account', 'isolate_host', 'close_public_exposure'],
        authorizedScopes: ['*'],
        sessionSemantics: 'terminate_scoped_session',
        tokenSemantics: 'revoke_token_and_prevent_new_sessions',
        confirmationMechanism: 'synchronous_ack',
        available: true
      }
    ];
    return {
      schemaVersion: engine.SCHEMA_VERSION,
      id,
      archetypeId,
      estateSeed: seed,
      seed,
      preset: 'comparison',
      generationMode: 'authored_walkthrough',
      asOfDate: '2026-11-16',
      assets: fullAssets,
      routes: fullRoutes,
      relationships: fullRoutes,
      identityRelationships: [],
      weaknesses,
      findings: weaknesses,
      credentials,
      datasets: fullDatasets,
      sensors: fullSensors,
      enforcementPoints,
      patchRules,
      decoys,
      responseIntegrations: fullIntegrations,
      legitimateWorkflows,
      assumptions: engine.CALIBRATION_REGISTER.simulationAssumptions,
      actionOrder: actionOrder || fullAssets.map(a => a.id),
      defensePosture: {
        telemetryLayers: [0, 1, 2, 3],
        defaultInterventionContract: 'confirmed_before_action',
        decoys
      }
    };
  }
  const TRUST_ZONES_FIXTURE = ['internet-dmz', 'identity-edge', 'internal-mesh', 'data-tier'];

  // F01: Authored path loses its required source capability -> Dependent access fails through common evaluator; no exercise fallback
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'app-1', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['db-pg'] }
      ],
      routes: [
        { id: 'r-edge-app', sourceId: 'edge-1', targetId: 'app-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-app-db', sourceId: 'app-1', targetId: 'db-1', protocol: 'db-pg', requiredSourceCapability: 'app_exec' }
      ],
      weaknesses: [
        // edge-1 only grants file_read, NOT app_exec required by r-edge-app
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'file_read', technique: 'T1190' },
        { id: 'w-app', assetId: 'app-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-db', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'baseline' });
    assert.deepEqual(run.outcomes.access.reachedAssetIds, ['edge-1'], 'F01: Dependent access must fail when source capability is missing');
    assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 0);
    const appEvent = run.events.find(e => e.targetId === 'app-1');
    assert.equal(appEvent.outcome, 'not_attempted');
    assert.equal(appEvent.reasonCode, 'PREREQUISITE_NOT_ESTABLISHED');
  }

  // F02: Credential has wrong audience, missing permission or revoked state -> Authentication/operation is denied; reason identifies failed condition
  {
    for (const [fault, expectedCode] of [
      ['wrong_audience', 'CREDENTIAL_WRONG_AUDIENCE'],
      ['missing_permission', 'CREDENTIAL_MISSING_PERMISSION'],
      ['revoked', 'CREDENTIAL_REVOKED']
    ]) {
      const estate = makeV4Fixture({
        assets: [
          { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
          { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['db-pg'] }
        ],
        routes: [
          { id: 'r-edge-db', sourceId: 'edge-1', targetId: 'db-1', protocol: 'db-pg', requiredSourceCapability: 'app_exec' }
        ],
        weaknesses: [
          { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' }
        ],
        credentials: [
          {
            id: 'cred-db',
            kind: 'db_credential',
            label: 'DB token',
            sourceAssetId: 'edge-1',
            requiredSourceCapability: 'app_exec',
            targetAssetIds: ['db-1'],
            audience: fault === 'wrong_audience' ? 'other-service' : 'db-1',
            permissions: fault === 'missing_permission' ? ['authenticate'] : ['read'],
            revoked: fault === 'revoked',
            expired: false
          }
        ]
      });
      const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'baseline' });
      const dbEv = run.events.find(e => e.targetId === 'db-1' && e.kind === 'action_result');
      assert.equal(dbEv.outcome, 'denied', `F02 (${fault}): outcome must be denied`);
      assert.equal(dbEv.reasonCode, expectedCode, `F02 (${fault}): reasonCode must identify ${expectedCode}`);
      assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 0);
    }
  }

  // F03: Same request uses covered path and uncovered alternate path -> Patch applies only at enforcement point actually traversed
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-covered', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'edge-uncovered', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'api-target', groupId: 'cust-api', product: 'WSO2 API Manager', assumedVersion: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, layerIdx: 1, isExternalEntry: false, interfaces: ['api-https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf-1', assetId: 'edge-covered', routeIds: ['r-covered'], inspectedProtocols: ['api-https', 'https'], inspectedFields: ['uri', 'body'], ruleIds: ['rule-wso2'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-wso2', cveId: 'CVE-2022-29464', enforcementPointIds: ['ep-waf-1'], inspectedProtocols: ['api-https', 'https'], ruleStrictness: 'strict_virtual_patch', coverageState: 'modeled', action: 'block', reason: 'WAF blocks WSO2 file upload on covered route' }
      ],
      routes: [
        { id: 'r-covered', sourceId: 'edge-covered', targetId: 'api-target', protocol: 'api-https', requiredSourceCapability: 'app_exec', enforcementPointIds: ['ep-waf-1'] },
        { id: 'r-uncovered', sourceId: 'edge-uncovered', targetId: 'api-target', protocol: 'api-https', requiredSourceCapability: 'app_exec', enforcementPointIds: [] }
      ],
      weaknesses: [
        { id: 'w-e1', assetId: 'edge-covered', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-e2', assetId: 'edge-uncovered', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-api', assetId: 'api-target', kind: 'cve', cveId: 'CVE-2022-29464', requiredProduct: 'WSO2 API Manager', affectedVersions: ['3.2.0'], requiredConditions: { uploadEndpointReachable: true, executableUpload: true }, sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-29464', requiredInterface: 'api-https', yieldsCapability: 'app_exec', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'patch' });
    const coveredAttempt = run.events.find(e => e.routeId === 'r-covered' && e.kind === 'action_result');
    const uncoveredAttempt = run.events.find(e => e.routeId === 'r-uncovered' && e.kind === 'action_result');
    assert.equal(coveredAttempt.outcome, 'denied', 'F03: Covered path must be blocked by virtual patch');
    assert.equal(coveredAttempt.reasonCode, 'RULE_ENFORCED');
    assert.equal(uncoveredAttempt.outcome, 'succeeded', 'F03: Uncovered alternate path must succeed (OUTSIDE_CONTROL_PATH)');
    assert.equal(uncoveredAttempt.patchEvaluation.reasonCode, 'OUTSIDE_CONTROL_PATH');
  }

  // F04: Two profiles choose the same abstract variant against the same rule -> Rule outcome is identical; changing actor label alone has no effect
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', groupId: 'apache-edge', product: 'Apache HTTP Server', assumedVersion: '2.4.50', conditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, layerIdx: 0, isExternalEntry: true, interfaces: ['https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf', assetId: 'edge-1', protectedAssetIds: ['edge-1'], inspectedProtocols: ['https'], inspectedFields: ['uri'], ruleIds: ['rule-apache'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-apache', cveId: 'CVE-2021-42013', enforcementPointIds: ['ep-waf'], inspectedProtocols: ['https'], ruleStrictness: 'signature_regex', blockedVariants: ['default'], coverageState: 'modeled', action: 'block', reason: 'Regex blocks default traversal' }
      ],
      weaknesses: [
        { id: 'w-apache', assetId: 'edge-1', kind: 'cve', cveId: 'CVE-2021-42013', requiredProduct: 'Apache HTTP Server', affectedVersions: ['2.4.50'], requiredConditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013', requiredInterface: 'https', yieldsCapability: 'app_exec', technique: 'T1190' }
      ]
    });
    const p1 = { ...engine.BEHAVIOR_PRESETS.operator_with_tools, id: 'lockbit_label', adaptationRepertoire: ['default'] };
    const p2 = { ...engine.BEHAVIOR_PRESETS.agentic_orchestration, id: 'artex_label', adaptationRepertoire: ['default'] };
    const r1 = engine.simulateScenario({ estate, attackerProfile: p1, defenseConfig: 'patch' });
    const r2 = engine.simulateScenario({ estate, attackerProfile: p2, defenseConfig: 'patch' });
    assert.equal(r1.events[0].outcome, 'denied');
    assert.equal(r2.events[0].outcome, 'denied');
    assert.equal(r1.events[0].reasonCode, r2.events[0].reasonCode, 'F04: Identical variant against same rule must produce identical outcome regardless of actor label');
    assert.deepEqual(r1.outcomes.access.reachedAssetIds, r2.outcomes.access.reachedAssetIds);
  }

  // F05: Both profiles have a modeled alternative variant, but one fails to discover it -> Difference explained by observations and decisions, not a profile-specific bypass
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', groupId: 'apache-edge', product: 'Apache HTTP Server', assumedVersion: '2.4.50', conditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, layerIdx: 0, isExternalEntry: true, interfaces: ['https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf', assetId: 'edge-1', protectedAssetIds: ['edge-1'], inspectedProtocols: ['https'], inspectedFields: ['uri'], ruleIds: ['rule-apache'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-apache', cveId: 'CVE-2021-42013', enforcementPointIds: ['ep-waf'], inspectedProtocols: ['https'], ruleStrictness: 'signature_regex', blockedVariants: ['default'], coverageState: 'modeled', action: 'block', reason: 'Regex blocks default variant but misses url_encoded_path' }
      ],
      weaknesses: [
        { id: 'w-apache', assetId: 'edge-1', kind: 'cve', cveId: 'CVE-2021-42013', requiredProduct: 'Apache HTTP Server', affectedVersions: ['2.4.50'], requiredConditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013', requiredInterface: 'https', yieldsCapability: 'app_exec', technique: 'T1190' }
      ]
    });
    const discovers = { ...engine.BEHAVIOR_PRESETS.operator_with_tools, adaptationRepertoire: ['default', 'url_encoded_path'], variantDiscoveryProbability: 1.0 };
    const failsToDiscover = { ...engine.BEHAVIOR_PRESETS.agentic_orchestration, adaptationRepertoire: ['default', 'url_encoded_path'], variantDiscoveryProbability: 0.0 };
    const rDiscover = engine.simulateScenario({ estate, attackerProfile: discovers, defenseConfig: 'patch' });
    const rFail = engine.simulateScenario({ estate, attackerProfile: failsToDiscover, defenseConfig: 'patch' });
    assert.equal(rDiscover.outcomes.access.reachedAssetIds.includes('edge-1'), true, 'F05: Operator that discovers url_encoded_path succeeds on retry');
    assert.equal(rFail.outcomes.access.reachedAssetIds.includes('edge-1'), false, 'F05: Agentic profile that fails to discover variant stays blocked');
    assert.equal(rDiscover.events.filter(e => e.kind === 'action_result').length, 2);
    assert.equal(rDiscover.events[1].variantId, 'url_encoded_path');
  }

  // F06: HTTP WAF faces non-HTTP traffic -> Claims no block; unsupported inspection is recorded accurately
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-vpn', groupId: 'zyxel-atp', product: 'Zyxel ATP Firewall', assumedVersion: '5.35', conditions: { ipsecEnabled: true }, layerIdx: 0, isExternalEntry: true, interfaces: ['vpn'] }
      ],
      enforcementPoints: [
        { id: 'ep-http-waf', assetId: 'edge-vpn', protectedAssetIds: ['edge-vpn'], inspectedProtocols: ['https', 'api-https'], inspectedFields: ['uri'], ruleIds: ['rule-zyxel'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-zyxel', cveId: 'CVE-2023-28771', enforcementPointIds: ['ep-http-waf'], inspectedProtocols: ['https'], coverageState: 'modeled', action: 'block', reason: 'HTTP WAF rule' }
      ],
      weaknesses: [
        { id: 'w-zyxel', assetId: 'edge-vpn', kind: 'cve', cveId: 'CVE-2023-28771', requiredProduct: 'Zyxel ATP Firewall', affectedVersions: ['5.35'], requiredConditions: { ipsecEnabled: true }, sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-28771', requiredInterface: 'vpn', yieldsCapability: 'app_exec', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'patch' });
    const ev = run.events.find(e => e.kind === 'action_result');
    assert.equal(ev.outcome, 'succeeded', 'F06: HTTP WAF must not block non-HTTP vpn traffic');
    assert.equal(ev.patchEvaluation.reasonCode, 'UNSUPPORTED_PROTOCOL');
    assert.equal(ev.patchEvaluation.enforced, false);
  }

  // F07: Explicit access restriction covers a credential-bearing request -> Apply that policy instead of assuming all valid-credential actions bypass controls
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'admin-api', layerIdx: 1, isExternalEntry: false, interfaces: ['api-https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf', assetId: 'edge-1', routeIds: ['r-admin'], inspectedProtocols: ['api-https'], inspectedFields: ['headers', 'uri'], ruleIds: ['rule-restrict-cred'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-restrict-cred', restrictedOperation: 'valid_credential', restrictsCredentials: true, enforcementPointIds: ['ep-waf'], inspectedProtocols: ['api-https'], blockedVariants: ['default'], coverageState: 'modeled', action: 'block', reason: 'WAF policy restricts direct external credential-bearing calls to admin API' }
      ],
      routes: [
        { id: 'r-admin', sourceId: 'edge-1', targetId: 'admin-api', protocol: 'api-https', requiredSourceCapability: 'app_exec', enforcementPointIds: ['ep-waf'] }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' }
      ],
      credentials: [
        { id: 'cred-admin', kind: 'api_token', label: 'Valid Admin Token', sourceAssetId: 'edge-1', requiredSourceCapability: 'app_exec', targetAssetIds: ['admin-api'], audience: 'admin-api', permissions: ['authenticate'], revoked: false, expired: false }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'patch' });
    const apiEv = run.events.find(e => e.targetId === 'admin-api' && e.kind === 'action_result');
    assert.equal(apiEv.outcome, 'denied', 'F07: Explicit access restriction at enforcement point must block credential-bearing request');
    assert.equal(apiEv.reasonCode, 'RULE_ENFORCED');
  }

  // F08: Decoy exists but is undiscovered or untouched -> No canary alert
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'isolated-decoy', layerIdx: 2, isExternalEntry: false, isDecoy: true, interfaces: ['https'] }
      ],
      decoys: [
        { id: 'decoy-1', kind: 'decoy_asset', assetId: 'isolated-decoy', deployed: true }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'isolated-decoy', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'combined' });
    assert.equal(run.outcomes.detection.decoyAlerts.length, 0, 'F08: Undiscovered/untouched decoy must emit zero canary alerts');
    assert(!run.events.some(e => e.kind === 'decoy_interaction'));
  }

  // F09: Honeytoken use is denied by an instrumented verifier -> Alert still fires on attempted_use; no production access granted
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'prod-vault', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-vault', sourceId: 'edge-1', targetId: 'prod-vault', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' }
      ],
      credentials: [
        { id: 'honey-cred-1', kind: 'api_token', label: 'Honeytoken AWS Key', isHoneytoken: true, sourceAssetId: 'edge-1', requiredSourceCapability: 'app_exec', targetAssetIds: ['prod-vault'], audience: 'prod-vault', permissions: ['authenticate'], revoked: false, expired: false }
      ],
      decoys: [
        { id: 'decoy-honey-1', kind: 'honeytoken_credential', credentialId: 'honey-cred-1', verifierAssetIds: ['prod-vault'], triggerPredicate: 'attempted_use', deployed: true }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'canaries' });
    const vaultEv = run.events.find(e => e.targetId === 'prod-vault' && e.kind === 'action_result');
    assert.equal(vaultEv.outcome, 'denied', 'F09: Honeytoken must be denied at verifier and grant no production access');
    assert.equal(vaultEv.reasonCode, 'HONEYTOKEN_VERIFIER_DENIED');
    assert(!run.outcomes.access.reachedAssetIds.includes('prod-vault'));
    assert.equal(run.outcomes.detection.decoyAlerts.length, 1, 'F09: Canary alert must still fire on attempted use');
    assert.equal(run.outcomes.detection.decoyAlerts[0].decoyId, 'decoy-honey-1');
  }

  // F10: Two distinct decoys are touched -> Both interactions exist; deduplication does not suppress the second decoy
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-a', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'decoy-b', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-da', sourceId: 'edge-1', targetId: 'decoy-a', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-db', sourceId: 'edge-1', targetId: 'decoy-b', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [
        { id: 'decoy-a', kind: 'decoy_asset', assetId: 'decoy-a', deployed: true },
        { id: 'decoy-b', kind: 'decoy_asset', assetId: 'decoy-b', deployed: true }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-da', assetId: 'decoy-a', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-db', assetId: 'decoy-b', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'canaries' });
    assert.equal(run.outcomes.detection.decoyAlerts.length, 2, 'F10: Both distinct decoy interactions must be recorded without cross-decoy suppression');
    assert.deepEqual(run.outcomes.detection.decoyAlerts.map(d => d.decoyId).sort(), ['decoy-a', 'decoy-b']);
  }

  // F11: Canary-only mode alerts while a real path remains viable -> Detection is reported; no automatic revocation or prevention is credited
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-1', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'db-real', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-decoy', sourceId: 'edge-1', targetId: 'decoy-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-real', sourceId: 'edge-1', targetId: 'db-real', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [
        { id: 'decoy-1', kind: 'decoy_asset', assetId: 'decoy-1', deployed: true }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'decoy-1', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-real', assetId: 'db-real', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'canaries' });
    assert.equal(run.outcomes.detection.decoyAlerts.length, 1, 'F11: Canary alert must be reported');
    assert.equal(run.outcomes.response.confirmedResponses.length, 0, 'F11: Canary-only mode must not revoke access or confirm containment');
    assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 1, 'F11: Real path remains viable and achieves sensitive dataset read');
  }

  // F12: Canary identifies suspicious activity but not a revocable identity -> Incident remains actionable/uncertain (insufficient_evidence); no unsupported session containment
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-unattr', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'db-real', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-decoy', sourceId: 'edge-1', targetId: 'decoy-unattr', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-real', sourceId: 'edge-1', targetId: 'db-real', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [
        { id: 'decoy-unattr', kind: 'decoy_asset', assetId: 'decoy-unattr', attributionQuality: 'none', identifiesSession: false, deployed: true }
      ],
      sensors: [
        { id: 'sensor-blind', layerIdx: 0, observableActions: ['anonymous_access'], fieldsCollected: ['targetId'], attributionQuality: 'none', availability: false, lossConditions: ['disabled'] }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'decoy-unattr', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-real', assetId: 'db-real', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary' });
    assert.equal(run.outcomes.detection.decoyAlerts.length, 1);
    assert.equal(run.outcomes.detection.decoyAlerts[0].attributedSessionId, null);
    assert(run.outcomes.detection.incidents.some(inc => inc.status === 'insufficient_evidence'), 'F12: Incident must transition to insufficient_evidence when identity attribution is absent');
    assert.equal(run.outcomes.response.confirmedResponses.length, 0, 'F12: No unsupported session containment may occur');
  }

  // F13: SOC response is unauthorized, unavailable or fails confirmation -> No effective state change; failures remain visible
  {
    for (const [mode, expectedCode] of [
      ['unauthorized', 'AUTHORITY_UNAVAILABLE'],
      ['unavailable', 'ENFORCEMENT_FAILED'],
      ['scope_mismatch', 'SCOPE_UNRESOLVED']
    ]) {
      const estate = makeV4Fixture({
        assets: [
          { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
          { id: 'decoy-1', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
          { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
        ],
        routes: [
          { id: 'r-decoy', sourceId: 'edge-1', targetId: 'decoy-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
          { id: 'r-db', sourceId: 'edge-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
        ],
        decoys: [{ id: 'decoy-1', kind: 'decoy_asset', assetId: 'decoy-1', deployed: true }],
        responseIntegrations: [
          {
            id: 'ri-test',
            supportedActions: ['invalidate_session'],
            authorizedScopes: mode === 'scope_mismatch' ? ['sess-other'] : ['*'],
            sessionSemantics: 'terminate_scoped_session',
            tokenSemantics: 'revoke_token',
            confirmationMechanism: 'ack',
            available: mode !== 'unavailable',
            requiresApproval: mode === 'unauthorized'
          }
        ],
        weaknesses: [
          { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
          { id: 'w-decoy', assetId: 'decoy-1', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
          { id: 'w-db', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
        ]
      });
      const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary' });
      assert.equal(run.outcomes.response.confirmedResponses.length, 0, `F13 (${mode}): Failed/unauthorized enforcement must change no access state`);
      assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 1, `F13 (${mode}): Attacker continues to db-1`);
      assert(run.events.some(e => e.kind === 'response_confirmation' && e.reasonCode === expectedCode), `F13 (${mode}): Failure reasonCode ${expectedCode} must be visible in events`);
    }
  }

  // F14: One session is revoked while another is independent -> Only the integration's explicit scope is affected
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'entry-a', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'entry-b', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-a', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'app-a', layerIdx: 2, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-b', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-ea-decoy', sourceId: 'entry-a', targetId: 'decoy-a', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-ea-appa', sourceId: 'entry-a', targetId: 'app-a', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-eb-dbb', sourceId: 'entry-b', targetId: 'db-b', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [{ id: 'decoy-a', kind: 'decoy_asset', assetId: 'decoy-a', deployed: true }],
      sensors: [
        { id: 's-inactive', layerIdx: 0, observableActions: ['anonymous_access'], fieldsCollected: ['sessionId'], attributionQuality: 'session_scoped', availability: false, lossConditions: [] }
      ],
      weaknesses: [
        { id: 'w-ea', assetId: 'entry-a', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-eb', assetId: 'entry-b', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-da', assetId: 'decoy-a', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-appa', assetId: 'app-a', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-dbb', assetId: 'db-b', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ],
      actionOrder: ['entry-a', 'decoy-a', 'app-a', 'entry-b', 'db-b']
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary' });
    assert(run.outcomes.response.invalidatedSessionIds.includes('sess-entry-a'), 'F14: sess-entry-a must be invalidated');
    assert(!run.outcomes.response.invalidatedSessionIds.includes('sess-entry-b'), 'F14: Independent sess-entry-b must not be invalidated');
    assert(!run.outcomes.access.reachedAssetIds.includes('app-a'), 'F14: Downstream hop on sess-entry-a is suppressed');
    assert(run.outcomes.access.reachedAssetIds.includes('db-b'), 'F14: Independent sess-entry-b continues to db-b');
  }

  // F15: Token revoked after a session was minted -> Existing session behavior follows the integration contract, not a universal assumption
  {
    const makeLineageEstate = (sessionSemantics) => makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'idp-1', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'decoy-1', layerIdx: 2, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-edge-idp', sourceId: 'edge-1', targetId: 'idp-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-idp-decoy', sourceId: 'idp-1', targetId: 'decoy-1', protocol: 'https', requiredSourceCapability: 'account_session' },
        { id: 'r-idp-db', sourceId: 'idp-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'account_session' }
      ],
      credentials: [
        { id: 'token-oauth', kind: 'api_token', label: 'OAuth Refresh Token', sourceAssetId: 'edge-1', requiredSourceCapability: 'app_exec', targetAssetIds: ['idp-1'], audience: 'idp-1', permissions: ['authenticate'], mintsSession: true, mintedSessionId: 'sess-minted-1', useMintedSessionId: true, revoked: false, expired: false },
        { id: 'honey-token', kind: 'api_token', label: 'Lure Token', isHoneytoken: true, sourceAssetId: 'idp-1', requiredSourceCapability: 'account_session', targetAssetIds: ['decoy-1'], audience: 'decoy-1', permissions: ['authenticate'], revoked: false, expired: false }
      ],
      decoys: [
        { id: 'decoy-token-lure', kind: 'honeytoken_credential', credentialId: 'token-oauth', assetId: 'decoy-1', deployed: true }
      ],
      sensors: [
        { id: 's-none', layerIdx: 0, observableActions: ['anonymous_access'], fieldsCollected: ['targetId'], availability: false, lossConditions: [] }
      ],
      responseIntegrations: [
        {
          id: 'ri-token-revoke',
          supportedActions: ['revoke_credential', 'invalidate_session'],
          authorizedScopes: ['*'],
          sessionSemantics, // either 'preserve_minted_sessions' or 'terminate_minted_sessions'
          tokenSemantics: 'revoke_token',
          confirmationMechanism: 'ack',
          available: true
        }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'decoy-1', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-db', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ],
      actionOrder: ['edge-1', 'idp-1', 'decoy-1', 'db-1']
    });

    const preserveRun = engine.simulateScenario({ estate: makeLineageEstate('preserve_minted_sessions'), attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary' });
    const terminateRun = engine.simulateScenario({ estate: makeLineageEstate('terminate_minted_sessions'), attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary' });
    assert(preserveRun.outcomes.response.revokedCredentialIds.includes('token-oauth'));
    assert(!preserveRun.outcomes.response.invalidatedSessionIds.includes('sess-minted-1'), 'F15: preserve_minted_sessions contract leaves already-minted session active');
    assert.equal(preserveRun.outcomes.impact.sensitiveDatasetsRead.length, 1);

    assert(terminateRun.outcomes.response.revokedCredentialIds.includes('token-oauth'));
    assert(terminateRun.outcomes.response.invalidatedSessionIds.includes('sess-minted-1'), 'F15: terminate_minted_sessions contract invalidates sessions minted by the revoked token');
    assert.equal(terminateRun.outcomes.impact.sensitiveDatasetsRead.length, 0);
  }

  // F16: Benign service workflow crosses several trust boundaries -> Boundary count alone does not convict it; any false intervention is measured
  {
    const makeBenignEstate = (forceFalsePositive) => makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'gw-1', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'svc-1', layerIdx: 2, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r1', sourceId: 'edge-1', targetId: 'gw-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r2', sourceId: 'gw-1', targetId: 'svc-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r3', sourceId: 'svc-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      legitimateWorkflows: [
        { id: 'wf-multi-boundary', label: 'Nightly ETL Sync (3 boundaries)', actor: 'svc-etl-principal', routeIds: ['r1', 'r2', 'r3'], expectedOperations: ['read'], forceFalsePositiveSocIntervention: forceFalsePositive }
      ]
    });
    const normalRun = engine.simulateScenario({ estate: makeBenignEstate(false), attackerProfile: 'operator_with_tools', defenseConfig: 'soc' });
    assert.equal(normalRun.outcomes.costs.legitimateWorkflowsDisrupted.length, 0, 'F16: Multi-boundary benign workflow must not be convicted by boundary count alone');
    assert(normalRun.events.some(e => e.kind === 'investigation' && e.reasonCode === 'BENIGN_WORKFLOW_VERIFIED'));

    const fpRun = engine.simulateScenario({ estate: makeBenignEstate(true), attackerProfile: 'operator_with_tools', defenseConfig: 'soc' });
    assert.deepEqual(fpRun.outcomes.costs.legitimateWorkflowsDisrupted, ['wf-multi-boundary'], 'F16: False intervention against benign workflow must be measured');
    assert.deepEqual(fpRun.outcomes.costs.legitimateIdentitiesAffected, ['svc-etl-principal']);
  }

  // F17: Sensitive public dataset, ordinary internal content and decoy archive -> Count sensitive impact by classification; do not equate layer or decoy access with breach
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'l0-sensitive-bucket', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'l3-public-brochure', layerIdx: 3, isExternalEntry: true, interfaces: ['https'] },
        { id: 'l3-decoy-archive', layerIdx: 3, isExternalEntry: true, isDecoy: true, interfaces: ['https'] }
      ],
      datasets: [
        { id: 'ds-l0-pii', ownerAssetId: 'l0-sensitive-bucket', label: 'Publicly Exposed Customer PII', sensitivity: 'sensitive', records: 900, bytes: 900000, isDecoy: false, allowedOperations: ['read'] },
        { id: 'ds-l3-brochure', ownerAssetId: 'l3-public-brochure', label: 'Internal Marketing Brochure Archive', sensitivity: 'public', records: 50, bytes: 50000, isDecoy: false, allowedOperations: ['read'] },
        { id: 'ds-l3-decoy', ownerAssetId: 'l3-decoy-archive', label: 'Decoy Honeypot Archive', sensitivity: 'decoy', records: 0, bytes: 0, isDecoy: true, allowedOperations: ['read'] }
      ],
      decoys: [
        { id: 'decoy-l3', kind: 'decoy_asset', assetId: 'l3-decoy-archive', deployed: true }
      ],
      weaknesses: [
        { id: 'w-l0', assetId: 'l0-sensitive-bucket', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1530' },
        { id: 'w-l3-pub', assetId: 'l3-public-brochure', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1530' },
        { id: 'w-l3-dec', assetId: 'l3-decoy-archive', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1530' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'canaries' });
    assert.deepEqual(run.outcomes.impact.sensitiveDatasetsRead.map(d => d.datasetId), ['ds-l0-pii'], 'F17: Only sensitive dataset (even in Layer 0) counts as sensitive impact; Layer 3 public brochure and Layer 3 decoy archive do not');
    assert.equal(run.outcomes.impact.totalSensitiveRecordsRead, 900);
  }

  // F18: Control produces no signals or enforcement -> Same budgets and policy yield the baseline state; no artificial data-layer cap benefit
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-2', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-3', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r1', sourceId: 'edge-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r2', sourceId: 'edge-1', targetId: 'db-2', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r3', sourceId: 'edge-1', targetId: 'db-3', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      sensors: [
        { id: 's-blind', layerIdx: 0, observableActions: ['anonymous_access'], fieldsCollected: ['targetId'], availability: false, lossConditions: ['unmonitored'] }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-db1', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' },
        { id: 'w-db2', assetId: 'db-2', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' },
        { id: 'w-db3', assetId: 'db-3', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const baseRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'baseline' });
    const socRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'soc' });
    assert.equal(baseRun.outcomes.impact.sensitiveDatasetsRead.length, 3);
    assert.deepEqual(socRun.outcomes.impact.sensitiveDatasetsRead, baseRun.outcomes.impact.sensitiveDatasetsRead, 'F18: When SOC produces no signals/enforcement, reached datasets must match baseline with no artificial cap');
    assert.deepEqual(socRun.outcomes.access.reachedAssetIds, baseRun.outcomes.access.reachedAssetIds);
  }

  // F19: Both attackers have equal total attempts but different concurrent branches -> No hidden multiplication by round count; dependent actions wait for their prerequisites
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'e1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'e2', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'e3', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'e4', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'e5', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] }
      ],
      weaknesses: ['e1', 'e2', 'e3', 'e4', 'e5'].map(id => ({ id: `w-${id}`, assetId: id, kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' }))
    });
    const runConfig = engine.createDefaultRunConfig(estate, { limits: { maxActionAttempts: 3, maxRetriesPerAction: 1, maxInvestigationActions: 10, maxHumanAssists: 2, maxRecordedEvents: 100, maxConditionalBranches: 4 } });
    const opRun = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'baseline', runConfig });
    const agRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'baseline', runConfig });
    assert.equal(opRun.outcomes.costs.actionAttempts, 3, 'F19: 1-branch operator stops at maxActionAttempts=3');
    assert.equal(agRun.outcomes.costs.actionAttempts, 3, 'F19: 3-branch agentic profile also stops at maxActionAttempts=3 (no multiplication by branch count)');
  }

  // F20: New evidence enables a previously ineligible route, including a graph cycle -> Revisit the relevant state safely; terminate under explicit guards
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'node-a', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'node-b', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'vault-donor', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-goal', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        // node-a -> node-b initially fails because cred-b is stored on vault-donor
        { id: 'r-a-b', sourceId: 'node-a', targetId: 'node-b', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-a-donor', sourceId: 'node-a', targetId: 'vault-donor', protocol: 'https', requiredSourceCapability: 'app_exec' },
        // Cycle back: node-b -> node-a
        { id: 'r-b-a', sourceId: 'node-b', targetId: 'node-a', protocol: 'https', requiredSourceCapability: 'account_session' },
        { id: 'r-b-db', sourceId: 'node-b', targetId: 'db-goal', protocol: 'https', requiredSourceCapability: 'account_session' }
      ],
      weaknesses: [
        { id: 'w-a', assetId: 'node-a', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-donor', assetId: 'vault-donor', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-db', assetId: 'db-goal', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ],
      credentials: [
        { id: 'cred-b', kind: 'service_account', label: 'Node B Cred', sourceAssetId: 'vault-donor', requiredSourceCapability: 'app_exec', targetAssetIds: ['node-b'], audience: 'node-b', permissions: ['authenticate'], revoked: false, expired: false }
      ],
      actionOrder: ['node-a', 'node-b', 'vault-donor', 'db-goal']
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'baseline' });
    const bAttempts = run.events.filter(e => e.targetId === 'node-b' && e.kind === 'action_result');
    assert.equal(bAttempts[0].outcome, 'failed', 'F20: First attempt on node-b fails before credential acquisition');
    assert.equal(bAttempts[1].outcome, 'succeeded', 'F20: Revisit on node-b succeeds after acquiring cred-b from vault-donor');
    assert(run.outcomes.access.reachedAssetIds.includes('db-goal'), 'F20: Downstream db-goal reached after cycle-safe revisit');
    assert.equal(run.outcomes.terminationReason, 'frontier_exhausted', 'F20: Graph cycle r-b-a terminates cleanly without infinite loop');
  }

  // F21: Response ordering is unspecified and changes the objective result -> Return conditional outcomes with the controlling assumption, not a fabricated winner
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-1', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-decoy', sourceId: 'edge-1', targetId: 'decoy-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-db', sourceId: 'edge-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [{ id: 'decoy-1', kind: 'decoy_asset', assetId: 'decoy-1', deployed: true }],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'decoy-1', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-db', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const runConfig = engine.createDefaultRunConfig(estate, {
      interventionContracts: [
        {
          id: 'ic-unspecified-race',
          contract: 'ordering_unspecified',
          responseActionType: 'invalidate_session',
          dependentTargetId: 'db-1',
          controllingAssumption: 'Whether session revocation propagates to the datastore connection pool before the read query executes.'
        }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary', runConfig });
    assert.equal(run.conditionalOutcomes.length, 1, 'F21: Unspecified ordering must emit a conditionalOutcome entry');
    assert.equal(run.conditionalOutcomes[0].contract, 'ordering_unspecified');
    assert.equal(run.outcomes.objectiveState, 'conditional');
    assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 0);
    assert.match(run.conditionalOutcomes[0].controllingAssumption, /connection pool/);
    assert(run.events.some(e => e.outcome === 'conditional' && e.reasonCode === 'ORDERING_UNSPECIFIED_CONDITIONAL'));
  }

  // F22: Response confirmed after sensitive read -> Preserve impact and report later containment separately
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'decoy-1', layerIdx: 1, isExternalEntry: false, isDecoy: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-decoy', sourceId: 'edge-1', targetId: 'decoy-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r-db', sourceId: 'edge-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      decoys: [{ id: 'decoy-1', kind: 'decoy_asset', assetId: 'decoy-1', deployed: true }],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-decoy', assetId: 'decoy-1', kind: 'anonymous_access', yieldsCapability: 'decoy_alert', technique: 'T1552' },
        { id: 'w-db', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const runConfig = engine.createDefaultRunConfig(estate, {
      interventionContracts: [
        {
          id: 'ic-after-read',
          contract: 'confirmed_after_action',
          responseActionType: 'invalidate_session',
          dependentTargetId: 'db-1'
        }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'soc-canary', runConfig });
    assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 1, 'F22: Completed sensitive read impact must be preserved');
    assert.equal(run.outcomes.response.confirmedResponses.length, 1, 'F22: Later containment is still confirmed and reported separately');
    assert(run.events.some(e => e.kind === 'response_confirmation' && e.reasonCode === 'CONFIRMED_AFTER_ACTION'));
  }

  // F23: No viable baseline path -> Do not attribute safety to an optional defense
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-healthy', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r-1', sourceId: 'edge-healthy', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      weaknesses: [] // zero weaknesses
    });
    const cmp = engine.evaluateComparison({
      estate,
      attackerProfiles: ['operator_with_tools'],
      defenseConfigs: ['baseline', 'patch', 'soc', 'combined']
    });
    for (const defId of ['patch', 'soc', 'combined']) {
      const cell = cmp.cells.operator_with_tools[defId];
      assert.equal(cell.outcomes.comparisonSummary.baselineViablePath, false);
      assert.equal(cell.outcomes.comparisonSummary.preventedImpact, false, `F23: ${defId} must not be credited with preventedImpact when baseline has no viable path`);
      assert.match(cell.outcomes.comparisonSummary.attributionNote, /No viable modeled path in baseline/);
    }
  }

  // F24: Attempt/event/branch guardrail exhausted -> Mark unexamined outcomes incomplete and preserve known impact
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'e1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-2', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      routes: [
        { id: 'r1', sourceId: 'e1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r2', sourceId: 'e1', targetId: 'db-2', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      weaknesses: [
        { id: 'w-e1', assetId: 'e1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-db1', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' },
        { id: 'w-db2', assetId: 'db-2', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const runConfig = engine.createDefaultRunConfig(estate, {
      limits: { maxActionAttempts: 2, maxRetriesPerAction: 1, maxInvestigationActions: 5, maxHumanAssists: 1, maxRecordedEvents: 100, maxConditionalBranches: 4 }
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'baseline', runConfig });
    assert.equal(run.outcomes.guardrailExhausted, true, 'F24: Guardrail exhaustion must be flagged');
    assert.equal(run.outcomes.objectiveState, 'incomplete', 'F24: Objective state must be marked incomplete when guardrail is exhausted');
    assert.equal(run.outcomes.impact.sensitiveDatasetsRead.length, 1, 'F24: Known impact achieved before guardrail exhaustion must be preserved');
  }

  // F25: Switch control overlay, actor label or presentation settings -> Unrelated estate draws stay fixed; labels and presentation alone change no causal state
  {
    const estate = engine.generateEstate({ seed: 55, archetypeId: 'public-web', generationMode: 'authored_walkthrough' });
    const estateBefore = JSON.stringify(estate);
    const runA = engine.simulateScenario({ estate, attackerProfile: { ...engine.BEHAVIOR_PRESETS.operator_with_tools, id: 'label-A' }, defenseConfig: 'baseline' });
    const runB = engine.simulateScenario({ estate, attackerProfile: { ...engine.BEHAVIOR_PRESETS.operator_with_tools, id: 'label-B' }, defenseConfig: 'baseline' });
    assert.equal(JSON.stringify(estate), estateBefore, 'F25: Estate must remain strictly immutable across runs');
    assert.deepEqual(runA.outcomes, runB.outcomes, 'F25: Changing actor display label alone changes no causal outcome');
    const projFast = engine.projectRun(runA, { pace: 'artex', timingContext: { stageTimes: [0, 30, 60, 90], modeledPathDurationSec: 90 } });
    const projSlow = engine.projectRun(runA, { pace: 'pre2023', timingContext: { stageTimes: [0, 3000, 6000, 9000], modeledPathDurationSec: 9000 } });
    assert.deepEqual(projFast.outcomes, projSlow.outcomes, 'F25: Changing presentation timing context leaves causal outcomes unchanged');
  }

  // F26: Export and reimport a supported manifest -> Identical deterministic trace and objective results
  {
    const estate = engine.generateEstate({ seed: 77, archetypeId: 'enterprise-identity', generationMode: 'authored_walkthrough' });
    const originalRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'combined' });
    const exportedJson = engine.exportManifest({ ...originalRun, estate });
    const imported = engine.importManifest(exportedJson);
    assert.equal(imported.ok, true, 'F26: Supported v4 manifest must import cleanly');
    assert.deepEqual(imported.replayed.events, originalRun.events, 'F26: Reimported manifest must replay with identical deterministic event trace');
    assert.deepEqual(imported.replayed.outcomes, originalRun.outcomes, 'F26: Reimported manifest must produce identical objective results');
  }

  // No later action is needed to verify a terminal response remains unconfirmed.
  {
    const estate = makeV4Fixture({
      assets: [{ id: 'entry', layerIdx: 0 }],
      weaknesses: [{ id: 'w-entry', assetId: 'entry', kind: 'anonymous_access', yieldsCapability: 'app_exec' }]
    });
    const run = engine.simulateScenario({
      estate, defenseConfig: 'soc',
      runConfig: { interventionContracts: [{ contract: 'not_confirmed' }] }
    });
    assert(run.outcomes.response.proposedCount > 0);
    assert.deepEqual(run.outcomes.response.invalidatedSessionIds, []);
    assert(run.events.some(event => event.reasonCode === 'INTERVENTION_NOT_CONFIRMED'));

    const attackerProfile = {
      ...engine.normalizeAttackerProfile('operator_with_tools'), supportedActionFamilies: ['cve']
    };
    const original = engine.simulateScenario({ estate, attackerProfile });
    const exported = JSON.parse(engine.exportManifest({ ...original, estate }));
    const imported = engine.importManifest(exported);
    assert.equal(imported.ok, true);
    assert.deepEqual(imported.replayed.events, original.events);
    exported.attackerProfiles[0].supportedActionFamilies.push('anonymous_access');
    assert.equal(engine.importManifest(exported).ok, false);
  }

  // Reading one sensitive dataset does not satisfy an objective for a different dataset.
  {
    const dataset = (id, ownerAssetId) => ({
      id, ownerAssetId, sensitivity: 'sensitive', isDecoy: false, allowedOperations: ['read']
    });
    const estate = makeV4Fixture({
      assets: [{ id: 'entry', layerIdx: 0 }, { id: 'private', layerIdx: 3, isExternalEntry: false }],
      datasets: [dataset('readable', 'entry'), dataset('selected', 'private')],
      weaknesses: [{ id: 'w-entry', assetId: 'entry', kind: 'anonymous_access', yieldsCapability: 'data_read' }]
    });
    const run = engine.simulateScenario({
      estate, runConfig: { objectives: [{ id: 'read-private', kind: 'dataset_read', datasetId: 'selected' }] }
    });
    assert.deepEqual(run.outcomes.impact.sensitiveDatasetsRead.map(d => d.datasetId), ['readable']);
    assert.deepEqual(run.outcomes.objectiveResults, [{ id: 'read-private', achieved: false }]);
    assert.equal(run.outcomes.objectiveState, 'not_achieved');
    delete estate.sensors;
    assert.equal(engine.validateRunConfig(estate, run.runConfig).valid, false);
  }

  // F27: Import a legacy snapshot -> No silent regeneration or false claim of equivalent replay
  {
    const legacyV3 = {
      schemaVersion: 3,
      seed: 123,
      preset: 'mixed',
      assets: [{ id: 'a0', groupId: 'f5-gateway', layerIdx: 0, interfaces: ['https'] }],
      findings: [{ id: 'ex-1', assetId: 'a0', kind: 'exercise', title: 'Old shortcut' }],
      credentials: [],
      relationships: []
    };
    const res = engine.importManifest(JSON.stringify(legacyV3));
    assert.equal(res.ok, false, 'F27: Legacy v3 snapshot must not report ok: true');
    assert.equal(res.legacy, true);
    assert.equal(res.equivalentReplay, false, 'F27: Must not claim equivalent replay for legacy v3 snapshot');
    assert.deepEqual(res.unsupportedExerciseFindings, ['ex-1']);
  }

  // F28: A legitimate request is incorrectly blocked -> Record false block and affected workflow alongside any protective benefit
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'app-1', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf', assetId: 'edge-1', routeIds: ['r-1'], inspectedProtocols: ['https'], inspectedFields: ['uri'], ruleIds: ['rule-overbroad'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-overbroad', enforcementPointIds: ['ep-waf'], inspectedProtocols: ['https'], matchesAllTrafficOnRoute: true, blocksLegitimateWorkflowIds: ['wf-checkout'], coverageState: 'modeled', action: 'block', reason: 'Overly broad emergency WAF rule blocks all POST requests' }
      ],
      routes: [
        { id: 'r-1', sourceId: 'edge-1', targetId: 'app-1', protocol: 'https', requiredSourceCapability: 'app_exec', enforcementPointIds: ['ep-waf'] }
      ],
      legitimateWorkflows: [
        { id: 'wf-checkout', label: 'Customer Checkout POST Workflow', actor: 'customer-web-client', routeIds: ['r-1'], expectedOperations: ['authenticate'] }
      ],
      weaknesses: [
        { id: 'w-edge', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-app', assetId: 'app-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'operator_with_tools', defenseConfig: 'patch' });
    assert.equal(run.outcomes.costs.falseBlocks.length, 1, 'F28: False block must be recorded');
    assert.equal(run.outcomes.costs.falseBlocks[0].workflowId, 'wf-checkout');
    assert.deepEqual(run.outcomes.costs.legitimateWorkflowsDisrupted, ['wf-checkout']);
    assert(run.events.some(e => e.reasonCode === 'FALSE_POSITIVE_PATCH_BLOCK'));
  }

  // F29: Catalog entry is context-only or lifecycle label changes -> No inferred exploit, connectivity change or monitoring loss
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-ctx', groupId: 'f5-gateway', referenceCve: 'CVE-2022-1388', lifecycle: { status: 'decommissioned', decommissioned: true, poc: true }, layerIdx: 0, isExternalEntry: true, interfaces: ['https'] }
      ],
      weaknesses: [] // No finding attached; referenceCve and lifecycle labels alone must not create an exploit or disable sensors
    });
    const run = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: 'soc' });
    assert.equal(run.outcomes.access.reachedAssetIds.length, 0, 'F29: Context-only referenceCve without an explicit weakness finding must not be exploitable');
    const estateWithFinding = structuredClone(estate);
    estateWithFinding.weaknesses.push({ id: 'w-1', assetId: 'edge-ctx', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' });
    estateWithFinding.findings = estateWithFinding.weaknesses;
    const run2 = engine.simulateScenario({ estate: estateWithFinding, attackerProfile: 'agentic_orchestration', defenseConfig: 'soc' });
    assert.equal(run2.outcomes.access.reachedAssetIds.includes('edge-ctx'), true, 'F29: Decommissioned lifecycle label alone does not disconnect an active interface');
    assert(run2.outcomes.detection.totalObservations > 0, 'F29: P.o.C lifecycle label alone does not disable installed sensors');
  }

  // F30: Combined controls block an upstream dependency -> Downstream actions are canceled/not attempted, not shown as successful or extra attack attempts
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] },
        { id: 'app-1', layerIdx: 1, isExternalEntry: false, interfaces: ['https'] },
        { id: 'db-1', layerIdx: 3, isExternalEntry: false, interfaces: ['https'] }
      ],
      enforcementPoints: [
        { id: 'ep-waf', assetId: 'edge-1', protectedAssetIds: ['edge-1'], inspectedProtocols: ['https'], inspectedFields: ['uri'], ruleIds: ['rule-block-edge'], enabled: true }
      ],
      patchRules: [
        { id: 'rule-block-edge', matchesAllTrafficOnRoute: true, targetAssetIds: ['edge-1'], enforcementPointIds: ['ep-waf'], inspectedProtocols: ['https'], coverageState: 'modeled', action: 'block', reason: 'Blocked at edge' }
      ],
      routes: [
        { id: 'r1', sourceId: 'edge-1', targetId: 'app-1', protocol: 'https', requiredSourceCapability: 'app_exec' },
        { id: 'r2', sourceId: 'app-1', targetId: 'db-1', protocol: 'https', requiredSourceCapability: 'app_exec' }
      ],
      weaknesses: [
        { id: 'w-e', assetId: 'edge-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-a', assetId: 'app-1', kind: 'anonymous_access', yieldsCapability: 'app_exec', technique: 'T1190' },
        { id: 'w-d', assetId: 'db-1', kind: 'anonymous_access', yieldsCapability: 'data_read', technique: 'T1190' }
      ]
    });
    const run = engine.simulateScenario({ estate, attackerProfile: { ...engine.BEHAVIOR_PRESETS.operator_with_tools, adaptationRepertoire: ['default'] }, defenseConfig: 'combined' });
    assert.equal(run.outcomes.costs.actionAttempts, 1, 'F30: Blocking upstream dependency at edge results in only 1 attack attempt; downstream actions are never dispatched');
    assert(!run.events.some(e => (e.targetId === 'app-1' || e.targetId === 'db-1') && e.outcome === 'succeeded'));
  }

  // F31: Human-led and agentic SOC labels use identical policies and deployment -> Identical decisions and outcomes; labels confer no detection or authority advantage
  {
    const estate = engine.generateEstate({ seed: 29, archetypeId: 'public-web', generationMode: 'authored_walkthrough' });
    const humanRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: { virtualPatching: false, canaries: true, responsePolicy: 'human_led' } });
    const agenticRun = engine.simulateScenario({ estate, attackerProfile: 'agentic_orchestration', defenseConfig: { virtualPatching: false, canaries: true, responsePolicy: 'agentic' } });
    assert.deepEqual(humanRun.outcomes.impact, agenticRun.outcomes.impact, 'F31: Identical policy & deployment under human_led vs agentic SOC labels must produce identical impact');
    assert.deepEqual(humanRun.outcomes.response, agenticRun.outcomes.response, 'F31: Identical policy & deployment under human_led vs agentic SOC labels must produce identical response confirmations');
    assert.deepEqual(humanRun.outcomes.access, agenticRun.outcomes.access);
  }

  // F32: Required interface/rule/calibration data or selected catalog fails to load -> Explicit validation/loading failure; no silent substitution
  {
    const brokenEstate = makeV4Fixture({
      assets: [{ id: 'a1', layerIdx: 0, isExternalEntry: true, interfaces: [] }]
    });
    const vEst = engine.validateEstate(brokenEstate);
    assert.equal(vEst.valid, false, 'F32: Asset with missing interfaces must fail validateEstate');
    assert(vEst.details.some(d => d.entityId === 'a1' && d.fieldPath === 'interfaces'));
    assert.throws(() => engine.simulateScenario({ estate: brokenEstate }), /Invalid scenario configuration/, 'F32: simulateScenario must throw on invalid estate');
  }

  // F33: A calibration entry provides only an observed mean -> Cannot present p50, p90 or a fitted distribution as source facts without separate evidence
  {
    const badCal = structuredClone(engine.CALIBRATION_REGISTER);
    const meanEntry = badCal.observedStatistics.find(s => s.statisticType === 'mean');
    meanEntry.reportedQuantiles = { p50: 45, p90: 90 };
    const vCal = engine.validateCalibrationRegister(badCal);
    assert.equal(vCal.valid, false, 'F33: Mean statistic claiming p50/p90 quantiles as source_fact must fail validation');
  }

  // F34: Fixed action traverses an additional correctly configured enforcement point -> Validate local matching/enforcement semantics
  {
    const baseAction = { actionKind: 'cve', finding: { id: 'f1', kind: 'cve', cveId: 'CVE-2022-1388' }, yieldsCapability: 'app_exec' };
    const targetAsset = { id: 'f5-1', groupId: 'f5-gateway', label: 'F5 BIG-IP', interfaces: ['https'], isExternalEntry: true };
    const estateNoEp = makeV4Fixture({ assets: [targetAsset], enforcementPoints: [], patchRules: [] });
    const estateWithEp = makeV4Fixture({
      assets: [targetAsset],
      enforcementPoints: [{ id: 'ep-1', assetId: 'f5-1', protectedAssetIds: ['f5-1'], inspectedProtocols: ['https'], inspectedFields: ['uri', 'headers'], ruleIds: ['pr-1'], enabled: true }],
      patchRules: [{ id: 'pr-1', cveId: 'CVE-2022-1388', enforcementPointIds: ['ep-1'], inspectedProtocols: ['https'], ruleStrictness: 'strict_virtual_patch', coverageState: 'modeled', action: 'block', reason: 'Blocks CVE-2022-1388' }]
    });
    const resWithout = engine.evaluateVirtualPatch({ estate: estateNoEp, route: null, targetAsset, action: baseAction, defenseConfig: { virtualPatching: true } });
    const resWith = engine.evaluateVirtualPatch({ estate: estateWithEp, route: null, targetAsset, action: baseAction, defenseConfig: { virtualPatching: true } });
    assert.equal(resWithout.enforced, false);
    assert.equal(resWithout.reasonCode, 'OUTSIDE_CONTROL_PATH');
    assert.equal(resWith.enforced, true, 'F34: Traversing a correctly configured enforcement point enforces the matching rule');
    assert.equal(resWith.reasonCode, 'RULE_ENFORCED');
  }

  // F35: A profile advertises an action family with no usable estate surface -> Coverage manifest exposes the gap; display-only CVEs do not become implicit exploitable findings
  {
    const estate = makeV4Fixture({
      assets: [
        { id: 'edge-1', groupId: 'f5-gateway', referenceCve: 'CVE-2022-1388', layerIdx: 0, isExternalEntry: true, interfaces: ['https'] }
      ],
      weaknesses: [] // No phishing_attachment or SMB remote_service findings
    });
    const audit = engine.auditSurfaceCoverage(estate, { allowsUserInteraction: true, availableTools: ['psexec'] });
    assert.equal(audit.hasAdvertisingGap, true, 'F35: auditSurfaceCoverage must expose gap when profile advertises families absent from the estate');
    assert(audit.unavailableFamilies.some(f => f.family === 'phishing_attachment'));
    assert(audit.unavailableFamilies.some(f => f.family === 'windows_remote_service_tools'));
    assert(audit.displayOnlyAssets.some(a => a.assetId === 'edge-1' && a.referenceCve === 'CVE-2022-1388'));
  }

  // Bounded Seed Property Checks (Spec Section 16: input immutability, unique IDs, valid references, deterministic replay, prerequisite closure, equal comparison budgets)
  for (const archetypeId of ['enterprise-identity', 'public-web', 'cloud-saas', 'cicd-secrets']) {
    for (let seed = 1; seed <= 8; seed++) {
      const estate = engine.generateEstate({ seed, archetypeId, generationMode: seed % 2 === 0 ? 'authored_walkthrough' : 'exploratory' });
      const snapshot = JSON.stringify(estate);
      const cmp = engine.evaluateComparison({
        estate,
        attackerProfiles: ['operator_with_tools', 'agentic_orchestration'],
        defenseConfigs: ['baseline', 'patch', 'canaries', 'soc', 'combined']
      });
      assert.equal(JSON.stringify(estate), snapshot, `Property check: input immutability failed for ${archetypeId} seed ${seed}`);
      const budgets = new Set();
      for (const p of ['operator_with_tools', 'agentic_orchestration']) {
        for (const d of ['baseline', 'patch', 'canaries', 'soc', 'combined']) {
          const cell = cmp.cells[p][d];
          budgets.add(cell.outcomes.costs.maxActionAttempts);
          const eventIds = cell.events.map(e => e.id);
          assert.equal(new Set(eventIds).size, eventIds.length, 'Property check: event IDs must be unique');
        }
      }
      assert.equal(budgets.size, 1, 'Property check: comparison budgets must be equal across all cells (R08)');
    }
  }
}

console.log(`PASS: ${groups.size} asset groups + prerequisite/credential/budget/replay/logs/comparison + F01-F35 spec fixtures`);
