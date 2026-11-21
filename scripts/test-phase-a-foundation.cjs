#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const engine = require('../js/wire-engine.js');
const catalogPath = path.join(__dirname, '..', 'assets', 'wire-defense-catalog.json');
const calibrationPath = path.join(__dirname, '..', 'assets', 'calibration.json');

let passed = 0;
function check(label, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  PASS  ${label}`);
  } catch (err) {
    console.error(`  FAIL  ${label}`);
    console.error(`        ${err.message}`);
    process.exit(1);
  }
}

console.log('\n── Phase A: Foundation & Integrity (WP1 + WP2) Verification ──');

// 1. Calibration Register (WP1, R14, F32, F33)
check('F32/F33: assets/calibration.json exists and passes validateCalibrationRegister', () => {
  assert(fs.existsSync(calibrationPath), 'assets/calibration.json must exist');
  const raw = JSON.parse(fs.readFileSync(calibrationPath, 'utf8'));
  const result = engine.validateCalibrationRegister(raw);
  assert.strictEqual(result.valid, true, `Calibration register invalid: ${result.errors.join('; ')}`);
  assert(Array.isArray(raw.observedStatistics) && raw.observedStatistics.length >= 6, 'Expected at least 6 observedStatistics entries');
  assert(Array.isArray(raw.simulationAssumptions) && raw.simulationAssumptions.length >= 10, 'Expected at least 10 simulationAssumptions entries');
  raw.observedStatistics.forEach((entry) => {
    assert.strictEqual(entry.provenanceType, 'historical_source');
    assert.strictEqual(entry.displayClassification, 'source_fact');
  });
  raw.simulationAssumptions.forEach((entry) => {
    assert.strictEqual(entry.displayClassification, 'synthetic_assumption');
  });
});

check('F33: validateCalibrationRegister rejects observed mean claiming p50/p90 quantiles or fittedDistribution', () => {
  const raw = JSON.parse(fs.readFileSync(calibrationPath, 'utf8'));
  const badQuantile = JSON.parse(JSON.stringify(raw));
  const meanStat = badQuantile.observedStatistics.find((s) => s.statisticType === 'mean');
  meanStat.reportedQuantiles = { p50: 48, p90: 120 };
  const res1 = engine.validateCalibrationRegister(badQuantile);
  assert.strictEqual(res1.valid, false, 'Expected rejection when observed mean claims p50/p90 quantiles');
  assert(res1.details.some((d) => d.fieldPath === 'reportedQuantiles'), 'Expected reportedQuantiles detail');

  const badDist = JSON.parse(JSON.stringify(raw));
  const meanStat2 = badDist.observedStatistics.find((s) => s.statisticType === 'mean');
  meanStat2.fittedDistribution = 'lognormal';
  const res2 = engine.validateCalibrationRegister(badDist);
  assert.strictEqual(res2.valid, false, 'Expected rejection when source_fact mean claims fittedDistribution');
  assert(res2.details.some((d) => d.fieldPath === 'fittedDistribution'), 'Expected fittedDistribution detail');
});

check('F32: validateCalibrationRegister rejects simulationAssumption with invalid provenance or out-of-range probability', () => {
  const raw = JSON.parse(fs.readFileSync(calibrationPath, 'utf8'));
  const badAssumption = JSON.parse(JSON.stringify(raw));
  badAssumption.simulationAssumptions[0].displayClassification = 'source_fact';
  const res = engine.validateCalibrationRegister(badAssumption);
  assert.strictEqual(res.valid, false, 'Expected rejection when simulationAssumption claims displayClassification="source_fact"');
  assert(res.details.some((d) => d.fieldPath === 'displayClassification'), 'Expected displayClassification detail');

  const badProb = JSON.parse(JSON.stringify(raw));
  const probEntry = badProb.simulationAssumptions.find((a) => a.unit === 'probability');
  probEntry.value = 1.5;
  const resProb = engine.validateCalibrationRegister(badProb);
  assert.strictEqual(resProb.valid, false, 'Expected rejection when probability assumption is outside [0, 1]');
  assert(resProb.details.some((d) => d.fieldPath === 'value'), 'Expected value detail');
});

// 2. Schema v4 Estate & RunConfig Validation across 4 archetypes and both generationModes (WP1 + WP2)
check('WP1/WP2: generateEstate emits Schema v4 across all archetypes and both generation modes', () => {
  assert.strictEqual(engine.SCHEMA_VERSION, 4, 'SCHEMA_VERSION must be 4');
  const archetypes = ['full-enterprise', 'enterprise-identity', 'public-web', 'cloud-saas', 'cicd-secrets'];
  const modes = ['exploratory', 'authored_walkthrough'];

  for (const archetypeId of archetypes) {
    for (const generationMode of modes) {
      const estate = engine.generateEstate({ seed: 42, archetypeId, generationMode });
      assert.strictEqual(estate.schemaVersion, 4, `Expected schemaVersion 4 for ${archetypeId}/${generationMode}`);
      assert.strictEqual(estate.archetypeId, archetypeId, `Expected archetypeId ${archetypeId}`);
      assert.strictEqual(estate.generationMode, generationMode, `Expected generationMode ${generationMode}`);
      assert(Array.isArray(estate.datasets) && estate.datasets.length > 0, 'Expected v4 datasets');
      assert(Array.isArray(estate.routes) && estate.routes.length > 0, 'Expected v4 routes');
      assert(Array.isArray(estate.enforcementPoints) && estate.enforcementPoints.length > 0, 'Expected v4 enforcementPoints');
      assert(Array.isArray(estate.patchRules) && estate.patchRules.length > 0, 'Expected v4 patchRules');
      assert(Array.isArray(estate.sensors) && estate.sensors.length > 0, 'Expected v4 sensors');
      assert(Array.isArray(estate.decoys), 'Expected v4 decoys array');
      assert(Array.isArray(estate.responseIntegrations) && estate.responseIntegrations.length > 0, 'Expected v4 responseIntegrations');
      assert(Array.isArray(estate.identityRelationships), 'Expected v4 identityRelationships array');
      assert(Array.isArray(estate.weaknesses) && estate.weaknesses.length > 0, 'Expected v4 weaknesses');
      assert(Array.isArray(estate.legitimateWorkflows) && estate.legitimateWorkflows.length > 0, 'Expected v4 legitimateWorkflows');
      assert(Array.isArray(estate.assumptions) && estate.assumptions.length > 0, 'Expected v4 assumptions');

      // Ensure zero kind: 'exercise' findings exist anywhere
      for (const f of estate.findings) {
        assert.notStrictEqual(f.kind, 'exercise', `Found banned kind: 'exercise' (${f.id})`);
      }

      const vRes = engine.validateEstate(estate);
      assert.strictEqual(vRes.valid, true, `validateEstate failed for ${archetypeId}/${generationMode}: ${vRes.errors.join('; ')}`);

      const sensitiveDs = estate.datasets.find((d) => d.sensitivity === 'sensitive' && !d.isDecoy);
      const rcRes = engine.validateRunConfig(estate, {
        manifestVersion: engine.RUN_MANIFEST_VERSION,
        trialSeed: 42,
        initialAccess: estate.assets.filter((a) => a.isExternalEntry).map((a) => a.id),
        initialKnowledge: ['public_dns'],
        objectives: [{ id: 'obj-read-primary', kind: 'dataset_read', datasetId: sensitiveDs.id }],
        limits: {
          maxActionAttempts: 250,
          maxRetriesPerAction: 2,
          maxInvestigationActions: 50,
          maxHumanAssists: 3,
          maxRecordedEvents: 500,
          maxConditionalBranches: 16
        },
        uncertaintyMode: 'report_conditional'
      });
      assert.strictEqual(rcRes.valid, true, `validateRunConfig failed for ${archetypeId}/${generationMode}: ${rcRes.errors.join('; ')}`);
    }
  }
});

check('Full enterprise shows all four areas using existing service routes', () => {
  for (const seed of [1, 2, 3, 42, 99]) {
    for (const generationMode of ['authored_walkthrough', 'exploratory']) {
      const options = { seed, archetypeId: 'full-enterprise', generationMode };
      const estate = engine.generateEstate(options);
      const routeIds = new Set(estate.overviewRouteIds);
      const overview = estate.routes.filter(route => routeIds.has(route.id));
      assert.equal(overview.length, routeIds.size);
      const groups = new Map(estate.assets.map(asset => [asset.id, asset.groupId]));
      const overviewPairs = overview.map(route => [groups.get(route.sourceId), groups.get(route.targetId)].join(' → '));
      for (const pair of [
        'forti-vpn → ad-identity', 'windows-management → windows-fleet-finance',
        'f5-gateway → cust-api', 'cust-api → app-engine', 'app-engine → db-rds',
        'cust-api → iot-hub', 'iot-hub → lake-ops',
        'iam-idp → cicd-runner', 'iam-idp → comp-registry', 'forti-vpn → vault-creds'
      ]) assert(overviewPairs.includes(pair), `Missing ${pair} on seed ${seed}`);
      assert.deepEqual(engine.generateEstate(options), estate);
      if (generationMode === 'exploratory') assert.deepEqual(estate.walkthroughRouteAssetIds, []);
    }
  }
});

// 3. F01 / R01: Removal of kind: 'exercise' and honest prerequisite enforcement in instantiateScenario / validateWalkthrough
check('F01/R01: validateEstate rejects kind: "exercise" and validateWalkthrough fails when required prerequisite is removed', () => {
  const estate = engine.generateEstate({ seed: 7, archetypeId: 'enterprise-identity', generationMode: 'authored_walkthrough' });
  const tainted = JSON.parse(JSON.stringify(estate));
  tainted.findings.push({ id: 'bad-ex', assetId: tainted.assets[0].id, kind: 'exercise', title: 'Fake shortcut' });
  const vRes = engine.validateEstate(tainted);
  assert.strictEqual(vRes.valid, false, 'validateEstate must reject kind: "exercise"');
  assert(vRes.details.some((d) => d.reason.includes('exercise')), 'Expected structured error mentioning exercise shortcut');

  // Verify walkthrough validation fails when a stage's findings and credentials are stripped
  const brokenEstate = JSON.parse(JSON.stringify(estate));
  const stage1Id = estate.walkthroughRouteAssetIds[1];
  brokenEstate.findings = brokenEstate.findings.filter((f) => f.assetId !== stage1Id);
  brokenEstate.credentials = brokenEstate.credentials.filter((c) => !(c.targetAssetIds || []).includes(stage1Id));
  const checkRes = engine.validateWalkthrough(brokenEstate, estate.walkthroughRouteAssetIds);
  assert.strictEqual(checkRes.valid, false, 'Expected walkthrough validation to fail when stage 1 prerequisites are removed');
  assert(checkRes.errors.length > 0, 'Expected descriptive prerequisite failure');
});

// 4. F17 / R09: Dataset sensitivity classification independent of layer
check('F17/R09: Protected-data breach depends on dataset sensitivity classification, not diagram layer', () => {
  const estate = engine.generateEstate({ seed: 11, archetypeId: 'public-web', generationMode: 'authored_walkthrough' });

  const layer0Asset = estate.assets.find((a) => a.layerIdx === 0 && !a.isDecoy);
  const layer3Assets = estate.assets.filter((a) => a.layerIdx === 3 && !a.isDecoy);
  assert(layer0Asset && layer3Assets.length > 0, 'Expected Layer 0 and Layer 3 assets');

  // Reclassify all Layer 3 datasets as public and assign a sensitive dataset to Layer 0
  for (const ds of estate.datasets) {
    if (ds.ownerAssetId === layer0Asset.id) {
      ds.sensitivity = 'sensitive';
      ds.isDecoy = false;
    } else if (layer3Assets.some((a) => a.id === ds.ownerAssetId)) {
      ds.sensitivity = 'public';
      ds.isDecoy = false;
    }
  }
  if (!estate.datasets.some((ds) => ds.ownerAssetId === layer0Asset.id)) {
    estate.datasets.push({
      id: `dataset-${layer0Asset.id}-edge-pii`,
      ownerAssetId: layer0Asset.id,
      label: 'Edge Cached Customer PII',
      records: 15000,
      bytes: 15000 * 1024,
      sensitivity: 'sensitive',
      isDecoy: false,
      allowedOperations: ['read']
    });
  }
  for (const l3 of layer3Assets) {
    l3.datasetSensitivity = 'public';
  }

  assert.strictEqual(
    engine.isSensitiveDatasetRead(layer0Asset, { yieldsCapability: 'data_read' }, estate, false),
    true,
    'Layer 0 asset owning a sensitive dataset must trigger protected-data read when yieldsCapability is data_read'
  );
  for (const l3 of layer3Assets) {
    assert.strictEqual(
      engine.isSensitiveDatasetRead(l3, { yieldsCapability: 'data_read' }, estate, false),
      false,
      `Layer 3 asset ${l3.id} owning only a public dataset must NOT trigger protected-data read`
    );
  }
});

// 5. F29 / F35: Catalog referenceRole and SURFACE_COVERAGE_MANIFEST audit
check('F29/F35: wire-defense-catalog.json labels all 100 examples with referenceRole and auditSurfaceCoverage passes', () => {
  const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
  assert.strictEqual(catalog.examples.length, 100, 'Expected 100 examples in wire-defense-catalog.json');
  const validRoles = new Set(['modeled_chain', 'modeled_weakness', 'context_only']);
  let contextOnlyCount = 0;
  let modeledCount = 0;
  for (const ex of catalog.examples) {
    assert(validRoles.has(ex.referenceRole), `Example #${ex.num} missing valid referenceRole: ${ex.referenceRole}`);
    if (ex.referenceRole === 'context_only') contextOnlyCount += 1;
    else modeledCount += 1;
  }
  assert(contextOnlyCount > 0 && modeledCount > 0, 'Expected both modeled and context_only examples in catalog');

  const estate = engine.generateEstate({ seed: 19, archetypeId: 'enterprise-identity', generationMode: 'authored_walkthrough' });
  const audit = engine.auditSurfaceCoverage(estate, engine.WIRE_ATTACKERS.lockbit);
  assert.strictEqual(audit.hasAdvertisingGap, false, `Surface coverage audit found gap: ${JSON.stringify(audit.unavailableFamilies)}`);
  assert(Object.keys(audit.manifest.groups).length >= 50, 'Expected all LAYER_CONFIG groups in SURFACE_COVERAGE_MANIFEST');

  // Verify auditSurfaceCoverage detects a gap if Windows email/phishing surfaces are stripped while an attacker profile advertises user-interaction phishing
  const strippedEstate = JSON.parse(JSON.stringify(estate));
  strippedEstate.findings = strippedEstate.findings.filter((f) => f.kind !== 'phishing_attachment');
  const gapAudit = engine.auditSurfaceCoverage(strippedEstate, { allowsUserInteraction: true });
  assert.strictEqual(gapAudit.hasAdvertisingGap, true, 'Expected auditSurfaceCoverage to flag missing phishing_attachment surface');
});

// 6. F27: Legacy v3 snapshot conversion refuses silent regeneration or equivalent replay claims
check('F27: migrateSnapshot marks schemaVersion 3 snapshots with kind: "exercise" as non-equivalent legacy drafts', () => {
  const baseV4 = engine.generateEstate({ seed: 99, archetypeId: 'public-web', generationMode: 'exploratory' });
  const legacyV3 = {
    schemaVersion: 3,
    seed: 99,
    preset: 'mixed',
    assets: baseV4.assets.slice(0, 2),
    findings: [
      { id: 'ex-n0-n1', assetId: baseV4.assets[0].id, kind: 'exercise', title: 'Legacy Exercise Shortcut' }
    ],
    credentials: [],
    relationships: []
  };

  const migrated = engine.migrateSnapshot(legacyV3);
  assert.strictEqual(migrated.ok, false, 'Legacy v3 snapshot with exercise findings must not report ok: true');
  assert.strictEqual(migrated.legacy, true, 'Expected legacy: true');
  assert.strictEqual(migrated.equivalentReplay, false, 'Expected equivalentReplay: false');
  assert.strictEqual(migrated.unsupportedExerciseFindings.length, 1, 'Expected unsupportedExerciseFindings to list the v3 exercise shortcut');
  assert(migrated.missingV4Entities.includes('datasets'), 'Expected missingV4Entities to report missing v4 entities');
  assert(migrated.draftScenario && migrated.draftScenario.findings.length === 0, 'Expected draftScenario to strip unsupported exercise findings');
});

console.log(`\nAll ${passed} Phase A (WP1 + WP2) checks passed.\n`);
