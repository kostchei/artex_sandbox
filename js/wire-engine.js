(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./gang-techniques.js'), require('../assets/calibration.json'));
  } else {
    root.WireEngine = factory(root.GangTechniques, root.WireCalibration || null);
  }
}(typeof self !== 'undefined' ? self : this, function (gangCatalogue, externalCalibration) {
  'use strict';

  const SCHEMA_VERSION = 4;
  const RUN_MANIFEST_VERSION = 1;
  const ENGINE_VERSION = '4.0.0';
  const MAX_ONWARD_PER_SOURCE = 2;
  const MAX_SUCCESS_PER_LAYER = 3;
  const WAF_PORTAL_COVERAGE = 0.66;
  const SOAR_DETECTION_RATE = 0.32;

  const BEHAVIOR_PRESETS = {
    operator_with_tools: {
      id: 'operator_with_tools',
      behaviorPreset: 'operator_with_tools',
      label: 'Operator with tools',
      supportedActionFamilies: ['cve', 'cve_authenticated', 'valid_credential', 'password_spray', 'anonymous_access', 'diagnostic_access', 'phishing_attachment', 'remote_service', 'persistence', 'encryption', 'data_exfiltration'],
      availableTools: ['cobalt_strike', 'psexec'],
      maxConcurrentBranches: 1,
      discoveryPolicy: 'depth_first_foothold',
      adaptationRepertoire: ['default', 'url_encoded_path', 'alternate_header_casing'],
      evidenceVerificationPolicy: 'strict_operator_judgment',
      humanAssistancePolicy: { requiredForAmbiguousContinuation: true, assistCost: 1 },
      retryEffortCost: 1,
      allowsUserInteraction: true,
      allowsPersistence: true,
      allowsRansomwareImpact: true
    },
    agentic_orchestration: {
      id: 'agentic_orchestration',
      behaviorPreset: 'agentic_orchestration',
      label: 'Agentic orchestration',
      supportedActionFamilies: ['cve', 'cve_authenticated', 'valid_credential', 'password_spray', 'anonymous_access', 'diagnostic_access', 'remote_service', 'data_exfiltration'],
      availableTools: [],
      maxConcurrentBranches: 3,
      discoveryPolicy: 'breadth_first_coordinated',
      adaptationRepertoire: ['default', 'url_encoded_path', 'chunked_transfer', 'json_content_type', 'alternate_header_casing'],
      evidenceVerificationPolicy: 'automated_hypothesis_check',
      humanAssistancePolicy: { requiredForAmbiguousContinuation: false, assistCost: 1 },
      retryEffortCost: 1,
      allowsUserInteraction: false,
      allowsPersistence: false,
      allowsRansomwareImpact: false
    }
  };

  function hashSemanticKey(trialSeed, namespace, entityId, actionVariantId = 'default', attemptOrdinal = 0) {
    return hashNode(trialSeed >>> 0, `${namespace}:${entityId}:${actionVariantId}:${attemptOrdinal}`, 0x9e3779b9);
  }

  const DEFAULT_CALIBRATION_REGISTER = {
    schemaVersion: 1,
    asOfDate: '2026-11-16',
    scope: 'Versioned calibration and provenance register separating historical source statistics from synthetic simulation assumptions (Spec Section 6.4, Invariant R14).',
    observedStatistics: [
      {
        id: 'crowdstrike-2021-ecrime-breakout-mean',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'CrowdStrike 2023 Global Threat Report',
        sourceUrl: 'https://www.crowdstrike.com/wp-content/uploads/2023/05/CrowdStrike2023GlobalThreatReport.pdf#page=9',
        publicationDate: '2023-02-28',
        observationPeriod: '2021-01-01/2021-12-31',
        population: 'Interactive eCrime intrusions observed by CrowdStrike OverWatch',
        statisticType: 'mean',
        value: 98,
        unit: 'minutes',
        reportedQuantiles: null,
        startMilestone: 'Initial host compromise',
        endMilestone: 'First lateral movement to another host (breakout)',
        notes: 'Reports an observed mean breakout time only. Does not establish time to sensitive record access, median (p50), p90, or distribution shape.'
      },
      {
        id: 'crowdstrike-2022-ecrime-breakout-mean',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'CrowdStrike 2023 Global Threat Report Executive Summary',
        sourceUrl: 'https://www.crowdstrike.com/wp-content/uploads/2023/02/2023-Global-Threat-Report-Executive-Summary.pdf',
        publicationDate: '2023-02-28',
        observationPeriod: '2022-01-01/2022-12-31',
        population: 'Interactive eCrime intrusions observed by CrowdStrike OverWatch',
        statisticType: 'mean',
        value: 84,
        unit: 'minutes',
        reportedQuantiles: null,
        startMilestone: 'Initial host compromise',
        endMilestone: 'First lateral movement to another host (breakout)',
        notes: 'Reports an observed mean breakout time only. Does not establish time to sensitive record access, median (p50), p90, or distribution shape.'
      },
      {
        id: 'crowdstrike-2023-ecrime-breakout-mean',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'CrowdStrike 2024 Global Threat Report Overview',
        sourceUrl: 'https://www.crowdstrike.com/en-us/blog/crowdstrike-2024-global-threat-report/',
        publicationDate: '2024-02-21',
        observationPeriod: '2023-01-01/2023-12-31',
        population: 'Interactive eCrime intrusions observed by CrowdStrike OverWatch',
        statisticType: 'mean',
        value: 62,
        unit: 'minutes',
        reportedQuantiles: null,
        startMilestone: 'Initial host compromise',
        endMilestone: 'First lateral movement to another host (breakout)',
        notes: 'Reports an observed mean breakout time only. Does not identify quantiles or AI attribution share.'
      },
      {
        id: 'crowdstrike-2023-ecrime-breakout-fastest',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'CrowdStrike 2024 Global Threat Report Overview',
        sourceUrl: 'https://www.crowdstrike.com/en-us/blog/crowdstrike-2024-global-threat-report/',
        publicationDate: '2024-02-21',
        observationPeriod: '2023-01-01/2023-12-31',
        population: 'Fastest single interactive eCrime breakout observed by CrowdStrike in 2023',
        statisticType: 'minimum_single_case',
        value: 127,
        unit: 'seconds',
        reportedQuantiles: null,
        startMilestone: 'Initial host compromise',
        endMilestone: 'First lateral movement to another host (breakout)',
        notes: 'Single minimum extremum (2 minutes 7 seconds); not a central tendency or population distribution.'
      },
      {
        id: 'mandiant-2022-dwell-median',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'Mandiant M-Trends 2023',
        sourceUrl: 'https://cloud.google.com/blog/transform/m-trends-2023-lessons-cyberattack-frontlines',
        publicationDate: '2023-04-18',
        observationPeriod: '2022-01-01/2022-12-31',
        population: 'Global intrusions investigated by Mandiant in 2022',
        statisticType: 'median',
        value: 16,
        unit: 'days',
        reportedQuantiles: { p50: 16 },
        startMilestone: 'Initial compromise',
        endMilestone: 'Detection / discovery of compromise',
        notes: 'Measures dwell time to discovery, which is distinct from operator breakout time or time to first sensitive record read.'
      },
      {
        id: 'gtig-2026-artex-typical-deep-access',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'GTIG: ARTEX and Friends Enter Agentic Offensive Frameworks',
        sourceUrl: 'https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks',
        publicationDate: '2026-10-31',
        observationPeriod: 'Campaign activity observed since at least August 2026',
        population: 'One ARTEX-associated actor tracked by Wiz Research and discussed in the GTIG/Mandiant report',
        statisticType: 'typical_case_narrative',
        value: 240,
        unit: 'minutes',
        reportedQuantiles: null,
        startMilestone: 'Initial compromised account foothold',
        endMilestone: 'Deep internal access',
        notes: 'Describes typical ~4-hour progression with burst/pause behavior and trial-and-error noise; not a universal parametric distribution.'
      },
      {
        id: 'gtig-2026-artex-fast-deep-access',
        provenanceType: 'historical_source',
        displayClassification: 'source_fact',
        sourceTitle: 'GTIG: ARTEX and Friends Enter Agentic Offensive Frameworks',
        sourceUrl: 'https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks',
        publicationDate: '2026-10-31',
        observationPeriod: 'Campaign activity observed since at least August 2026',
        population: 'Single fast intrusion case by an ARTEX-associated actor studied by GTIG/Mandiant',
        statisticType: 'single_case',
        value: 15,
        unit: 'minutes',
        reportedQuantiles: null,
        startMilestone: 'Initial compromised account foothold',
        endMilestone: 'Deep internal access',
        notes: 'Single fast case (15 minutes); does not establish a universal ARTEX median or stealth advantage.'
      }
    ],
    simulationAssumptions: [
      {
        id: 'assumption-pre2023-nominal-path-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'WIRE_READ_MINUTES.pre2023',
        distribution: { shape: 'discrete_uniform', min: 80, max: 270, unit: 'minutes' },
        applicableConditions: 'Conventional operator_with_tools profile nominal 4-layer path duration context',
        referencedStatisticIds: ['crowdstrike-2021-ecrime-breakout-mean', 'crowdstrike-2022-ecrime-breakout-mean'],
        justification: 'Illustrative presentation range anchored near historical 84-98 minute mean breakout figures, extended to 270 minutes to span multi-stage lateral and data-access progression.',
        uncertaintyTreatment: 'seeded_draw_presentation_context',
        reviewNote: 'Presentation context only; must not directly force control success or failure without causal prerequisite and response checks.'
      },
      {
        id: 'assumption-artex-nominal-path-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'WIRE_READ_MINUTES.artex',
        distribution: { shape: 'discrete_uniform', min: 45, max: 75, unit: 'minutes' },
        applicableConditions: 'Agentic orchestration profile nominal 4-layer path duration context',
        referencedStatisticIds: ['gtig-2026-artex-typical-deep-access', 'gtig-2026-artex-fast-deep-access'],
        justification: 'Illustrative presentation band between the 15-minute fast case and 4-hour typical deep-access observation reported by GTIG.',
        uncertaintyTreatment: 'seeded_draw_presentation_context',
        reviewNote: 'Presentation context only; does not imply universal agentic speed or guaranteed SOC evasion.'
      },
      {
        id: 'assumption-stage-weight-allocation',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'wireTiming.stageWeights',
        distribution: { shape: 'seeded_normalized_weights', minWeight: 0.15, maxWeight: 1.15, unit: 'ratio' },
        applicableConditions: 'Allocation of nominal path duration across layers 1..3',
        referencedStatisticIds: [],
        justification: 'Public reporting does not disaggregate total intrusion time into per-layer intervals; weights are synthetic scenario allocations.',
        uncertaintyTreatment: 'seeded_draw',
        reviewNote: 'Explicit synthetic stage allocation.'
      },
      {
        id: 'assumption-additional-ingress-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'reentryDurationSec',
        value: 300,
        unit: 'seconds',
        applicableConditions: 'Additional external ingress attempts after the initial foothold attempt',
        referencedStatisticIds: [],
        justification: 'Equal 5-minute scenario cost applied identically to all attacker profiles when probing secondary external entry points.',
        uncertaintyTreatment: 'fixed_parameter',
        reviewNote: 'Applied identically across conventional and agentic profiles.'
      },
      {
        id: 'assumption-local-persistence-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'persistence.modeledDurationSec',
        value: 120,
        unit: 'seconds',
        applicableConditions: 'Local registry startup persistence action (T1547.001) on executed Windows hosts',
        referencedStatisticIds: [],
        justification: 'Synthetic scheduling duration for post-exploitation persistence step.',
        uncertaintyTreatment: 'fixed_parameter',
        reviewNote: 'Requires established app_exec and persist_user permission.'
      },
      {
        id: 'assumption-local-encryption-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'encryption.modeledDurationSec',
        value: 300,
        unit: 'seconds',
        applicableConditions: 'Local file encryption action (T1486) on executed Windows hosts',
        referencedStatisticIds: [],
        justification: 'Synthetic scheduling duration for local endpoint encryption step.',
        uncertaintyTreatment: 'fixed_parameter',
        reviewNote: 'Requires established app_exec and write_local_files permission.'
      },
      {
        id: 'assumption-data-export-duration',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'data_exfiltration.modeledDurationSec',
        value: { baseSetupSec: 120, bytesPerSec: 524288 },
        unit: 'seconds',
        applicableConditions: 'Bulk data export following a confirmed sensitive dataset read',
        referencedStatisticIds: [],
        justification: 'Synthetic 120-second setup plus size-proportional transfer duration (or 120 seconds when dataset size is unknown).',
        uncertaintyTreatment: 'deterministic_formula',
        reviewNote: 'Requires prior data_read, controlled collection host, and boolean egress permission.'
      },
      {
        id: 'assumption-waf-portal-coverage',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'WAF_PORTAL_COVERAGE',
        value: 0.66,
        unit: 'probability',
        applicableConditions: 'Probability that a public SSL-VPN/GlobalProtect web portal is routed behind an inline WAF enforcement point in exploratory estates',
        referencedStatisticIds: [],
        justification: 'Models partial inline WAF coverage across edge portals so virtual patching is neither universally present nor absent.',
        uncertaintyTreatment: 'seeded_bernoulli',
        reviewNote: 'Bounded in [0, 1]; held constant across attacker comparisons on the same estate.'
      },
      {
        id: 'assumption-soar-base-detection-rate',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'SOAR_DETECTION_RATE',
        value: 0.32,
        unit: 'probability',
        applicableConditions: 'Per-action baseline behavioral detection probability on monitored layers when a modeled ML hypothesis exists',
        referencedStatisticIds: [],
        justification: 'Synthetic per-node detection probability representing imperfect single-event behavioral alerting prior to cross-boundary correlation.',
        uncertaintyTreatment: 'seeded_bernoulli',
        reviewNote: 'Bounded in [0, 1]; held constant on the estate.'
      },
      {
        id: 'assumption-soc-response-latencies',
        provenanceType: 'expert_assumption',
        displayClassification: 'synthetic_assumption',
        parameter: 'defensePosture.latencies',
        distribution: {
          collectionDelaySec: { min: 0, max: 30 },
          decisionDelaySec: { min: 15, max: 60 },
          responseDelaySec: { min: 60, max: 1800 }
        },
        unit: 'seconds',
        applicableConditions: 'Estate-owned telemetry collection, incident decision, and response enforcement latency ranges',
        referencedStatisticIds: [],
        justification: 'Models variation in automated and human-assisted SOC response pipelines across generated estates.',
        uncertaintyTreatment: 'seeded_draw_on_estate',
        reviewNote: 'Owned by the estate defensePosture; invariant when switching attacker profiles.'
      }
    ]
  };

  const CALIBRATION_REGISTER = externalCalibration || DEFAULT_CALIBRATION_REGISTER;

  if (!gangCatalogue?.gangs) throw new Error('Gang technique catalogue must load before WireEngine');

  // Affiliate initial access is not described by ransomware-software entries alone.
  // These are separately sourced supplements, never attributed to Threat Vision.
  const GANG_SUPPLEMENTS = {
    lockbit: { techniques: ['T1189','T1190','T1133','T1566','T1078','T1003','T1555.003','T1567.002','T1021.001'],
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a' },
    conti: { techniques: ['T1078','T1133','T1566.001','T1566.002','T1110','T1558.003','T1567.002','T1021.001'],
      analystMapped: ['T1567.002','T1021.001'],
      techniqueSources: {'T1567.002':'https://www.cyber.gov.au/advisory/2021-010-asds-acsc-ransomware-profile-conti',
        'T1021.001':'https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/'},
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a' },
    blackcat: { techniques: ['T1078','T1133','T1190','T1567.002','T1021.001'],
      analystMapped: ['T1078','T1133','T1190','T1567.002','T1021.001'],
      techniqueSources: {'T1021.001':'https://www.sygnia.co/blog/blackcat-ransomware/'},
      source: 'https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/' },
    hive: { techniques: ['T1133','T1190','T1566.001','T1059','T1070','T1112','T1562','T1537','T1486','T1490','T1021.001','T1047'],
      analystMapped: ['T1021.001','T1047'],
      techniqueSources: { 'T1021.001': 'https://www.ic3.gov/CSA/2021/210825.pdf',
        'T1047':'https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-hive' },
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a' },
    revil: { techniques: ['T1567.002','T1021.001'], analystMapped: ['T1567.002','T1021.001'],
      source: 'https://unit42.paloaltonetworks.com/revil-threat-actors/' },
    solarwinds: { techniques: ['T1195.002','T1190','T1078','T1550.001','T1552','T1059','T1021.001','T1041','T1530'],
      analystMapped: ['T1190','T1552','T1021.001','T1041','T1530'],
      source: 'https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise' },
    darkside: { techniques: ['T1078','T1133','T1110.003','T1190','T1021.001','T1021.002','T1047','T1486','T1567.002'],
      analystMapped: ['T1190'],
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a' },
    log4shell: { techniques: ['T1190','T1059','T1505','T1068','T1552','T1078','T1041','T1567.002'],
      analystMapped: ['T1552','T1078','T1041','T1567.002'],
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a' },
    cl0p: { techniques: ['T1190','T1505','T1505.003','T1059','T1068','T1552','T1078','T1041','T1567.002'],
      analystMapped: ['T1552','T1078','T1567.002'],
      source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a' }
  };
  // Tool use is attributed separately from the ransomware software's technique list.
  const COBALT_STRIKE_SOURCES = {
    lockbit:'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a',
    conti:'https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/',
    blackcat:'https://www.sygnia.co/blog/blackcat-ransomware/',
    hive:'https://www.hhs.gov/sites/default/files/ransomware-trends-q1-2022.pdf',
    revil:'https://unit42.paloaltonetworks.com/revil-threat-actors/',
    darkside:'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a'
  };
  const COBALT_STRIKE_METHOD_SOURCE = 'https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm';
  const PSEXEC_SOURCES = {
    lockbit:'https://www.cyber.gov.au/advisory/understanding-ransomware-threat-actors-lockbit',
    conti:'https://www.hhs.gov/sites/default/files/ransomware-trends-q1-2022.pdf',
    blackcat:'https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/',
    hive:'https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-hive',
    revil:'https://unit42.paloaltonetworks.com/revil-threat-actors/',
    darkside:'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a'
  };
  const PSEXEC_METHOD_SOURCE = 'https://learn.microsoft.com/en-us/sysinternals/downloads/psexec';
  const LATERAL_TOOL_METHODS = [
    {tool:'cobalt_strike',protocol:'smb',technique:'T1569.002',permission:'service_execute',label:'Cobalt Strike Beacon · remote service',source:COBALT_STRIKE_METHOD_SOURCE},
    {tool:'cobalt_strike',protocol:'wmi',technique:'T1047',permission:'execute',label:'Cobalt Strike Beacon · WMI remote execution',source:COBALT_STRIKE_METHOD_SOURCE},
    {tool:'psexec',protocol:'smb',technique:'T1569.002',permission:'service_execute',label:'PsExec · SMB remote-service execution',source:PSEXEC_METHOD_SOURCE}
  ];
  // Scenario preferences among reported methods, not measured prevalence or a universal playbook.
  // REvil retains its preceding tool order; this review changes the other four profiles.
  const GANG_LATERAL_ORDER = {
    lockbit:['psexec','cobalt_strike:smb','T1021.002','T1021.001','cobalt_strike:wmi','T1047'],
    conti:['cobalt_strike:wmi','cobalt_strike:smb','psexec','T1021.001','T1021.002','T1047'],
    blackcat:['psexec','T1021.001','cobalt_strike:smb','cobalt_strike:wmi','T1021.002','T1047'],
    hive:['T1021.001','T1047','psexec','cobalt_strike:wmi','cobalt_strike:smb'],
    revil:['cobalt_strike:smb','cobalt_strike:wmi','T1021.001','psexec'],
    solarwinds:['T1021.001','T1078'],
    darkside:['psexec','cobalt_strike:smb','T1021.001','T1021.002','cobalt_strike:wmi','T1047'],
    log4shell:['T1021.001','T1078'],
    cl0p:['T1021.001','T1078']
  };
  function lateralMethod(action) {
    return action.finding?.tool === 'cobalt_strike' ? `cobalt_strike:${action.finding.requiredInterface}`
      : action.finding?.tool || action.technique;
  }
  function lateralRank(action,profile) {
    const order=GANG_LATERAL_ORDER[profile?.gangId];
    if(!order || action.finding?.kind!=='remote_service')return 0;
    const rank=order.indexOf(lateralMethod(action));
    return rank<0?order.length:rank;
  }
  const DATA_EXPORT_METHODS = {
    lockbit:{technique:'T1567.002',tool:'Rclone',destination:'External cloud storage'},
    conti:{technique:'T1567.002',tool:'Rclone',destination:'External cloud file-sharing account'},
    blackcat:{technique:'T1567.002',tool:'MEGAsync / Rclone',destination:'External cloud storage'},
    hive:{technique:'T1537',tool:'Rclone',destination:'External MEGA account'},
    revil:{technique:'T1567.002',tool:'Rclone',destination:'External cloud storage'},
    solarwinds:{technique:'T1041',tool:'Encrypted C2 / HTTPS staging',destination:'External actor staging infrastructure'},
    darkside:{technique:'T1567.002',tool:'Rclone',destination:'External cloud storage'},
    log4shell:{technique:'T1041',tool:'JNDI / HTTP outbound transfer',destination:'External actor endpoint'},
    cl0p:{technique:'T1041',tool:'LEMURLOOT web shell HTTPS export',destination:'External extortion staging server'}
  };
  const ARTEX_EVIDENCE_SOURCE = 'https://github.com/RuoJi6/ARTEX/blob/6997a4661921395072290becc50380db8dacb04e/evidence/store.go';
  // Authored ordering among documented methods, not measured gang probabilities.
  const GANG_ENTRY_ORDER = {
    lockbit: ['T1133','T1190','T1566'], conti: ['T1566','T1133'],
    blackcat: ['T1133','T1190'], hive: ['T1566','T1133','T1190'], revil: ['T1566','T1189'],
    solarwinds: ['T1195.002','T1190','T1078','T1552'],
    darkside: ['T1133','T1078','T1190'],
    log4shell: ['T1190','T1552'],
    cl0p: ['T1190','T1552']
  };

  function techniqueMatches(documented, actionTechnique) {
    // A parent filter includes its children; a child never licenses its siblings.
    return documented === actionTechnique || actionTechnique?.startsWith(`${documented}.`);
  }

  function gangTechniqueEvidence(gangId, technique, context = {}) {
    if(context?.tool === 'psexec')return PSEXEC_SOURCES[gangId] && technique === 'T1569.002'
      ? {basis:'affiliate_reporting',technique,tool:'psexec',analystMapped:true,
        source:PSEXEC_SOURCES[gangId],methodSource:PSEXEC_METHOD_SOURCE} : null;
    if(context?.tool === 'cobalt_strike')return COBALT_STRIKE_SOURCES[gangId] && ['T1047','T1569.002'].includes(technique)
      ? {basis:'affiliate_reporting',technique,tool:'cobalt_strike',analystMapped:true,
        source:COBALT_STRIKE_SOURCES[gangId],methodSource:COBALT_STRIKE_METHOD_SOURCE,
        interpretation:'Reported affiliate tool use; transport is an authored choice from documented tool capabilities.'} : null;
    const profile = gangCatalogue.gangs[gangId];
    const supplement = GANG_SUPPLEMENTS[gangId];
    if ((!profile && !supplement) || !technique) return null;
    const mapped = profile && Object.keys(profile.techniques).find(id => techniqueMatches(id, technique));
    if (mapped) return { basis: 'threat_vision_attack_mapping', technique: mapped,
      evidence: profile.techniques[mapped].evidence, source: gangCatalogue.sources.threatVision };
    const documented = supplement?.techniques.find(id => techniqueMatches(id, technique));
    return documented ? { basis: 'affiliate_reporting', technique: documented,
      analystMapped: supplement.analystMapped?.includes(documented) || false,
      source: supplement.techniqueSources?.[documented] || supplement.source } : null;
  }

  function actionPolicy(action, sourceAsset, targetAsset, profile) {
    if (action.finding?.requiresUserInteraction && profile?.allowsUserInteraction !== true) return null;
    if (action.actionKind === 'encryption' && profile?.allowsRansomwareImpact !== true) return null;
    if (action.actionKind === 'persistence' && profile?.allowsPersistence !== true) return null;
    if(action.finding?.tool) {
      const tool=action.finding.tool;
      const supported=LATERAL_TOOL_METHODS.some(method=>method.tool===tool && method.technique===action.technique &&
        method.protocol===action.finding.requiredInterface && method.permission===action.finding.requiredPermission);
      if(!supported || action.finding.kind !== 'remote_service' || !profile?.availableTools?.includes(tool))return null;
      if(!profile.gangId)return {basis:'modeled_action',tool,source:tool==='psexec'?PSEXEC_METHOD_SOURCE:COBALT_STRIKE_METHOD_SOURCE,
        interpretation:'Explicitly configured tool inventory; not evidence of historical ARTEX tool use.'};
      return gangTechniqueEvidence(profile.gangId,action.technique,action.finding);
    }
    // REvil's software WMI entry concerns local process termination, not remote execution.
    if(profile?.gangId === 'revil' && action.finding?.kind === 'remote_service' && action.technique === 'T1047')return null;
    if (!profile?.gangId) return { basis: 'modeled_action' };
    const evidence = gangTechniqueEvidence(profile.gangId, action.technique);
    if (evidence) return evidence;
    // Ordinary use of a scoped credential after a foothold is supporting access,
    // not evidence of a gang-specific exploit or an initial-access capability.
    if (sourceAsset && action.actionKind === 'valid_credential') return { basis: 'modeled_supporting_access' };
    if (sourceAsset && targetAsset.isDecoy) return { basis: 'modeled_decoy_interaction' };
    return null;
  }

  const TRUST_ZONES = ['internet-dmz', 'identity-edge', 'internal-mesh', 'data-tier'];

  // Equal demo coverage across seeds; public incident reports do not establish rates for these categories.
  const MIXED_DIAGNOSTIC_OPENINGS = [
    {
      openingType: 'low_exposure',
      title: 'Low exposure',
      requiredCondition: 'unredactedSupportCapture',
      description: 'An approved support capture retains a staging status credential visible to the signed-in diagnostics viewer.'
    },
    {
      openingType: 'misconfiguration',
      title: 'Misconfiguration',
      requiredCondition: 'overbroadDiagnosticsSharing',
      description: 'An overly broad sharing policy lets the signed-in diagnostics viewer see a restricted staging build log containing a status credential.'
    },
    {
      openingType: 'low_vulnerability',
      title: 'Low vulnerability',
      requiredCondition: 'limitedDiagnosticReadDefect',
      description: 'A read-only defect exposes a staging status credential to the signed-in diagnostics viewer.'
    }
  ];

  // Demo-design budgets per layer (starting targets for exploitable findings, not risk rates)
  const LAYER_FINDING_BUDGETS = [
    { min: 2, max: 3 },
    { min: 2, max: 3 },
    { min: 2, max: 3 },
    { min: 1, max: 2 }
  ];

  // Historical analogues for an isolated Layer 1 event in the browser.
  const EDGE_MISCONFIGURATIONS = [
    { id: 'default-admin', asset: 'External Device Admin Portal', title: 'Default admin credentials', icon: 'iot.png', interfaces: ['device-management'], assumedAccount: true, reference: 'Unitronics device intrusions', source: 'https://www.cisa.gov/sites/default/files/2024-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors.pdf' },
    { id: 'rdp-exposed', asset: 'Internet-Facing Remote Desktop', title: 'Remote Desktop exposed directly', icon: 'remote-access.png', interfaces: ['rdp'], assumedAccount: true, reference: 'SamSam ransomware incidents', source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a' },
    { id: 'legacy-vpn', asset: 'Legacy VPN Portal', title: 'Legacy VPN account still enabled without MFA', icon: 'remote-access.png', interfaces: ['vpn'], assumedAccount: true, reference: 'Colonial Pipeline breach', source: 'https://www.govinfo.gov/content/pkg/CHRG-117hhrg45085/html/CHRG-117hhrg45085.htm' },
    { id: 'test-tenant', asset: 'Nonproduction Cloud Tenant', title: 'Test tenant account excluded from MFA', icon: 'identity.png', interfaces: ['https'], assumedAccount: true, reference: 'Microsoft Midnight Blizzard incident', source: 'https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/' },
    { id: 'data-allowlist', asset: 'Public Cloud Data Warehouse Login', title: 'Cloud warehouse reachable without trusted-network restrictions', icon: 'data.png', interfaces: ['https'], assumedAccount: true, reference: 'UNC5537 Snowflake customer compromises', source: 'https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion' },
    { id: 'public-storage', asset: 'Public Document Storage', title: 'Sensitive storage allows anonymous read', icon: 'data.png', interfaces: ['storage-s3', 'https'], reference: 'Ascension mortgage document breach', source: 'https://search.ftc.gov/system/files/documents/cases/1923126ascensioncomplaint.pdf' },
    { id: 'public-kubernetes', asset: 'Public Kubernetes Console', title: 'Kubernetes dashboard with no authentication', icon: 'cloud-infrastructure.png', interfaces: ['https'], reference: 'RedLock investigation of Tesla cryptojacking', source: 'https://www.ten-inc.com/documents/RedLock_Whitepaper_2018.pdf' },
    { id: 'public-docker', asset: 'Public Container Management Interface', title: 'Docker management API with no authentication', icon: 'components.png', interfaces: ['http'], reference: 'Unit 42 investigation of compromised Docker hosts', source: 'https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/' },
    { id: 'waf-forwarding', asset: 'Public Cloud Application Gateway', title: 'WAF permits unintended backend access', icon: 'network.png', interfaces: ['https'], reference: 'Capital One cloud data breach', source: 'https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson' },
    { id: 'public-web-config', asset: 'Public Application Configuration', title: 'Web server publishes deployment configuration', icon: 'configuration.png', interfaces: ['https'], reference: 'Unit 42 cloud extortion investigation', source: 'https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/' },
    { id: 'datadog-proxy', asset: 'Customer-Managed Datadog Proxy', title: 'Unauthenticated proxy exposes logs', icon: 'threat-detection.png', interfaces: ['https'], illustration: 'git-to-idp', reference: 'User-supplied scenario. Datadog documentation provides product context.', source: 'https://docs.datadoghq.com/data_security/agent/' }
  ];

  // Advisory-backed appliance families. Affected builds and configurations are
  // assigned only when that family receives a modeled finding in an estate.
  const EDGE_APPLIANCES = {
    'f5-gateway': { cve: 'CVE-2022-1388', product: 'F5 BIG-IP', version: '16.1.0', conditions: { managementReachable: true }, source: 'https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf' },
    'ivanti-connect': { cve: 'CVE-2023-46805', product: 'Ivanti Connect Secure', version: '22.4R2', conditions: { gatewayWebEnabled: true }, source: 'https://www.ivanti.com/blog/security-update-for-ivanti-connect-secure-and-ivanti-policy-secure-gateways' },
    'forti-vpn': { cve: 'CVE-2018-13379', product: 'Fortinet FortiGate', version: '6.0.4', conditions: { sslVpnEnabled: true }, source: 'https://www.fortinet.com/blog/psirt-blogs/fortios-ssl-vulnerability' },
    'pan-globalprotect': { cve: 'CVE-2024-3400', product: 'Palo Alto Networks PAN-OS Firewall', version: '10.2.8', conditions: { globalProtectEnabled: true }, source: 'https://security.paloaltonetworks.com/CVE-2024-3400' },
    'citrix-adc': { cve: 'CVE-2023-3519', product: 'Citrix NetScaler ADC', version: '13.1-48.47', conditions: { gatewayMode: true }, source: 'https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf' },
    'cisco-asa': { cve: 'CVE-2020-3452', product: 'Cisco ASA Firewall', version: '9.12.3', conditions: { webVpnEnabled: true }, source: 'https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ro-path-KJuQhB86.html' },
    'sonicwall-sma': { cve: 'CVE-2021-20016', product: 'SonicWall SMA 100', version: '10.2.0.6', conditions: { sslVpnEnabled: true }, source: 'https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2021-005/' },
    'sophos-firewall': { cve: 'CVE-2022-1040', product: 'Sophos Firewall', version: '18.5 MR2 before hotfix', conditions: { userPortalEnabled: true }, source: 'https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce' },
    'zyxel-atp': { cve: 'CVE-2023-28771', product: 'Zyxel ATP Firewall', version: '5.35', conditions: { ipsecEnabled: true }, source: 'https://www.zyxel.com/global/en/support/security-advisories/zyxels-guidance-for-the-recent-attacks-on-the-zywall-devices' },
    'checkpoint-quantum': { cve: 'CVE-2024-24919', product: 'Check Point Quantum Security Gateway', version: 'R81.20 before hotfix', conditions: { remoteAccessVpnEnabled: true }, source: 'https://advisories.checkpoint.com/defense/advisories/public/2024/cpai-2024-0353.html/' }
  };

  const REVIEWED_EXAMPLES = {
    ...EDGE_APPLIANCES,
    'apache-edge': { cve: 'CVE-2021-42013', product: 'Apache HTTP Server', version: '2.4.50', conditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013' },
    'cust-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'partner-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'wso2-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'sentry-auth': { cve: 'CVE-2023-38035', product: 'Ivanti Sentry', version: '9.18.0', conditions: { adminPort8443Reachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38035' },
    'ad-identity': { cve: 'CVE-2022-26923', product: 'Active Directory Domain Services', version: 'Windows Server 2022', conditions: { adcsEnrollmentEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-26923' },
    'ivanti-epm': { cve: 'CVE-2024-29824', product: 'Ivanti EPM', version: '2022 SU5', conditions: { coreServerReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29824' },
    'exchange': { cve: 'CVE-2021-26855', product: 'Microsoft Exchange Server', version: '2019 CU8', conditions: { ewsExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-26855' },
    'app-engine': { cve: 'CVE-2022-22965', product: 'Spring Framework', version: '5.3.17', conditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true }, source: 'https://spring.io/security/cve-2022-22965/' },
    'spring-svc': { cve: 'CVE-2022-22965', product: 'Spring Framework', version: '5.3.17', conditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true }, source: 'https://spring.io/security/cve-2022-22965/' },
    'log4j-svc': { cve: 'CVE-2021-44228', product: 'Apache Log4j 2', version: '2.14.1', conditions: { jndiLookupsEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
    'iot-hub': { cve: 'CVE-2021-44228', product: 'Apache Log4j 2', version: '2.14.1', conditions: { jndiLookupsEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
    'confluence-node': { cve: 'CVE-2023-22527', product: 'Atlassian Confluence Data Center', version: '8.5.3', conditions: { templateEndpointExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-22527' },
    'confluence-admin': { cve: 'CVE-2023-22515', product: 'Atlassian Confluence Server', version: '8.5.1', conditions: { setupEndpointExposed: true }, source: 'https://support.atlassian.com/atlassian-knowledge-base/kb/faq-for-cve-2023-22515/' },
    'weblogic': { cve: 'CVE-2020-14882', product: 'Oracle WebLogic Server', version: '12.2.1.4.0', conditions: { adminConsoleReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2020-14882' },
    'sql-reporting': { cve: 'CVE-2020-0618', product: 'SQL Server Reporting Services', version: '2016', conditions: { reportViewerExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2020-0618' },
    'forti-ems': { cve: 'CVE-2023-48788', product: 'Fortinet FortiClient EMS', version: '7.2.2', conditions: { fcmDaemonReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-48788' },
    'cicd-runner': { cve: 'CVE-2023-42793', product: 'JetBrains TeamCity', version: '2023.05.3', conditions: { restAuthBypass: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-42793' },
    'activemq': { cve: 'CVE-2023-46604', product: 'Apache ActiveMQ', version: '5.18.2', conditions: { openWirePortExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-46604' },
    'moveit-sftp': { cve: 'CVE-2023-34362', product: 'Progress MOVEit Transfer', version: '2023.0.0', conditions: { webTransferEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362' },
    'ai-core': { cve: 'CVE-2026-42271', product: 'LiteLLM Proxy', version: '1.83.6', conditions: { mcpTestEndpointsEnabled: true }, source: 'https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g' },
    'redis-debian': { cve: 'CVE-2022-0543', product: 'Debian Redis', version: '5:6.0.16-1', conditions: { luaSandboxUnpatched: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0543' }
  };

  // Multi-variant product-pool CVE specifications so every displayed kevByVariant
  // in LAYER_CONFIG has an audited, explicit specification (Spec Section 7.1, F35).
  const REVIEWED_VARIANT_CVES = {
    'CVE-2021-42013': { product: 'Apache HTTP Server', version: '2.4.50', conditions: { cgiEnabled: true, pathNormalizationUnpatched: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013' },
    'CVE-2023-46747': { product: 'F5 BIG-IP Advanced WAF', version: '17.1.0', conditions: { tmuiReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-46747' },
    'CVE-2025-64446': { product: 'Fortinet FortiWeb WAF', version: '7.4.1', conditions: { managementInterfaceReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2025-64446' },
    'CVE-2023-3519': { product: 'Citrix NetScaler ADC', version: '13.1-48.47', conditions: { gatewayMode: true }, source: 'https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf' },
    'CVE-2018-5412': { product: 'Imperva SecureSphere WAF', version: '13.0', conditions: { managementAccessEstablished: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2018-5412' },
    'CVE-2022-22954': { product: 'VMware Workspace ONE Access', version: '21.08.0.0', conditions: { catalogPortalEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22954' },
    'CVE-2018-8340': { product: 'Microsoft AD FS', version: '2016', conditions: { extranetLockoutBypassable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2018-8340' },
    'CVE-2021-3827': { product: 'Red Hat Keycloak', version: '13.0.0', conditions: { bruteForceProtectionMisconfigured: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3827' },
    'CVE-2023-32707': { product: 'Splunk Enterprise', version: '9.0.4', conditions: { editUserCapabilityGranted: true }, source: 'https://advisory.splunk.com/advisories/SVD-2023-0602' },
    'CVE-2020-4888': { product: 'IBM QRadar SIEM', version: '7.3.3', conditions: { authenticatedSessionPresent: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2020-4888' },
    'CVE-2026-78597': { product: 'Elastic Security / Kibana', version: '8.15.0', conditions: { entityStoreRolePresent: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2026-78597' },
    'CVE-2026-25769': { product: 'Wazuh Server', version: '4.8.0', conditions: { workerKeyCompromised: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2026-25769' },
    'CVE-2023-0669': { product: 'Fortra GoAnywhere MFT', version: '7.1.1', conditions: { adminLicenseServletExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-0669' },
    'CVE-2022-46169': { product: 'Cacti Network Monitoring Server', version: '1.2.22', conditions: { remoteAgentPollerEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-46169' },
    'CVE-2022-29712': { product: 'LibreNMS', version: '22.3.0', conditions: { serviceParamEditable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-29712' },
    'CVE-2021-35225': { product: 'SolarWinds NPM', version: '2020.2.6', conditions: { OrionAlertingReadable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-35225' }
  };

  // Coherent infrastructure archetypes (Spec Section 7.1).
  const INFRASTRUCTURE_ARCHETYPES = {
    'full-enterprise': {
      id: 'full-enterprise',
      title: 'Full enterprise',
      description: 'Employee systems, public applications, cloud workloads and software delivery on one estate.',
      preferredIngressGroups: ['f5-gateway', 'forti-vpn'],
      defaultWalkthroughId: 'walkthrough-public-web'
    },
    'enterprise-identity': {
      id: 'enterprise-identity',
      title: 'Enterprise identity and endpoints',
      description: 'Remote access, user/service identities, workstation/server access and internal data.',
      requiredRelationships: ['remote-access-to-identity', 'endpoint-to-management', 'management-to-fileserver', 'fileserver-to-data'],
      defensiveVariations: ['identity_restrictions', 'endpoint_telemetry', 'management_isolation'],
      preferredIngressGroups: ['forti-vpn', 'cisco-asa', 'checkpoint-quantum'],
      layerFocusGroups: [['forti-vpn', 'windows-desktop', 'windows-rdp'], ['ad-identity', 'iam-idp', 'ivanti-epm', 'windows-management'], ['weblogic', 'forti-ems', 'windows-file-server'], ['mssql-db', 'db-rds', 'windows-records']],
      defaultWalkthroughId: 'walkthrough-enterprise-identity'
    },
    'public-web': {
      id: 'public-web',
      title: 'Public web and internal data',
      description: 'Public application, middleware, application identity and datastore permissions.',
      requiredRelationships: ['edge-to-api-gateway', 'api-gateway-to-app-middleware', 'app-middleware-to-datastore'],
      defensiveVariations: ['waf_placement', 'exposed_origin', 'application_telemetry', 'least_privilege'],
      preferredIngressGroups: ['f5-gateway', 'pan-globalprotect', 'apache-edge', 'citrix-adc'],
      layerFocusGroups: [['f5-gateway', 'pan-globalprotect', 'apache-edge'], ['cust-api', 'waf-proxy', 'wso2-api'], ['app-engine', 'spring-svc', 'log4j-svc', 'moveit-sftp'], ['db-rds', 'lake-cust', 'nosql-doc']],
      defaultWalkthroughId: 'walkthrough-public-web'
    },
    'cloud-saas': {
      id: 'cloud-saas',
      title: 'Cloud and SaaS',
      description: 'Tenant identities, role grants, API permissions and cloud datasets.',
      requiredRelationships: ['cloud-ingress-to-tenant-idp', 'tenant-idp-to-saas-service', 'saas-service-to-cloud-lake'],
      defensiveVariations: ['audit_coverage', 'session_controls', 'credential_scope', 'direct_data_access'],
      preferredIngressGroups: ['public-s3', 'public-blob', 'sophos-firewall', 'ivanti-connect'],
      layerFocusGroups: [['public-s3', 'public-blob', 'ivanti-connect', 'sophos-firewall'], ['iam-idp', 'exchange', 'cust-api'], ['confluence-admin', 'confluence-node', 'iot-hub', 'ai-core'], ['lake-ops', 'lake-cust', 'litellm-db']],
      defaultWalkthroughId: 'walkthrough-cloud-saas'
    },
    'cicd-secrets': {
      id: 'cicd-secrets',
      title: 'CI/CD and operational secrets',
      description: 'Repository, runner, service identity, artifact/configuration store and deployment target.',
      requiredRelationships: ['repo-or-edge-to-idp-or-vault', 'idp-to-cicd-runner', 'cicd-runner-to-deployment-datastore'],
      defensiveVariations: ['secret_handling', 'runner_isolation', 'token_scope', 'deployment_authorization'],
      preferredIngressGroups: ['public-gitlab', 'public-bitbucket', 'f5-gateway', 'ivanti-connect'],
      layerFocusGroups: [['public-gitlab', 'public-bitbucket', 'f5-gateway'], ['iam-idp', 'vault-creds', 'cust-api'], ['cicd-runner', 'comp-registry', 'vuln-scan', 'activemq'], ['db-rds', 'redis-debian', 'lake-cust']],
      defaultWalkthroughId: 'walkthrough-cicd-secrets'
    }
  };

  // Concise attack descriptions based on the linked vulnerability records.
  const CVE_ATTACK_DESCRIPTIONS = {
    "CVE-2018-13379": "FortiOS SSL VPN path traversal can expose system files, including session information.",
    "CVE-2018-5412": "Imperva SecureSphere local code execution vulnerability.",
    "CVE-2018-8340": "AD FS authentication bypass can allow an attacker to bypass multi-factor authentication.",
    "CVE-2019-11510": "Pulse Connect Secure path traversal lets an unauthenticated attacker read server files.",
    "CVE-2020-0618": "SQL Server Reporting Services deserialization can lead to remote code execution.",
    "CVE-2020-10148": "SolarWinds Orion API authentication bypass allows remote command execution and supply-chain update compromise.",
    "CVE-2020-1472": "Zerologon abuses Netlogon authentication to gain domain controller privileges.",
    "CVE-2020-14882": "WebLogic console access controls can be bypassed, allowing remote compromise.",
    "CVE-2020-4888": "IBM QRadar deserialization of crafted Java objects can execute commands.",
    "CVE-2021-26855": "ProxyLogon uses server-side request forgery to send requests through Exchange.",
    "CVE-2021-30116": "Kaseya VSA authentication bypass and SQL injection allows RMM supply-chain ransomware deployment.",
    "CVE-2021-35225": "A SolarWinds NPM flaw can disclose information to a user with limited access.",
    "CVE-2021-3827": "A Keycloak flaw can allow authentication protections to be bypassed.",
    "CVE-2021-42013": "Apache path traversal can expose files and, in some configurations, execute commands.",
    "CVE-2021-44228": "Log4Shell: attacker-controlled log content can trigger a malicious JNDI lookup and remote code execution.",
    "CVE-2022-0543": "A Debian Redis Lua sandbox escape can allow a client to execute system commands.",
    "CVE-2022-1388": "F5 BIG-IP iControl REST authentication bypass can allow remote command execution.",
    "CVE-2022-22954": "VMware Workspace ONE template injection can allow remote code execution.",
    "CVE-2022-22965": "Spring4Shell abuses data binding in affected deployments to execute code.",
    "CVE-2022-26134": "Confluence OGNL injection can allow an unauthenticated attacker to execute code.",
    "CVE-2022-26923": "Certifried abuses Active Directory certificate enrollment to impersonate a computer account.",
    "CVE-2022-29464": "A WSO2 file-upload flaw can let an attacker upload files and execute code.",
    "CVE-2022-29712": "Command injection through LibreNMS service configuration parameters.",
    "CVE-2022-30190": "Follina uses a crafted document to invoke MSDT and execute code.",
    "CVE-2022-42475": "A FortiOS SSL VPN heap overflow can allow unauthenticated remote code execution.",
    "CVE-2022-46169": "Cacti command injection can allow unauthenticated code execution when a vulnerable polling configuration is present.",
    "CVE-2022-47966": "ManageEngine SAML processing can allow remote code execution through a vulnerable XML library.",
    "CVE-2023-0669": "GoAnywhere MFT deserialization can allow unauthenticated remote code execution.",
    "CVE-2023-20198": "Cisco IOS XE web UI access controls can be bypassed to create a privileged account.",
    "CVE-2023-22515": "Confluence broken access control can let an attacker create an administrator account.",
    "CVE-2023-22527": "Confluence template injection can allow unauthenticated remote code execution.",
    "CVE-2023-24489": "A ShareFile storage zones controller flaw can allow unauthenticated remote compromise.",
    "CVE-2023-27350": "PaperCut authentication bypass can allow code execution with SYSTEM privileges.",
    "CVE-2023-2868": "Barracuda Email Security Gateway command injection can enable remote code execution.",
    "CVE-2023-29357": "SharePoint authentication bypass can let an attacker gain administrator privileges using forged tokens.",
    "CVE-2023-32707": "A Splunk Enterprise vulnerability can allow privilege escalation.",
    "CVE-2023-34362": "MOVEit Transfer SQL injection can give an unauthenticated attacker access to its database.",
    "CVE-2023-3519": "NetScaler ADC and Gateway code injection can allow unauthenticated remote code execution.",
    "CVE-2023-36884": "A crafted Office document can exploit a Windows and Office remote code execution vulnerability.",
    "CVE-2023-38035": "Ivanti Sentry authentication bypass can expose restricted administrative functionality.",
    "CVE-2023-42793": "TeamCity authentication bypass can allow access to administrative functions.",
    "CVE-2023-46604": "ActiveMQ OpenWire deserialization can allow remote shell command execution.",
    "CVE-2023-46747": "F5 BIG-IP configuration utility authentication bypass can allow remote system commands.",
    "CVE-2023-46805": "Ivanti Connect Secure authentication bypass can expose restricted resources.",
    "CVE-2023-48788": "FortiClient EMS SQL injection can allow unauthorized code or command execution.",
    "CVE-2023-4966": "Citrix Bleed can leak NetScaler session tokens from appliance memory.",
    "CVE-2024-1086": "A Linux netfilter use-after-free can allow a local attacker to escalate privileges.",
    "CVE-2024-1709": "ScreenConnect authentication bypass can allow unauthorized administrative access.",
    "CVE-2024-21887": "Ivanti Connect Secure command injection can allow an attacker with administrative access to execute commands.",
    "CVE-2024-27198": "TeamCity authentication bypass can allow an unauthenticated attacker to gain administrative access.",
    "CVE-2024-29824": "Ivanti EPM SQL injection can let an unauthenticated attacker on the same network execute code.",
    "CVE-2024-3400": "PAN-OS GlobalProtect command injection can allow unauthenticated code execution as root.",
    "CVE-2024-37085": "ESXi authentication bypass can grant elevated access through a specially named Active Directory group.",
    "CVE-2024-4577": "PHP CGI argument injection can allow remote code execution in affected Windows configurations.",
    "CVE-2025-64446": "FortiWeb path traversal can let a remote attacker reach restricted management functionality.",
    "CVE-2026-25769": "A compromised Wazuh worker can exploit deserialization to execute code on the cluster master.",
    "CVE-2026-42271": "LiteLLM MCP test endpoint command injection can allow a user with a valid API key to execute commands.",
    "CVE-2026-78597": "A low-privileged Kibana user can invoke an Entity Store operation to create unauthorized API credentials."
  };

  // CISA KEV catalog grouped by simulation layer; only explicit product mappings are assigned.
  const LAYER_KEVS = [
    [
      { id: 'CVE-2024-4577', title: 'PHP CGI Arg Injection RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46805', title: 'Ivanti Connect Secure Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2024-3400', title: 'PAN-OS Command Injection RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-3519', title: 'Citrix NetScaler ADC Unauth RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-20198', title: 'Cisco IOS XE Priv Escalation', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2024-21887', title: 'Ivanti Connect Policy Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-1388', title: 'F5 BIG-IP iControl REST Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-42475', title: 'FortiOS SSL-VPN Heap Buffer Overflow', tech: 'T1190', inKev: true, reqInterface: 'vpn', yields: 'app_exec' },
      { id: 'CVE-2018-13379', title: 'FortiOS SSL-VPN Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2020-3452', title: 'Cisco ASA VPN File Disclosure', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2021-20016', title: 'SonicWall SMA SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2022-1040', title: 'Sophos Firewall Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-28771', title: 'Zyxel ATP Command Injection', tech: 'T1190', inKev: true, reqInterface: 'vpn', yields: 'app_exec' },
      { id: 'CVE-2024-24919', title: 'Check Point VPN Information Disclosure', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2019-11510', title: 'Pulse Connect Secure Arbitrary File Read', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2021-42013', title: 'Apache HTTP Server Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' }
    ],
    [
      { id: 'CVE-2023-22515', title: 'Confluence Broken Access Control', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2024-27198', title: 'TeamCity Admin Token Minting', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2023-38035', title: 'Ivanti Sentry API Auth Bypass', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-4966', title: 'Citrix Bleed Session Leak', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2024-1709', title: 'ScreenConnect Auth Bypass', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2021-26855', title: 'ProxyLogon Exchange SSRF', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-26923', title: 'Active Directory Certifried Spoofing', tech: 'T1068', inKev: true, reqInterface: 'ad-rpc', yields: 'account_session' },
      { id: 'CVE-2023-29357', title: 'SharePoint OAuth Token Bypass', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2022-29464', title: 'WSO2 API Arbitrary File Upload', tech: 'T1505', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2024-29824', title: 'Ivanti EPM Core SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46747', title: 'F5 BIG-IP Configuration Utility Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-22954', title: 'VMware Workspace ONE Access Template Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-32707', title: 'Splunk Enterprise Privilege Escalation', tech: 'T1068', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2025-64446', title: 'FortiWeb Management Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2023-3519', title: 'NetScaler ADC Remote Code Execution', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2018-5412', title: 'Imperva SecureSphere Local Code Execution', tech: 'T1068', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-3827', title: 'Keycloak MFA Bypass', tech: 'T1556', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2018-8340', title: 'AD FS MFA Bypass', tech: 'T1556', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2020-4888', title: 'IBM QRadar Deserialization', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2026-78597', title: 'Kibana Entity Store Credential Creation', tech: 'T1098', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2026-25769', title: 'Wazuh Server Deserialization', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' }
    ],
    [
      { id: 'CVE-2026-42271', title: 'LiteLLM MCP command execution (valid API key required)', tech: 'T1059', inKev: false, reqInterface: 'api-https', requiresAuth: true, yields: 'app_exec' },
      { id: 'CVE-2023-48788', title: 'FortiClient EMS SQL injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2020-0618', title: 'SQL Server Reporting Services RCE', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-44228', title: 'Log4Shell JNDI Remote Code Execution', tech: 'T1059', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2023-22527', title: 'Confluence OGNL Template Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-22965', title: 'Spring4Shell Data Binding RCE', tech: 'T1190', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2023-2868', title: 'Barracuda ESG Command Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-30190', title: 'MSDT Follina Command RCE', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46604', title: 'ActiveMQ OpenWire Deserialization RCE', tech: 'T1059', inKev: true, reqInterface: 'amqp', yields: 'app_exec' },
      { id: 'CVE-2022-46169', title: 'Cacti Unauth Command Injection RCE', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-29712', title: 'LibreNMS service parameter command injection', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-35225', title: 'SolarWinds NPM information disclosure', tech: 'T1552', inKev: false, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2023-42793', title: 'TeamCity Authentication Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2020-14882', title: 'Oracle WebLogic Console Access Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-22515', title: 'Confluence Broken Access Control', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2023-34362', title: 'MOVEit Transfer SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-0669', title: 'GoAnywhere MFT Deserialization RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' }
    ],
    [
      { id: 'CVE-2023-27350', title: 'PaperCut Setup Wizard DB Dump', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2020-1472', title: 'Zerologon Cryptographic Hash Dump', tech: 'T1003', inKev: true, reqInterface: 'ad-rpc', yields: 'data_read' },
      { id: 'CVE-2023-36884', title: 'Office Document File Exfiltration', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2023-48788', title: 'FortiClient EMS SQLi Database Dump', tech: 'T1041', inKev: true, reqInterface: 'db-mssql', yields: 'data_read' },
      { id: 'CVE-2022-47966', title: 'ManageEngine SAML RCE & PostgreSQL Dump', tech: 'T1041', inKev: true, reqInterface: 'db-pg', yields: 'data_read' },
      { id: 'CVE-2024-37085', title: 'VMware ESXi AD Bypass & VMFS Disk Dump', tech: 'T1005', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2023-24489', title: 'Citrix ShareFile Storage Zone Exfiltration', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-26134', title: 'Confluence OGNL DB Pool Credential Harvest', tech: 'T1003', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2024-1086', title: 'Linux Netfilter PrivEsc & Vault DB Dump', tech: 'T1003', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-22954', title: 'VMware Workspace ONE SSTI DB Secrets Dump', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-0543', title: 'Debian Redis Lua Sandbox Escape', tech: 'T1059', inKev: true, reqInterface: 'redis', yields: 'data_read' },
      { id: 'CVE-2020-0618', title: 'SQL Server Reporting Services RCE', tech: 'T1059', inKev: false, reqInterface: 'db-mssql', yields: 'data_read' }
    ]
  ];

  const KEV_MITIGATION_RULES = {
    'CVE-2026-42271': { waf: { mitigates: false, reason: 'The internal LiteLLM proxy is not assumed to be covered by the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic response detects unexpected subprocess execution by the proxy.' } },
    'CVE-2024-4577': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2 / SC-7', reason: 'WAF query regex drops %ad PHP CGI argument injection' }, ml: { mitigates: false, reason: 'Edge CGI exploit bypasses internal behavioral telemetry' } },
    'CVE-2023-46805': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF virtual patch restricts unauthenticated /api/v1/cav/client endpoints' }, ml: { mitigates: false, reason: 'Perimeter auth bypass occurs before internal ML baseline can flag session' } },
    'CVE-2024-3400': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Targeted virtual patch filters malicious HTTP requests to the GlobalProtect portal when covered.' }, ml: { mitigates: false, reason: 'Edge firewall OS injection executes at edge appliance firmware layer' } },
    'CVE-2023-3519': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF protocol validator drops malformed HTTP Host header buffer overflow' }, ml: { mitigates: false, reason: 'Edge ADC stack overflow executes pre-auth before user identity creation' } },
    'CVE-2023-20198': { waf: { mitigates: false, reason: 'Direct REST management endpoint bypasses edge reverse proxy' }, ml: { mitigates: false, reason: 'Direct network boundary exploitation circumvents internal host ML agents' } },
    'CVE-2024-21887': { waf: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' }, ml: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' } },
    'CVE-2022-1388': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF drops hop-by-hop Connection header smuggling to /mgmt/shared/authn' }, ml: { mitigates: false, reason: 'Edge appliance admin bypass executes outside host mesh' } },
    'CVE-2022-42475': { waf: { mitigates: false, reason: 'VPN binary protocol heap overflow bypasses L7 HTTP reverse proxy' }, ml: { mitigates: false, reason: 'Edge VPN daemon heap overwrite occurs before telemetry ingestion' } },
    'CVE-2023-22515': { waf: { mitigates: false, reason: 'Legitimate HTTP requests to /setup endpoints pass perimeter WAF inspection' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation flags setup wizard execution on established production instance' } },
    'CVE-2024-27198': { waf: { mitigates: false, reason: 'OAuth/Auth endpoint traversal passes standard perimeter HTTP parsers' }, ml: { mitigates: true, control: 'NIST IA-5 / AC-3', reason: 'Agentic SOC Mitigation isolates service on forged administrative token minting' } },
    'CVE-2023-38035': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'Edge WAF blocks unauthenticated HTTP requests to MICS port 8443 interface' }, ml: { mitigates: false, reason: 'Admin API interface lacks granular internal behavioral baseline' } },
    'CVE-2023-4966': { waf: { mitigates: false, reason: 'Outbound session token memory disclosure occurs in TLS response stream' }, ml: { mitigates: true, control: 'NIST AC-3 / IA-5', reason: 'Zero-Trust ML halts stolen session token used across divergent IP/fingerprint' } },
    'CVE-2024-1709': { waf: { mitigates: false, reason: 'Setup wizard URI /SetupWizard.aspx is considered valid application traffic by WAF' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation blocks unauthorized admin account creation out-of-band' } },
    'CVE-2021-26855': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2 / SC-7', reason: 'WAF virtual patch filters X-AnonResource-Backend SSRF header' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects internal SSRF lateral probe to backend Exchange RPC' } },
    'CVE-2022-26923': { waf: { mitigates: false, reason: 'Active Directory certificate enrollment traffic is outside HTTP WAF scope' }, ml: { mitigates: true, control: 'NIST IA-5 / AC-3', reason: 'Agentic SOC Mitigation detects anomalous dNSHostName attribute modification on computer account' } },
    'CVE-2023-29357': { waf: { mitigates: false, reason: 'Forged JWT signing alg=none tokens pass initial TLS termination proxies' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation isolates spoofed farm administrator claims without valid IdP signature' } },
    'CVE-2021-44228': { waf: { mitigates: false, reason: 'Nested/obfuscated JNDI ${jndi:ldap://...} strings bypass edge WAF pattern matching' }, ml: { mitigates: true, control: 'NIST SI-4 / SC-7', reason: 'Agentic SOC Mitigation terminates unexpected outbound LDAP/RMI egress from worker node' } },
    'CVE-2023-22527': { waf: { mitigates: false, reason: 'OGNL template injection resides inside legitimate JSON/POST application payload' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects anomalous subprocess spawning /bin/sh from java.exe' } },
    'CVE-2022-22965': { waf: { mitigates: false, reason: 'Spring parameter binding injection evades standard perimeter URL signatures' }, ml: { mitigates: true, control: 'NIST SI-4 / SI-3', reason: 'Agentic SOC Mitigation halts unexpected file write to Tomcat webapps/ROOT/shell.jsp' } },
    'CVE-2022-29464': { waf: { mitigates: false, reason: 'Multipart file upload endpoint accepts standard HTTP multipart requests' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Zero-Trust agent blocks execution of newly dropped unapproved JSP binary' } },
    'CVE-2023-2868': { waf: { mitigates: false, reason: 'Perimeter WAF does not inspect deep internal tar archive attachments' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects anomalous reverse shell connection to foreign IP' } },
    'CVE-2022-30190': { waf: { mitigates: false, reason: 'MSDT URI handler protocol payload passes perimeter proxies as normal doc link' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation terminates rogue sdiagnhost.exe process execution' } },
    'CVE-2023-46604': { waf: { mitigates: false, reason: 'OpenWire TCP 61616 protocol traffic bypasses perimeter HTTP WAF' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation terminates anomalous Java ClassPathXmlApplicationContext load' } },
    'CVE-2022-46169': { waf: { mitigates: false, reason: 'Forwarded-For header spoofing bypasses remote agent authentication' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation flags shell command injection in poller.php execution' } },
    'CVE-2023-42793': { waf: { mitigates: false, reason: 'The internal TeamCity management service is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Behavioral monitoring detects an anomalous TeamCity administrative session and build execution.' } },
    'CVE-2023-34362': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2', reason: 'WAF SQLi virtual patch inspects & blocks malformed X-MOVEit headers' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects abnormal mass query exfiltration on core SQL tables' } },
    'CVE-2023-27350': { waf: { mitigates: false, reason: 'Setup wizard bypass occurs over legitimate administrative web interface' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation blocks unauthenticated database dump and lateral admin spawn' } },
    'CVE-2020-1472': { waf: { mitigates: false, reason: 'Zerologon exploits Netlogon RPC (TCP 135/445), not covered by HTTP/WAF' }, ml: { mitigates: true, control: 'NIST AC-3 / IA-5', reason: 'Agentic SOC Mitigation flags anomalous NetrServerAuthenticate with 16 zero-bytes' } },
    'CVE-2023-36884': { waf: { mitigates: false, reason: 'Office document protocol payload bypasses perimeter application firewalls' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation halts SearchFilterHost.exe memory injection and credential dump' } },
    'CVE-2023-0669': { waf: { mitigates: false, reason: 'Encrypted deserialization payload in GoAnywhere passes perimeter proxies' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects abnormal customer storage zone file exfiltration' } },
    'CVE-2023-48788': { waf: { mitigates: false, reason: 'FortiClient EMS SQL injection occurs inside internal enterprise client RPC' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects xp_cmdshell execution and mass DB schema dumping' } },
    'CVE-2022-47966': { waf: { mitigates: false, reason: 'SAML XML body injection evades edge pattern matchers without deep cert validation' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation blocks anomalous PostgreSQL data export and child process execution' } },
    'CVE-2024-37085': { waf: { mitigates: false, reason: 'ESXi hypervisor management protocol operates outside perimeter WAF boundaries' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation alerts on rogue ESX Admins group creation attempting VMFS storage exfil' } },
    'CVE-2023-24489': { waf: { mitigates: false, reason: 'Unauthenticated file upload to Storage Zone Controller bypasses perimeter checks' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation halts unexpected high-volume S3 customer lake exfiltration' } },
    'CVE-2022-26134': { waf: { mitigates: false, reason: 'OGNL payload executed against internal application server pool' }, ml: { mitigates: true, control: 'NIST IA-5', reason: 'Agentic SOC Mitigation detects memory dumping of database connection credentials' } },
    'CVE-2024-1086': { waf: { mitigates: false, reason: 'Local Linux kernel netfilter double-free exploit is internal to host OS' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation terminates unauthorized privilege escalation targeting root vault databases' } },
    'CVE-2022-22954': { waf: { mitigates: false, reason: 'SSTI expression inside OAuth client parameters bypasses standard URI filters' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects lateral dump of embedded identity database secrets' } },
    'CVE-2018-13379': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Virtual patch filters malicious requests to the FortiOS SSL VPN web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2019-11510': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Virtual patch filters malicious requests to the Pulse web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2021-42013': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2', reason: 'WAF rule blocks traversal requests.' }, ml: { mitigates: false, reason: 'The edge server is outside internal behavioral monitoring.' } },
    'CVE-2024-29824': { waf: { mitigates: false, reason: 'The EPM core server is on the internal network.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Monitoring flags anomalous EPM database activity.' } },
    'CVE-2020-14882': { waf: { mitigates: false, reason: 'The internal WebLogic console is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Monitoring flags anomalous console access.' } },
    'CVE-2022-0543': { waf: { mitigates: false, reason: 'Redis protocol traffic is outside the HTTP WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Monitoring flags unexpected Redis child processes.' } },
    'CVE-2020-0618': { waf: { mitigates: false, reason: 'The internal reporting service is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Monitoring flags unexpected reporting-service execution.' } },
    'CVE-2020-10148': { waf: { mitigates: false, reason: 'Signed build-pipeline and internal Orion management traffic bypasses perimeter HTTP WAF filters.' }, ml: { mitigates: true, control: 'NIST SI-4 / CM-14', reason: 'Behavioral monitoring flags anomalous Orion child-process execution and unauthorized SAML/AD token minting.' } },
    'CVE-2021-30116': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Virtual patch blocks unauthenticated Kaseya VSA /dl.asp and SQLi parameter payloads when covered by an inline WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Behavioral monitoring detects anomalous RMM mass agent package deployment and encoded PowerShell execution.' } },
    'CVE-2023-46747': { waf: { mitigates: false, reason: 'The BIG-IP management interface is assumed reachable outside the protected application path.' }, ml: { mitigates: false, reason: 'The appliance management plane is outside internal host monitoring.' } },
    'CVE-2023-32707': { waf: { mitigates: false, reason: 'The Splunk management service is internal.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Monitoring flags anomalous administrative role changes.' } },
    'CVE-2020-3452': { waf: { mitigates: true, appliesToGroups: ['cisco-asa'], inspectedProtocols: ['https'], control: 'NIST SI-2 / SC-7', reason: 'Virtual patch filters directory-traversal requests to the Cisco ASA WebVPN web services when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2021-20016': { waf: { mitigates: true, appliesToGroups: ['sonicwall-sma'], inspectedProtocols: ['https'], control: 'NIST SI-2 / SC-7', reason: 'SQL-injection virtual patch inspects and blocks malformed requests to the SonicWall SMA management portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2022-1040': { waf: { mitigates: true, appliesToGroups: ['sophos-firewall'], inspectedProtocols: ['https'], control: 'NIST SI-2 / SC-7', reason: 'Virtual patch blocks the authentication-bypass request to the Sophos Firewall user portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2023-28771': { waf: { mitigates: false, reason: 'Zyxel ATP IKE/UDP-500 command injection is outside the L7 HTTP WAF scope.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2024-24919': { waf: { mitigates: true, appliesToGroups: ['checkpoint-quantum'], inspectedProtocols: ['https'], control: 'NIST SI-2 / SC-7', reason: 'Virtual patch filters the pre-auth arbitrary-file-read request to the Check Point remote-access portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } }
  };

  ['CVE-2025-64446', 'CVE-2018-5412', 'CVE-2021-3827', 'CVE-2018-8340', 'CVE-2020-4888', 'CVE-2026-78597', 'CVE-2026-25769', 'CVE-2022-29712', 'CVE-2021-35225'].forEach(id => {
    KEV_MITIGATION_RULES[id] = {
      waf: { mitigates: false, reason: 'The management or service path is outside the perimeter WAF.' },
      ml: { mitigates: true, control: 'NIST SI-4', reason: 'The scenario assumes independent monitoring detects the anomalous activity.' }
    };
  });

  // Coverage is an explicit declaration, separate from whether a CVE is in KEV.
  // Legacy declarations are normalized here so every executable control has the
  // same boundary contract without duplicating state in the renderer.
  for (const rule of Object.values(KEV_MITIGATION_RULES)) {
    for (const control of ['waf', 'ml']) {
      const declaration = rule[control];
      if (!declaration || typeof declaration.reason !== 'string' || !declaration.reason.trim()) continue;
      if (!declaration.state) declaration.state = declaration.mitigates ? 'modeled' : 'unsupported';
    }
  }

  const LAYER_CONFIG = [
    {
      name: '01 / Cloud Ingress',
      xBand: [0.08, 0.22],
      clusters: [
        {
          name: 'AWS Cloud Perimeter',
          targets: [
            { id: 'public-s3', icon: 'data.png', interfaces: ['storage-s3', 'https'], attackTechnique: 'T1530', attackDescription: 'Data from Cloud Storage', publicExposure: 'S3 bucket permits anonymous public read; the contents are not assumed to contain credentials.', variants: ['Amazon S3 · Bucket'] },
            { id: 'ivanti-connect', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2023-46805'], variants: ['Ivanti Connect Secure VPN'] },
            { id: 'f5-gateway', icon: 'network.png', interfaces: ['https'], kevByVariant: ['CVE-2022-1388'], variants: ['F5 BIG-IP Management Interface'] },
            { id: 'forti-vpn', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2018-13379'], variants: ['Fortinet FortiGate SSL VPN'] },
            { id: 'cisco-asa', icon: 'network.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2020-3452'], variants: ['Cisco ASA Firewall'] }
          ]
        },
        {
          name: 'Azure Enterprise',
          targets: [
            { id: 'public-blob', icon: 'data.png', interfaces: ['storage-s3', 'https'], attackTechnique: 'T1530', attackDescription: 'Data from Cloud Storage', publicExposure: 'Azure Blob container permits anonymous public read; the contents are not assumed to contain credentials.', variants: ['Azure Blob Storage · Container'] },
            { id: 'pan-globalprotect', icon: 'network.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2024-3400'], variants: ['PAN-OS GlobalProtect Gateway'] },
            { id: 'sonicwall-sma', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2021-20016'], variants: ['SonicWall SMA 100'] },
            { id: 'sophos-firewall', icon: 'network.png', interfaces: ['https'], kevByVariant: ['CVE-2022-1040'], variants: ['Sophos Firewall'] }
          ]
        },
        {
          name: 'GCP & Partners',
          targets: [
            { id: 'public-gitlab', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'GitLab project is publicly readable contrary to its intended access policy.', variants: ['GitLab · Project'] },
            { id: 'public-bitbucket', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'Bitbucket repository is publicly readable contrary to its intended access policy.', variants: ['Bitbucket · Repository'] },
            { id: 'citrix-adc', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-3519'], variants: ['Citrix NetScaler ADC Gateway'] },
            { id: 'zyxel-atp', icon: 'network.png', interfaces: ['vpn'], kevByVariant: ['CVE-2023-28771'], variants: ['Zyxel ATP Firewall'] },
            { id: 'checkpoint-quantum', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2024-24919'], variants: ['Check Point Quantum Gateway'] },
            { id: 'apache-edge', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-42013'], variants: ['Apache HTTP Server 2.4.50 Edge'] },
            { id: 'support-diagnostics', preset: 'mixed', icon: 'configuration.png', interfaces: ['https'], variants: ['Support Diagnostics Portal'] },
            { id: 'external-misconfig', preset: 'mixed', icon: 'configuration.png', variants: ['External service'] }
          ]
        }
      ]
    },
    {
      name: '02 / Gateways & Auth',
      xBand: [0.32, 0.46],
      clusters: [
        {
          name: 'API Gateways',
          targets: [
            { id: 'cust-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464', 'CVE-2022-29464', 'CVE-2022-29464'], variants: ['WSO2 Customer API GW #01', 'WSO2 Customer API GW #02', 'WSO2 Customer API GW #03'] },
            { id: 'partner-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464', 'CVE-2022-29464', 'CVE-2022-29464'], variants: ['WSO2 Partner API Gateway', 'WSO2 B2B Webhook Gateway', 'WSO2 Partner Sync Gateway'] },
            { id: 'waf-proxy', icon: 'server-infrastructure.png', interfaces: ['https'], isSecurity: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2023-46747', 'CVE-2025-64446', 'CVE-2023-3519', 'CVE-2018-5412'], variants: ['F5 BIG-IP Advanced WAF', 'Fortinet FortiWeb WAF', 'Citrix NetScaler WAF + Gateway', 'Imperva SecureSphere WAF'] },
            { id: 'wso2-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464'], variants: ['WSO2 API Manager'] },
            { id: 'exchange', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-26855'], variants: ['Microsoft Exchange Server'] },
            { id: 'staging-status', preset: 'mixed', icon: 'api.png', interfaces: ['api-https'], variants: ['Staging Status API'] }
          ]
        },
        {
          name: 'Identity & Access',
          targets: [
            { id: 'iam-idp', icon: 'identity.png', interfaces: ['https'], supportsSpray: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2022-22954', 'CVE-2018-8340', 'CVE-2021-3827', null], variants: ['VMware Workspace ONE Access IdP', 'Microsoft AD FS IdP', 'Red Hat Keycloak IdP', 'Okta Identity Cloud'] },
            { id: 'vault-creds', icon: 'configuration.png', interfaces: ['https', 'api-https'], isSecurity: true, variants: ['HashiCorp Vault Secrets Server'] },
            { id: 'sentry-auth', icon: 'endpoint.png', interfaces: ['https'], supportsSpray: true, kevByVariant: ['CVE-2023-38035', 'CVE-2023-38035'], variants: ['Ivanti Sentry GW 01', 'Ivanti Sentry GW 02'] },
            { id: 'ad-identity', icon: 'identity.png', interfaces: ['ad-rpc', 'https'], supportsSpray: true, kevByVariant: ['CVE-2022-26923'], variants: ['Active Directory Domain Controller'] },
            { id: 'ivanti-epm', icon: 'endpoint.png', interfaces: ['https'], kevByVariant: ['CVE-2024-29824'], variants: ['Ivanti Endpoint Manager Core'] }
          ]
        },
        {
          name: 'Boundary Controls',
          targets: [
            { id: 'threat-det', icon: 'threat-detection.png', interfaces: ['https'], isSecurity: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2023-32707', 'CVE-2020-4888', 'CVE-2026-78597', 'CVE-2026-25769'], variants: ['Splunk Enterprise', 'IBM QRadar SIEM', 'Elastic Security / Kibana', 'Wazuh Server'] }
          ]
        }
      ]
    },
    {
      name: '03 / Services Mesh',
      xBand: [0.54, 0.70],
      clusters: [
        {
          name: 'Core Applications',
          targets: [
            { id: 'app-engine', icon: 'application.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-22965', 'CVE-2022-22965', 'CVE-2022-22965'], variants: ['Spring MVC WAR / Tomcat / JDK 9+ (Core)', 'Spring MVC WAR / Tomcat / JDK 9+ (Billing)', 'Spring MVC WAR / Tomcat / JDK 9+ (Checkout)'] },
            { id: 'comp-registry', icon: 'components.png', interfaces: ['api-https', 'https'], variants: ['Container Registry'] },
            { id: 'cicd-runner', icon: 'cicd.png', interfaces: ['https'], kevByVariant: ['CVE-2023-42793'], variants: ['JetBrains TeamCity Build Server'] },
            { id: 'activemq', icon: 'components.png', interfaces: ['amqp'], kevByVariant: ['CVE-2023-46604'], variants: ['Apache ActiveMQ Message Broker'] },
            { id: 'moveit-sftp', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-34362', 'CVE-2023-0669'], variants: ['MOVEit Transfer (B2B EDI Integration)', 'GoAnywhere MFT (FinOps Data Exchange)'] }
          ]
        },
        {
          name: 'Internal Microservices',
          targets: [
            { id: 'log4j-svc', icon: 'server-infrastructure.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2021-44228', 'CVE-2021-44228'], variants: ['Service using Log4j 2 #01', 'Service using Log4j 2 #02'] },
            { id: 'spring-svc', icon: 'application.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-22965', 'CVE-2022-22965'], variants: ['Spring MVC WAR (Tomcat / JDK 9+) A', 'Spring MVC WAR (Tomcat / JDK 9+) B'] },
            { id: 'confluence-node', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-22527'], variants: ['Internal Confluence Data Center'] },
            { id: 'confluence-admin', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2023-22515'], variants: ['Confluence Server 8.5.1'] },
            { id: 'weblogic', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2020-14882'], variants: ['Oracle WebLogic Admin Console'] },
            { id: 'sql-reporting', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2020-0618'], variants: ['SQL Server Reporting Services'] },
            { id: 'forti-ems', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-48788'], variants: ['FortiClient EMS Server'] }
          ]
        },
        {
          name: 'AI & Operations',
          targets: [
            { id: 'ai-core', icon: 'ai.png', interfaces: ['api-https'], kevByVariant: ['CVE-2026-42271'], variants: ['LiteLLM Proxy 1.83.6'] },
            { id: 'iot-hub', icon: 'iot.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2021-44228'], variants: ['IoT Ingestion using Log4j 2'] },
            { id: 'vuln-scan', icon: 'vulnerability-management.png', interfaces: ['https'], isSecurity: true, productPool: true, maxInstances: 1, includeChance: 0.9, kevByVariant: ['CVE-2022-46169', 'CVE-2022-29712', 'CVE-2021-35225', null, null, null], variants: ['Cacti Network Monitoring Server', 'LibreNMS 22.3.0', 'SolarWinds NPM 2020.2.6', 'Zabbix Network Monitor', 'PRTG Network Monitor', 'ManageEngine OpManager'] }
          ]
        }
      ]
    },
    {
      name: '04 / Data Stores & Secrets',
      xBand: [0.78, 0.92],
      clusters: [
        {
          name: 'Data Stores: Customer Records & Orders',
          targets: [
            { id: 'lake-cust', icon: 'data.png', interfaces: ['storage-s3', 'https'], isLake: true, variants: ['Customer Lake S3 (Parquet · Data Platform)', 'Customer Lake S3 (Curated · BI Team)', 'Customer Lake S3 (Cold Archive · Compliance)'] },
            { id: 'db-rds', icon: 'server-infrastructure.png', interfaces: ['db-pg'], isDb: true, variants: ['Customer Postgres RDS (Primary · Core DBA)', 'Customer Postgres RDS (Replica 1 · Read Ops)', 'Customer MySQL RDS (Orders · Merchant Team)'] }
          ]
        },
        {
          name: 'Data Stores: Analytics, Document & Secrets',
          targets: [
            { id: 'lake-ops', icon: 'data.png', interfaces: ['storage-s3', 'https'], variants: ['Snowflake Warehouse (SnowSQL · Enterprise BI)', 'ClickHouse Telemetry Lake (SecOps Team)', 'BigQuery Analytics Lake (Marketing Data)'] },
            { id: 'nosql-doc', icon: 'server-infrastructure.png', interfaces: ['db-pg', 'https'], isDb: true, variants: ['MongoDB Cluster (DocStore · Mobile App Team)', 'Redis Cache Cluster (In-Memory · Session Ops)', 'Cassandra DB (Streaming · Event Team)'] },
            { id: 'litellm-db', icon: 'server-infrastructure.png', interfaces: ['db-pg'], isDb: true, variants: ['LiteLLM PostgreSQL Database'] },
            { id: 'mssql-db', icon: 'server-infrastructure.png', interfaces: ['db-mssql'], isDb: true, variants: ['Microsoft SQL Server Database'] },
            { id: 'redis-debian', icon: 'server-infrastructure.png', interfaces: ['redis'], isDb: true, kevByVariant: ['CVE-2022-0543'], variants: ['Debian Redis Session Cache'] }
          ]
        }
      ]
    }
  ];

  const ALLOWED_CONNECTIONS = {
    'support-diagnostics': ['staging-status'],
    'public-gitlab': ['iam-idp'],
    'ivanti-connect': ['cust-api', 'iam-idp'],
    'f5-gateway': ['cust-api', 'partner-api', 'waf-proxy', 'wso2-api'],
    'forti-vpn': ['sentry-auth', 'ivanti-epm', 'iam-idp', 'ad-identity', 'vault-creds', 'threat-det'],
    'cisco-asa': ['iam-idp', 'ad-identity'],
    'sonicwall-sma': ['sentry-auth', 'iam-idp'],
    'sophos-firewall': ['exchange', 'iam-idp'],
    'zyxel-atp': ['partner-api', 'iam-idp'],
    'checkpoint-quantum': ['iam-idp', 'ad-identity'],
    'apache-edge': ['cust-api', 'exchange'],
    'pan-globalprotect': ['cust-api', 'iam-idp'],
    'citrix-adc': ['wso2-api'],
    'cust-api': ['app-engine', 'spring-svc', 'iot-hub', 'ai-core', 'log4j-svc', 'activemq'],
    'partner-api': ['app-engine', 'iot-hub', 'moveit-sftp'],
    'waf-proxy': ['app-engine', 'spring-svc', 'confluence-node'],
    'iam-idp': ['app-engine', 'spring-svc', 'cicd-runner', 'comp-registry'],
    'wso2-api': ['app-engine', 'spring-svc', 'moveit-sftp', 'ai-core'],
    'sentry-auth': ['app-engine', 'spring-svc', 'forti-ems', 'sql-reporting'],
    'exchange': ['confluence-admin'],
    'ivanti-epm': ['forti-ems', 'weblogic', 'vuln-scan'],
    'app-engine': ['lake-cust', 'db-rds', 'nosql-doc', 'redis-debian'],
    'moveit-sftp': ['lake-cust'],
    'confluence-node': ['mssql-db'],
    'confluence-admin': ['mssql-db'],
    'spring-svc': ['db-rds', 'nosql-doc'],
    'iot-hub': ['lake-ops', 'nosql-doc'],
    'ai-core': ['litellm-db'],
    'activemq': ['nosql-doc', 'redis-debian'],
    'cicd-runner': ['db-rds'],
    'sql-reporting': ['mssql-db'],
    'forti-ems': ['mssql-db'],
    'weblogic': ['db-rds']
  };

  // Existing service routes that orient the operator before playback reveals activity.
  const FULL_ENTERPRISE_OVERVIEW = {
    'forti-vpn': ['ad-identity', 'iam-idp', 'vault-creds'],
    'public-gitlab': ['iam-idp'],
    'f5-gateway': ['cust-api'],
    'cust-api': ['app-engine', 'iot-hub'],
    'iam-idp': ['app-engine', 'cicd-runner', 'comp-registry'],
    'app-engine': ['db-rds'],
    'iot-hub': ['lake-ops'],
    'cicd-runner': ['db-rds'],
    'windows-desktop': ['windows-management'],
    'windows-rdp': ['windows-management'],
    'windows-management': ['windows-fleet-finance']
  };

  const EXTERNAL_ENTRY_GROUPS = new Set([
    ...Object.keys(EDGE_APPLIANCES), 'apache-edge', 'public-s3', 'public-blob',
    'public-gitlab', 'public-bitbucket', 'support-diagnostics', 'external-misconfig'
  ]);

  const DEFENSE_SCENARIOS = {
    baseline: { tag: '01 / BASELINE', name: 'Baseline (Unmitigated)' },
    patch: { tag: '02 / VIRTUAL PATCH', name: 'Virtual Patch (WAF)' },
    canaries: { tag: '03 / CANARIES', name: 'Canaries (Alert Only)' },
    defender: { tag: '04 / AGENTIC SOAR', name: 'Agentic SOAR' },
    soc: { tag: '04 / AGENTIC SOC', name: 'Agentic SOC' },
    'soc-canary': { tag: '05 / SOC + CANARY', name: 'Agentic SOC + Canary' },
    combined: { tag: '05 / DEFENSE IN DEPTH', name: 'Defense in Depth' }
  };

  function createRng(seed) {
    let a = (seed >>> 0) || 1;
    return function () {
      a |= 0;
      a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function hashNode(seed, id, salt) {
    let hash = ((salt >>> 0) ^ (seed >>> 0)) >>> 0;
    for (let i = 0; i < id.length; i++) {
      hash = Math.imul(hash ^ id.charCodeAt(i), 16777619);
    }
    hash ^= hash >>> 16; hash = Math.imul(hash, 0x7feb352d);
    hash ^= hash >>> 15; hash = Math.imul(hash, 0x846ca68b);
    hash ^= hash >>> 16;
    return (hash >>> 0) / 4294967296;
  }

  function soarDetects(assetId, seed, multiplier = 1) {
    return hashNode(seed, assetId, 2166136261) < Math.min(0.95, SOAR_DETECTION_RATE * multiplier);
  }

  function wafPortalCovered(assetId, seed) {
    return hashNode(seed, assetId, 0x9e3779b9) < WAF_PORTAL_COVERAGE;
  }

  function getTargetDef(groupId) {
    for (let l = 0; l < LAYER_CONFIG.length; l++) {
      for (const cluster of LAYER_CONFIG[l].clusters) {
        for (const t of cluster.targets) {
          if (t.id === groupId) return { def: t, layerIdx: l, clusterName: cluster.name };
        }
      }
    }
    return null;
  }

  function findKev(layerIdx, cveId) {
    if (!cveId) return null;
    return (LAYER_KEVS[layerIdx] || []).find(k => k.id === cveId) || null;
  }

  function inferConnectionProtocol(sourceAsset, targetAsset) {
    const tIfaces = targetAsset.interfaces;
    if (tIfaces.includes('db-pg')) return 'db-pg';
    if (tIfaces.includes('db-mssql')) return 'db-mssql';
    if (tIfaces.includes('redis')) return 'redis';
    if (tIfaces.includes('amqp')) return 'amqp';
    if (tIfaces.includes('ad-rpc')) return 'ad-rpc';
    if (tIfaces.includes('storage-s3')) return 'storage-s3';
    if (tIfaces.includes('api-https')) return 'api-https';
    return 'https';
  }

  function inferTrustBoundary(sourceLayer, targetLayer) {
    if (sourceLayer === 0 && targetLayer === 1) return 'dmz-to-edge';
    if (sourceLayer === 1 && targetLayer === 2) return 'edge-to-mesh';
    if (sourceLayer === 2 && targetLayer === 3) return 'mesh-to-data';
    return 'same-zone';
  }

  // Build the surface coverage manifest (Spec Section 7.1, F35) classifying every
  // advertised group and variant in LAYER_CONFIG as executable vs. contextual.
  const SURFACE_COVERAGE_MANIFEST = (function buildSurfaceCoverageManifest() {
    const groups = {};
    LAYER_CONFIG.forEach((layer, layerIdx) => {
      layer.clusters.forEach(cluster => {
        cluster.targets.forEach(target => {
          const reviewed = REVIEWED_EXAMPLES[target.id];
          const variants = target.variants.map((label, vIdx) => {
            const cveId = target.kevByVariant ? target.kevByVariant[vIdx] : null;
            const cveSpec = (reviewed && reviewed.cve === cveId) ? reviewed : (cveId ? REVIEWED_VARIANT_CVES[cveId] : null);
            const executableCve = !!(cveId && reviewed && reviewed.cve === cveId && findKev(layerIdx, cveId));
            const surfaceKind = executableCve
              ? 'executable_cve'
              : target.publicExposure
                ? 'executable_public_exposure'
                : (target.id === 'support-diagnostics' || target.id === 'external-misconfig')
                  ? 'executable_misconfiguration'
                  : (target.supportsSpray || layerIdx === 3 || target.id === 'staging-status')
                    ? 'executable_credential_or_spray'
                    : 'contextual_only';
            return {
              variantIdx: vIdx,
              label,
              cveId,
              surfaceKind,
              executableThroughDefaultGenerator: executableCve || !!target.publicExposure || target.supportsSpray || layerIdx === 3 || ['support-diagnostics', 'external-misconfig', 'staging-status'].includes(target.id),
              hasReviewedCveMetadata: !cveId || !!cveSpec
            };
          });
          groups[target.id] = {
            groupId: target.id,
            layerIdx,
            clusterName: cluster.name,
            interfaces: [...(target.interfaces || ['https'])],
            variants
          };
        });
      });
    });
    return { schemaVersion: 1, groups };
  }());

  function auditSurfaceCoverage(estate, attackerProfile = null) {
    const presentInterfaces = new Set((estate?.assets || []).flatMap(a => a.interfaces || []));
    const presentFindingKinds = new Set((estate?.findings || []).map(f => f.kind));
    const displayOnlyAssets = (estate?.assets || []).filter(a => {
      const hasFinding = (estate?.findings || []).some(f => f.assetId === a.id);
      const hasInboundCred = (estate?.credentials || []).some(c =>
        c.targetAssetIds?.includes(a.id) || (!c.targetAssetIds?.length && c.targetGroupIds?.includes(a.groupId)));
      return !hasFinding && !hasInboundCred;
    }).map(a => ({ assetId: a.id, groupId: a.groupId, referenceCve: a.referenceCve || null, role: 'contextual_or_healthy' }));

    const advertisedFamilies = [];
    if (attackerProfile) {
      if (attackerProfile.allowsUserInteraction) advertisedFamilies.push({ family: 'phishing_attachment', requiredInterface: 'email', requiredKind: 'phishing_attachment' });
      if (attackerProfile.availableTools?.includes('psexec') || attackerProfile.availableTools?.includes('cobalt_strike')) {
        advertisedFamilies.push({ family: 'windows_remote_service_tools', requiredInterface: 'smb', requiredKind: 'remote_service' });
      }
      if (attackerProfile.allowsRansomwareImpact) advertisedFamilies.push({ family: 'endpoint_encryption', requiredInterface: null, requiredKind: 'encryption' });
      if (attackerProfile.allowsPersistence) advertisedFamilies.push({ family: 'registry_persistence', requiredInterface: null, requiredKind: 'persistence' });
    }
    const unavailableFamilies = advertisedFamilies.filter(item =>
      (item.requiredInterface && !presentInterfaces.has(item.requiredInterface)) ||
      (item.requiredKind && !presentFindingKinds.has(item.requiredKind))
    );
    return {
      manifest: SURFACE_COVERAGE_MANIFEST,
      displayOnlyAssets,
      advertisedFamilies,
      unavailableFamilies,
      hasAdvertisingGap: unavailableFamilies.length > 0
    };
  }

  function validateCalibrationRegister(register = CALIBRATION_REGISTER) {
    const errors = [];
    const details = [];
    const fail = (entityId, fieldPath, reason) => {
      errors.push(`${entityId} (${fieldPath}): ${reason}`);
      details.push({ entityId, fieldPath, reason });
    };
    if (!register || typeof register !== 'object') {
      fail('calibration', 'root', 'Calibration register must be an object');
      return { valid: false, errors, warnings: [], details };
    }
    if (register.schemaVersion !== 1) fail('calibration', 'schemaVersion', `Expected schemaVersion 1, got ${register.schemaVersion}`);
    if (!Array.isArray(register.observedStatistics) || register.observedStatistics.length === 0) {
      fail('calibration', 'observedStatistics', 'observedStatistics must be a non-empty array');
    }
    if (!Array.isArray(register.simulationAssumptions) || register.simulationAssumptions.length === 0) {
      fail('calibration', 'simulationAssumptions', 'simulationAssumptions must be a non-empty array');
    }
    if (errors.length) return { valid: false, errors, warnings: [], details };

    const statIds = new Set();
    for (const stat of register.observedStatistics) {
      const id = stat?.id || 'unknown_stat';
      if (!stat?.id || statIds.has(stat.id)) fail(id, 'id', 'Duplicate or missing observedStatistic id');
      statIds.add(id);
      if (stat.provenanceType !== 'historical_source') fail(id, 'provenanceType', 'observedStatistic must have provenanceType="historical_source"');
      if (!stat.sourceUrl || !stat.publicationDate || !stat.population || !stat.statisticType || !stat.unit || !stat.startMilestone || !stat.endMilestone) {
        fail(id, 'fields', 'Missing required observedStatistic provenance or milestone fields');
      }
      // Fixture F33: An observed mean cannot present p50, p90, or a fitted distribution as source_fact without separate evidence.
      if (stat.statisticType === 'mean' && stat.displayClassification === 'source_fact') {
        if (stat.reportedQuantiles && (stat.reportedQuantiles.p50 != null || stat.reportedQuantiles.p90 != null)) {
          fail(id, 'reportedQuantiles', 'An observed mean cannot present p50 or p90 quantiles as source_fact without separate quantile evidence (F33)');
        }
        if (stat.fittedDistribution) {
          fail(id, 'fittedDistribution', 'An observed mean cannot present a fitted distribution as source_fact (F33)');
        }
      }
    }

    const assumptionIds = new Set();
    for (const assumption of register.simulationAssumptions) {
      const id = assumption?.id || 'unknown_assumption';
      if (!assumption?.id || assumptionIds.has(assumption.id)) fail(id, 'id', 'Duplicate or missing simulationAssumption id');
      assumptionIds.add(id);
      if (!['historical_source', 'vendor_reference', 'expert_assumption', 'authored_fixture'].includes(assumption.provenanceType)) {
        fail(id, 'provenanceType', `Invalid provenanceType: ${assumption.provenanceType}`);
      }
      if (assumption.displayClassification !== 'synthetic_assumption') {
        fail(id, 'displayClassification', 'simulationAssumption must carry displayClassification="synthetic_assumption"');
      }
      if (assumption.unit === 'probability' && (typeof assumption.value !== 'number' || assumption.value < 0 || assumption.value > 1)) {
        fail(id, 'value', 'Probability assumption must be a number in [0, 1]');
      }
      for (const refId of assumption.referencedStatisticIds || []) {
        if (!statIds.has(refId)) fail(id, 'referencedStatisticIds', `Unknown referencedStatisticId: ${refId}`);
      }
    }
    return { valid: errors.length === 0, errors, warnings: [], details };
  }

  function validateEstate(estate) {
    const errors = [];
    const warnings = [];
    const details = [];
    const fail = (entityId, fieldPath, reason) => {
      errors.push(reason);
      details.push({ entityId, fieldPath, reason });
    };
    if (!estate || typeof estate !== 'object') {
      fail('estate', 'root', 'Estate must be an object');
      return { valid: false, errors, warnings, details };
    }
    if (estate.schemaVersion !== SCHEMA_VERSION) {
      fail(estate.id || 'estate', 'schemaVersion', `Expected schemaVersion ${SCHEMA_VERSION}, got ${estate.schemaVersion}`);
    }
    if (!['mixed', 'demo', 'logs', 'comparison'].includes(estate.preset)) {
      fail(estate.id || 'estate', 'preset', `Invalid preset: ${estate.preset}`);
    }
    if (estate.archetypeId != null && !INFRASTRUCTURE_ARCHETYPES[estate.archetypeId]) {
      fail(estate.id || 'estate', 'archetypeId', `Invalid archetypeId: ${estate.archetypeId}`);
    }
    if (estate.generationMode != null && !['exploratory', 'authored_walkthrough'].includes(estate.generationMode)) {
      fail(estate.id || 'estate', 'generationMode', `Invalid generationMode: ${estate.generationMode}`);
    }
    if (!Array.isArray(estate.assets)) fail('estate', 'assets', 'assets must be an array');
    if (!Array.isArray(estate.findings)) fail('estate', 'findings', 'findings must be an array');
    if (!Array.isArray(estate.credentials)) fail('estate', 'credentials', 'credentials must be an array');
    if (!Array.isArray(estate.relationships)) fail('estate', 'relationships', 'relationships must be an array');
    if (errors.length) return { valid: false, errors, warnings, details };

    const assetIds = new Set();
    for (const a of estate.assets) {
      if (!a.id || assetIds.has(a.id)) fail(a?.id || 'asset', 'id', `Duplicate or missing asset id: ${a.id}`);
      assetIds.add(a.id);
      if (a.endpointIds && (!Array.isArray(a.endpointIds) || !a.endpointIds.length ||
          new Set(a.endpointIds).size !== a.endpointIds.length || a.endpointCount !== a.endpointIds.length)) {
        fail(a.id, 'endpointIds', `Invalid fleet endpoint inventory on ${a.id}`);
      }
      if (typeof a.layerIdx !== 'number' || a.layerIdx < 0 || a.layerIdx > 3) {
        fail(a.id, 'layerIdx', `Invalid layerIdx on asset ${a.id}`);
      }
      if (!Array.isArray(a.interfaces) || a.interfaces.length === 0) {
        fail(a.id, 'interfaces', `Asset ${a.id} must declare interfaces`);
      } else if (a.interfaces.some(iface => typeof iface !== 'string' || !iface.trim() || iface !== iface.trim())) {
        fail(a.id, 'interfaces', `Asset ${a.id} has an invalid interface identifier`);
      }
    }

    if (estate.actionOrder != null && !Array.isArray(estate.actionOrder)) fail('estate', 'actionOrder', 'actionOrder must be an array');
    if (Array.isArray(estate.actionOrder) && estate.actionOrder.length) {
      const order = new Set(estate.actionOrder);
      if (order.size !== estate.actionOrder.length) fail('estate', 'actionOrder', 'Duplicate actionOrder IDs');
      for (const id of order) if (!assetIds.has(id)) fail(id, 'actionOrder', `Unknown actionOrder ID ${id}`);
      for (const id of assetIds) if (!order.has(id)) fail(id, 'actionOrder', `Missing actionOrder ID ${id}`);
    }
    if (estate.defensePosture?.decoys) {
      if (!Array.isArray(estate.defensePosture.decoys)) fail('estate', 'defensePosture.decoys', 'Decoys must be an array');
      else for (const decoy of estate.defensePosture.decoys) {
        if (decoy.kind === 'honeytoken_credential' || decoy.credentialId) {
          if (!estate.credentials.some(c => c.id === decoy.credentialId)) {
            fail(decoy?.credentialId || 'decoy', 'defensePosture.decoys', `Undeployed honeytoken decoy ${decoy.credentialId}`);
          }
        } else if (!estate.assets.some(a => a.id === decoy.assetId && a.isDecoy)) {
          fail(decoy?.assetId || 'decoy', 'defensePosture.decoys', `Undeployed decoy ${decoy.assetId}`);
        }
      }
    }
    const findingIds = new Set();
    for (const f of estate.findings) {
      if (!f.id || findingIds.has(f.id)) fail(f?.id || 'finding', 'id', `Duplicate or missing finding id: ${f.id}`);
      findingIds.add(f.id);
      if (!assetIds.has(f.assetId)) fail(f.id, 'assetId', `Finding ${f.id} references unknown asset ${f.assetId}`);
      if (f.kind === 'exercise') {
        fail(f.id, 'kind', `Legacy exercise shortcut finding ${f.id} is prohibited in Schema v4; use instantiateScenario with explicit prerequisites`);
      }
      if (f.kind === 'cve') {
        const rule = KEV_MITIGATION_RULES[f.cveId];
        if (!rule?.waf || !rule?.ml) fail(f.id, 'cveId', `Missing declared control coverage for ${f.cveId}`);
        else for (const control of ['waf', 'ml']) {
          const declaration = rule[control];
          if (!['modeled', 'not_applicable', 'unsupported', 'unknown'].includes(declaration.state) || !declaration.reason?.trim()) {
            fail(f.id, `coverage.${control}`, `Invalid ${control} coverage declaration for ${f.cveId}`);
          }
          if (declaration.state !== 'modeled' && declaration.mitigates) fail(f.id, `coverage.${control}`, `Non-modeled ${control} coverage cannot mitigate ${f.cveId}`);
        }
      }
    }

    const credIds = new Set();
    for (const c of estate.credentials) {
      if (!c.id || credIds.has(c.id)) fail(c?.id || 'credential', 'id', `Duplicate or missing credential id: ${c.id}`);
      credIds.add(c.id);
      if (!assetIds.has(c.sourceAssetId)) fail(c.id, 'sourceAssetId', `Credential ${c.id} references unknown sourceAssetId ${c.sourceAssetId}`);
    }

    const enforcementPointById = new Map();
    if (estate.enforcementPoints != null) {
      if (!Array.isArray(estate.enforcementPoints)) fail('estate', 'enforcementPoints', 'enforcementPoints must be an array');
      else for (const ep of estate.enforcementPoints) {
        if (!ep.id || enforcementPointById.has(ep.id)) fail(ep?.id || 'enforcementPoint', 'id', `Duplicate or missing enforcementPoint id: ${ep?.id}`);
        enforcementPointById.set(ep.id, ep);
        if (ep.assetId && !assetIds.has(ep.assetId)) fail(ep.id, 'assetId', `EnforcementPoint ${ep.id} references unknown asset ${ep.assetId}`);
        if (!Array.isArray(ep.inspectedProtocols) || ep.inspectedProtocols.length === 0) {
          fail(ep.id, 'inspectedProtocols', `EnforcementPoint ${ep.id} must declare inspectedProtocols`);
        }
      }
    }

    const relIds = new Set();
    const routesToCheck = estate.routes || estate.relationships;
    for (const r of routesToCheck) {
      if (!r.id || relIds.has(r.id)) fail(r?.id || 'relationship', 'id', `Duplicate or missing relationship id: ${r.id}`);
      relIds.add(r.id);
      if (!assetIds.has(r.sourceId)) fail(r.id, 'sourceId', `Relationship ${r.id} references unknown sourceId ${r.sourceId}`);
      if (!assetIds.has(r.targetId)) fail(r.id, 'targetId', `Relationship ${r.id} references unknown targetId ${r.targetId}`);
      if (r.sourceId === r.targetId) fail(r.id, 'targetId', `Relationship ${r.id} is a self-loop`);
      if (r.direction !== 'outbound') fail(r.id, 'direction', `Relationship ${r.id} has invalid direction ${r.direction}`);
      if (typeof r.protocol !== 'string' || !r.protocol.trim() || r.protocol !== r.protocol.trim()) fail(r.id, 'protocol', `Relationship ${r.id} must declare a valid protocol`);
      if (Array.isArray(r.enforcementPointIds)) {
        for (const epId of r.enforcementPointIds) {
          if (!enforcementPointById.has(epId)) fail(r.id, 'enforcementPointIds', `Route ${r.id} references unknown enforcementPoint ${epId}`);
        }
      }
    }

    if (estate.datasets != null) {
      if (!Array.isArray(estate.datasets)) fail('estate', 'datasets', 'datasets must be an array');
      else {
        const dsIds = new Set();
        for (const ds of estate.datasets) {
          if (!ds.id || dsIds.has(ds.id)) fail(ds?.id || 'dataset', 'id', `Duplicate or missing dataset id: ${ds?.id}`);
          dsIds.add(ds.id);
          if (!assetIds.has(ds.ownerAssetId)) fail(ds.id, 'ownerAssetId', `Dataset ${ds.id} references unknown ownerAssetId ${ds.ownerAssetId}`);
          if (!['sensitive', 'public', 'internal_non_sensitive', 'decoy'].includes(ds.sensitivity)) {
            fail(ds.id, 'sensitivity', `Dataset ${ds.id} has invalid sensitivity ${ds.sensitivity}`);
          }
          if (typeof ds.isDecoy !== 'boolean' || (ds.sensitivity === 'decoy') !== ds.isDecoy) {
            fail(ds.id, 'isDecoy', `Dataset ${ds.id} isDecoy flag must match sensitivity="decoy"`);
          }
        }
      }
    }

    if (estate.sensors != null) {
      if (!Array.isArray(estate.sensors)) fail('estate', 'sensors', 'sensors must be an array');
      else {
        const sensorIds = new Set();
        for (const s of estate.sensors) {
          if (!s.id || sensorIds.has(s.id)) fail(s?.id || 'sensor', 'id', `Duplicate or missing sensor id: ${s?.id}`);
          sensorIds.add(s.id);
          if (s.assetId && !assetIds.has(s.assetId)) fail(s.id, 'assetId', `Sensor ${s.id} references unknown assetId ${s.assetId}`);
          if (!Array.isArray(s.observableActions) || s.observableActions.length === 0) {
            fail(s.id, 'observableActions', `Sensor ${s.id} must declare observableActions`);
          }
        }
      }
    }

    if (estate.patchRules != null) {
      if (!Array.isArray(estate.patchRules)) fail('estate', 'patchRules', 'patchRules must be an array');
      else {
        const ruleIds = new Set();
        for (const pr of estate.patchRules) {
          if (!pr.id || ruleIds.has(pr.id)) fail(pr?.id || 'patchRule', 'id', `Duplicate or missing patchRule id: ${pr?.id}`);
          ruleIds.add(pr.id);
          for (const epId of pr.enforcementPointIds || []) {
            const ep = enforcementPointById.get(epId);
            if (!ep) fail(pr.id, 'enforcementPointIds', `PatchRule ${pr.id} references unknown enforcementPoint ${epId}`);
            else if (Array.isArray(pr.inspectedProtocols) && pr.inspectedProtocols.some(p => !ep.inspectedProtocols.includes(p))) {
              fail(pr.id, 'inspectedProtocols', `PatchRule ${pr.id} requests protocol not inspected by enforcementPoint ${epId}`);
            }
          }
        }
      }
    }

    if (estate.responseIntegrations != null) {
      if (!Array.isArray(estate.responseIntegrations)) fail('estate', 'responseIntegrations', 'responseIntegrations must be an array');
      else {
        const riIds = new Set();
        for (const ri of estate.responseIntegrations) {
          if (!ri.id || riIds.has(ri.id)) fail(ri?.id || 'responseIntegration', 'id', `Duplicate or missing responseIntegration id: ${ri?.id}`);
          riIds.add(ri.id);
          if (!Array.isArray(ri.supportedActions) || ri.supportedActions.length === 0) {
            fail(ri.id, 'supportedActions', `ResponseIntegration ${ri.id} must declare supportedActions`);
          }
          if (!Array.isArray(ri.authorizedScopes) || ri.authorizedScopes.length === 0) {
            fail(ri.id, 'authorizedScopes', `ResponseIntegration ${ri.id} must declare authorizedScopes`);
          }
        }
      }
    }

    if (estate.assumptions != null) {
      if (!Array.isArray(estate.assumptions)) fail('estate', 'assumptions', 'assumptions must be an array');
      else for (const a of estate.assumptions) {
        if (!['historical_source', 'vendor_reference', 'expert_assumption', 'authored_fixture'].includes(a?.provenanceType)) {
          fail(a?.id || 'assumption', 'provenanceType', `Assumption ${a?.id} has invalid provenanceType ${a?.provenanceType}`);
        }
        if (a?.unit === 'probability' && (typeof a.value !== 'number' || a.value < 0 || a.value > 1)) {
          fail(a.id, 'value', `Assumption ${a.id} probability value must be in [0, 1]`);
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings, details };
  }

  function validateRunConfig(estate, runConfig) {
    const estateValidation = validateEstate(estate);
    const errors = [...estateValidation.errors];
    const warnings = [...(estateValidation.warnings || [])];
    const details = [...(estateValidation.details || [])];
    const fail = (entityId, fieldPath, reason) => {
      errors.push(reason);
      details.push({ entityId, fieldPath, reason });
    };
    if (!runConfig || typeof runConfig !== 'object') {
      fail('runConfig', 'root', 'runConfig must be an object');
      return { valid: false, errors, warnings, details };
    }
    if (runConfig.manifestVersion !== RUN_MANIFEST_VERSION) {
      fail('runConfig', 'manifestVersion', `Expected manifestVersion ${RUN_MANIFEST_VERSION}, got ${runConfig.manifestVersion}`);
    }
    if (!Number.isInteger(runConfig.trialSeed)) {
      fail('runConfig', 'trialSeed', 'trialSeed must be an integer');
    }
    if (!Array.isArray(runConfig.initialAccess)) fail('runConfig', 'initialAccess', 'initialAccess must be an array');
    if (!Array.isArray(runConfig.initialKnowledge)) fail('runConfig', 'initialKnowledge', 'initialKnowledge must be an array');
    if (!Array.isArray(runConfig.objectives)) {
      fail('runConfig', 'objectives', 'objectives must be an array');
    }
    if (!runConfig.limits || typeof runConfig.limits !== 'object') {
      fail('runConfig', 'limits', 'limits must be an object');
    } else {
      for (const key of ['maxActionAttempts', 'maxRetriesPerAction', 'maxInvestigationActions', 'maxHumanAssists', 'maxRecordedEvents', 'maxConditionalBranches']) {
        if (!Number.isInteger(runConfig.limits[key]) || runConfig.limits[key] < 1) {
          fail('runConfig', `limits.${key}`, `limits.${key} must be a positive integer`);
        }
      }
    }
    if (!['report_conditional', 'unresolved'].includes(runConfig.uncertaintyMode)) {
      fail('runConfig', 'uncertaintyMode', `Invalid uncertaintyMode: ${runConfig.uncertaintyMode}`);
    }
    if (!estateValidation.valid) return { valid: false, errors, warnings, details };
    for (const key of ['routes', 'identityRelationships', 'weaknesses', 'datasets', 'sensors',
      'enforcementPoints', 'patchRules', 'decoys', 'responseIntegrations', 'legitimateWorkflows', 'assumptions']) {
      if (!Array.isArray(estate[key])) fail('estate', key, `Estate must declare ${key} as an array`);
    }
    const assetIds = new Set(estate.assets.map(a => a.id));
    const datasets = new Map((Array.isArray(estate.datasets) ? estate.datasets : []).map(d => [d.id, d]));
    const objectiveIds = new Set();
    if (Array.isArray(runConfig.objectives)) {
      for (const obj of runConfig.objectives) {
        if (!obj?.id || objectiveIds.has(obj.id)) fail('objective', 'id', 'Objective must declare a unique id');
        objectiveIds.add(obj?.id);
        if (obj?.kind === 'asset_privilege') {
          if (!assetIds.has(obj.targetAssetId) || !obj.requiredCapability) {
            fail(obj.id, 'targetAssetId', 'Privilege objective requires a known asset and a capability');
          }
        } else if (obj?.kind === 'dataset_read' || obj?.kind === 'dataset_export') {
          const dataset = datasets.get(obj.datasetId);
          if (!dataset || (obj.targetAssetId != null && dataset.ownerAssetId !== obj.targetAssetId)) {
            fail(obj.id, 'datasetId', `Objective ${obj.id} requires a known dataset and matching owner`);
          }
        } else {
          fail(obj?.id || 'objective', 'kind', `Unsupported objective kind: ${obj?.kind}`);
        }
      }
    }
    if (runConfig.interventionContracts != null) {
      if (!Array.isArray(runConfig.interventionContracts)) {
        fail('runConfig', 'interventionContracts', 'interventionContracts must be an array');
      } else {
        for (const ic of runConfig.interventionContracts) {
          if (!['confirmed_before_action', 'confirmed_after_action', 'not_confirmed', 'ordering_unspecified'].includes(ic?.contract)) {
            fail(ic?.id || 'interventionContract', 'contract', `Invalid intervention contract: ${ic?.contract}`);
          }
        }
      }
    }
    return { valid: errors.length === 0, errors, warnings, details };
  }

  function cveTooltip(kev) {
    if (!kev) return '';
    return `${kev.id} · ${CVE_ATTACK_DESCRIPTIONS[kev.id] || kev.title}`;
  }

  /**
   * Evaluate all distinct eligible actions an attacker in `state` can perform on `targetAsset`
   * via `relationship` (or external entry). Never grants access without explicit reachability + prerequisites.
   */
  function evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate, options = {}) {
    const targetFindings = estate.findings.filter(f => f.assetId === targetAsset.id);
    const actions = [];
    let lastReason = null;
    const accessProtocol = relationship?.protocol || (targetAsset.interfaces.length === 1 ? targetAsset.interfaces[0] : null);

    // 1. Reachability check
    let reachability = '';
    if (!sourceAsset) {
      if (!targetAsset.isExternalEntry) {
        return [{ eligible: false, reason: `${targetAsset.label} is not externally reachable.` }];
      }
      reachability = 'External internet ingress';
    } else {
      if (!relationship) {
        return [{ eligible: false, reason: `No directed relationship from ${sourceAsset.label} to ${targetAsset.label}.` }];
      }
      if (relationship.direction !== 'outbound') {
        return [{ eligible: false, reason: `Relationship direction (${relationship.direction}) does not permit access.` }];
      }
      if (relationship.sourceId !== sourceAsset.id || relationship.targetId !== targetAsset.id) {
        return [{ eligible: false, reason: 'Relationship endpoints do not match this action.' }];
      }
      const sourceState = state.reachedAssets.get(sourceAsset.id);
      if (!relationship.requiredSourceCapability || !sourceState?.capabilities.has(relationship.requiredSourceCapability)) {
        return [{ eligible: false, reason: 'Required source capability for this relationship is not established.' }];
      }
      if (!targetAsset.interfaces.includes(relationship.protocol)) {
        return [{ eligible: false, reason: `Protocol mismatch: route uses ${relationship.protocol}, target exposes [${targetAsset.interfaces.join(', ')}].` }];
      }
      reachability = `${sourceAsset.label} -> ${targetAsset.label} (${relationship.protocol})`;
    }

    // 2. Check findings on targetAsset independently
    for (const f of targetFindings) {
      if (f.kind === 'phishing_attachment') {
        if (sourceAsset || !targetAsset.interfaces.includes('email') ||
            f.requiresUserInteraction !== true || targetAsset.conditions?.userOpensAttachment !== true ||
            targetAsset.conditions?.attachmentExecutionAllowed !== true ||
            targetAsset.conditions?.mailFilterBlocksAttachment !== false) {
          lastReason = targetAsset.conditions?.mailFilterBlocksAttachment === true ? 'Mail filtering blocks the phishing attachment.'
            : targetAsset.conditions?.userOpensAttachment === false ? 'The user does not open the phishing attachment.'
            : targetAsset.conditions?.attachmentExecutionAllowed === false ? 'Attachment execution is disabled on the Windows desktop.'
            : 'Phishing requires delivered mail, a user opening the attachment, and permitted execution.';
          continue;
        }
        actions.push({ eligible: true, actionKind: f.kind, finding: f, technique: 'T1566.001',
          requiredAccess: 'Delivered attachment + user execution', reachability,
          grantedPermissions: targetAsset.localUserPermissions || [],
          yieldsCapability: 'app_exec', credentialUsed: null, reason: f.description });
        continue;
      }
      if (f.kind === 'remote_service') {
        const sourceCapability = ['cobalt_strike','psexec'].includes(f.tool) ? 'app_exec' : f.requiredSourceCapability;
        if(sourceCapability && !state.reachedAssets.get(sourceAsset?.id)?.capabilities.has(sourceCapability)) {
          lastReason = 'Required source capability for the lateral tool is not established.';
          continue;
        }
        const protocol = relationship?.protocol || f.requiredInterface;
        const credentialCheck = diagnoseCredentialForTarget(state, targetAsset, f.requiredPermission, protocol);
        const credential = credentialCheck.credential;
        if (!f.requiredPermission || !credential || !targetAsset.interfaces.includes(f.requiredInterface) ||
            protocol !== f.requiredInterface || targetAsset.conditions?.remoteLoginEnabled !== true ||
            (protocol === 'rdp' && !Array.isArray(targetAsset.conditions?.mfaProtocols) && typeof targetAsset.conditions?.mfaEnforced !== 'boolean') ||
            (targetAsset.endpointIds && !targetAsset.endpointIds.some(id => credential.endpointScope?.includes(id)))) {
          lastReason = credentialCheck.reason || 'Remote access requires its actual protocol, an authorized credential, enabled login and an established authentication policy.';
          continue;
        }
        actions.push({ eligible: true, actionKind: f.kind, finding: f, technique: f.technique,
          ...(f.tool && {tool:f.tool}),
          credentialUsed: credential, requiredAccess: `Scoped ${f.requiredPermission} credential`, reachability,
          grantedPermissions: credential.permissions || [],
          endpointScope: targetAsset.endpointIds?.filter(id => credential.endpointScope?.includes(id)) || [],
          yieldsCapability: f.yieldsCapability, reason: f.description });
        continue;
      }
      if (f.kind === 'diagnostic_access') {
        const diagnosticLogin = diagnoseCredentialForTarget(state, targetAsset, 'read_diagnostics', accessProtocol);
        if (!diagnosticLogin.usable) {
          return [{ eligible: false, finding: f, reason: 'Reading diagnostics requires an authorized diagnostics viewer.' }];
        }
        if (targetAsset.conditions?.[f.requiredCondition] !== true) {
          return [{ eligible: false, finding: f, reason: 'The diagnostic exposure is absent.' }];
        }
        const action = {
          eligible: true,
          actionKind: 'diagnostic_access',
          finding: f,
          credentialUsed: diagnosticLogin.credential,
          requiredAccess: 'Signed-in diagnostics viewer',
          reachability,
          yieldsCapability: 'diagnostic_read',
          reason: f.description
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }
      if (f.kind === 'anonymous_access') {
        const action = {
          eligible: true,
          actionKind: 'anonymous_access',
          finding: f,
          credentialUsed: null,
          technique: f.technique || 'T1530',
          requiredAccess: 'Unauthenticated (anonymous access enabled)',
          reachability,
          yieldsCapability: f.yieldsCapability || 'data_read',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: f.description || 'Anonymous access misconfiguration permits unauthenticated read.'
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }

      if (f.kind === 'cve') {
        // Product / version / interface / auth prerequisite checks
        if (!f.requiredProduct || !f.affectedVersions?.includes(targetAsset.assumedVersion) || !f.sourceUrl || !f.requiredConditions || !Object.entries(f.requiredConditions).every(([key, value]) => targetAsset.conditions?.[key] === value)) {
          lastReason = `Applicability or configuration for ${f.cveId} is not established.`;
          continue;
        }
        if (f.requiredProduct && f.requiredProduct !== targetAsset.product) {
          continue;
        }
        if (f.requiredInterface && !targetAsset.interfaces.includes(f.requiredInterface)) {
          continue;
        }
        if (relationship && f.requiredInterface !== relationship.protocol) continue;
        if (f.requiresAuth) {
          const matchingCred = diagnoseCredentialForTarget(state, targetAsset, f.requiredPermission || 'authenticate', accessProtocol).credential;
          if (!matchingCred) {
            lastReason = `${f.cveId} requires an authorized credential for ${targetAsset.label}.`;
            continue;
          }
          const action = {
            eligible: true,
            actionKind: 'cve_authenticated',
            finding: f,
            credentialUsed: matchingCred,
            technique: f.technique || 'T1059',
            requiredAccess: `Authenticated (${matchingCred.label})`,
            reachability,
            yieldsCapability: f.yieldsCapability || 'app_exec',
            exposesCredentialId: f.exposesCredentialId || null,
            reason: `${f.cveId} exploited using acquired credential ${matchingCred.label}.`
          };
          if (options.firstOnly) return [action];
          actions.push(action);
          continue;
        }
        const action = {
          eligible: true,
          actionKind: 'cve',
          finding: f,
          credentialUsed: null,
          technique: f.technique || 'T1190',
          requiredAccess: 'Unauthenticated interface reachability',
          reachability,
          yieldsCapability: f.yieldsCapability || 'app_exec',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: `${f.cveId} applicable to ${targetAsset.product} ${targetAsset.assumedVersion} over ${f.requiredInterface}.`
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }

      if (f.kind === 'password_spray') {
        if (f.syntheticAccountUsesSprayedPassword !== true) {
          lastReason = 'No matching synthetic account password is established.';
          continue;
        }
        if (f.mfaProtected) {
          lastReason = `Password spray on ${targetAsset.label} blocked by MFA enforcement.`;
          continue;
        }
        if (f.rateLimited) {
          lastReason = `Password spray on ${targetAsset.label} blocked by account lockout / rate limiting.`;
          continue;
        }
        const action = {
          eligible: true,
          actionKind: 'password_spray',
          finding: f,
          credentialUsed: null,
          technique: 'T1110.003',
          requiredAccess: 'Reachable authentication endpoint without MFA or lockout',
          reachability,
          yieldsCapability: 'account_session',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: `Password spray succeeded against account on ${targetAsset.label} (no MFA/lockout).`
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }
    }

    // 3. Check if attacker holds a valid, non-revoked, in-scope credential
    const credCheck = diagnoseCredentialForTarget(state, targetAsset, targetAsset.layerIdx === 3 ? 'read' : 'authenticate', accessProtocol);
    if (credCheck.usable && targetAsset.accessModel !== 'windows_remote_service' && !targetFindings.some(f => f.kind === 'remote_service')) {
      const action = {
        eligible: true,
        actionKind: 'valid_credential',
        finding: targetFindings.find(finding => finding.kind === 'assumed_edge_account') || null,
        credentialUsed: credCheck.credential,
        technique: 'T1078',
        requiredAccess: `Acquired credential: ${credCheck.credential.label} (scope: ${credCheck.credential.scope})`,
        reachability,
        yieldsCapability: targetAsset.layerIdx === 3 ? 'data_read' : 'account_session',
        exposesCredentialId: null,
        reason: targetAsset.groupId === 'staging-status'
          ? 'Staging status access established. Production access requires a separate authorization.'
          : `Authenticated to ${targetAsset.label} using ${credCheck.credential.label} (no CVE needed).`
      };
      if (options.firstOnly) return [action];
      actions.push(action);
    }

    if (actions.length > 0) {
      return actions;
    }

    if (credCheck.reason) {
      return [{ eligible: false, reason: credCheck.reason }];
    }

    if (targetFindings.length > 0) {
      return [{
        eligible: false,
        finding: targetFindings.find(f=>relationship && f.requiredInterface===relationship.protocol) || targetFindings[0],
        reason: lastReason || `Finding on ${targetAsset.label} did not match product/version/interface prerequisites.`
      }];
    }

    return [{
      eligible: false,
      reason: `No access established for ${targetAsset.label}.`
    }];
  }

  /**
   * Evaluate whether an attacker in `state` can act on `targetAsset` via `relationship` (or external entry).
   * Never grants access without explicit reachability + satisfied prerequisites.
   */
  function evaluateAction(state, sourceAsset, targetAsset, relationship, estate) {
    return evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate, { firstOnly: true })[0];
  }

  function evaluatePostCompromiseAction(state, asset, finding, estate) {
    const reach = state.reachedAssets.get(asset.id);
    if(finding.kind==='data_exfiltration') {
      const collector=estate.assets.find(a=>a.id===finding.collectorId);
      const controlled=state.reachedAssets.get(finding.collectorId);
      if(!reach?.capabilities.has('data_read') || !collector ||
          !controlled || (!finding.responseExport && !controlled.capabilities.has('app_exec'))) {
        return {eligible:false,finding,reason:'Data transfer requires readable data and a controlled collection host.'};
      }
      const egressAllowed=collector.egress?.[finding.responseExport?'responseExportAllowed':'cloudUploadAllowed'];
      if(typeof egressAllowed!=='boolean')return {eligible:false,finding,
        reason:'Export could not be evaluated: the collection host outbound policy is unspecified. Data access is confirmed; export permission is unknown.'};
      return {eligible:true,actionKind:finding.kind,finding,technique:finding.technique,
        yieldsCapability:'data_exfiltrated',credentialUsed:null,dataTransfer:finding.dataTransfer,
        egressAllowed,
        requiredAccess:'Previously read data + collection host + permitted outbound channel',
        reachability:`${asset.label} via ${collector.label} -> ${finding.dataTransfer.destination}`,
        reason:`${finding.dataTransfer.records==null?'Data (record count unknown)':`${finding.dataTransfer.records} records`} transferred using ${finding.dataTransfer.tool} to ${finding.dataTransfer.destination}.`};
    }
    const permission = finding.kind === 'encryption' ? 'write_local_files' : 'persist_user';
    const enabled = finding.kind === 'encryption' ? asset.conditions?.localFilesWritable : asset.conditions?.startupChangesAllowed;
    const endpointIds = (asset.endpointIds || [asset.id]).filter(id =>
      reach?.endpointPermissions?.get(id)?.has(permission));
    if (!reach?.capabilities.has('app_exec') || enabled !== true || !endpointIds.length) {
      return { eligible: false, finding, reason: `Local ${finding.kind} requires established execution, ${permission} rights and the endpoint configuration.` };
    }
    return { eligible: true, actionKind: finding.kind, finding, technique: finding.technique,
      credentialUsed: null, yieldsCapability: finding.kind === 'encryption' ? 'encrypted_files' : 'persistence_installed',
      affectedEndpointIds: endpointIds, requiredAccess: `Established execution + ${permission}`,
      reachability: `Local action on already reached ${asset.label}`, reason: finding.description };
  }

  function diagnoseCredentialForTarget(state, targetAsset, permission = 'authenticate', protocol = null) {
    let rejectedReason = null;
    for (const cred of state.acquiredCredentials.values()) {
      const groupMatch = Array.isArray(cred.targetGroupIds) && cred.targetGroupIds.includes(targetAsset.groupId);
      const assetMatch = Array.isArray(cred.targetAssetIds) && cred.targetAssetIds.includes(targetAsset.id);
      if (Array.isArray(cred.targetAssetIds) && cred.targetAssetIds.length ? !assetMatch : !groupMatch) continue;
      const targetSuffix = ` for ${targetAsset.label}`;
      const label = cred.label || cred.kind?.replaceAll('_', ' ') || 'Account';
      const shortLabel = label.endsWith(targetSuffix) ? label.slice(0, -targetSuffix.length) : label;
      const credentialName = /\bcredential\b/i.test(shortLabel) ? shortLabel : `${shortLabel} credential`;
      const subject = credentialName.charAt(0).toUpperCase() + credentialName.slice(1);
      if (state.revokedCredentials.has(cred.id) || cred.revoked) {
        rejectedReason = `${subject} is revoked.`;
        continue;
      }
      // MFA belongs to the accepting service, not every use of a domain account.
      // Legacy account/host flags apply to interactive access only; Windows Hello
      // on a desktop does not add MFA to SMB/WMI or an already running process.
      const mfaProtocols = targetAsset.conditions?.mfaProtocols;
      const interactive = ['rdp', 'vpn', 'http', 'https'].includes(protocol);
      const requiresMfa = Array.isArray(mfaProtocols) ? mfaProtocols.includes(protocol)
        : interactive && (targetAsset.conditions?.mfaEnforced === true || cred.mfaRequired === true);
      if (requiresMfa) {
        rejectedReason = `${protocol.toUpperCase()} access requires MFA.`;
        continue;
      }
      if (cred.expired || (cred.audience && cred.audience !== targetAsset.id)) {
        rejectedReason = `${subject} is expired or has the wrong audience.`;
        continue;
      }
      const permissions = cred.permissions || (cred.scope ? [cred.scope] : []);
      if (!permissions.includes(permission)) {
        rejectedReason = `${subject} lacks ${permission} permission.`;
        continue;
      }
      return { usable: true, credential: cred };
    }
    return { usable: false, reason: rejectedReason };
  }

  function evaluateDefense(targetAsset, action, mode, seed, isCanary, options = {}) {
    if (!targetAsset || !Array.isArray(targetAsset.interfaces) || targetAsset.interfaces.length === 0) throw new Error('evaluateDefense requires a validated target asset with interfaces');
    if (!action || typeof action !== 'object') throw new Error('evaluateDefense requires a validated action');
    const attackerProfile = options.attackerProfile || null;
    const defensePosture = options.defensePosture || null;
    const layerMonitored = !defensePosture?.telemetryLayers || defensePosture.telemetryLayers.includes(targetAsset.layerIdx);

    if (isCanary) {
      if (mode === 'canaries') {
        return {
          addressed: false,
          alertOnly: true,
          badge: 'CANARY TRIGGERED · ALERT ONLY',
          control: 'NIST SI-4',
          reason: 'Decoy interaction emitted a high-confidence alert without blocking or containing the session.'
        };
      }
      if (mode === 'combined' || mode === 'soc-canary') {
        return {
          addressed: true,
          badge: 'CONTAINED · CANARY TRIGGER',
          control: 'NIST SI-4',
          reason: 'Access to the decoy generated an alert; Agentic SOC immediately contained the session.'
        };
      }
    }
    if (action.actionKind === 'diagnostic_access') {
      return { addressed: false, badge: 'SCOPED CREDENTIAL EXPOSED', reason: action.reason };
    }
    if(action.actionKind==='data_exfiltration')return action.egressAllowed
      ? {addressed:false,badge:'DATA TRANSFER',reason:action.reason}
      : {addressed:true,badge:'EGRESS BLOCKED',reason:'Outbound transfer is denied by the collection host egress policy.'};
    if (['phishing_attachment', 'remote_service', 'persistence', 'encryption'].includes(action.actionKind)) {
      return { addressed: false, badge: action.technique,
        reason: `${action.reason} HTTP virtual patching does not cover this Windows endpoint action.` };
    }

    if (mode === 'baseline' || mode === 'canaries') {
      return {
        addressed: false,
        badge: mode === 'canaries' ? 'UNMITIGATED · NO DECOY HIT' : 'EXPLOITED',
        reason: mode === 'canaries'
          ? 'Canaries alert on decoy contact only; non-decoy paths remain unblocked.'
          : 'Baseline scenario unmitigated: zero active defenses applied.'
      };
    }

    const isHttpSurface = targetAsset.interfaces.some(i => ['https', 'api-https', 'repo-http', 'storage-s3'].includes(i));
    const nonHttpGroups = new Set(['aws-vpn', 'az-net', 'az-branch', 'partner-gw', 'zyxel-atp']);
    const isNonHttpProtocol = nonHttpGroups.has(targetAsset.groupId) || !isHttpSurface;
    const portalIds = new Set(['forti-vpn', 'pulse-vpn', 'pan-globalprotect']);
    const portalCovered = !portalIds.has(targetAsset.groupId) || wafPortalCovered(targetAsset.id, seed);
    const socEnabled = mode === 'defender' || mode === 'soc' || mode === 'soc-canary' || mode === 'combined';

    if (action.actionKind === 'anonymous_access') {
      if (socEnabled && layerMonitored && soarDetects(targetAsset.id, seed)) {
        return { addressed: true, badge: 'CONTAINED · AGENTIC SOC', control: 'NIST AC-3 / SI-4', reason: 'Agentic SOC detects and closes the public exposure.' };
      }
      return { addressed: false, badge: 'PUBLIC EXPOSURE', reason: action.reason };
    }

    if (action.actionKind === 'valid_credential' || action.actionKind === 'password_spray') {
      if (socEnabled && layerMonitored && soarDetects(targetAsset.id, seed)) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: 'NIST SI-4 / AC-3',
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: action.actionKind === 'password_spray'
            ? 'Agentic SOC detects password-spray anomaly and locks the target account.'
            : 'Agentic SOC detects anomalous credential use and revokes the token.'
        };
      }
      return {
        addressed: false,
        badge: action.actionKind === 'password_spray' ? 'T1110.003 · SPRAY' : 'T1078 · VALID ACCOUNTS',
        reason: action.reason
      };
    }

    // CVE action
    const cveId = action.finding && action.finding.cveId;
    const rule = KEV_MITIGATION_RULES[cveId];
    if (!rule) throw new Error(`Missing declared control coverage for ${cveId}`);
    const groupCovered = !rule.waf?.appliesToGroups || rule.waf.appliesToGroups.includes(targetAsset.groupId);
    const protocolCovered = !rule.waf?.inspectedProtocols || targetAsset.interfaces.some(i => rule.waf.inspectedProtocols.includes(i));
    const wafRuleMatches = !isNonHttpProtocol && portalCovered && groupCovered && protocolCovered && rule.waf?.state === 'modeled' && !!rule.waf?.mitigates;
    const chosenVariant = action.variantId || 'default';
    const ruleAllowedVariants = rule.waf?.allowedVariants || (rule.waf?.ruleStrictness === 'signature_regex' ? ['chunked_transfer', 'json_content_type'] : []);
    const wafVariantMissed = wafRuleMatches && ruleAllowedVariants.includes(chosenVariant);
    const wafMitigates = wafRuleMatches && !wafVariantMissed;
    const soarMitigates = layerMonitored && rule.ml?.state === 'modeled' && !!rule.ml?.mitigates && soarDetects(targetAsset.id, seed);

    if (mode === 'patch') {
      if (isNonHttpProtocol) {
        return { addressed: false, badge: 'WAF BLIND', reason: 'WAF operates at L7 HTTP; blind to non-HTTP protocols.' };
      }
      if (wafVariantMissed) {
        return { addressed: false, badge: 'WAF RULE NOT MATCHED', reason: `Modeled request variant (${chosenVariant}) did not match static signature WAF rule.` };
      }
      if (wafMitigates) {
        return { addressed: true, badge: 'SHIELDED · WAF VIRTUAL PATCH', control: rule.waf.control, reason: rule.waf.reason };
      }
      return {
        addressed: false,
        badge: 'WAF BYPASS',
        reason: !portalCovered ? 'Public portal is not behind the inline WAF.' : (rule.waf?.reason || 'Vulnerability unaddressed by perimeter WAF.')
      };
    }

    if (mode === 'defender' || mode === 'soc' || mode === 'soc-canary') {
      if (!layerMonitored) {
        return { addressed: false, badge: 'TELEMETRY GAP', reason: `Infrastructure telemetry blind spot on Layer ${targetAsset.layerIdx + 1}.` };
      }
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return {
        addressed: false,
        badge: 'ML MISSED',
        reason: rule.ml?.mitigates ? 'Agentic SOC detection missed this attack.' : (rule.ml?.reason || 'Activity does not trigger the detection rule.')
      };
    }

    if (mode === 'combined') {
      if (wafMitigates) {
        return { addressed: true, badge: 'SHIELDED · WAF VIRTUAL PATCH', control: rule.waf.control, reason: rule.waf.reason };
      }
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return { addressed: false, badge: 'UNADDRESSED', reason: 'The attack bypassed the WAF rule and Agentic SOC detection.' };
    }

    return { addressed: false, badge: 'EXPLOITED', reason: 'Unmitigated.' };
  }

  // ---------------------------------------------------------------------------
  // Phase B (WP3 + WP4): Route-Based WAF Virtual Patching (§9), Per-Decoy Canary
  // Triggers (§10), SOC State Machine (§11), Intervention Contracts (§12), and
  // Knowledge-Limited Frontier Execution (`simulateScenario`, §5–§8).
  // ---------------------------------------------------------------------------

  const DEFENSE_CONFIG_PRESETS = {
    baseline: { id: 'baseline', label: 'Baseline', virtualPatching: false, canaries: false, responsePolicy: 'observe_only' },
    patch: { id: 'patch', label: 'Virtual Patching', virtualPatching: true, canaries: false, responsePolicy: 'observe_only' },
    canaries: { id: 'canaries', label: 'Canary Only', virtualPatching: false, canaries: true, responsePolicy: 'observe_only' },
    soc: { id: 'soc', label: 'Agentic SOC', virtualPatching: false, canaries: false, responsePolicy: 'agentic' },
    'soc-canary': { id: 'soc-canary', label: 'SOC + Canary', virtualPatching: false, canaries: true, responsePolicy: 'agentic' },
    combined: { id: 'combined', label: 'All Three (Defense-in-Depth)', virtualPatching: true, canaries: true, responsePolicy: 'agentic' },
    playbook: { id: 'playbook', label: 'Playbook SOC', virtualPatching: false, canaries: false, responsePolicy: 'playbook' },
    human_led: { id: 'human_led', label: 'Human-Led SOC', virtualPatching: false, canaries: false, responsePolicy: 'human_led' }
  };

  function normalizeDefenseConfig(input) {
    if (typeof input === 'string') {
      const preset = DEFENSE_CONFIG_PRESETS[input];
      if (!preset) throw new Error(`Unknown defense preset: ${input}`);
      return { ...preset };
    }
    if (!input || typeof input !== 'object') {
      return { ...DEFENSE_CONFIG_PRESETS.baseline };
    }
    const virtualPatching = !!input.virtualPatching;
    const canaries = !!input.canaries;
    const responsePolicy = input.responsePolicy || 'observe_only';
    if (!['observe_only', 'playbook', 'human_led', 'agentic'].includes(responsePolicy)) {
      throw new Error(`Invalid responsePolicy: ${responsePolicy}`);
    }
    return {
      id: input.id || `${virtualPatching ? 'patch' : 'nopatch'}-${canaries ? 'canary' : 'nocanary'}-${responsePolicy}`,
      label: input.label || `Patch:${virtualPatching ? 'on' : 'off'} · Canary:${canaries ? 'on' : 'off'} · SOC:${responsePolicy}`,
      virtualPatching,
      canaries,
      responsePolicy
    };
  }

  function normalizeAttackerProfile(input) {
    if (typeof input === 'string') {
      if (BEHAVIOR_PRESETS[input]) return structuredClone(BEHAVIOR_PRESETS[input]);
      const wireAttacker = WIRE_ATTACKERS[input];
      if (wireAttacker) {
        const base = BEHAVIOR_PRESETS[wireAttacker.behaviorPreset] || BEHAVIOR_PRESETS.operator_with_tools;
        return {
          ...structuredClone(base),
          id: input,
          displayLabel: PRE2023_ATTACK_PATTERNS[input]?.label || (input === 'artex' ? 'ARTEX' : input),
          gangId: wireAttacker.pace === 'pre2023' ? input : null,
          availableTools: [
            ...(COBALT_STRIKE_SOURCES[input] ? ['cobalt_strike'] : []),
            ...(PSEXEC_SOURCES[input] ? ['psexec'] : [])
          ]
        };
      }
      if (ATTACKER_PROFILES[input]) return structuredClone(ATTACKER_PROFILES[input]);
      throw new Error(`Unknown attackerProfile: ${input}`);
    }
    if (!input || typeof input !== 'object') {
      return structuredClone(BEHAVIOR_PRESETS.operator_with_tools);
    }
    const presetKey = input.behaviorPreset || (input.maxConcurrentBranches > 1 ? 'agentic_orchestration' : 'operator_with_tools');
    const base = BEHAVIOR_PRESETS[presetKey] || BEHAVIOR_PRESETS.operator_with_tools;
    return {
      ...structuredClone(base),
      ...structuredClone(input),
      behaviorPreset: presetKey
    };
  }

  /**
   * Route-based WAF virtual patching evaluator (Spec Section 9, Invariants R04, R05, Fixtures F03–F07, F28, F34).
   * Evaluates inline rules only at enforcementPoints actually traversed by the route or service hook.
   */
  function evaluateVirtualPatch({ estate, route, targetAsset, action, variantId = 'default', defenseConfig }) {
    if (!defenseConfig?.virtualPatching) {
      return {
        covered: false,
        matched: false,
        enforced: false,
        ruleId: null,
        enforcementPointId: null,
        reasonCode: 'CONTROL_DISABLED',
        reason: 'Virtual patching is disabled in this defense configuration.'
      };
    }

    const protocol = route?.protocol || action?.finding?.requiredInterface || targetAsset?.interfaces?.[0] || 'https';
    const traversedEpIds = Array.isArray(route?.enforcementPointIds)
      ? route.enforcementPointIds
      : (!route && targetAsset?.isExternalEntry)
        ? (estate.enforcementPoints || [])
            .filter(ep => ep.assetId === targetAsset.id || (Array.isArray(ep.protectedAssetIds) && ep.protectedAssetIds.includes(targetAsset.id)) || (!ep.protectedAssetIds && ep.id === 'ep-edge-waf' && (!['forti-vpn', 'pulse-vpn', 'pan-globalprotect'].includes(targetAsset.groupId) || wafPortalCovered(targetAsset.id, estate.estateSeed ?? estate.seed ?? 1))))
            .map(ep => ep.id)
        : [];

    if (!traversedEpIds.length) {
      return {
        covered: false,
        matched: false,
        enforced: false,
        ruleId: null,
        enforcementPointId: null,
        reasonCode: 'OUTSIDE_CONTROL_PATH',
        reason: `Route to ${targetAsset?.label || targetAsset?.id} does not traverse an inline virtual patch enforcement point.`
      };
    }

    const epById = new Map((estate.enforcementPoints || []).map(ep => [ep.id, ep]));
    const rulesById = new Map((estate.patchRules || []).map(r => [r.id, r]));

    let lastCode = 'OUTSIDE_CONTROL_PATH';
    let lastReason = 'No applicable virtual patch rule at traversed enforcement point.';
    let lastEpId = traversedEpIds[0];

    for (const epId of traversedEpIds) {
      const ep = epById.get(epId);
      if (!ep || ep.enabled === false) {
        lastCode = 'INSPECTION_UNAVAILABLE';
        lastReason = `Enforcement point ${epId} is disabled or unavailable.`;
        lastEpId = epId;
        continue;
      }
      if (!Array.isArray(ep.inspectedProtocols) || !ep.inspectedProtocols.includes(protocol)) {
        lastCode = 'UNSUPPORTED_PROTOCOL';
        lastReason = `Enforcement point ${epId} inspects [${(ep.inspectedProtocols || []).join(', ')}]; cannot inspect ${protocol}.`;
        lastEpId = epId;
        continue;
      }
      if (ep.inspectionAvailable === false) {
        lastCode = 'INSPECTION_UNAVAILABLE';
        lastReason = `Payload inspection is unavailable on enforcement point ${epId}.`;
        lastEpId = epId;
        continue;
      }

      const candidateRules = (ep.ruleIds || [])
        .map(id => rulesById.get(id))
        .filter(Boolean);

      for (const rule of candidateRules) {
        const cveMatches = rule.cveId && action?.finding?.cveId === rule.cveId;
        const operationMatches = rule.restrictedOperation && (
          action?.actionKind === rule.restrictedOperation ||
          action?.yieldsCapability === rule.restrictedOperation ||
          (rule.restrictsCredentials && action?.actionKind === 'valid_credential')
        );
        const targetMatches = !rule.targetAssetIds || rule.targetAssetIds.includes(targetAsset.id);
        const groupMatches = !rule.appliesToGroups || rule.appliesToGroups.includes(targetAsset.groupId);
        const protoMatches = !rule.inspectedProtocols || rule.inspectedProtocols.includes(protocol);

        if (!targetMatches || !groupMatches || !protoMatches) continue;
        if (!cveMatches && !operationMatches && !rule.matchesAllTrafficOnRoute) continue;

        if (rule.coverageState === 'unknown') {
          return {
            covered: false,
            matched: false,
            enforced: false,
            ruleId: rule.id,
            enforcementPointId: ep.id,
            reasonCode: 'COVERAGE_UNKNOWN',
            reason: rule.reason || `Coverage state for rule ${rule.id} is unknown.`
          };
        }

        // Check whether the modeled variant matches the rule predicate (Spec Section 8.3 & 9, F04, F05)
        const blockedVariants = Array.isArray(rule.blockedVariants)
          ? rule.blockedVariants
          : rule.ruleStrictness === 'signature_regex'
            ? ['default', 'alternate_header_casing']
            : ['default', 'url_encoded_path', 'chunked_transfer', 'json_content_type', 'alternate_header_casing'];

        const matched = blockedVariants.includes(variantId);
        if (!matched) {
          lastCode = 'RULE_NOT_MATCHED';
          lastReason = `Rule ${rule.id} at ${ep.id} covers ${rule.cveId || rule.restrictedOperation}, but variant '${variantId}' did not match signature predicate.`;
          lastEpId = ep.id;
          continue;
        }

        if (rule.action === 'monitor' || rule.monitorOnly) {
          return {
            covered: true,
            matched: true,
            enforced: false,
            ruleId: rule.id,
            enforcementPointId: ep.id,
            control: rule.control || 'NIST SI-4',
            reasonCode: 'MONITOR_ONLY',
            reason: rule.reason || `Rule ${rule.id} matched in monitor-only mode.`
          };
        }

        return {
          covered: true,
          matched: true,
          enforced: true,
          ruleId: rule.id,
          enforcementPointId: ep.id,
          control: rule.control || 'NIST SC-7 / SI-2',
          reasonCode: 'RULE_ENFORCED',
          reason: rule.reason || `Rule ${rule.id} enforced at ${ep.id}.`
        };
      }

      if (lastCode === 'OUTSIDE_CONTROL_PATH') {
        lastCode = 'RULE_NOT_MATCHED';
        lastReason = `Enforcement point ${ep.id} inspected ${protocol} request, but no deployed rule matched the operation.`;
        lastEpId = ep.id;
      }
    }

    return {
      covered: lastCode === 'RULE_NOT_MATCHED',
      matched: false,
      enforced: false,
      ruleId: null,
      enforcementPointId: lastEpId,
      reasonCode: lastCode,
      reason: lastReason
    };
  }

  /**
   * Per-decoy canary interaction evaluator (Spec Section 10, Invariants R06, R07, Fixtures F08–F12).
   * Tracks interactions and deduplication by (decoyId, principalId/sessionId), supports trigger on denied
   * honeytoken use at an instrumented verifier, and never directly revokes access without SOC execution.
   */
  function evaluateDecoyInteraction({ estate, targetAsset, action, actor, outcome, defenseConfig, triggeredDecoyKeys }) {
    if (!defenseConfig?.canaries) return null;
    const decoys = estate.decoys || estate.defensePosture?.decoys || [];
    const matchingDecoy = decoys.find(d => {
      if (d.deployed === false) return false;
      if (d.assetId && d.assetId === targetAsset.id) return true;
      if (d.credentialId && action?.credentialUsed?.id === d.credentialId) {
        if (!d.verifierAssetIds || d.verifierAssetIds.includes(targetAsset.id)) return true;
      }
      return false;
    });

    if (!matchingDecoy) return null;
    if (matchingDecoy.alertDestination === null || matchingDecoy.instrumented === false) return null;

    const triggerPredicate = matchingDecoy.triggerPredicate || (matchingDecoy.credentialId ? 'attempted_use' : 'any_interaction');
    const triggersOnDenied = triggerPredicate === 'attempted_use' || triggerPredicate === 'any_interaction';
    if (outcome !== 'succeeded' && !triggersOnDenied) return null;

    const attributionIdentity = matchingDecoy.attributionQuality === 'none' || matchingDecoy.identifiesSession === false
      ? null
      : (actor?.sessionId || actor?.principalId || null);
    const dedupKey = `${matchingDecoy.id}:${attributionIdentity || 'unattributed'}`;
    const isDuplicate = triggeredDecoyKeys.has(dedupKey);
    triggeredDecoyKeys.add(dedupKey);

    return {
      decoyId: matchingDecoy.id,
      decoyKind: matchingDecoy.kind || (matchingDecoy.credentialId ? 'honeytoken_credential' : 'decoy_asset'),
      targetAssetId: targetAsset.id,
      credentialId: matchingDecoy.credentialId || action?.credentialUsed?.id || null,
      triggerPredicate,
      triggeredOnOutcome: outcome,
      attributedSessionId: attributionIdentity,
      attributedPrincipalId: attributionIdentity ? (actor?.principalId || attributionIdentity) : null,
      attributionConfidence: attributionIdentity ? 'high' : 'ambiguous_unattributed',
      dedupKey,
      isDuplicate,
      alertDelivered: !isDuplicate
    };
  }

  /**
   * Sensor observation generator (Spec Section 11.1, Invariant R03, R04).
   * Sensors emit only events they can observe, with explicit availability, fieldsCollected, and attributionQuality.
   */
  function emitSensorObservations({ estate, targetAsset, sourceAsset, route, action, actor, outcome, trialSeed, attemptOrdinal = 0 }) {
    const observations = [];
    const sensors = (estate.sensors || []).filter(s => {
      if (s.assetId && s.assetId === targetAsset.id) return true;
      if (typeof s.layerIdx === 'number' && s.layerIdx === targetAsset.layerIdx && !s.assetId) return true;
      if (!s.assetId && s.layerIdx == null) return true;
      return false;
    });

    for (const sensor of sensors) {
      if (sensor.availability === false) continue;
      const actionKind = action?.actionKind || 'access_check';
      if (Array.isArray(sensor.observableActions) && !sensor.observableActions.includes(actionKind) && !sensor.observableActions.includes('*')) {
        continue;
      }
      const cveId = action?.finding?.cveId;
      const mlRule = cveId ? KEV_MITIGATION_RULES[cveId]?.ml : null;
      const hasStaticHypothesis = !!(mlRule && mlRule.state === 'modeled' && mlRule.mitigates);
      const behavioralDraw = hashSemanticKey(trialSeed, 'observation', targetAsset.id, actionKind, attemptOrdinal);
      const detectionThreshold = typeof sensor.detectionProbability === 'number'
        ? sensor.detectionProbability
        : SOAR_DETECTION_RATE;

      let hypothesis = null;
      if (actionKind === 'phishing_attachment' && outcome === 'succeeded') {
        hypothesis = 'Anomalous user-executed attachment spawning child process on endpoint.';
      } else if (actionKind === 'data_exfiltration' && outcome === 'succeeded') {
        hypothesis = 'High-volume outbound data transfer from internal collection host.';
      } else if (actionKind === 'encryption' || actionKind === 'persistence') {
        hypothesis = `Endpoint modification (${actionKind}) outside approved maintenance window.`;
      } else if (hasStaticHypothesis && (sensor.deterministicDetection || behavioralDraw < detectionThreshold)) {
        hypothesis = mlRule.reason;
      } else if (sensor.deterministicDetection || ((actionKind === 'password_spray' || actionKind === 'valid_credential' || actionKind === 'anonymous_access') && behavioralDraw < detectionThreshold)) {
        hypothesis = `Behavioral anomaly on ${targetAsset.label} (${actionKind}).`;
      }

      const fields = {};
      for (const f of sensor.fieldsCollected || ['sourceId', 'targetId', 'sessionId']) {
        if (f === 'sourceId') fields.sourceId = sourceAsset?.id || null;
        if (f === 'targetId') fields.targetId = targetAsset.id;
        if (f === 'protocol') fields.protocol = route?.protocol || action?.finding?.requiredInterface || null;
        if (f === 'principalId' && sensor.attributionQuality !== 'none') fields.principalId = actor?.principalId || null;
        if (f === 'sessionId' && sensor.attributionQuality === 'session_scoped') fields.sessionId = actor?.sessionId || null;
        if (f === 'technique') fields.technique = action?.technique || null;
        if (f === 'credentialId') fields.credentialId = action?.credentialUsed?.id || null;
      }

      observations.push({
        sensorId: sensor.id,
        targetAssetId: targetAsset.id,
        sourceAssetId: sourceAsset?.id || null,
        routeId: route?.id || null,
        actionKind,
        outcome,
        fields,
        attributionQuality: sensor.attributionQuality || 'session_scoped',
        suspiciousHypothesis: hypothesis,
        isBenignWorkflow: !!actor?.isBenignWorkflow
      });
    }

    return observations;
  }

  /**
   * Scoped response executor (Spec Section 11.2, Invariants R05, R07, Fixtures F13–F15).
   * Checks integration availability, authority, supported actions, authorized scopes, and session/token lineage.
   */
  function executeScopedResponse({ estate, proposedAction, worldState, defenderState }) {
    const dedupKey = `${proposedAction.actionType}:${proposedAction.targetScopeId}`;
    if (defenderState.confirmedResponses.has(dedupKey)) {
      return {
        status: 'confirmed',
        idempotentDuplicate: true,
        dedupKey,
        integrationId: proposedAction.integrationId,
        actionType: proposedAction.actionType,
        targetScopeId: proposedAction.targetScopeId,
        stateChanges: [],
        reasonCode: 'IDEMPOTENT_ALREADY_CONFIRMED',
        reason: `Response ${dedupKey} was already confirmed earlier in this run.`
      };
    }

    const integrations = estate.responseIntegrations || [];
    const integration = integrations.find(ri =>
      ri.supportedActions?.includes(proposedAction.actionType) &&
      (ri.authorizedScopes?.includes('*') || ri.authorizedScopes?.includes(proposedAction.targetScopeId))
    ) || integrations.find(ri => ri.supportedActions?.includes(proposedAction.actionType));

    if (!integration) {
      return {
        status: 'unsupported',
        dedupKey,
        integrationId: null,
        actionType: proposedAction.actionType,
        targetScopeId: proposedAction.targetScopeId,
        stateChanges: [],
        reasonCode: 'INTEGRATION_UNSUPPORTED',
        reason: `No response integration supports ${proposedAction.actionType}.`
      };
    }

    if (integration.available === false || estate.defensePosture?.enforcementSucceeds === false) {
      return {
        status: 'failed',
        dedupKey,
        integrationId: integration.id,
        actionType: proposedAction.actionType,
        targetScopeId: proposedAction.targetScopeId,
        stateChanges: [],
        reasonCode: 'ENFORCEMENT_FAILED',
        reason: `Response integration ${integration.id} is unavailable or failed confirmation.`
      };
    }

    if (integration.requiresApproval || estate.defensePosture?.responseAuthority === false) {
      return {
        status: 'approval_required',
        dedupKey,
        integrationId: integration.id,
        actionType: proposedAction.actionType,
        targetScopeId: proposedAction.targetScopeId,
        stateChanges: [],
        reasonCode: 'AUTHORITY_UNAVAILABLE',
        reason: `Response ${proposedAction.actionType} on ${proposedAction.targetScopeId} lacks automated authority or requires manual approval.`
      };
    }

    const scopeAuthorized = integration.authorizedScopes?.includes('*') || integration.authorizedScopes?.includes(proposedAction.targetScopeId);
    if (!scopeAuthorized || !proposedAction.targetScopeId) {
      return {
        status: 'scope_unresolved',
        dedupKey,
        integrationId: integration.id,
        actionType: proposedAction.actionType,
        targetScopeId: proposedAction.targetScopeId,
        stateChanges: [],
        reasonCode: 'SCOPE_UNRESOLVED',
        reason: `Target scope '${proposedAction.targetScopeId || 'unknown'}' is outside authorized scopes [${(integration.authorizedScopes || []).join(', ')}] of ${integration.id}.`
      };
    }

    const stateChanges = [];
    if (proposedAction.actionType === 'invalidate_session') {
      worldState.invalidatedSessions.add(proposedAction.targetScopeId);
      stateChanges.push({ kind: 'session_invalidated', sessionId: proposedAction.targetScopeId });
    } else if (proposedAction.actionType === 'revoke_credential') {
      worldState.revokedCredentials.add(proposedAction.targetScopeId);
      stateChanges.push({ kind: 'credential_revoked', credentialId: proposedAction.targetScopeId });
      // Respect integration token/session lineage contract (Spec Section 11.2, Fixture F15):
      // revoking a token only invalidates already-minted sessions when sessionSemantics === 'terminate_minted_sessions'.
      if (integration.sessionSemantics === 'terminate_minted_sessions' || integration.tokenSemantics === 'revoke_token_and_terminate_minted_sessions') {
        for (const [sessId, lineage] of worldState.sessionLineage.entries()) {
          if (lineage.mintedByCredentialId === proposedAction.targetScopeId) {
            worldState.invalidatedSessions.add(sessId);
            stateChanges.push({ kind: 'minted_session_invalidated', sessionId: sessId, credentialId: proposedAction.targetScopeId });
          }
        }
      }
    } else if (proposedAction.actionType === 'disable_account') {
      worldState.disabledAccounts.add(proposedAction.targetScopeId);
      stateChanges.push({ kind: 'account_disabled', principalId: proposedAction.targetScopeId });
      if (integration.sessionSemantics === 'terminate_scoped_session' || integration.sessionSemantics === 'terminate_all_principal_sessions') {
        for (const [sessId, lineage] of worldState.sessionLineage.entries()) {
          if (lineage.principalId === proposedAction.targetScopeId) {
            worldState.invalidatedSessions.add(sessId);
            stateChanges.push({ kind: 'principal_session_invalidated', sessionId: sessId });
          }
        }
      }
    } else if (proposedAction.actionType === 'isolate_host') {
      worldState.isolatedHosts.add(proposedAction.targetScopeId);
      stateChanges.push({ kind: 'host_isolated', assetId: proposedAction.targetScopeId });
    } else if (proposedAction.actionType === 'close_public_exposure') {
      worldState.closedExposures.add(proposedAction.targetScopeId);
      stateChanges.push({ kind: 'public_exposure_closed', assetId: proposedAction.targetScopeId });
    }

    defenderState.confirmedResponses.set(dedupKey, {
      integrationId: integration.id,
      actionType: proposedAction.actionType,
      targetScopeId: proposedAction.targetScopeId,
      stateChanges
    });

    return {
      status: 'confirmed',
      dedupKey,
      integrationId: integration.id,
      actionType: proposedAction.actionType,
      targetScopeId: proposedAction.targetScopeId,
      stateChanges,
      reasonCode: 'RESPONSE_CONFIRMED',
      reason: `Confirmed ${proposedAction.actionType} on ${proposedAction.targetScopeId} via ${integration.id}.`
    };
  }

  /**
   * Default run configuration builder for Schema v4 `simulateScenario`.
   */
  function createDefaultRunConfig(estate, overrides = {}) {
    const externalEntries = (estate?.assets || []).filter(a => a.isExternalEntry).map(a => a.id);
    const sensitiveDatasets = (estate?.datasets || []).filter(d => d.sensitivity === 'sensitive' && !d.isDecoy);
    const defaultObjectives = sensitiveDatasets.map(ds => ({
      id: `obj-read-${ds.id}`, kind: 'dataset_read', datasetId: ds.id, targetAssetId: ds.ownerAssetId
    }));
    return {
      manifestVersion: RUN_MANIFEST_VERSION,
      trialSeed: Number.isInteger(overrides.trialSeed) ? overrides.trialSeed : (estate?.estateSeed ?? estate?.seed ?? 1),
      initialAccess: overrides.initialAccess || externalEntries,
      initialKnowledge: overrides.initialKnowledge || externalEntries,
      objectives: overrides.objectives || defaultObjectives,
      limits: {
        maxActionAttempts: 100,
        maxRetriesPerAction: 2,
        maxInvestigationActions: 20,
        maxHumanAssists: 4,
        maxRecordedEvents: 10000,
        maxConditionalBranches: 16,
        ...(overrides.limits || {})
      },
      interventionContracts: overrides.interventionContracts || [],
      uncertaintyMode: overrides.uncertaintyMode || 'report_conditional'
    };
  }

  /**
   * Core causal simulation engine (Spec Sections 5–13, Invariants R01–R14, WP3 + WP4 + WP5).
   * Evaluates a frontier of known candidate actions under equal maxActionAttempts budgets,
   * knowledge-limited attacker discovery/adaptation, route-based virtual patching, per-decoy
   * canary triggers, SOC incident/investigation/authority state machine, and explicit
   * intervention contracts (`confirmed_before_action`, `confirmed_after_action`,
   * `not_confirmed`, `ordering_unspecified`).
   * Never mutates its input arguments.
   */
  function simulateScenario({ estate: rawEstate, attackerProfile: rawProfile, defenseConfig: rawDefense, runConfig: rawRunConfig } = {}) {
    if (!rawEstate || typeof rawEstate !== 'object') {
      throw new Error('simulateScenario requires a valid estate object');
    }
    const estate = structuredClone(rawEstate);
    const attackerProfile = normalizeAttackerProfile(rawProfile);
    const defenseConfig = normalizeDefenseConfig(rawDefense);
    const runConfig = createDefaultRunConfig(estate, rawRunConfig || {});

    const validation = validateRunConfig(estate, runConfig);
    if (!validation.valid) {
      throw new Error(`Invalid scenario configuration: ${validation.errors.join('; ')}`);
    }

    const assetById = new Map(estate.assets.map(a => [a.id, a]));
    const routes = estate.routes || estate.relationships || [];
    const orderRank = new Map((estate.actionOrder?.length ? estate.actionOrder : estate.assets.map(a => a.id)).map((id, idx) => [id, idx]));
    const rankOf = id => orderRank.get(id) ?? 9999;

    // Separate World State, Attacker Knowledge, and Defender State (Spec Section 6.3, R02, R03)
    const worldState = {
      reachedAssets: new Map(),
      acquiredCredentials: new Map(
        (estate.credentials || [])
          .filter(c => c.startingAccess || runConfig.initialKnowledge.includes(c.id))
          .map(c => [c.id, structuredClone(c)])
      ),
      revokedCredentials: new Set((estate.credentials || []).filter(c => c.revoked).map(c => c.id)),
      invalidatedSessions: new Set(),
      disabledAccounts: new Set(),
      isolatedHosts: new Set(),
      closedExposures: new Set(),
      sessionLineage: new Map() // sessionId -> { principalId, rootAssetId, mintedByCredentialId, parentSessionId }
    };

    const attackerKnowledge = {
      knownAssetIds: new Set([...runConfig.initialAccess, ...runConfig.initialKnowledge].filter(id => assetById.has(id))),
      knownRouteIds: new Set(),
      knownCredentialIds: new Set([...worldState.acquiredCredentials.keys()]),
      triedVariantsByTarget: new Map(), // `${routeId || 'EXT'}:${targetId}:${findingId}` -> Set(variantId)
      attemptOrdinalByLineage: new Map(),
      validatedDiscoveries: 0,
      duplicatedWork: 0,
      abandonedBranches: 0,
      assistanceRequests: 0
    };

    // Seed initial routes from initial known external assets
    for (const id of attackerKnowledge.knownAssetIds) {
      const asset = assetById.get(id);
      if (asset?.isExternalEntry) {
        for (const r of routes) {
          if (r.sourceId === id) attackerKnowledge.knownRouteIds.add(r.id);
        }
      }
    }

    const defenderState = {
      observations: [],
      incidents: new Map(), // incidentId -> { id, status, targetScopeId, principalId, evidenceIds, history, proposedActions }
      triggeredDecoyKeys: new Set(),
      decoyAlerts: [],
      investigationsExecuted: 0,
      confirmedResponses: new Map(),
      pendingInterventions: [], // queued reactive responses awaiting intervention contract resolution
      legitimateWorkflowsDisrupted: [],
      legitimateIdentitiesAffected: new Set(),
      falseBlocks: []
    };

    const events = [];
    let sequence = 0;
    const recordEvent = (ev) => {
      if (events.length >= runConfig.limits.maxRecordedEvents) {
        return null;
      }
      sequence += 1;
      const entry = {
        id: ev.id || `event-${sequence}`,
        sequence,
        causalParentIds: ev.causalParentIds || [],
        branchId: ev.branchId || 'branch-1',
        kind: ev.kind,
        actionId: ev.actionId || null,
        actor: ev.actor || { principalId: 'attacker-principal', sessionId: 'session-initial' },
        sourceId: ev.sourceId ?? null,
        targetId: ev.targetId ?? null,
        routeId: ev.routeId ?? null,
        outcome: ev.outcome,
        reasonCode: ev.reasonCode || 'EVALUATED',
        reason: ev.reason || '',
        evidenceIds: ev.evidenceIds || [],
        controlId: ev.controlId || null,
        stateChanges: ev.stateChanges || [],
        objectiveChanges: ev.objectiveChanges || [],
        assumptionIds: ev.assumptionIds || []
      };
      // Copy any domain metadata fields (finding, credentialUsed, technique, variantId, etc.)
      if (ev.meta) Object.assign(entry, ev.meta);
      events.push(entry);
      return entry;
    };

    // Evaluate legitimate workflows against inline virtual patches and SOC (Spec Section 9 & 11.3, Fixtures F16, F28)
    for (const wf of estate.legitimateWorkflows || []) {
      const wfRoutes = (wf.routeIds || []).map(rid => routes.find(r => r.id === rid)).filter(Boolean);
      const wfSessionId = `session-benign-${wf.id}`;
      const wfPrincipalId = wf.actor || `principal-benign-${wf.id}`;
      let wfBlocked = false;

      for (const r of wfRoutes) {
        const target = assetById.get(r.targetId);
        if (!target) continue;
        // Check if a misconfigured virtual patch rule falsely blocks legitimate workflow traffic (F28)
        if (defenseConfig.virtualPatching) {
          const epById = new Map((estate.enforcementPoints || []).map(ep => [ep.id, ep]));
          const rulesById = new Map((estate.patchRules || []).map(pr => [pr.id, pr]));
          for (const epId of r.enforcementPointIds || []) {
            const ep = epById.get(epId);
            if (!ep || ep.enabled === false) continue;
            for (const ruleId of ep.ruleIds || []) {
              const rule = rulesById.get(ruleId);
              if (!rule) continue;
              if (rule.blocksLegitimateWorkflowIds?.includes(wf.id) || (rule.matchesAllTrafficOnRoute && (!rule.targetAssetIds || rule.targetAssetIds.includes(target.id)))) {
                wfBlocked = true;
                defenderState.falseBlocks.push({
                  workflowId: wf.id,
                  routeId: r.id,
                  ruleId: rule.id,
                  enforcementPointId: ep.id
                });
                defenderState.legitimateWorkflowsDisrupted.push(wf.id);
                defenderState.legitimateIdentitiesAffected.add(wfPrincipalId);
                recordEvent({
                  kind: 'action_result',
                  actionId: `benign-${wf.id}-${r.id}`,
                  actor: { principalId: wfPrincipalId, sessionId: wfSessionId, isBenignWorkflow: true },
                  sourceId: r.sourceId,
                  targetId: target.id,
                  routeId: r.id,
                  outcome: 'denied',
                  reasonCode: 'FALSE_POSITIVE_PATCH_BLOCK',
                  reason: `Legitimate workflow ${wf.label} was blocked by overly broad rule ${rule.id} at ${ep.id}.`,
                  controlId: rule.id
                });
              }
            }
          }
        }
      }

      // Check benign multi-boundary workflow against SOC policy (Fixture F16):
      // Boundary count alone must not convict a documented legitimate workflow unless the policy is misconfigured.
      if (!wfBlocked && wfRoutes.length >= 2 && defenseConfig.responsePolicy !== 'observe_only') {
        const obsEvent = recordEvent({
          kind: 'observation',
          actionId: `obs-benign-${wf.id}`,
          actor: { principalId: wfPrincipalId, sessionId: wfSessionId, isBenignWorkflow: true },
          sourceId: wfRoutes[0]?.sourceId || null,
          targetId: wfRoutes[wfRoutes.length - 1]?.targetId || null,
          routeId: wfRoutes[wfRoutes.length - 1]?.id || null,
          outcome: 'succeeded',
          reasonCode: 'BENIGN_BOUNDARY_CROSSING_OBSERVED',
          reason: `Observed ${wfRoutes.length} boundary crossings by legitimate workflow ${wf.label}.`
        });
        if (wf.forceFalsePositiveSocIntervention) {
          defenderState.legitimateWorkflowsDisrupted.push(wf.id);
          defenderState.legitimateIdentitiesAffected.add(wfPrincipalId);
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: obsEvent ? [obsEvent.id] : [],
            actor: { principalId: 'soc-policy', sessionId: wfSessionId },
            targetId: wfRoutes[wfRoutes.length - 1]?.targetId || null,
            outcome: 'succeeded',
            reasonCode: 'ERRONEOUS_BENIGN_CONTAINMENT',
            reason: `Erroneous containment disrupted legitimate workflow ${wf.label}.`
          });
        } else {
          defenderState.investigationsExecuted = Math.min(
            runConfig.limits.maxInvestigationActions,
            defenderState.investigationsExecuted + 1
          );
          recordEvent({
            kind: 'investigation',
            causalParentIds: obsEvent ? [obsEvent.id] : [],
            actor: { principalId: 'soc-policy', sessionId: wfSessionId },
            targetId: wfRoutes[wfRoutes.length - 1]?.targetId || null,
            outcome: 'succeeded',
            reasonCode: 'BENIGN_WORKFLOW_VERIFIED',
            reason: `Investigation verified ${wf.label} (${wfRoutes.length} boundaries crossed) matches authorized service pattern; incident closed without containment.`
          });
        }
      }
    }

    // Budget and metric counters
    let actionAttempts = 0;
    let retriesUsed = 0;
    let humanAssistsUsed = 0;
    let controlBlocks = 0;
    let policyDenials = 0;
    let actionFailures = 0;
    let canceledActions = 0;
    let guardrailExhausted = false;
    let orderingUnresolved = false;
    let assistanceBudgetExhausted = false;
    let guardrailReason = null;
    const conditionalOutcomes = [];

    // Build initial frontier from attacker's known entry points (R02: no inspection of hidden findings or isDecoy)
    const frontier = [];
    const enqueuedKeys = new Set();
    let branchCounter = 0;

    const enqueueCandidate = (cand) => {
      // Attacker cannot see `isDecoy`; only skip undeployed decoys that do not exist in the active overlay
      const deployedDecoyIds = new Set(
        (estate.decoys || estate.defensePosture?.decoys || [])
          .filter(d => d.deployed !== false)
          .map(d => d.assetId)
          .filter(Boolean)
      );
      if (cand.targetAsset.isDecoy || cand.targetAsset.isDecoyAsset) {
        if (!defenseConfig.canaries || (deployedDecoyIds.size > 0 && !deployedDecoyIds.has(cand.targetAsset.id))) {
          return;
        }
      }
      const key = `${cand.sourceAsset?.id || 'EXT'}->${cand.targetAsset.id}:${cand.route?.id || 'EXT'}:${cand.localFinding?.id || ''}:${cand.variantId || 'default'}:${cand.credentialSnapshot || ''}:${cand.sourceCapSnapshot || ''}`;
      if (enqueuedKeys.has(key)) return;
      enqueuedKeys.add(key);
      frontier.push({ ...cand, frontierKey: key });
    };

    const getCredentialSnapshot = (targetAsset) =>
      [...worldState.acquiredCredentials.values()]
        .filter(c => !worldState.revokedCredentials.has(c.id) && !c.revoked && (
          c.targetAssetIds?.includes(targetAsset.id) || (!c.targetAssetIds?.length && c.targetGroupIds?.includes(targetAsset.groupId))
        ))
        .map(c => c.id)
        .sort()
        .join(',');

    const getSourceCapSnapshot = (sourceAsset) =>
      sourceAsset ? [...(worldState.reachedAssets.get(sourceAsset.id)?.capabilities || [])].sort().join(',') : 'EXT';

    const initialEntries = estate.assets
      .filter(a => attackerKnowledge.knownAssetIds.has(a.id) && (a.isExternalEntry || runConfig.initialAccess.includes(a.id)))
      .sort((a, b) => rankOf(a.id) - rankOf(b.id));

    for (const entry of initialEntries) {
      branchCounter += 1;
      const sessionId = entry.sessionId || `sess-${entry.id}`;
      const principalId = `principal-${entry.id}`;
      worldState.sessionLineage.set(sessionId, {
        principalId,
        rootAssetId: entry.id,
        mintedByCredentialId: null,
        parentSessionId: null
      });
      enqueueCandidate({
        sourceAsset: null,
        targetAsset: entry,
        route: null,
        localFinding: null,
        variantId: 'default',
        retryCount: 0,
        branchId: `branch-${branchCounter}`,
        sessionId,
        principalId,
        causalParentIds: [],
        credentialSnapshot: getCredentialSnapshot(entry),
        sourceCapSnapshot: 'EXT'
      });
    }

    // Helper to look up intervention contract for a reactive response vs. a dependent action (Spec Section 12, R11, F21, F22)
    function resolveInterventionContract(pendingResp, candidateStep) {
      const contracts = runConfig.interventionContracts || [];
      const exactMatch = contracts.find(ic =>
        (!ic.responseActionType || ic.responseActionType === pendingResp.actionType) &&
        (!ic.targetScopeId || ic.targetScopeId === pendingResp.targetScopeId || ic.targetScopeId === candidateStep.sessionId) &&
        (!ic.dependentTargetId || ic.dependentTargetId === candidateStep.targetAsset.id) &&
        (!ic.dependentActionId || ic.dependentActionId === candidateStep.route?.id || ic.dependentActionId === candidateStep.targetAsset.id)
      );
      if (exactMatch) return exactMatch;
      // Check if there is a contract for this responseActionType + scope that targets a specific future dependent step
      const futureDependentMatch = contracts.find(ic =>
        (!ic.responseActionType || ic.responseActionType === pendingResp.actionType) &&
        (!ic.targetScopeId || ic.targetScopeId === pendingResp.targetScopeId || ic.targetScopeId === candidateStep.sessionId) &&
        (ic.dependentTargetId || ic.dependentActionId)
      );
      if (futureDependentMatch) return futureDependentMatch;
      if (estate.defensePosture?.defaultInterventionContract) {
        return { contract: estate.defensePosture.defaultInterventionContract };
      }
      return { contract: 'ordering_unspecified' };
    }

    // SOC Incident & Investigation State Machine processor (Spec Section 11, Invariants R03, R05, R07, F11–F15, F31)
    function processSocObservations(newObservations, decoyAlert, causalEventId, stepContext) {
      const policy = defenseConfig.responsePolicy;
      const allSignals = [...newObservations.filter(o => o.suspiciousHypothesis), ...(decoyAlert && decoyAlert.alertDelivered ? [decoyAlert] : [])];
      if (!allSignals.length) return;

      for (const sig of allSignals) {
        const isDecoySig = !!sig.decoyId;
        const attributedSession = isDecoySig ? sig.attributedSessionId : sig.fields?.sessionId;
        const attributedPrincipal = isDecoySig ? sig.attributedPrincipalId : sig.fields?.principalId;
        const incKey = attributedSession || `unattributed-${sig.targetAssetId}`;

        let incident = defenderState.incidents.get(incKey);
        if (!incident) {
          incident = {
            id: `incident-${defenderState.incidents.size + 1}`,
            key: incKey,
            status: 'untriaged',
            targetScopeId: attributedSession,
            principalId: attributedPrincipal,
            targetAssetId: sig.targetAssetId,
            credentialId: sig.credentialId || sig.fields?.credentialId || null,
            evidenceIds: [],
            transitions: [],
            proposedActions: []
          };
          defenderState.incidents.set(incKey, incident);
        }

        incident.evidenceIds.push(causalEventId);
        const transition = (newStatus, rationale) => {
          incident.status = newStatus;
          incident.transitions.push({ status: newStatus, rationale, evidenceIds: [...incident.evidenceIds] });
          recordEvent({
            kind: 'incident_update',
            causalParentIds: [causalEventId],
            branchId: stepContext.branchId,
            actor: { principalId: `soc-${policy}`, sessionId: attributedSession || 'unattributed' },
            targetId: sig.targetAssetId,
            outcome: 'succeeded',
            reasonCode: `INCIDENT_${newStatus.toUpperCase()}`,
            reason: rationale,
            evidenceIds: [...incident.evidenceIds]
          });
        };

        transition('investigating', isDecoySig
          ? `Triaging canary decoy alert (${sig.decoyId}) on ${sig.targetAssetId}.`
          : `Triaging sensor observation (${sig.sensorId}): ${sig.suspiciousHypothesis}`);

        // Observe-only mode (including Canary-only mode, R07, F11) records incident & detection but executes no active response
        if (policy === 'observe_only') {
          transition('closed', 'Observation-only response policy: alert and evidence recorded; no active containment proposed.');
          continue;
        }

        // Execute bounded investigation action if needed (Spec Section 11.1)
        if (defenderState.investigationsExecuted < runConfig.limits.maxInvestigationActions) {
          defenderState.investigationsExecuted += 1;
          recordEvent({
            kind: 'investigation',
            causalParentIds: [causalEventId],
            branchId: stepContext.branchId,
            actor: { principalId: `soc-${policy}`, sessionId: attributedSession || 'unattributed' },
            targetId: sig.targetAssetId,
            outcome: 'succeeded',
            reasonCode: 'INVESTIGATION_COMPLETED',
            reason: attributedSession
              ? `Correlated activity to session '${attributedSession}' and verified exposure context.`
              : `Investigated alert on ${sig.targetAssetId}, but session attribution is absent.`
          });
        }

        // Fixture F12: Canary or sensor identifies suspicious activity, but not a revocable session/identity
        if (!attributedSession && !incident.credentialId) {
          transition('insufficient_evidence', 'High-confidence suspicious activity observed, but telemetry lacks revocable session or credential attribution (F12).');
          continue;
        }

        // Propose scoped response action(s) (Spec Section 11.2, R07: proposal alone is not enforcement)
        // Fixture F31: human_led and agentic policies with identical configuration make identical decisions.
        const proposedActionType = sig.decoyKind === 'honeytoken_credential' && incident.credentialId
          ? 'revoke_credential'
          : attributedSession
            ? 'invalidate_session'
            : 'revoke_credential';
        const targetScopeId = proposedActionType === 'revoke_credential' ? incident.credentialId : attributedSession;

        // Avoid queuing duplicate response proposals for the same (actionType, targetScopeId)
        if (incident.proposedActions.some(p => p.actionType === proposedActionType && p.targetScopeId === targetScopeId)) {
          continue;
        }

        const proposal = {
          id: `proposal-${incident.id}-${incident.proposedActions.length + 1}`,
          incidentId: incident.id,
          actionType: proposedActionType,
          targetScopeId,
          targetAssetId: sig.targetAssetId,
          causalEventId
        };
        incident.proposedActions.push(proposal);
        transition('action_proposed', `Proposed ${proposedActionType} for scope '${targetScopeId}'.`);

        const propEv = recordEvent({
          kind: 'response_proposal',
          causalParentIds: [causalEventId],
          branchId: stepContext.branchId,
          actor: { principalId: `soc-${policy}`, sessionId: attributedSession || 'unattributed' },
          targetId: sig.targetAssetId,
          outcome: 'succeeded',
          reasonCode: 'RESPONSE_PROPOSED',
          reason: `SOC policy (${policy}) proposed ${proposedActionType} on '${targetScopeId}'.`,
          evidenceIds: [...incident.evidenceIds]
        });

        // Queue reactive intervention for contract evaluation (Spec Section 12)
        defenderState.pendingInterventions.push({
          ...proposal,
          incident,
          proposalEventId: propEv?.id || causalEventId
        });
      }
    }

    // Apply or defer pending reactive interventions according to declared interventionContracts (Spec Section 12)
    function applyPendingInterventionsForStep(candidateStep) {
      const remaining = [];
      for (const pending of defenderState.pendingInterventions) {
        const contractSpec = resolveInterventionContract(pending, candidateStep);
        const contract = contractSpec.contract;

        // If a contract specifies a dependentTargetId or dependentActionId that has not been reached yet,
        // keep the pending intervention queued until that dependent step is evaluated.
        const targetsSpecificStep = !!(contractSpec.dependentTargetId || contractSpec.dependentActionId);
        const matchesThisStep = (!contractSpec.dependentTargetId || contractSpec.dependentTargetId === candidateStep.targetAsset.id) &&
          (!contractSpec.dependentActionId || contractSpec.dependentActionId === candidateStep.route?.id || contractSpec.dependentActionId === candidateStep.targetAsset.id);

        if (targetsSpecificStep && !matchesThisStep) {
          remaining.push(pending);
          continue;
        }

        if (contract === 'confirmed_after_action') {
          pending.confirmAfterStepKey = candidateStep.frontierKey;
          remaining.push(pending);
          continue;
        }

        if (contract === 'not_confirmed') {
          pending.incident.status = 'enforcement_failed';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId],
            branchId: candidateStep.branchId,
            actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
            targetId: pending.targetAssetId,
            outcome: 'failed',
            reasonCode: 'INTERVENTION_NOT_CONFIRMED',
            reason: `Intervention contract 'not_confirmed': ${pending.actionType} on '${pending.targetScopeId}' was not confirmed.`
          });
          continue;
        }

        if (contract === 'ordering_unspecified') {
          // Record conditional outcome branch (Spec Section 12, R11, F21)
          const affectsThisStep = pending.targetScopeId === candidateStep.sessionId ||
            (pending.actionType === 'revoke_credential' && worldState.acquiredCredentials.has(pending.targetScopeId));
          if (affectsThisStep) {
            const preview = executeScopedResponse({
              estate, proposedAction: pending,
              worldState: structuredClone(worldState),
              defenderState: structuredClone(defenderState)
            });
            if (preview.status !== 'confirmed') {
              pending.incident.status = preview.status === 'approval_required' ? 'awaiting_authority' : 'enforcement_failed';
              recordEvent({
                kind: 'response_confirmation',
                causalParentIds: [pending.proposalEventId],
                branchId: candidateStep.branchId,
                targetId: pending.targetAssetId,
                outcome: 'failed',
                controlId: preview.integrationId,
                reasonCode: preview.reasonCode,
                reason: preview.reason
              });
              continue;
            }
            if (conditionalOutcomes.length >= runConfig.limits.maxConditionalBranches) {
              guardrailExhausted = true;
              guardrailReason = 'maxConditionalBranches';
            } else {
              conditionalOutcomes.push({
                id: `cond-${conditionalOutcomes.length + 1}`,
                contract: 'ordering_unspecified',
                responseActionType: pending.actionType,
                targetScopeId: pending.targetScopeId,
                dependentTargetId: candidateStep.targetAsset.id,
                dependentRouteId: candidateStep.route?.id || null,
                controllingAssumption: contractSpec.controllingAssumption || `Whether ${pending.actionType} on '${pending.targetScopeId}' is effective at the access check for ${candidateStep.targetAsset.label}.`,
                status: 'unresolved'
              });
            }
            recordEvent({
              kind: 'response_confirmation',
              causalParentIds: [pending.proposalEventId],
              branchId: candidateStep.branchId,
              actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
              targetId: candidateStep.targetAsset.id,
              outcome: 'conditional',
              reasonCode: 'ORDERING_UNSPECIFIED_CONDITIONAL',
              reason: `Unspecified ordering between ${pending.actionType} (${pending.targetScopeId}) and access to ${candidateStep.targetAsset.label}; the dependent action was left unresolved.`
            });
            // Stop at the disputed action so later events cannot imply either ordering.
            orderingUnresolved = true;
            return;
          }
          remaining.push(pending);
          continue;
        }

        // Explicitly confirmed before the dependent action.
        const execResult = executeScopedResponse({
          estate,
          proposedAction: pending,
          worldState,
          defenderState
        });

        if (execResult.status === 'confirmed') {
          pending.incident.status = 'enforcement_confirmed';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId],
            branchId: candidateStep.branchId,
            actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
            targetId: pending.targetAssetId,
            outcome: 'succeeded',
            reasonCode: execResult.reasonCode,
            reason: execResult.reason,
            controlId: execResult.integrationId,
            stateChanges: execResult.stateChanges
          });
        } else if (execResult.status === 'approval_required') {
          pending.incident.status = 'awaiting_authority';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId],
            branchId: candidateStep.branchId,
            actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
            targetId: pending.targetAssetId,
            outcome: 'denied',
            reasonCode: execResult.reasonCode,
            reason: execResult.reason,
            controlId: execResult.integrationId
          });
        } else {
          pending.incident.status = 'enforcement_failed';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId],
            branchId: candidateStep.branchId,
            actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
            targetId: pending.targetAssetId,
            outcome: 'failed',
            reasonCode: execResult.reasonCode,
            reason: execResult.reason,
            controlId: execResult.integrationId
          });
        }
      }
      defenderState.pendingInterventions = remaining;
    }

    function confirmDeferredAfterActionInterventions(completedStep, completedEventId) {
      const remaining = [];
      for (const pending of defenderState.pendingInterventions) {
        if (pending.confirmAfterStepKey === completedStep.frontierKey) {
          const execResult = executeScopedResponse({
            estate,
            proposedAction: pending,
            worldState,
            defenderState
          });
          pending.incident.status = execResult.status === 'confirmed' ? 'enforcement_confirmed' : 'enforcement_failed';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId, completedEventId].filter(Boolean),
            branchId: completedStep.branchId,
            actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
            targetId: pending.targetAssetId,
            outcome: execResult.status === 'confirmed' ? 'succeeded' : 'failed',
            reasonCode: execResult.status === 'confirmed' ? 'CONFIRMED_AFTER_ACTION' : execResult.reasonCode,
            reason: `${execResult.reason} (Confirmed after action on ${completedStep.targetAsset.label}; completed impact is preserved.)`,
            controlId: execResult.integrationId,
            stateChanges: execResult.stateChanges
          });
        } else {
          remaining.push(pending);
        }
      }
      defenderState.pendingInterventions = remaining;
    }

    // Main Frontier Execution Loop (Spec Section 5 & Section 8.2)
    // Concurrency selects up to `maxConcurrentBranches` independent candidates per batch reading a common
    // pre-action state, while every attempted action consumes the same shared `maxActionAttempts` budget.
    const maxBranches = Math.max(1, attackerProfile.maxConcurrentBranches || 1);
    const visitedStateTransitions = new Set();

    function scoreCandidateForPolicy(cand) {
      if (cand.localFinding) {
        if (cand.localFinding.kind === 'data_exfiltration') return 5;
        if (cand.localFinding.kind === 'persistence') return 15;
        if (cand.localFinding.kind === 'encryption') return 900;
      }
      // Check if candidate leads directly to an objective target
      const isObjTarget = runConfig.objectives.some(o => o.targetAssetId === cand.targetAsset.id);
      if (isObjTarget) return 25;
      if (attackerProfile.discoveryPolicy === 'depth_first_foothold') {
        // Depth-first prefers exploring discovered nodes from an established foothold in layer/actionOrder sequence before trying new Layer 0 entries
        return cand.sourceAsset ? (10 + cand.targetAsset.layerIdx * 5) : 80;
      }
      // Breadth-first coordinated explores across available branches
      return 30 + cand.targetAsset.layerIdx * 5;
    }

    while (frontier.length > 0 && !orderingUnresolved) {
      if (events.length >= runConfig.limits.maxRecordedEvents) {
        guardrailExhausted = true;
        guardrailReason = 'maxRecordedEvents';
        break;
      }
      if (actionAttempts >= runConfig.limits.maxActionAttempts) {
        guardrailExhausted = true;
        guardrailReason = 'maxActionAttempts';
        break;
      }

      frontier.sort((a, b) =>
        scoreCandidateForPolicy(a) - scoreCandidateForPolicy(b) ||
        rankOf(a.targetAsset.id) - rankOf(b.targetAsset.id) ||
        (a.route?.id || '').localeCompare(b.route?.id || '')
      );

      // Select batch of up to `maxBranches` independent actions whose prerequisites are currently satisfied
      const batch = [];
      const batchTargets = new Set();
      for (let i = 0; i < frontier.length && batch.length < maxBranches; i++) {
        const cand = frontier[i];
        // Avoid dispatching two concurrent workers to the exact same target+capability in the same batch
        const targetCapKey = `${cand.targetAsset.id}:${cand.localFinding?.kind || 'access'}`;
        if (batchTargets.has(targetCapKey)) {
          attackerKnowledge.duplicatedWork += 1;
          continue;
        }
        batchTargets.add(targetCapKey);
        batch.push(cand);
        frontier.splice(i, 1);
        i -= 1;
      }

      if (batch.length === 0 && frontier.length > 0) {
        batch.push(frontier.shift());
      }

      // Snapshot common pre-action world state for this concurrent batch (Spec Section 8.2:
      // "Actions selected together read a common pre-action state. A dependent action cannot use
      // a credential that another action in the same batch has not yet produced.")
      const preBatchCredentials = new Map(worldState.acquiredCredentials);
      const preBatchReached = new Map(
        [...worldState.reachedAssets.entries()].map(([k, v]) => [k, {
          ...v,
          capabilities: new Set(v.capabilities),
          endpointPermissions: v.endpointPermissions ? new Map([...v.endpointPermissions.entries()].map(([ek, ev]) => [ek, new Set(ev)])) : new Map()
        }])
      );

      for (const step of batch) {
        if (events.length >= runConfig.limits.maxRecordedEvents) {
          guardrailExhausted = true;
          guardrailReason = 'maxRecordedEvents';
          break;
        }

        // Resolve any reactive interventions scheduled before this step
        applyPendingInterventionsForStep(step);
        if (orderingUnresolved || guardrailExhausted) break;

        const actor = { principalId: step.principalId, sessionId: step.sessionId };

        // 1. Check if session, principal, or source host was contained/isolated before dispatch (R12, F30:
        // "Do not increment attack-attempt counters for actions canceled before dispatch.")
        const sessionContained = worldState.invalidatedSessions.has(step.sessionId) ||
          worldState.disabledAccounts.has(step.principalId) ||
          (step.sourceAsset && worldState.isolatedHosts.has(step.sourceAsset.id)) ||
          worldState.isolatedHosts.has(step.targetAsset.id);

        if (sessionContained) {
          canceledActions += 1;
          recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-suppressed`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'suppressed',
            reasonCode: 'SESSION_OR_HOST_CONTAINED',
            reason: `Candidate action on ${step.targetAsset.label} was suppressed before dispatch because session '${step.sessionId}' or host scope was contained.`,
            meta: {
              finding: step.localFinding || null,
              suppressionPhase: 'queued'
            }
          });
          continue;
        }

        // Check visited state guard (Spec Section 7.1, F20: cycle guard keyed on capabilities + credentials + variant)
        const stateVisitKey = `${step.sourceAsset?.id || 'EXT'}->${step.targetAsset.id}:${step.route?.id || 'EXT'}:${step.localFinding?.id || ''}:${step.variantId || 'default'}:${getCredentialSnapshot(step.targetAsset)}:${getSourceCapSnapshot(step.sourceAsset)}`;
        if (visitedStateTransitions.has(stateVisitKey)) {
          continue;
        }
        visitedStateTransitions.add(stateVisitKey);

        // Check attempt budget before dispatching an actual attempt
        if (actionAttempts >= runConfig.limits.maxActionAttempts) {
          guardrailExhausted = true;
          guardrailReason = 'maxActionAttempts';
          recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-budget`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'budget_exhausted',
            reasonCode: 'MAX_ACTION_ATTEMPTS_REACHED',
            reason: `Attempt budget (${runConfig.limits.maxActionAttempts}) exhausted before evaluating ${step.targetAsset.label}.`
          });
          break;
        }

        // Evaluate prerequisites against pre-batch state snapshot
        const evalStateSnapshot = {
          reachedAssets: preBatchReached,
          acquiredCredentials: preBatchCredentials,
          revokedCredentials: worldState.revokedCredentials
        };

        const feasibleActions = step.localFinding
          ? [evaluatePostCompromiseAction(evalStateSnapshot, step.targetAsset, step.localFinding, estate)]
          : evaluateDistinctActions(evalStateSnapshot, step.sourceAsset, step.targetAsset, step.route, estate);

        // Filter by attackerProfile repertoire & policy
        const policyAllowed = feasibleActions.filter(a =>
          a.eligible &&
          (!Array.isArray(attackerProfile.supportedActionFamilies) || attackerProfile.supportedActionFamilies.includes(a.actionKind)) &&
          actionPolicy(a, step.sourceAsset, step.targetAsset, attackerProfile)
        ).sort((a, b) => lateralRank(a, attackerProfile) - lateralRank(b, attackerProfile));

        const lineageKey = `${step.route?.id || 'EXT'}:${step.targetAsset.id}`;
        const attemptOrdinal = (attackerKnowledge.attemptOrdinalByLineage.get(lineageKey) || 0) + 1;
        attackerKnowledge.attemptOrdinalByLineage.set(lineageKey, attemptOrdinal);

        // If no action is eligible, check whether this was a policy skip, route prerequisite failure, or actual denied/failed attempt
        if (policyAllowed.length === 0) {
          const rawFailure = feasibleActions[0] || { eligible: false, reason: 'No eligible action.' };
          const isRouteMissingCap = /Required source capability|No directed relationship|Relationship direction/i.test(rawFailure.reason || '');
          const routeHasOnlyUnsupportedMethods = (() => {
            if (!attackerProfile?.gangId) return false;
            const methods = step.localFinding
              ? [step.localFinding]
              : (estate.findings || []).filter(f => f.assetId === step.targetAsset.id && (!step.route || !f.requiredInterface || f.requiredInterface === step.route.protocol));
            return methods.length > 0 && methods.every(finding => !actionPolicy({ finding, technique: finding.technique }, step.sourceAsset, step.targetAsset, attackerProfile));
          })();
          const isPolicyUnsupported = feasibleActions.some(a => a.eligible) || routeHasOnlyUnsupportedMethods;

          if (isRouteMissingCap || isPolicyUnsupported) {
            // Not dispatched as an external attack attempt
            recordEvent({
              kind: 'action_result',
              actionId: `action-${step.targetAsset.id}-not-attempted`,
              causalParentIds: step.causalParentIds,
              branchId: step.branchId,
              actor,
              sourceId: step.sourceAsset?.id || null,
              targetId: step.targetAsset.id,
              routeId: step.route?.id || null,
              outcome: 'not_attempted',
              reasonCode: isPolicyUnsupported ? 'OUTSIDE_ATTACKER_REPERTOIRE' : 'PREREQUISITE_NOT_ESTABLISHED',
              reason: isPolicyUnsupported
                ? `No applicable action in attacker profile repertoire for ${step.targetAsset.label}.`
                : rawFailure.reason,
              meta: { policySkipped: isPolicyUnsupported, finding: rawFailure.finding || null }
            });
            continue;
          }

          // Dispatched probe that failed or was denied by target access/credential/MFA rules (F01, F02, F09)
          actionAttempts += 1;
          const isCredentialOrPolicyDenial = /revoked|expired|wrong audience|lacks .* permission|requires MFA|blocked by MFA|rate limiting|denied|authorized/i.test(rawFailure.reason || '');
          if (isCredentialOrPolicyDenial) policyDenials += 1;
          else actionFailures += 1;

          const reasonCode = /wrong audience/i.test(rawFailure.reason || '') ? 'CREDENTIAL_WRONG_AUDIENCE'
            : /revoked/i.test(rawFailure.reason || '') ? 'CREDENTIAL_REVOKED'
            : /expired/i.test(rawFailure.reason || '') ? 'CREDENTIAL_EXPIRED'
            : /lacks .* permission/i.test(rawFailure.reason || '') ? 'CREDENTIAL_MISSING_PERMISSION'
            : /MFA/i.test(rawFailure.reason || '') ? 'MFA_REQUIRED_DENIED'
            : /Protocol mismatch/i.test(rawFailure.reason || '') ? 'PROTOCOL_INTERFACE_MISMATCH'
            : 'PREREQUISITE_CHECK_FAILED';

          // Check if failed attempt used a honeytoken credential (Fixture F09: denied honeytoken use at instrumented verifier still triggers canary!)
          const attemptedHoneytoken = [...preBatchCredentials.values()].find(c =>
            c.isHoneytoken || (estate.decoys || []).some(d => d.credentialId === c.id)
          );
          const failActionObj = {
            actionKind: attemptedHoneytoken ? 'valid_credential' : (rawFailure.finding?.kind || 'access_probe'),
            finding: rawFailure.finding || null,
            credentialUsed: attemptedHoneytoken || null
          };

          const failEv = recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-attempt-${attemptOrdinal}`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: isCredentialOrPolicyDenial ? 'denied' : 'failed',
            reasonCode,
            reason: rawFailure.reason,
            meta: {
              finding: rawFailure.finding || null,
              credentialUsed: attemptedHoneytoken || null,
              variantId: step.variantId || 'default'
            }
          });

          // Evaluate decoy interaction even on denied/failed request (Spec Section 10, R06, F09)
          const decoyAlert = evaluateDecoyInteraction({
            estate,
            targetAsset: step.targetAsset,
            action: failActionObj,
            actor,
            outcome: isCredentialOrPolicyDenial ? 'denied' : 'failed',
            defenseConfig,
            triggeredDecoyKeys: defenderState.triggeredDecoyKeys
          });
          if (decoyAlert) {
            defenderState.decoyAlerts.push(decoyAlert);
            recordEvent({
              kind: 'decoy_interaction',
              causalParentIds: failEv ? [failEv.id] : [],
              branchId: step.branchId,
              actor,
              sourceId: step.sourceAsset?.id || null,
              targetId: step.targetAsset.id,
              routeId: step.route?.id || null,
              outcome: 'succeeded',
              reasonCode: 'CANARY_DECOY_TRIGGERED',
              reason: `Canary decoy '${decoyAlert.decoyId}' triggered on ${decoyAlert.triggeredOnOutcome} request (${decoyAlert.triggerPredicate}).`,
              controlId: decoyAlert.decoyId,
              meta: { decoyAlert }
            });
          }

          const newObs = emitSensorObservations({
            estate,
            targetAsset: step.targetAsset,
            sourceAsset: step.sourceAsset,
            route: step.route,
            action: failActionObj,
            actor,
            outcome: isCredentialOrPolicyDenial ? 'denied' : 'failed',
            trialSeed: runConfig.trialSeed,
            attemptOrdinal
          });
          for (const obs of newObs) {
            defenderState.observations.push(obs);
            recordEvent({
              kind: 'observation',
              causalParentIds: failEv ? [failEv.id] : [],
              branchId: step.branchId,
              actor,
              sourceId: obs.sourceAssetId,
              targetId: obs.targetAssetId,
              routeId: obs.routeId,
              outcome: 'succeeded',
              reasonCode: obs.suspiciousHypothesis ? 'SUSPICIOUS_OBSERVATION' : 'TELEMETRY_COLLECTED',
              reason: obs.suspiciousHypothesis || `Telemetry collected by ${obs.sensorId}.`,
              controlId: obs.sensorId,
              meta: { observation: obs }
            });
          }
          if (failEv) {
            processSocObservations(newObs, decoyAlert, failEv.id, { ...step, credentialUsed: attemptedHoneytoken });
          }
          continue;
        }

        // Execute the first distinct eligible action
        const existingReach = worldState.reachedAssets.get(step.targetAsset.id);
        const distinctCandidates = existingReach
          ? policyAllowed.filter(c => !existingReach.capabilities.has(c.yieldsCapability))
          : policyAllowed;

        if (distinctCandidates.length === 0) {
          attackerKnowledge.duplicatedWork += 1;
          continue;
        }

        const chosenAction = { ...distinctCandidates[0], variantId: step.variantId || 'default' };

        // Check if this action requires human assistance under the attacker profile (Spec Section 8.1)
        if (chosenAction.finding?.requiresHumanAssist || (step.targetAsset.conditions?.requiresContextContinuation && attackerProfile.humanAssistancePolicy?.requiredForAmbiguousContinuation)) {
          const assistCost = attackerProfile.humanAssistancePolicy?.assistCost ?? 1;
          if (humanAssistsUsed + assistCost > runConfig.limits.maxHumanAssists) {
            assistanceBudgetExhausted = true;
            attackerKnowledge.abandonedBranches += 1;
            recordEvent({
              kind: 'action_result',
              actionId: `action-${step.targetAsset.id}-assist-exhausted`,
              causalParentIds: step.causalParentIds,
              branchId: step.branchId,
              actor,
              sourceId: step.sourceAsset?.id || null,
              targetId: step.targetAsset.id,
              routeId: step.route?.id || null,
              outcome: 'budget_exhausted',
              reasonCode: 'MAX_HUMAN_ASSISTS_REACHED',
              reason: `Human assistance budget (${runConfig.limits.maxHumanAssists}) exhausted on ${step.targetAsset.label}.`
            });
            continue;
          }
          humanAssistsUsed += assistCost;
          attackerKnowledge.assistanceRequests += 1;
        }

        // Check if public exposure was closed by SOC earlier
        if (chosenAction.actionKind === 'anonymous_access' && worldState.closedExposures.has(step.targetAsset.id)) {
          actionAttempts += 1;
          controlBlocks += 1;
          recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-exposure-closed`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'denied',
            reasonCode: 'PUBLIC_EXPOSURE_CLOSED',
            reason: `Public exposure on ${step.targetAsset.label} was closed by a confirmed SOC response.`
          });
          continue;
        }

        // Dispatch the attempt!
        actionAttempts += 1;

        // 2. Evaluate inline Virtual Patching at traversed enforcementPoints (Spec Section 9, F03–F07)
        const patchResult = evaluateVirtualPatch({
          estate,
          route: step.route,
          targetAsset: step.targetAsset,
          action: chosenAction,
          variantId: chosenAction.variantId,
          defenseConfig
        });

        // Also check collection host egress policy for data_exfiltration
        const egressBlocked = chosenAction.actionKind === 'data_exfiltration' && chosenAction.egressAllowed === false;

        if (patchResult.enforced || egressBlocked) {
          controlBlocks += 1;
          const blockEv = recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-attempt-${attemptOrdinal}`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'denied',
            reasonCode: egressBlocked ? 'EGRESS_POLICY_DENIED' : patchResult.reasonCode,
            reason: egressBlocked ? 'Outbound transfer is denied by the collection host egress policy.' : patchResult.reason,
            controlId: egressBlocked ? 'egress-policy' : patchResult.ruleId,
            meta: {
              finding: chosenAction.finding || null,
              credentialUsed: chosenAction.credentialUsed || null,
              technique: chosenAction.technique || null,
              variantId: chosenAction.variantId,
              patchEvaluation: patchResult
            }
          });

          // Fallible adaptation after a blocked request (Spec Section 8.3, F04, F05):
          // The blocked request supplies only that the attempt was rejected; if the profile has untried variants
          // in its adaptationRepertoire and retry budget remains, it may enqueue an adaptation attempt.
          if (patchResult.enforced && step.retryCount < runConfig.limits.maxRetriesPerAction && retriesUsed < runConfig.limits.maxActionAttempts) {
            const triedKey = `${step.route?.id || 'EXT'}:${step.targetAsset.id}:${chosenAction.finding?.id || ''}`;
            if (!attackerKnowledge.triedVariantsByTarget.has(triedKey)) {
              attackerKnowledge.triedVariantsByTarget.set(triedKey, new Set([chosenAction.variantId]));
            }
            const triedSet = attackerKnowledge.triedVariantsByTarget.get(triedKey);
            const repertoire = attackerProfile.adaptationRepertoire || ['default'];
            const nextVariant = repertoire.find(v => !triedSet.has(v));
            if (nextVariant) {
              triedSet.add(nextVariant);
              // Optional discovery probability for alternative variant (F05)
              const canDiscoverVariant = typeof attackerProfile.variantDiscoveryProbability === 'number'
                ? hashSemanticKey(runConfig.trialSeed, 'attacker_adapt', step.targetAsset.id, nextVariant, attemptOrdinal) < attackerProfile.variantDiscoveryProbability
                : true;
              if (canDiscoverVariant) {
                retriesUsed += 1;
                enqueueCandidate({
                  ...step,
                  variantId: nextVariant,
                  retryCount: step.retryCount + 1,
                  causalParentIds: blockEv ? [blockEv.id] : step.causalParentIds
                });
              }
            }
          }
          continue;
        }

        // Check if target is a honeytoken or decoy asset (Spec Section 10, R06, R07:
        // "A honeytoken must not silently grant production access; a real credential intentionally used as a monitored lure needs an explicit, separately labeled scenario.")
        const isTargetDecoy = !!(step.targetAsset.isDecoy || step.targetAsset.isDecoyAsset ||
          (estate.decoys || []).some(d => d.assetId === step.targetAsset.id));
        const isCredHoneytoken = !!(chosenAction.credentialUsed?.isHoneytoken ||
          (estate.decoys || []).some(d => d.credentialId && d.credentialId === chosenAction.credentialUsed?.id && !d.assetId));

        if (isCredHoneytoken && !chosenAction.credentialUsed?.grantsProductionAccessAsMonitoredLure) {
          policyDenials += 1;
          const honeyEv = recordEvent({
            kind: 'action_result',
            actionId: `action-${step.targetAsset.id}-attempt-${attemptOrdinal}`,
            causalParentIds: step.causalParentIds,
            branchId: step.branchId,
            actor,
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'denied',
            reasonCode: 'HONEYTOKEN_VERIFIER_DENIED',
            reason: `Honeytoken credential '${chosenAction.credentialUsed.label}' was rejected by instrumented verifier on ${step.targetAsset.label}; no production access granted.`,
            meta: {
              finding: chosenAction.finding || null,
              credentialUsed: chosenAction.credentialUsed,
              variantId: chosenAction.variantId
            }
          });
          const decoyAlert = evaluateDecoyInteraction({
            estate,
            targetAsset: step.targetAsset,
            action: chosenAction,
            actor,
            outcome: 'denied',
            defenseConfig,
            triggeredDecoyKeys: defenderState.triggeredDecoyKeys
          });
          if (decoyAlert) {
            defenderState.decoyAlerts.push(decoyAlert);
            recordEvent({
              kind: 'decoy_interaction',
              causalParentIds: honeyEv ? [honeyEv.id] : [],
              branchId: step.branchId,
              actor,
              sourceId: step.sourceAsset?.id || null,
              targetId: step.targetAsset.id,
              routeId: step.route?.id || null,
              outcome: 'succeeded',
              reasonCode: 'CANARY_HONEYTOKEN_TRIGGERED',
              reason: `Honeytoken '${decoyAlert.credentialId}' triggered alert at verifier ${step.targetAsset.label}.`,
              controlId: decoyAlert.decoyId,
              meta: { decoyAlert }
            });
            if (honeyEv) processSocObservations([], decoyAlert, honeyEv.id, { ...step, credentialUsed: chosenAction.credentialUsed });
          }
          continue;
        }

        // 4. Commit successful action effects to worldState and attackerKnowledge
        const stateChanges = [];
        const objectiveChanges = [];
        let activeSessionId = step.sessionId;

        // Mint new session if credential specifies session-minting behavior (Spec Section 6.2 & 11.2, F15)
        if (chosenAction.credentialUsed && chosenAction.credentialUsed.mintsSession !== false) {
          const mintedSessionId = chosenAction.credentialUsed.mintedSessionId || `${step.sessionId}-via-${chosenAction.credentialUsed.id}`;
          if (!worldState.sessionLineage.has(mintedSessionId)) {
            worldState.sessionLineage.set(mintedSessionId, {
              principalId: chosenAction.credentialUsed.principal || step.principalId,
              rootAssetId: worldState.sessionLineage.get(step.sessionId)?.rootAssetId || step.targetAsset.id,
              mintedByCredentialId: chosenAction.credentialUsed.id,
              parentSessionId: step.sessionId
            });
            stateChanges.push({ kind: 'session_minted', sessionId: mintedSessionId, credentialId: chosenAction.credentialUsed.id });
          }
          if (chosenAction.credentialUsed.useMintedSessionId) {
            activeSessionId = mintedSessionId;
          }
        }

        const currentReach = worldState.reachedAssets.get(step.targetAsset.id);
        if (currentReach) {
          currentReach.capabilities.add(chosenAction.yieldsCapability);
        } else {
          worldState.reachedAssets.set(step.targetAsset.id, {
            layerIdx: step.targetAsset.layerIdx,
            sourceId: step.sourceAsset?.id || null,
            sessionId: activeSessionId,
            capabilities: new Set([chosenAction.yieldsCapability]),
            endpointPermissions: new Map()
          });
        }
        const updatedReach = worldState.reachedAssets.get(step.targetAsset.id);
        const accessibleEndpoints = step.targetAsset.endpointIds ? (chosenAction.endpointScope || []) : [step.targetAsset.id];
        for (const epId of accessibleEndpoints) {
          if (!updatedReach.endpointPermissions.has(epId)) updatedReach.endpointPermissions.set(epId, new Set());
          for (const perm of chosenAction.grantedPermissions || []) updatedReach.endpointPermissions.get(epId).add(perm);
        }
        stateChanges.push({
          kind: 'capability_granted',
          assetId: step.targetAsset.id,
          capability: chosenAction.yieldsCapability,
          sessionId: activeSessionId
        });

        // Discover credentials stored on targetAsset that are now readable by acquired capabilities
        // (Attacker discovers stored credentials regardless of whether the verifier later rejects them as revoked/expired, F02)
        const newlyAcquiredCreds = [];
        for (const cred of estate.credentials || []) {
          if (cred.sourceAssetId !== step.targetAsset.id) continue;
          const capOk = !!cred.requiredSourceCapability && updatedReach.capabilities.has(cred.requiredSourceCapability);
          const epOk = !cred.sourceEndpointIds || cred.sourceEndpointIds.some(id => updatedReach.endpointPermissions.has(id));
          if (capOk && epOk && !worldState.acquiredCredentials.has(cred.id)) {
            const clonedCred = structuredClone(cred);
            worldState.acquiredCredentials.set(cred.id, clonedCred);
            attackerKnowledge.knownCredentialIds.add(cred.id);
            newlyAcquiredCreds.push(clonedCred);
            stateChanges.push({ kind: 'credential_acquired', credentialId: cred.id, sourceAssetId: step.targetAsset.id });
          }
        }

        // Discover outbound routes and adjacent assets from targetAsset (R02: only after reaching targetAsset)
        const outRoutes = routes.filter(r => r.sourceId === step.targetAsset.id);
        for (const r of outRoutes) {
          attackerKnowledge.knownRouteIds.add(r.id);
          if (!attackerKnowledge.knownAssetIds.has(r.targetId)) {
            attackerKnowledge.knownAssetIds.add(r.targetId);
            attackerKnowledge.validatedDiscoveries += 1;
          }
        }

        // Evaluate dataset & objective impact (Spec Section 6.2 & 13.3, R09, F17)
        const ownedDatasets = (estate.datasets || []).filter(ds =>
          ds.ownerAssetId === step.targetAsset.id && ds.sensitivity === 'sensitive' && !ds.isDecoy
        );
        const readDatasets = !isTargetDecoy && chosenAction.yieldsCapability === 'data_read'
          ? ownedDatasets.filter(ds => ds.allowedOperations?.includes('read')) : [];
        const sensitiveRead = readDatasets.length > 0;
        if (sensitiveRead) {
          for (const ds of readDatasets) {
            objectiveChanges.push({
              kind: 'dataset_read',
              datasetId: ds.id,
              ownerAssetId: step.targetAsset.id,
              records: ds.records ?? null,
              bytes: ds.bytes ?? null
            });
          }

        }
        if (chosenAction.actionKind === 'data_exfiltration' && chosenAction.dataTransfer) {
          objectiveChanges.push({
            kind: 'dataset_export',
            datasetId: chosenAction.dataTransfer.datasetId,
            records: chosenAction.dataTransfer.records ?? null,
            bytes: chosenAction.dataTransfer.bytes ?? null,
            destination: chosenAction.dataTransfer.destination
          });
        }

        const reasonCode = chosenAction.actionKind === 'valid_credential' ? 'AUTHORIZED_SCOPED_CREDENTIALS'
          : chosenAction.actionKind === 'cve' || chosenAction.actionKind === 'cve_authenticated' ? 'EXPLOITED_MODELED_WEAKNESS'
          : chosenAction.actionKind === 'anonymous_access' ? 'PUBLIC_EXPOSURE_ACCESS'
          : chosenAction.actionKind === 'data_exfiltration' ? 'AUTHORIZED_EGRESS_EXPORT'
          : 'ACTION_SUCCEEDED';

        const actionEv = recordEvent({
          kind: 'action_result',
          actionId: `action-${step.targetAsset.id}-attempt-${attemptOrdinal}`,
          causalParentIds: step.causalParentIds,
          branchId: step.branchId,
          actor: { principalId: step.principalId, sessionId: activeSessionId },
          sourceId: step.sourceAsset?.id || null,
          targetId: step.targetAsset.id,
          routeId: step.route?.id || null,
          outcome: 'succeeded',
          reasonCode,
          reason: chosenAction.reason,
          stateChanges,
          objectiveChanges,
          assumptionIds: (estate.assumptions || []).slice(0, 2).map(a => a.id),
          meta: {
            actionKind: chosenAction.actionKind,
            finding: chosenAction.finding || null,
            credentialUsed: chosenAction.credentialUsed || null,
            technique: chosenAction.technique || null,
            tool: chosenAction.tool || null,
            variantId: chosenAction.variantId,
            grantedCapability: chosenAction.yieldsCapability,
            acquiredCredentials: newlyAcquiredCreds,
            isProtectedRead: sensitiveRead,
            dataTransfer: chosenAction.dataTransfer || null,
            affectedEndpointIds: chosenAction.affectedEndpointIds || null,
            patchEvaluation: patchResult
          }
        });

        if (objectiveChanges.length > 0) {
          recordEvent({
            kind: 'objective_impact',
            causalParentIds: actionEv ? [actionEv.id] : [],
            branchId: step.branchId,
            actor: { principalId: step.principalId, sessionId: activeSessionId },
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'succeeded',
            reasonCode: sensitiveRead ? 'SENSITIVE_DATASET_READ' : 'SENSITIVE_DATASET_EXPORTED',
            reason: sensitiveRead
              ? `Sensitive dataset read on ${step.targetAsset.label}.`
              : `Sensitive dataset exported from ${step.targetAsset.label}.`,
            objectiveChanges
          });
        }

        // 5. Evaluate decoy interaction & sensor observations for this action
        const decoyAlert = evaluateDecoyInteraction({
          estate,
          targetAsset: step.targetAsset,
          action: chosenAction,
          actor: { principalId: step.principalId, sessionId: activeSessionId },
          outcome: 'succeeded',
          defenseConfig,
          triggeredDecoyKeys: defenderState.triggeredDecoyKeys
        });
        if (decoyAlert) {
          defenderState.decoyAlerts.push(decoyAlert);
          recordEvent({
            kind: 'decoy_interaction',
            causalParentIds: actionEv ? [actionEv.id] : [],
            branchId: step.branchId,
            actor: { principalId: step.principalId, sessionId: activeSessionId },
            sourceId: step.sourceAsset?.id || null,
            targetId: step.targetAsset.id,
            routeId: step.route?.id || null,
            outcome: 'succeeded',
            reasonCode: 'CANARY_DECOY_TRIGGERED',
            reason: `Canary decoy '${decoyAlert.decoyId}' triggered on ${step.targetAsset.label}.`,
            controlId: decoyAlert.decoyId,
            meta: { decoyAlert }
          });
        }

        const newObs = emitSensorObservations({
          estate,
          targetAsset: step.targetAsset,
          sourceAsset: step.sourceAsset,
          route: step.route,
          action: chosenAction,
          actor: { principalId: step.principalId, sessionId: activeSessionId },
          outcome: 'succeeded',
          trialSeed: runConfig.trialSeed,
          attemptOrdinal
        });
        for (const obs of newObs) {
          defenderState.observations.push(obs);
          recordEvent({
            kind: 'observation',
            causalParentIds: actionEv ? [actionEv.id] : [],
            branchId: step.branchId,
            actor: { principalId: step.principalId, sessionId: activeSessionId },
            sourceId: obs.sourceAssetId,
            targetId: obs.targetAssetId,
            routeId: obs.routeId,
            outcome: 'succeeded',
            reasonCode: obs.suspiciousHypothesis ? 'SUSPICIOUS_OBSERVATION' : 'TELEMETRY_COLLECTED',
            reason: obs.suspiciousHypothesis || `Telemetry collected by ${obs.sensorId}.`,
            controlId: obs.sensorId,
            meta: { observation: obs }
          });
        }

        if (actionEv) {
          processSocObservations(newObs, decoyAlert, actionEv.id, {
            ...step,
            sessionId: activeSessionId,
            credentialUsed: chosenAction.credentialUsed
          });
          confirmDeferredAfterActionInterventions(step, actionEv.id);
        }

        // 6. Expand frontier with newly discovered routes, post-compromise actions, and capability/credential revisits (F20)
        if (!step.localFinding) {
          // Enqueue data exfiltration if sensitive dataset was read
          const exportableDataset = readDatasets.find(ds => ds.allowedOperations.includes('export'));
          if (exportableDataset) {
            const responseExport = !attackerProfile.gangId;
            const method = DATA_EXPORT_METHODS[attackerProfile.gangId];
            if (responseExport || method) {
              let collectorId = step.sourceAsset?.id || step.targetAsset.id;
              if (!responseExport) {
                while (collectorId && !worldState.reachedAssets.get(collectorId)?.capabilities.has('app_exec')) {
                  collectorId = worldState.reachedAssets.get(collectorId)?.sourceId;
                }
              }
              const ds = exportableDataset;
              const records = ds?.records ?? (Number.isSafeInteger(step.targetAsset.dataHandling?.records) ? step.targetAsset.dataHandling.records : null);
              const bytes = ds?.bytes ?? (Number.isSafeInteger(step.targetAsset.dataHandling?.bytes) ? step.targetAsset.dataHandling.bytes : null);
              const exfilFinding = {
                id: `EXFIL:${step.targetAsset.id}`,
                kind: 'data_exfiltration',
                assetId: step.targetAsset.id,
                collectorId: collectorId || step.targetAsset.id,
                responseExport,
                transferScope: activeSessionId,
                technique: method?.technique || 'T1041',
                title: responseExport ? 'HTTP/API bulk data export' : 'Data exfiltration',
                dataTransfer: {
                  datasetId: ds?.id || step.targetAsset.id,
                  dataset: ds?.label || step.targetAsset.dataHandling?.label || `Sensitive records · ${step.targetAsset.label}`,
                  records,
                  bytes,
                  tool: responseExport ? 'HTTP/API bulk extraction' : method.tool,
                  destination: responseExport ? 'Attacker-controlled workspace' : method.destination
                }
              };
              enqueueCandidate({
                sourceAsset: step.targetAsset,
                targetAsset: step.targetAsset,
                route: null,
                localFinding: exfilFinding,
                variantId: 'default',
                retryCount: 0,
                branchId: step.branchId,
                sessionId: activeSessionId,
                principalId: step.principalId,
                causalParentIds: actionEv ? [actionEv.id] : [],
                credentialSnapshot: getCredentialSnapshot(step.targetAsset),
                sourceCapSnapshot: getSourceCapSnapshot(step.targetAsset)
              });
            }
          }

          // Enqueue local persistence / encryption findings if app_exec was established
          if (updatedReach.capabilities.has('app_exec')) {
            for (const lf of (estate.findings || []).filter(f => f.assetId === step.targetAsset.id && ['persistence', 'encryption'].includes(f.kind))) {
              if (!actionPolicy({ actionKind: lf.kind, finding: lf, technique: lf.technique }, step.targetAsset, step.targetAsset, attackerProfile)) continue;
              enqueueCandidate({
                sourceAsset: step.targetAsset,
                targetAsset: step.targetAsset,
                route: null,
                localFinding: lf,
                variantId: 'default',
                retryCount: 0,
                branchId: step.branchId,
                sessionId: activeSessionId,
                principalId: step.principalId,
                causalParentIds: actionEv ? [actionEv.id] : [],
                credentialSnapshot: getCredentialSnapshot(step.targetAsset),
                sourceCapSnapshot: getSourceCapSnapshot(step.targetAsset)
              });
            }
          }

          // Enqueue outbound routes from targetAsset (including same-layer, cross-layer, or return paths, Spec Section 7.1, F20)
          for (const r of outRoutes) {
            const nextTarget = assetById.get(r.targetId);
            if (!nextTarget) continue;
            enqueueCandidate({
              sourceAsset: step.targetAsset,
              targetAsset: nextTarget,
              route: r,
              localFinding: null,
              variantId: 'default',
              retryCount: 0,
              branchId: step.branchId,
              sessionId: activeSessionId,
              principalId: step.principalId,
              causalParentIds: actionEv ? [actionEv.id] : [],
              credentialSnapshot: getCredentialSnapshot(nextTarget),
              sourceCapSnapshot: getSourceCapSnapshot(step.targetAsset)
            });
          }
        }

        // Revisit previously reached routes when newly acquired credentials or capabilities unlock them (Spec Section 7.1, F20)
        if (newlyAcquiredCreds.length > 0) {
          for (const r of routes) {
            if (!worldState.reachedAssets.has(r.sourceId)) continue;
            const srcAsset = assetById.get(r.sourceId);
            const tgtAsset = assetById.get(r.targetId);
            if (!srcAsset || !tgtAsset) continue;
            const matchesNewCred = newlyAcquiredCreds.some(c =>
              c.targetAssetIds?.includes(tgtAsset.id) || (!c.targetAssetIds?.length && c.targetGroupIds?.includes(tgtAsset.groupId))
            );
            if (matchesNewCred) {
              const srcReach = worldState.reachedAssets.get(r.sourceId);
              enqueueCandidate({
                sourceAsset: srcAsset,
                targetAsset: tgtAsset,
                route: r,
                localFinding: null,
                variantId: 'default',
                retryCount: 0,
                branchId: step.branchId,
                sessionId: srcReach.sessionId || activeSessionId,
                principalId: step.principalId,
                causalParentIds: actionEv ? [actionEv.id] : [],
                credentialSnapshot: getCredentialSnapshot(tgtAsset),
                sourceCapSnapshot: getSourceCapSnapshot(srcAsset)
              });
            }
          }
        }
      }
    }

    // Reaching the end of the frontier is not itself a confirmation.
    if (!guardrailExhausted && !orderingUnresolved) {
      for (const pending of defenderState.pendingInterventions) {
        const contract = resolveInterventionContract(pending, {
          targetAsset: { id: null }, sessionId: pending.targetScopeId
        });
        if (contract.dependentTargetId || contract.dependentActionId ||
            contract.contract !== 'confirmed_before_action') {
          const unconfirmed = contract.contract === 'not_confirmed';
          pending.incident.status = unconfirmed ? 'enforcement_failed' : 'awaiting_confirmation';
          recordEvent({
            kind: 'response_confirmation',
            causalParentIds: [pending.proposalEventId],
            targetId: pending.targetAssetId,
            outcome: unconfirmed ? 'failed' : 'unresolved',
            reasonCode: unconfirmed ? 'INTERVENTION_NOT_CONFIRMED' : 'NO_CONFIRMATION_RECORDED',
            reason: 'The run ended without confirmation for this response.'
          });
          continue;
        }
        const execResult = executeScopedResponse({
          estate,
          proposedAction: pending,
          worldState,
          defenderState
        });
        pending.incident.status = execResult.status === 'confirmed' ? 'enforcement_confirmed' : 'enforcement_failed';
        recordEvent({
          kind: 'response_confirmation',
          causalParentIds: [pending.proposalEventId],
          actor: { principalId: `soc-${defenseConfig.responsePolicy}`, sessionId: pending.targetScopeId || 'unattributed' },
          targetId: pending.targetAssetId,
          outcome: execResult.status === 'confirmed' ? 'succeeded' : 'failed',
          reasonCode: execResult.reasonCode,
          reason: execResult.reason,
          controlId: execResult.integrationId,
          stateChanges: execResult.stateChanges
        });
      }
      defenderState.pendingInterventions = [];
    }

    // Derive final outcomes & metrics (Spec Section 13.3)
    const sensitiveDatasetsRead = [];
    const sensitiveDatasetsExported = [];
    for (const ev of events) {
      if (ev.kind === 'action_result' && ev.outcome === 'succeeded') {
        for (const oc of ev.objectiveChanges || []) {
          if (oc.kind === 'dataset_read' && !sensitiveDatasetsRead.some(d => d.datasetId === oc.datasetId)) {
            sensitiveDatasetsRead.push(oc);
          }
          if (oc.kind === 'dataset_export' && !sensitiveDatasetsExported.some(d => d.datasetId === oc.datasetId)) {
            sensitiveDatasetsExported.push(oc);
          }
        }
      }
    }

    const objectiveResults = runConfig.objectives.map(objective => {
      const { id, kind, datasetId, targetAssetId, requiredCapability } = objective;
      let achieved;
      if (kind === 'asset_privilege') {
        achieved = worldState.reachedAssets.get(targetAssetId)?.capabilities.has(requiredCapability) ?? false;
      } else {
        const impact = kind === 'dataset_read' ? sensitiveDatasetsRead : sensitiveDatasetsExported;
        achieved = impact.some(change => change.datasetId === datasetId);
      }
      return { id, achieved };
    });
    const achievedCount = objectiveResults.filter(result => result.achieved).length;
    if (!guardrailExhausted && assistanceBudgetExhausted) {
      guardrailExhausted = true;
      guardrailReason = 'maxHumanAssists';
    }
    const objectiveState = guardrailExhausted ? 'incomplete'
      : orderingUnresolved ? 'conditional'
      : achievedCount && achievedCount === objectiveResults.length ? 'achieved'
      : achievedCount ? 'partially_achieved'
      : objectiveResults.length && actionAttempts > 0 ? 'not_achieved' : 'not_attempted';

    return {
      engineVersion: ENGINE_VERSION,
      schemaVersion: SCHEMA_VERSION,
      manifestVersion: RUN_MANIFEST_VERSION,
      estateId: estate.id,
      archetypeId: estate.archetypeId,
      trialSeed: runConfig.trialSeed,
      attackerProfile: structuredClone(attackerProfile),
      defenseConfig,
      runConfig,
      events,
      conditionalOutcomes,
      outcomes: {
        objectiveState,
        objectiveResults,
        terminationReason: guardrailExhausted ? `guardrail_exhausted:${guardrailReason}`
          : orderingUnresolved ? 'ordering_unresolved' : 'frontier_exhausted',
        guardrailExhausted,
        guardrailReason,
        access: {
          reachedAssetIds: [...worldState.reachedAssets.keys()],
          privilegesByAsset: Object.fromEntries(
            [...worldState.reachedAssets.entries()].map(([id, r]) => [id, [...r.capabilities]])
          ),
          sessions: Object.fromEntries(worldState.sessionLineage.entries()),
          acquiredCredentialIds: [...worldState.acquiredCredentials.keys()]
        },
        impact: {
          sensitiveDatasetsRead,
          sensitiveDatasetsExported,
          totalSensitiveRecordsRead: sensitiveDatasetsRead.reduce((sum, d) => sum + (d.records || 0), 0),
          totalSensitiveUnitsExported: sensitiveDatasetsExported.reduce((sum, d) => sum + (d.records || 0), 0)
        },
        detection: {
          totalObservations: defenderState.observations.length,
          suspiciousObservations: defenderState.observations.filter(o => o.suspiciousHypothesis).length,
          incidents: [...defenderState.incidents.values()],
          decoyAlerts: defenderState.decoyAlerts,
          missedActivityCount: events.filter(e => e.kind === 'action_result' && e.outcome === 'succeeded').length - defenderState.observations.filter(o => o.outcome === 'succeeded').length
        },
        response: {
          proposedCount: [...defenderState.incidents.values()].reduce((s, inc) => s + inc.proposedActions.length, 0),
          confirmedResponses: [...defenderState.confirmedResponses.values()],
          invalidatedSessionIds: [...worldState.invalidatedSessions],
          revokedCredentialIds: [...worldState.revokedCredentials],
          isolatedHostIds: [...worldState.isolatedHosts],
          closedExposureIds: [...worldState.closedExposures]
        },
        costs: {
          actionAttempts,
          maxActionAttempts: runConfig.limits.maxActionAttempts,
          retriesUsed,
          humanAssistsUsed,
          investigationsExecuted: defenderState.investigationsExecuted,
          controlBlocks,
          policyDenials,
          actionFailures,
          canceledActions,
          branchBreadth: branchCounter,
          duplicatedWork: attackerKnowledge.duplicatedWork,
          abandonedBranches: attackerKnowledge.abandonedBranches,
          validatedDiscoveries: attackerKnowledge.validatedDiscoveries,
          legitimateWorkflowsDisrupted: defenderState.legitimateWorkflowsDisrupted,
          legitimateIdentitiesAffected: [...defenderState.legitimateIdentitiesAffected],
          falseBlocks: defenderState.falseBlocks
        }
      }
    };
  }

  /**
   * Projects a completed causal run trace (`simulateScenario` or `simulateWireRun` result)
   * with historical elapsed-time context, UI node/route states, "Why" explanations, and tickets,
   * without mutating the trace or altering its causal outcomes (Spec Sections 5, 12, 14, WP5).
   */
  function projectRun(run, presentationConfig = {}) {
    if (!run || typeof run !== 'object') {
      throw new Error('projectRun requires a valid simulation run object');
    }
    const pace = presentationConfig.pace || (run.attackerProfile?.behaviorPreset === 'agentic_orchestration' || run.attackerProfile?.id === 'artex' ? 'artex' : 'pre2023');
    const seed = presentationConfig.seed ?? run.trialSeed ?? 1;
    const timingContext = presentationConfig.timingContext || wireTiming(seed, pace);
    const stageTimes = timingContext.stageTimes || [0, 900, 1800, 2700];

    const projectedEvents = (run.events || []).map((ev, idx) => {
      const copy = structuredClone(ev);
      if (typeof copy.timeSec !== 'number') {
        const stepIncrement = Math.max(5, Math.round((timingContext.modeledPathDurationSec || 2700) / Math.max(8, run.events.length)));
        copy.startSec = idx * stepIncrement;
        copy.timeSec = (idx + 1) * stepIncrement;
      }
      copy.displayElapsedLabel = formatDurationSeconds(copy.timeSec);
      copy.provenanceClassification = 'simulated_outcome';
      return copy;
    });

    // Derive node and route visual states & "Why" explanations (Spec Section 14)
    const nodeStates = {};
    const routeStates = {};
    const tickets = [];

    for (const ev of projectedEvents) {
      if (ev.kind && ev.kind !== 'action_result' && ev.kind !== 'decoy_interaction' && ev.kind !== 'response_confirmation') {
        continue;
      }
      const targetId = ev.targetId;
      if (!targetId) continue;
      if (!nodeStates[targetId]) {
        nodeStates[targetId] = {
          assetId: targetId,
          visualState: 'no_access',
          compromised: false,
          contained: false,
          patchPrevented: false,
          policyDenied: false,
          decoyAlerted: false,
          impacted: false,
          conditional: false,
          incomplete: false,
          why: []
        };
      }
      const ns = nodeStates[targetId];
      if (ev.outcome === 'succeeded' && ev.kind !== 'decoy_interaction' && ev.kind !== 'response_confirmation') {
        ns.compromised = true;
        if (ev.isProtectedRead || (ev.objectiveChanges && ev.objectiveChanges.length > 0)) {
          ns.impacted = true;
          ns.visualState = 'impact';
        } else if (ns.visualState !== 'impact') {
          ns.visualState = 'access_established';
        }
      } else if ((ev.outcome === 'denied' || ev.outcome === 'blocked') && (ev.controlId || ev.mitigation?.addressed)) {
        ns.patchPrevented = true;
        if (!ns.compromised) ns.visualState = 'patch_prevention';
      } else if (ev.outcome === 'denied' || ev.outcome === 'ineligible') {
        ns.policyDenied = true;
        if (!ns.compromised && !ns.patchPrevented) ns.visualState = 'policy_denial';
      } else if (ev.outcome === 'suppressed' || (ev.kind === 'response_confirmation' && ev.outcome === 'succeeded')) {
        ns.contained = true;
        // Spec Section 14: "A contained session and an already compromised dataset may coexist visually."
        if (!ns.impacted && !ns.compromised) ns.visualState = 'confirmed_containment';
      } else if (ev.outcome === 'conditional') {
        ns.conditional = true;
        ns.visualState = 'conditional_outcome';
      } else if (ev.outcome === 'budget_exhausted') {
        ns.incomplete = true;
        if (!ns.compromised) ns.visualState = 'incomplete_exploration';
      }

      if (ev.kind === 'decoy_interaction' || ev.outcome === 'alert_only' || ev.grantedCapability === 'decoy_alert') {
        ns.decoyAlerted = true;
        if (!ns.compromised && !ns.contained) ns.visualState = 'decoy_alert';
      }

      ns.why.push({
        eventId: ev.id || null,
        sequence: ev.sequence ?? null,
        timeSec: ev.timeSec,
        outcome: ev.outcome,
        reasonCode: ev.reasonCode || null,
        reason: ev.reason || '',
        prerequisites: ev.requiredAccess || null,
        controlId: ev.controlId || ev.mitigation?.control || null,
        scope: ev.actor?.sessionId || ev.scope || null,
        assumptionIds: ev.assumptionIds || []
      });

      const routeId = ev.routeId || ev.relationshipId;
      if (routeId) {
        routeStates[routeId] = {
          routeId,
          visualState: ns.visualState,
          lastOutcome: ev.outcome,
          reasonCode: ev.reasonCode || null,
          reason: ev.reason || ''
        };
      }

      if (['succeeded', 'denied', 'blocked', 'suppressed', 'alert_only', 'conditional'].includes(ev.outcome)) {
        tickets.push({
          id: `ticket-${tickets.length + 1}`,
          eventId: ev.id || null,
          targetId,
          severity: ns.impacted ? 'CRITICAL' : (ns.decoyAlerted || ns.contained || ns.patchPrevented) ? 'HIGH' : 'INFO',
          title: ev.reasonCode || ev.technique || ev.outcome.toUpperCase(),
          detail: ev.reason || '',
          elapsedLabel: ev.displayElapsedLabel
        });
      }
    }

    return {
      ...structuredClone(run),
      projectedEvents,
      nodeStates,
      routeStates,
      tickets,
      presentationContext: {
        pace,
        nominalPathDurationSec: timingContext.modeledPathDurationSec,
        stageTimes,
        provenanceClassification: 'synthetic_assumption',
        referencedAssumptionId: pace === 'artex' ? 'assumption-artex-nominal-path-duration' : 'assumption-pre2023-nominal-path-duration',
        note: 'Historical elapsed time is presentation context only and does not determine control or attack outcomes.'
      }
    };
  }

  /**
   * Paired comparison evaluator across multiple attacker profiles and defense configurations
   * on the same immutable estate and shared runConfig budgets (Spec Sections 5 & 13, R08, WP5).
   */
  function evaluateComparison({ estate, attackerProfiles, defenseConfigs, runConfig } = {}) {
    if (!estate || typeof estate !== 'object') {
      throw new Error('evaluateComparison requires a valid estate');
    }
    const baseEstateJson = JSON.stringify(estate);
    const profiles = (Array.isArray(attackerProfiles) && attackerProfiles.length > 0
      ? attackerProfiles
      : ['operator_with_tools', 'agentic_orchestration']
    ).map(normalizeAttackerProfile);

    const defenses = (Array.isArray(defenseConfigs) && defenseConfigs.length > 0
      ? defenseConfigs
      : ['baseline', 'patch', 'canaries', 'soc', 'soc-canary', 'combined']
    ).map(normalizeDefenseConfig);

    const sharedRunConfig = createDefaultRunConfig(estate, runConfig || {});
    const validation = validateRunConfig(estate, sharedRunConfig);
    if (!validation.valid) {
      throw new Error(`Invalid comparison configuration: ${validation.errors.join('; ')}`);
    }

    const cells = {};
    for (const profile of profiles) {
      cells[profile.id] = {};
      for (const defense of defenses) {
        const simRun = simulateScenario({
          estate,
          attackerProfile: profile,
          defenseConfig: defense,
          runConfig: sharedRunConfig
        });
        cells[profile.id][defense.id] = projectRun(simRun, {
          seed: sharedRunConfig.trialSeed,
          pace: profile.behaviorPreset === 'agentic_orchestration' ? 'artex' : 'pre2023'
        });
      }
      // Compute incremental prevented impact against corresponding baseline cell (Spec Section 13.3, F23)
      const baselineCell = Object.values(cells[profile.id]).find(cell => {
        const cfg = cell.defenseConfig;
        return !cfg.virtualPatching && !cfg.canaries && cfg.responsePolicy === 'observe_only';
      });
      const baselineViable = baselineCell && baselineCell.outcomes.impact.sensitiveDatasetsRead.length > 0;
      for (const defense of defenses) {
        const cell = cells[profile.id][defense.id];
        const cellImpact = cell.outcomes.impact.sensitiveDatasetsRead.length > 0;
        const hasAttributableIntervention = cell.outcomes.costs.controlBlocks > 0 || cell.outcomes.response.confirmedResponses.length > 0;
        cell.outcomes.comparisonSummary = {
          baselineViablePath: baselineViable,
          preventedImpact: !!(baselineViable && !cellImpact && hasAttributableIntervention &&
            !['incomplete', 'conditional'].includes(cell.outcomes.objectiveState)),
          attributionNote: !baselineViable
            ? 'No viable modeled path in baseline; safety is not attributed to optional defenses (F23).'
            : (!cellImpact && hasAttributableIntervention)
              ? 'Impact prevented by attributable control intervention.'
              : cellImpact
                ? 'Sensitive dataset impact occurred.'
                : 'No sensitive dataset impact.'
        };
      }
    }

    if (JSON.stringify(estate) !== baseEstateJson) {
      throw new Error('Invariant violation: evaluateComparison mutated input estate');
    }

    return {
      manifestVersion: RUN_MANIFEST_VERSION,
      engineVersion: ENGINE_VERSION,
      schemaVersion: SCHEMA_VERSION,
      estate: structuredClone(estate),
      attackerProfiles: profiles,
      defenseConfigs: defenses,
      runConfig: sharedRunConfig,
      calibrationProvenance: {
        schemaVersion: CALIBRATION_REGISTER.schemaVersion,
        asOfDate: CALIBRATION_REGISTER.asOfDate,
        observedStatisticIds: CALIBRATION_REGISTER.observedStatistics.map(s => s.id),
        simulationAssumptionIds: CALIBRATION_REGISTER.simulationAssumptions.map(a => a.id)
      },
      cells
    };
  }

  /**
   * Exports a durable, deterministic manifest containing the full estate, profiles, control overlays,
   * initial state, objective definitions, budgets, intervention contracts, seeds, engine version,
   * assumption provenance, and event trace (Spec Section 5 & 13.2, Fixture F26).
   */
  function exportManifest(comparisonOrRun) {
    if (!comparisonOrRun || typeof comparisonOrRun !== 'object') {
      throw new Error('exportManifest requires a comparison or simulation run object');
    }
    const isComparison = !!comparisonOrRun.cells && !!comparisonOrRun.estate;
    const payload = {
      format: 'wire-simulation-manifest',
      manifestVersion: RUN_MANIFEST_VERSION,
      engineVersion: ENGINE_VERSION,
      schemaVersion: SCHEMA_VERSION,
      exportedAt: '2026-11-21T00:00:00.000Z',
      kind: isComparison ? 'comparison' : 'single_run',
      estate: structuredClone(comparisonOrRun.estate || null),
      attackerProfiles: structuredClone(comparisonOrRun.attackerProfiles || (comparisonOrRun.attackerProfile ? [comparisonOrRun.attackerProfile] : [])),
      defenseConfigs: structuredClone(comparisonOrRun.defenseConfigs || (comparisonOrRun.defenseConfig ? [comparisonOrRun.defenseConfig] : [])),
      runConfig: structuredClone(comparisonOrRun.runConfig || null),
      assumptions: structuredClone(CALIBRATION_REGISTER.simulationAssumptions),
      observedStatistics: structuredClone(CALIBRATION_REGISTER.observedStatistics),
      ...(isComparison
        ? { cells: structuredClone(comparisonOrRun.cells) }
        : { events: structuredClone(comparisonOrRun.events || []), outcomes: structuredClone(comparisonOrRun.outcomes || null) })
    };
    return JSON.stringify(payload, null, 2);
  }

  /**
   * Imports and validates a JSON manifest or returns an explicit compatibility error (Spec Section 5, 13.2, 15, F26, F27).
   * Never silently regenerates a legacy v3 snapshot.
   */
  function importManifest(jsonOrObject) {
    try {
      return replayManifest(jsonOrObject);
    } catch (err) {
      return { ok: false, errors: [`Invalid manifest: ${err.message}`] };
    }
  }

  function exportWirePlayback(estate, attackerId, run) {
    return JSON.stringify({
      format: 'wire-simulation-manifest',
      manifestVersion: RUN_MANIFEST_VERSION,
      engineVersion: ENGINE_VERSION,
      schemaVersion: SCHEMA_VERSION,
      kind: 'wire_playback',
      estate,
      attackerId,
      defenseConfig: run.defenseConfig,
      events: run.events,
      controls: run.controls
    }, null, 2);
  }

  function replayManifest(jsonOrObject) {
    let parsed;
    try {
      parsed = typeof jsonOrObject === 'string' ? JSON.parse(jsonOrObject) : structuredClone(jsonOrObject);
    } catch (err) {
      return {
        ok: false,
        valid: false,
        errors: [`Invalid JSON manifest: ${err.message}`]
      };
    }

    if (!parsed || typeof parsed !== 'object') {
      return { ok: false, valid: false, errors: ['Manifest must be a JSON object'] };
    }

    // Check if user passed a raw legacy v3 estate snapshot instead of a v4 manifest (Fixture F27)
    if (parsed.schemaVersion && parsed.schemaVersion !== SCHEMA_VERSION) {
      return convertLegacySnapshot(parsed);
    }
    if (parsed.estate && parsed.estate.schemaVersion !== SCHEMA_VERSION) {
      return convertLegacySnapshot(parsed.estate);
    }

    if (parsed.format !== 'wire-simulation-manifest' || parsed.manifestVersion !== RUN_MANIFEST_VERSION) {
      return {
        ok: false,
        valid: false,
        errors: [`Unsupported manifest format or version (expected format='wire-simulation-manifest', manifestVersion=${RUN_MANIFEST_VERSION})`]
      };
    }

    if (!parsed.estate) {
      return { ok: false, valid: false, errors: ['Manifest is missing required estate object'] };
    }

    if (parsed.engineVersion !== ENGINE_VERSION || !['single_run', 'comparison', 'wire_playback'].includes(parsed.kind)) {
      return { ok: false, errors: ['Unsupported simulation engine version or manifest kind.'] };
    }
    if (parsed.kind === 'wire_playback') {
      const { estate, attackerId, defenseConfig, events, controls } = parsed;
      if (!defenseConfig || typeof defenseConfig.virtualPatching !== 'boolean' ||
          typeof defenseConfig.canaries !== 'boolean' || !defenseConfig.responsePolicy) {
        return { ok: false, errors: ['Playback manifest requires explicit defense switches.'] };
      }
      const replayed = simulateWireRun(estate, 'baseline', attackerId, { defenseConfig });
      if (JSON.stringify(events) !== JSON.stringify(replayed.events) ||
          JSON.stringify(controls) !== JSON.stringify(replayed.controls)) {
        return { ok: false, errors: ['Playback trace differs from the recorded run.'] };
      }
      return { ok: true, kind: parsed.kind, manifest: parsed, replayed };
    }
    if (!Array.isArray(parsed.attackerProfiles) || !parsed.attackerProfiles.length ||
        !Array.isArray(parsed.defenseConfigs) || !parsed.defenseConfigs.length) {
      return { ok: false, errors: ['Manifest requires explicit attacker profiles and defense configurations.'] };
    }

    const validation = validateRunConfig(parsed.estate, parsed.runConfig);
    if (!validation.valid) {
      return {
        ok: false,
        valid: false,
        errors: validation.errors,
        details: validation.details
      };
    }

    // Re-run deterministically to verify replay integrity
    if (parsed.kind === 'comparison') {
      const replayed = evaluateComparison({
        estate: parsed.estate,
        attackerProfiles: parsed.attackerProfiles,
        defenseConfigs: parsed.defenseConfigs,
        runConfig: parsed.runConfig
      });
      if (JSON.stringify(parsed.cells) !== JSON.stringify(replayed.cells)) {
        return { ok: false, errors: ['Replayed comparison cells differ from the recorded results.'] };
      }
      return {
        ok: true,
        valid: true,
        kind: 'comparison',
        manifest: parsed,
        replayed
      };
    }

    const replayedRun = simulateScenario({
      estate: parsed.estate,
      attackerProfile: parsed.attackerProfiles?.[0] || 'operator_with_tools',
      defenseConfig: parsed.defenseConfigs?.[0] || 'baseline',
      runConfig: parsed.runConfig
    });
    if (JSON.stringify(parsed.events) !== JSON.stringify(replayedRun.events) ||
        JSON.stringify(parsed.outcomes) !== JSON.stringify(replayedRun.outcomes)) {
      return { ok: false, errors: ['Replayed events or outcomes differ from the recorded run.'] };
    }
    return {
      ok: true,
      valid: true,
      kind: 'single_run',
      manifest: parsed,
      replayed: replayedRun
    };
  }

  // Dataset classification and objective predicates determine sensitive data impact,
  // independently of diagram layer or public reachability (Spec Invariant R09, WP1 Exit Gate, F17).
  function isSensitiveDatasetRead(targetAsset, action, estate, isCanary) {
    if (!action || action.yieldsCapability !== 'data_read' || isCanary || targetAsset?.isDecoy) {
      return false;
    }
    if (Array.isArray(estate?.datasets) && estate.datasets.length > 0) {
      const owned = estate.datasets.filter(ds => ds.ownerAssetId === targetAsset.id);
      if (owned.length > 0) {
        return owned.some(ds => ds.sensitivity === 'sensitive' && !ds.isDecoy);
      }
    }
    if (targetAsset?.datasetSensitivity) {
      return targetAsset.datasetSensitivity === 'sensitive';
    }
    return targetAsset?.layerIdx === 3 && !targetAsset?.isDecoy;
  }

  /**
   * Pure, deterministic, bounded graph traversal and action evaluator.
   */
  function simulateEstate(estate, mode = 'baseline', timing = null) {
    const validation = validateEstate(estate);
    if (!validation.valid) {
      throw new Error(`Invalid estate: ${validation.errors.join('; ')}`);
    }

    const assetById = new Map(estate.assets.map(a => [a.id, a]));
    const orderRank = new Map((estate.actionOrder?.length ? estate.actionOrder : estate.assets.map(a => a.id)).map((id, idx) => [id, idx]));
    const rankOf = id => orderRank.get(id);

    const defensePosture = estate.defensePosture || null;
    const defenseConfig = timing?.defenseConfig;
    const canariesEnabled = defenseConfig?.canaries ?? ['canaries', 'soc-canary', 'combined'].includes(mode);
    const canaryAssets = new Set(
      defensePosture && Array.isArray(defensePosture.decoys)
        ? defensePosture.decoys.map(d => d.assetId).filter(Boolean)
        : estate.assets.filter(a => a.isDecoy).map(a => a.id)
    );
    const canaryAsset = estate.assets.find(a => a.isDecoy && canaryAssets.has(a.id)) ?? null;

    const state = {
      reachedAssets: new Map(),
      acquiredCredentials: new Map(estate.credentials.filter(cred => cred.startingAccess).map(cred => [cred.id, cred])),
      revokedCredentials: new Set()
    };

    const visitedTransitions = new Set();
    const layerSuccessCount = [0, 0, 0, 0];
    const events = [];
    const controls = [];
    const signals = new Map();
    const containedSessions = new Set();
    const sessionHops = new Map();
    const triggeredDecoys = new Set();
    const attackerProfile = timing?.attackerProfile || null;

    const credentialSignature = target => [...state.acquiredCredentials.values()].filter(cred =>
      cred.targetAssetIds?.length ? cred.targetAssetIds.includes(target.id) : cred.targetGroupIds?.includes(target.groupId))
      .map(cred=>cred.id).sort().join(',');
    const routeKey = (source,target,relationship) => `${source?.id || 'EXTERNAL'}->${target.id}:${relationship?.id || 'EXT'}:${credentialSignature(target)}:${[...(state.reachedAssets.get(source?.id)?.capabilities || [])].sort().join(',')}`;
    const actionKey = action => `${action.actionKind}:${action.finding?.id || ''}:${action.credentialUsed?.id || ''}:${action.yieldsCapability}`;
    const routeUnsupported = (source,target,relationship,localFinding) => {
      if(!attackerProfile?.gangId)return false;
      const methods=localFinding?[localFinding]:estate.findings.filter(f=>f.assetId===target.id &&
        (!relationship || !f.requiredInterface || f.requiredInterface===relationship.protocol));
      return methods.length>0 && methods.every(finding=>!actionPolicy({finding,technique:finding.technique},source,target,attackerProfile));
    };

    function scopeFor(source, capability) {
      const reach=state.reachedAssets.get(source.id);
      const owner=reach?.capabilityScopes?.get(capability || (reach.capabilities.has('app_exec')?'app_exec':[...reach.capabilities][0]));
      if(owner)return owner;
      let entry = source.id;
      let parent = state.reachedAssets.get(entry)?.sourceId;
      while (parent) {
        entry = parent;
        parent = state.reachedAssets.get(entry)?.sourceId;
      }
      return entry;
    }

    function signal(scope, targetId, source, timeSec, contain = true) {
      const collectionDelay = timing?.collectionDelay ?? 0;
      const observedAt = timeSec + collectionDelay;
      controls.push({ scope, targetId, source, timeSec: observedAt, control: 'signal' });
      if (!contain) return;
      if (timing?.responseAuthority === false) {
        controls.push({scope, targetId, source, timeSec: observedAt, control: 'denied'});
        return;
      }
      const responseScope = timing?.responseScope ?? scope;
      const decisionAt = observedAt + (timing?.decisionDelay ?? 0);
      const effectiveAt = Math.max(decisionAt, observedAt + (timing?.responseDelay ?? 0));
      if ((signals.get(responseScope) ?? Infinity) <= effectiveAt) return;
      for (let i = controls.length - 1; i >= 0; i--) {
        if (controls[i].scope === responseScope && controls[i].timeSec >= observedAt && ['decision', 'enforced', 'failed'].includes(controls[i].control)) controls.splice(i, 1);
      }
      controls.push({ scope: responseScope, targetId, source, timeSec: decisionAt, control: 'decision' });
      controls.push({ scope: responseScope, targetId, source, timeSec: effectiveAt, control: timing?.enforcementSucceeds === false ? 'failed' : 'enforced' });
      if (timing?.enforcementSucceeds === false) return;
      signals.set(responseScope, effectiveAt);
      containedSessions.add(responseScope);
    }

    function recordTelemetry(source, target, action, scope, timeSec, isCanary) {
      if (!timing) return;
      if (isCanary) {
        if (canariesEnabled && !triggeredDecoys.has(target.id)) {
          triggeredDecoys.add(target.id);
          signal(scope, target.id, 'canary', timeSec, timing.respond);
        }
        return;
      }
      if (!timing.respond) return;
      const layerMonitored = !defensePosture?.telemetryLayers || defensePosture.telemetryLayers.includes(target.layerIdx);
      if (!layerMonitored || target.groupId === 'staging-status') return;
      if (action.actionKind === 'phishing_attachment') {
        signal(scope, target.id, 'endpoint', timeSec, true);
        return;
      }
      const hops = (sessionHops.get(scope) || 0) + 1;
      sessionHops.set(scope, hops);
      // Cross-boundary sequence correlation triggers on >= 2 monitored hops
      if (hops >= 2 && target.layerIdx >= 1) {
        signal(scope, target.id, 'boundary', timeSec, true);
      }
    }

    let eligibleTransitions = 0;
    let attemptedTransitions = 0;
    let succeededTransitions = 0;
    let blockedTransitions = 0;
    let ineligibleTransitions = 0;
    let truncated = false;
    let dataReached = false;
    let activeStep = null;
    const explorationLimit = timing?.explorationLimit ?? 1000;
    let evaluatedTransitions = 0;

    function processTransition(sourceAsset, targetAsset, relationship) {
      const localFinding = activeStep?.localFinding;
      const timeSec = activeStep?.timeSec ?? timing?.stageTimes?.[targetAsset.layerIdx];
      const startSec = activeStep?.startSec;
      const scope = timing ? (localFinding?.transferScope || (sourceAsset ? scopeFor(sourceAsset,relationship?.requiredSourceCapability) : targetAsset.id)) : null;
      const transitionKey = activeStep?.transitionKey || (localFinding ? `LOCAL:${localFinding.id}` : routeKey(sourceAsset,targetAsset,relationship));
      if (visitedTransitions.has(transitionKey)) return false;
      visitedTransitions.add(transitionKey);

      if (scope && containedSessions.has(scope) && (signals.get(scope) ?? Infinity) <= timeSec) {
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: localFinding || null,
          ...(localFinding && {actionKind:localFinding.kind}),
          credentialUsed: null,
          technique: localFinding?.technique || null,
          requiredAccess: null,
          reachability: `${sourceAsset ? sourceAsset.label : 'External'} -> ${targetAsset.label}`,
          grantedCapability: null,
          acquiredCredentials: [],
          scope,
          mitigation: {
            addressed: true,
            badge: 'CONTAINED · AGENTIC SOC',
            control: 'NIST SI-4 / AC-3',
            reason: 'Session contained by Agentic SOC before this hop.'
          },
          outcome: 'suppressed',
          timeSec, startSec,
          suppressionPhase: activeStep?.suppressionPhase || 'in_flight',
          enforcementSec: signals.get(scope),
          scheduledEffectSec: activeStep?.scheduledEffectSec ?? timeSec,
          reason: 'Action effect suppressed because session containment was effective at or before completion.'
        });
        return false;
      }

      const isCanary = canaryAssets.has(targetAsset.id);
      if ((isCanary || targetAsset.isDecoy) && (!isCanary || (mode !== 'canaries' && mode !== 'soc-canary' && mode !== 'combined'))) {
        return false;
      }
      if (evaluatedTransitions >= explorationLimit) { truncated = true; return false; }
      evaluatedTransitions++;
      attemptedTransitions++;
      const feasible = localFinding ? [evaluatePostCompromiseAction(state, targetAsset, localFinding, estate)]
        : evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate);
      const allowed = feasible.filter(action => action.eligible && actionPolicy(action, sourceAsset, targetAsset, attackerProfile))
        .sort((a,b)=>lateralRank(a,attackerProfile)-lateralRank(b,attackerProfile));
      const candidates = activeStep?.plannedActionKeys ? allowed.filter(action=>activeStep.plannedActionKeys.includes(actionKey(action))) : allowed;
      if(allowed.length && !candidates.length){
        ineligibleTransitions++;
        events.push({sourceId:sourceAsset?.id || null,targetId:targetAsset.id,relationshipId:relationship?.id || null,
          finding:allowed[0].finding || null,outcome:'ineligible',analysisKind:'failed_probe',
          reason:'Access prerequisites changed during this check; the newly available method needs a separate attempt.'});
        return false;
      }
      const unsupported=routeUnsupported(sourceAsset,targetAsset,relationship,localFinding);
      if (!candidates.length && (feasible.some(action => action.eligible)||unsupported)) {
        ineligibleTransitions++;
        events.push({ sourceId: sourceAsset?.id || null, targetId: targetAsset.id,
          relationshipId: relationship?.id || null, outcome: 'ineligible',
          policySkipped: true, reason: `No applicable action in ${attackerProfile?.gangId || 'this attacker'}'s repertoire; user-interaction prerequisites are enforced.` });
        return false;
      }

      if (!candidates.length) {
        ineligibleTransitions++;
        const supportedFinding = !localFinding && relationship && estate.findings.filter(f=>f.assetId===targetAsset.id &&
          f.requiredInterface===relationship.protocol && actionPolicy({finding:f,technique:f.technique},sourceAsset,targetAsset,attackerProfile))
          .sort((a,b)=>lateralRank({finding:a,technique:a.technique},attackerProfile)-lateralRank({finding:b,technique:b.technique},attackerProfile))[0];
        const failure = supportedFinding ? evaluateDistinctActions(state,sourceAsset,targetAsset,relationship,
          {...estate,findings:estate.findings.filter(f=>f.assetId!==targetAsset.id || f.id===supportedFinding.id)})[0] : feasible[0];
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: failure.finding || null,
          ...(localFinding && {actionKind:localFinding.kind,dataTransfer:localFinding.dataTransfer}),
          analysisKind:/source capability|No directed relationship|Protocol mismatch|Relationship direction/i.test(failure.reason || '')?'route_review':'failed_probe',
          outcome: 'ineligible',
          reason: failure.reason
        });
        return;
      }

      const existingReach = state.reachedAssets.get(targetAsset.id);
      const distinctActions = existingReach
        ? candidates.filter(c => !existingReach.capabilities.has(c.yieldsCapability))
        : candidates;

      if (existingReach && distinctActions.length === 0) {
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          outcome: 'revisit',
          reason: `${targetAsset.label} already reached with the same capability via an earlier path.`
        });
        return;
      }

      let gainedAccess = false;
      for (const action of distinctActions) {
        const attackerEvidence = actionPolicy(action, sourceAsset, targetAsset, attackerProfile);
        if(attackerProfile?.gangId && action.finding?.kind==='remote_service' && sourceAsset) {
          attackerEvidence.selectionPreference={method:lateralMethod(action),rank:lateralRank(action,attackerProfile),
            basis:'authored_order_among_reported_methods'};
        }
        const currentReach = state.reachedAssets.get(targetAsset.id);
        if (currentReach && currentReach.capabilities.has(action.yieldsCapability)) {
          continue;
        }

        eligibleTransitions++;
        // Timed SOC consumes evidence through the response lifecycle, never an instant lookup block.
        const preventionMode = defenseConfig
          ? (isCanary && canariesEnabled ? 'canaries' : defenseConfig.virtualPatching ? 'patch' : 'baseline')
          : timing && ['soc', 'soc-canary', 'combined'].includes(mode)
            ? (isCanary ? 'canaries' : mode === 'combined' ? 'patch' : 'baseline') : mode;
        const mitigation = evaluateDefense(targetAsset, action, preventionMode, estate.seed, isCanary, {
          attackerProfile,
          defensePosture
        });

        if (mitigation.addressed) {
          blockedTransitions++;
          if (mitigation.revokeCredentialId) {
            state.revokedCredentials.add(mitigation.revokeCredentialId);
          }
          if (isCanary && canariesEnabled && timing?.respond) {
            recordTelemetry(sourceAsset, targetAsset, action, scope, timeSec, true);
          }
          events.push({
            sourceId: sourceAsset ? sourceAsset.id : null,
            targetId: targetAsset.id,
            relationshipId: relationship ? relationship.id : null,
            finding: action.finding,
            credentialUsed: action.credentialUsed,
            technique: action.technique,
            attackerEvidence,
            ...(localFinding && {actionKind:action.actionKind,dataTransfer:action.dataTransfer}),
            requiredAccess: action.requiredAccess,
            reachability: action.reachability,
            grantedCapability: null,
            acquiredCredentials: [],
            ...(scope && { scope }),
            mitigation,
            outcome: 'blocked',
            reason: mitigation.reason
          });
          continue;
        }

        // Count reached assets; display density never limits modeled access.
        const sourceId = sourceAsset ? sourceAsset.id : null;
        const alreadyReached = !!currentReach;

        // Grant capability and update state
        gainedAccess = true;
        succeededTransitions++;
        const sensitiveRead = isSensitiveDatasetRead(targetAsset, action, estate, isCanary);
        if (!alreadyReached && !isCanary) layerSuccessCount[targetAsset.layerIdx]++;
        if (sensitiveRead) dataReached = true;

        let caps;
        if (currentReach) {
          currentReach.capabilities.add(action.yieldsCapability);
          caps = currentReach.capabilities;
        } else {
          caps = new Set([action.yieldsCapability]);
          state.reachedAssets.set(targetAsset.id, {
            layerIdx: targetAsset.layerIdx,
            sourceId,
            capabilities: caps,
            viaFindingId: action.finding ? action.finding.id : null,
            viaCredentialId: action.credentialUsed ? action.credentialUsed.id : null
          });
        }
        const reached = state.reachedAssets.get(targetAsset.id);
        if(!reached.capabilityScopes)reached.capabilityScopes=new Map();
        reached.capabilityScopes.set(action.yieldsCapability,scope);
        if (!reached.endpointPermissions) reached.endpointPermissions = new Map();
        const accessibleEndpoints = targetAsset.endpointIds ? action.endpointScope || [] : [targetAsset.id];
        for (const id of accessibleEndpoints) {
          if (!reached.endpointPermissions.has(id)) reached.endpointPermissions.set(id, new Set());
          for (const permission of action.grantedPermissions || []) reached.endpointPermissions.get(id).add(permission);
        }

        // Collect any synthetic credentials stored on targetAsset that are now accessible
        const newlyAcquired = [];
        for (const cred of estate.credentials) {
          if (cred.sourceAssetId !== targetAsset.id) continue;
          if (state.revokedCredentials.has(cred.id) || cred.revoked) continue;
          const capOk = !!cred.requiredSourceCapability && caps.has(cred.requiredSourceCapability);
          const sourceEndpointOk = !cred.sourceEndpointIds || cred.sourceEndpointIds.some(id=>reached.endpointPermissions.has(id));
          if (capOk && sourceEndpointOk && !state.acquiredCredentials.has(cred.id)) {
            state.acquiredCredentials.set(cred.id, cred);
            newlyAcquired.push(cred);
          }
        }

        events.push({
          sourceId,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: action.finding,
          credentialUsed: action.credentialUsed,
          technique: action.technique,
          attackerEvidence,
          requiredAccess: action.requiredAccess,
          reachability: action.reachability,
          grantedCapability: action.yieldsCapability,
          ...(action.tool && {tool:action.tool}),
          isProtectedRead: sensitiveRead,
          ...(action.yieldsCapability==='data_read' && targetAsset.dataHandling && {dataFound:targetAsset.dataHandling}),
          ...(action.dataTransfer && {dataTransfer:action.dataTransfer}),
          ...(localFinding && { actionKind: action.actionKind, affectedEndpointIds: action.affectedEndpointIds }),
          acquiredCredentials: newlyAcquired,
          ...(scope && { scope }),
          mitigation,
          outcome: isCanary && canariesEnabled && (timing ? !timing.respond : mode === 'canaries') ? 'alert_only' : 'succeeded',
          reason: mitigation.alertOnly ? mitigation.reason : action.reason
        });
        if (localFinding) {
          const monitoredAsset=action.actionKind==='data_exfiltration'?assetById.get(localFinding.collectorId):targetAsset;
          if (timing?.respond && (!defensePosture?.telemetryLayers || defensePosture.telemetryLayers.includes(monitoredAsset?.layerIdx))) {
            signal(scope, targetAsset.id, action.actionKind==='data_exfiltration'?'data-transfer':'endpoint', timeSec, true);
          }
        } else recordTelemetry(sourceAsset, targetAsset, action, scope, timeSec, isCanary);
      }
      return gainedAccess;
    }

    const entryAssets = estate.assets
      .filter(a => a.layerIdx === 0 && a.isExternalEntry)
      .sort((a, b) => rankOf(a.id) - rankOf(b.id));

    if (attackerProfile?.maxConcurrentBranches) {
      // Workers start only from discovered access. Finish/containment ties favor enforcement.
      const frontier = entryAssets.map(entry => ({ sourceAsset: null, targetAsset: entry, relationship: null, readySec: 0 }));
      const running = [];
      const enqueued = new Set(entryAssets.map(a => routeKey(null,a,null)));
      const workers = attackerProfile.maxConcurrentBranches;
      let clock = 0, initialAccessReserved = false, preferredScope = null;
      const assess = step => {
        const feasible=step.localFinding ? [evaluatePostCompromiseAction(state,step.targetAsset,step.localFinding,estate)]
          : evaluateDistinctActions(state, step.sourceAsset, step.targetAsset, step.relationship, estate);
        const candidates = feasible
          .filter(action => action.eligible && actionPolicy(action, step.sourceAsset, step.targetAsset, attackerProfile))
          .sort((a,b)=>lateralRank(a,attackerProfile)-lateralRank(b,attackerProfile));
        const distinct=candidates.filter(action=>!state.reachedAssets.get(step.targetAsset.id)?.capabilities.has(action.yieldsCapability));
        const duplicateInFlight=distinct.length>0 && distinct.every(action=>running.some(job=>
          job.targetAsset.id===step.targetAsset.id && job.plannedCapabilities.includes(action.yieldsCapability)));
        // Decisions about an unsupported method or an already obtained capability
        // do not represent another timed attack. Real failed probes retain time.
        const unsupported=routeUnsupported(step.sourceAsset,step.targetAsset,step.relationship,step.localFinding);
        const noWork=candidates.length>0&&!distinct.length || !candidates.length&&(feasible.some(action=>action.eligible)||unsupported) ||
          !step.localFinding&&visitedTransitions.has(routeKey(step.sourceAsset,step.targetAsset,step.relationship));
        return {feasible,candidates,distinct,duplicateInFlight,noWork};
      };
      const priority = (step, assessment) => {
        if(assessment.noWork)return -100;
        if(step.localFinding){
          if(step.localFinding.kind==='encryption')return 1000; // collection/exfiltration and dead-end checks precede impact
          return step.localFinding.kind==='persistence'?5:10;
        }
        const sameFoothold=step.sourceAsset && scopeFor(step.sourceAsset,step.relationship?.requiredSourceCapability)===preferredScope;
        if(!step.sourceAsset){
          const order=GANG_ENTRY_ORDER[attackerProfile.gangId] || [];
          const ranks=assessment.candidates.map(action=>order.findIndex(id=>techniqueMatches(id,action.technique))).filter(rank=>rank>=0);
          return attackerProfile.gangId ? (preferredScope?200:0)+(ranks.length?Math.min(...ranks):10) : 60;
        }
        if(!assessment.candidates.length)return sameFoothold?100:150;
        const dataRead=assessment.candidates.some(action=>action.yieldsCapability==='data_read');
        return attackerProfile.gangId ? (sameFoothold?20:50)+(dataRead?0:10) : dataRead?20:40;
      };
      while (frontier.length || running.length) {
        if (evaluatedTransitions >= explorationLimit) { truncated = true; break; }
        while (frontier.length && running.length < workers) {
          const assessments=new Map(frontier.map(step=>[step,assess(step)]));
          const methodRank=step=>assessments.get(step).candidates.length
            ? Math.min(...assessments.get(step).candidates.map(action=>lateralRank(action,attackerProfile))) : 0;
          frontier.sort((a, b) => priority(a,assessments.get(a)) - priority(b,assessments.get(b)) ||
            rankOf(a.targetAsset.id) - rankOf(b.targetAsset.id) || methodRank(a)-methodRank(b));
          // Wait for an in-flight attempt before spending another worker on the
          // same capability. If it fails, the alternate route remains available.
          const index=frontier.findIndex(step=>!assessments.get(step).duplicateInFlight);
          if(index<0)break;
          const step = frontier.splice(index,1)[0], assessment=assessments.get(step);
          step.transitionKey=step.localFinding?`LOCAL:${step.localFinding.id}`:routeKey(step.sourceAsset,step.targetAsset,step.relationship);
          const layer = step.targetAsset.layerIdx;
          let duration = step.localFinding?.modeledDurationSec ?? timing.actionDurations?.[layer] ?? Math.max(0, timing.stageTimes[layer] - (layer ? timing.stageTimes[layer - 1] : 0));
          if(assessment.noWork)duration=0;
          else if(!step.sourceAsset&&assessment.distinct.length){
            if(initialAccessReserved)duration=Math.max(duration,timing.reentryDurationSec || 0);
            initialAccessReserved=true;
          }
          const startSec = Math.max(clock, step.readySec);
          const scope = step.localFinding?.transferScope || (step.sourceAsset ? scopeFor(step.sourceAsset,step.relationship?.requiredSourceCapability) : step.targetAsset.id);
          if ((signals.get(scope) ?? Infinity) <= startSec) {
            activeStep = {...step, startSec, timeSec: startSec, scheduledEffectSec: startSec + duration, suppressionPhase: 'queued'};
            processTransition(step.sourceAsset, step.targetAsset, step.relationship);
            activeStep = null;
            continue;
          }
          running.push({ ...step, plannedCapabilities:assessment.distinct.map(action=>action.yieldsCapability),
            plannedActionKeys:assessment.candidates.map(actionKey),
            startSec, timeSec: startSec + duration, scheduledEffectSec: startSec + duration, suppressionPhase: 'in_flight' });
        }
        if (!running.length) continue;
        // Confirmed enforcement cancels in-flight effects and frees the worker at that time.
        for (const step of running) {
          const scope = step.localFinding?.transferScope || (step.sourceAsset ? scopeFor(step.sourceAsset,step.relationship?.requiredSourceCapability) : step.targetAsset.id);
          step.timeSec = Math.min(step.timeSec, signals.get(scope) ?? Infinity);
        }
        running.sort((a, b) => a.timeSec - b.timeSec || rankOf(a.targetAsset.id) - rankOf(b.targetAsset.id));
        activeStep = running.shift();
        clock = activeStep.timeSec;
        const before = events.length;
        const ok = processTransition(activeStep.sourceAsset, activeStep.targetAsset, activeStep.relationship);
        for (let i = before; i < events.length; i++) Object.assign(events[i], {timeSec: clock, startSec: activeStep.startSec});
        const newAccess=events.slice(before).find(event=>event.outcome==='succeeded'&&!event.sourceId);
        if(newAccess && !preferredScope)preferredScope=newAccess.scope;
        for(const read of events.slice(before).filter(event=>event.outcome==='succeeded'&&event.isProtectedRead)) {
          const target=assetById.get(read.targetId), responseExport=!attackerProfile.gangId;
          const method=DATA_EXPORT_METHODS[attackerProfile.gangId];
          if(!responseExport&&!method)continue;
          const key=`EXFIL:${target.id}`;
          if(enqueued.has(key))continue;
          enqueued.add(key);
          // Follow the established read path to a host the session controls.
          let collectorId=read.sourceId || read.targetId;
          if(!responseExport)while(collectorId&&!state.reachedAssets.get(collectorId)?.capabilities.has('app_exec'))
            collectorId=state.reachedAssets.get(collectorId)?.sourceId;
          const records=Number.isSafeInteger(target.dataHandling?.records)&&target.dataHandling.records>0?target.dataHandling.records:null;
          const bytes=Number.isSafeInteger(target.dataHandling?.bytes)&&target.dataHandling.bytes>0?target.dataHandling.bytes:null;
          const finding={id:key,kind:'data_exfiltration',assetId:target.id,collectorId,responseExport,transferScope:read.scope,
            technique:method?.technique || null,title:responseExport?'HTTP/API bulk data export':'Data exfiltration',
            sourceUrl:responseExport?ARTEX_EVIDENCE_SOURCE:gangTechniqueEvidence(attackerProfile.gangId,method.technique)?.source,
            // Unknown size uses the synthetic setup duration, without inventing throughput or volume.
            modeledDurationSec:120+(bytes==null?0:Math.ceil(bytes/(512*1024))),
            timingBasis:bytes==null?'Synthetic 120-second export duration; data size unknown':'Synthetic setup plus size-based transfer duration',
            dataTransfer:{datasetId:target.id,dataset:target.dataHandling?.label || `Sensitive records · ${target.label}`,records,bytes,
              tool:responseExport?'HTTP/API bulk extraction':method.tool,
              destination:responseExport?'Attacker-controlled workspace':method.destination}};
          frontier.push({sourceAsset:target,targetAsset:target,relationship:null,localFinding:finding,readySec:clock});
        }
        if (ok && !activeStep.localFinding && state.reachedAssets.get(activeStep.targetAsset.id)?.capabilities.has('app_exec')) {
          for (const finding of estate.findings.filter(f => f.assetId === activeStep.targetAsset.id && ['persistence','encryption'].includes(f.kind))) {
            const probe = {actionKind: finding.kind, finding, technique: finding.technique};
            if (!actionPolicy(probe, activeStep.targetAsset, activeStep.targetAsset, attackerProfile)) continue;
            const key = `LOCAL:${finding.id}`;
            if (enqueued.has(key)) continue;
            enqueued.add(key);
            frontier.push({sourceAsset:activeStep.targetAsset, targetAsset:activeStep.targetAsset,
              relationship:null, localFinding:finding, readySec:clock});
          }
        }
        if (ok && !activeStep.localFinding && activeStep.targetAsset.layerIdx < 3) {
          const out = estate.relationships.filter(r => r.sourceId === activeStep.targetAsset.id)
            .sort((a,b) => rankOf(a.targetId) - rankOf(b.targetId));
          for (const rel of out) {
            if (assetById.get(rel.targetId)?.isDecoy && !canariesEnabled) continue;
            const key = routeKey(activeStep.targetAsset,assetById.get(rel.targetId),rel);
            if (enqueued.has(key)) continue;
            enqueued.add(key);
            frontier.push({sourceAsset: activeStep.targetAsset, targetAsset: assetById.get(rel.targetId), relationship: rel, readySec: clock});
          }
        }
        const recovered = events.slice(before).flatMap(event=>event.acquiredCredentials || []);
        if (recovered.length) {
          for (const rel of estate.relationships) {
            if (!state.reachedAssets.has(rel.sourceId)) continue;
            const target=assetById.get(rel.targetId);
            if (!recovered.some(cred=>cred.targetAssetIds?.includes(target.id) || (!cred.targetAssetIds?.length && cred.targetGroupIds?.includes(target.groupId)))) continue;
            const key=routeKey(assetById.get(rel.sourceId),target,rel);
            if(enqueued.has(key))continue;
            enqueued.add(key);
            frontier.push({sourceAsset:assetById.get(rel.sourceId),targetAsset:target,relationship:rel,readySec:clock});
          }
        }
      }
      activeStep = null;
    } else {
      // Plain graph traversal also supports same-layer Windows/application flows.
      const pending=entryAssets.map(target=>({source:null,target,rel:null}));
      while(pending.length) {
        const {source,target,rel}=pending.shift();
        if(!processTransition(source,target,rel))continue;
        for(const next of estate.relationships.filter(r=>r.sourceId===target.id)
          .sort((a,b)=>rankOf(a.targetId)-rankOf(b.targetId))) {
          pending.push({source:target,target:assetById.get(next.targetId),rel:next});
        }
      }
    }

    const completeFourLayerPath = [...state.reachedAssets.entries()].some(([id, entry]) => {
      if (entry.layerIdx !== 3) return false;
      const layers = new Set();
      while (id && state.reachedAssets.has(id)) {
        const step = state.reachedAssets.get(id);
        layers.add(step.layerIdx);
        id = step.sourceId;
      }
      return [0, 1, 2, 3].every(layer => layers.has(layer));
    });

    return {
      mode,
      canaryAssetId: canaryAsset ? canaryAsset.id : null,
      events,
      controls,
      summary: {
        discoveredDatasets:events.filter(e=>e.outcome==='succeeded'&&e.isProtectedRead).map(e=>e.targetId),
        exfiltratedDatasets:events.filter(e=>e.outcome==='succeeded'&&e.actionKind==='data_exfiltration').map(e=>e.dataTransfer),
        encryptedEndpointIds: [...new Set(events.filter(e => e.outcome === 'succeeded' && e.actionKind === 'encryption').flatMap(e => e.affectedEndpointIds))],
        persistentEndpointIds: [...new Set(events.filter(e => e.outcome === 'succeeded' && e.actionKind === 'persistence').flatMap(e => e.affectedEndpointIds))],
        layerSuccessCounts: layerSuccessCount,
        eligibleTransitions,
        attemptedTransitions,
        succeededTransitions,
        blockedTransitions,
        ineligibleTransitions,
        containedSessions: containedSessions.size,
        evaluatedTransitions,
        explorationLimit,
        budgetUnit: 'evaluated transitions',
        suppressedTransitions: events.filter(e => e.outcome === 'suppressed').length,
        truncated,
        dataReached,
        completeFourLayerPath,
        preset: estate.preset,
        intentionalPathNote: estate.intentionalPathNote || null
      }
    };
  }

  function shuffleWithRng(arr, rng) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }

  const SCENARIO_TEMPLATES = {
    'default-walkthrough': {
      id: 'default-walkthrough',
      title: 'Authored Multi-Layer Enterprise Walkthrough',
      archetypeId: 'public-web',
      generationMode: 'authored_walkthrough',
      requireCompletePathProbability: 0.85
    },
    'walkthrough-enterprise-identity': {
      id: 'walkthrough-enterprise-identity',
      title: 'Authored Enterprise Identity & Endpoints Walkthrough',
      archetypeId: 'enterprise-identity',
      generationMode: 'authored_walkthrough',
      preferredIngress: 'forti-vpn',
      requireCompletePathProbability: 1.0
    },
    'walkthrough-public-web': {
      id: 'walkthrough-public-web',
      title: 'Authored Public Web & Internal Data Walkthrough',
      archetypeId: 'public-web',
      generationMode: 'authored_walkthrough',
      preferredIngress: 'f5-gateway',
      requireCompletePathProbability: 1.0
    },
    'walkthrough-cloud-saas': {
      id: 'walkthrough-cloud-saas',
      title: 'Authored Cloud & SaaS Identity Walkthrough',
      archetypeId: 'cloud-saas',
      generationMode: 'authored_walkthrough',
      preferredIngress: 'ivanti-connect',
      requireCompletePathProbability: 1.0
    },
    'walkthrough-cicd-secrets': {
      id: 'walkthrough-cicd-secrets',
      title: 'Authored CI/CD & Operational Secrets Walkthrough',
      archetypeId: 'cicd-secrets',
      generationMode: 'authored_walkthrough',
      preferredIngress: 'f5-gateway',
      requireCompletePathProbability: 1.0
    }
  };

  function validateWalkthrough(estate, routeAssetIds = null) {
    const chainIds = routeAssetIds || estate.walkthroughRouteAssetIds || [];
    if (!Array.isArray(chainIds) || chainIds.length === 0) {
      return { valid: false, errors: ['Authored walkthrough has no declared routeAssetIds'] };
    }
    const assetById = new Map((estate.assets || []).map(a => [a.id, a]));
    const rels = estate.routes || estate.relationships || [];
    const state = {
      reachedAssets: new Map(),
      acquiredCredentials: new Map((estate.credentials || []).filter(c => c.startingAccess).map(c => [c.id, c])),
      revokedCredentials: new Set()
    };
    const errors = [];
    for (let i = 0; i < chainIds.length; i++) {
      const target = assetById.get(chainIds[i]);
      const source = i === 0 ? null : assetById.get(chainIds[i - 1]);
      if (!target) {
        errors.push(`Walkthrough stage ${i} references missing asset ${chainIds[i]}`);
        break;
      }
      const rel = i === 0 ? null : rels.find(r => r.sourceId === source?.id && r.targetId === target.id);
      const actions = evaluateDistinctActions(state, source, target, rel, estate);
      const eligible = actions.filter(a => a.eligible);
      if (eligible.length === 0) {
        errors.push(`Unsatisfied walkthrough condition at stage ${i} (${target.id}): ${actions[0]?.reason || 'No eligible action'}`);
        break;
      }
      const chosen = eligible[0];
      const caps = new Set([chosen.yieldsCapability]);
      state.reachedAssets.set(target.id, { layerIdx: target.layerIdx, sourceId: source?.id || null, capabilities: caps });
      for (const cred of estate.credentials || []) {
        if (cred.sourceAssetId === target.id && !cred.revoked && caps.has(cred.requiredSourceCapability)) {
          state.acquiredCredentials.set(cred.id, cred);
        }
      }
    }
    return { valid: errors.length === 0, errors };
  }

  /**
   * Instantiates an authored walkthrough scenario on an estate using real prerequisite-checked
   * weaknesses and scoped credentials, and validates the intended route through the ordinary
   * evaluator (Spec Section 7.2, WP2 Exit Gate, Fixture F01).
   */
  function instantiateScenario(templateOrId, estateContext, options = {}) {
    const template = typeof templateOrId === 'string'
      ? (SCENARIO_TEMPLATES[templateOrId] || SCENARIO_TEMPLATES['default-walkthrough'])
      : (templateOrId || SCENARIO_TEMPLATES['default-walkthrough']);
    const assets = estateContext.assets;
    const relationships = estateContext.routes || estateContext.relationships;
    const findings = estateContext.weaknesses || estateContext.findings;
    const credentials = estateContext.credentials;
    const rng = options.rng || createRng(estateContext.estateSeed ?? estateContext.seed ?? 1);
    const preferredIngress = options.preferredIngress ?? template.preferredIngress;

    const addCve = options.addCveFindingForAsset || ((asset) => {
      const info = getTargetDef(asset.groupId);
      const reviewed = REVIEWED_EXAMPLES[asset.groupId];
      if (!reviewed) return false;
      const cveId = info?.def.kevByVariant ? info.def.kevByVariant[asset.variantIdx ?? 0] : reviewed.cve;
      if (!cveId || cveId !== reviewed.cve) return false;
      const kev = findKev(asset.layerIdx, cveId);
      if (!kev) return false;
      asset.assumedVersion = reviewed.version;
      asset.conditions = { ...asset.conditions, ...reviewed.conditions };
      findings.push({
        id: `finding-${asset.id}-${cveId}`,
        assetId: asset.id,
        kind: 'cve',
        cveId,
        inKev: !!kev.inKev,
        provenance: 'authored_fixture',
        provenanceType: 'authored_fixture',
        requiredProduct: reviewed.product,
        affectedVersions: [reviewed.version],
        requiredConditions: { ...reviewed.conditions },
        sourceUrl: reviewed.source,
        sourceReviewed: '2026-11-16',
        requiredInterface: kev.reqInterface || asset.interfaces[0],
        requiresAuth: !!kev.requiresAuth,
        technique: kev.tech || 'T1190',
        title: kev.title,
        description: CVE_ATTACK_DESCRIPTIONS[cveId] || kev.title,
        yieldsCapability: kev.yields || (asset.layerIdx === 3 ? 'data_read' : 'app_exec')
      });
      return true;
    });

    const assignCred = options.assignCredentialOnSource || ((srcAsset, targetAsset, scope = 'read', requiredSourceCapability = 'app_exec') => {
      const credId = `cred-${srcAsset.id}-to-${targetAsset.id}`;
      if (credentials.some(c => c.id === credId)) return;
      const permissions = scope === 'read' ? ['read'] : scope === 'authenticate' ? ['authenticate'] : [scope];
      credentials.push({
        id: credId,
        kind: targetAsset.layerIdx === 3 ? 'db_credential' : 'service_account',
        label: `${scope} credential for ${targetAsset.groupId}`,
        scope,
        permissions,
        targetGroupIds: [],
        targetAssetIds: [targetAsset.id],
        audience: targetAsset.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: srcAsset.id,
        requiredSourceCapability
      });
    });

    const priority = seedVerifiedPath(assets, relationships, preferredIngress, rng, findings, credentials, addCve, assignCred);
    if (Array.isArray(estateContext.actionOrder) && priority.length) {
      estateContext.actionOrder.splice(0, estateContext.actionOrder.length, ...priority, ...estateContext.actionOrder.filter(id => !priority.includes(id)));
    }
    estateContext.generationMode = 'authored_walkthrough';
    estateContext.scenarioId = template.id;
    estateContext.walkthroughRouteAssetIds = priority;

    if (options.validateImmediately !== false && priority.length > 0) {
      const activeStages = priority.filter((id, idx) => idx < 3 || findings.some(f => f.assetId === id) || credentials.some(c => c.targetAssetIds?.includes(id)));
      const check = validateWalkthrough(estateContext, activeStages);
      if (!check.valid) {
        throw new Error(`Invalid authored walkthrough (${template.id}): ${check.errors.join('; ')}`);
      }
    }
    return priority;
  }

  function seedVerifiedPath(assets, relationships, preferredIngress, rng, findings, credentials, addCveFindingForAsset, assignCredentialOnSource) {
    const byId = new Map(assets.map(asset => [asset.id, asset]));
    const bySource = new Map();
    for (const link of relationships) {
      if (!bySource.has(link.sourceId)) bySource.set(link.sourceId, []);
      bySource.get(link.sourceId).push(link);
    }

    function findRoute(asset, incoming = null) {
      const stage = { asset, link: incoming };
      if (asset.layerIdx === 3) return [stage];
      for (const link of shuffleWithRng(bySource.get(asset.id) || [], rng)) {
        const next = byId.get(link.targetId);
        if (next.layerIdx !== asset.layerIdx + 1) continue;
        const tail = findRoute(next, link);
        if (tail) return [stage, ...tail];
      }
      return null;
    }

    const startingPoints = shuffleWithRng(assets.filter(asset => asset.isExternalEntry && asset.groupId !== 'support-diagnostics'), rng);
    startingPoints.sort((a, b) => Number(b.groupId === preferredIngress) - Number(a.groupId === preferredIngress));
    let route;
    for (const start of startingPoints) {
      route = findRoute(start);
      if (route) break;
    }
    if (!route) return [];

    const [s0, s1, s2, s3] = route;
    const fromLogs = rng() < 0.25;
    let cap0 = 'app_exec';

    if (fromLogs) {
      if (!findings.some(f => f.assetId === s0.asset.id)) {
        findings.push({
          id: `finding-${s0.asset.id}-logs`,
          assetId: s0.asset.id,
          kind: 'anonymous_access',
          inKev: false,
          provenance: 'synthetic_assumption',
          technique: 'T1552.001',
          title: 'Credential exposed in sample logs',
          description: 'Exposed diagnostics/application logs contain a service token.',
          yieldsCapability: 'file_read'
        });
      }
      cap0 = findings.find(f => f.assetId === s0.asset.id)?.yieldsCapability || 'file_read';
      s1.link.requiredSourceCapability = cap0;
      credentials.push({
        id: `cred-path-${s0.asset.id}-to-${s1.asset.id}`,
        kind: 'api_token',
        label: `Token from ${s0.asset.label}`,
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [s1.asset.id],
        audience: s1.asset.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: s0.asset.id,
        requiredSourceCapability: cap0
      });
    } else {
      if (!findings.some(f => f.assetId === s0.asset.id)) {
        if (!addCveFindingForAsset(s0.asset)) {
          findings.push({
            id: `finding-${s0.asset.id}-edge`,
            assetId: s0.asset.id,
            kind: 'anonymous_access',
            inKev: false,
            provenance: 'synthetic_assumption',
            technique: 'T1190',
            title: 'Exposed edge service',
            description: 'External interface permits unauthenticated access.',
            yieldsCapability: 'app_exec'
          });
        }
      }
      cap0 = findings.find(f => f.assetId === s0.asset.id)?.yieldsCapability || 'app_exec';
      s1.link.requiredSourceCapability = cap0;
      if (cap0 === 'file_read' && !credentials.some(c => c.sourceAssetId === s0.asset.id && c.targetAssetIds?.includes(s1.asset.id))) {
        credentials.push({
          id: `cred-path-${s0.asset.id}-to-${s1.asset.id}`,
          kind: 'api_token',
          label: `Token disclosed via ${s0.asset.label}`,
          scope: 'authenticate',
          permissions: ['authenticate'],
          targetGroupIds: [],
          targetAssetIds: [s1.asset.id],
          audience: s1.asset.id,
          revoked: false,
          expired: false,
          mfaRequired: false,
          sourceAssetId: s0.asset.id,
          requiredSourceCapability: 'file_read'
        });
      }
    }

    // Layer 1
    let cap1 = 'account_session';
    if (cap0 === 'app_exec' && !fromLogs) {
      if (!findings.some(f => f.assetId === s1.asset.id)) {
        addCveFindingForAsset(s1.asset);
      }
      const f1 = findings.find(f => f.assetId === s1.asset.id);
      if (f1 && (!f1.requiredInterface || f1.requiredInterface === s1.link.protocol)) {
        cap1 = f1.yieldsCapability || 'app_exec';
      } else {
        assignCredentialOnSource(s0.asset, s1.asset, 'authenticate', cap0);
        cap1 = 'account_session';
      }
    } else {
      cap1 = 'account_session';
    }
    s2.link.requiredSourceCapability = cap1;

    // Layer 2
    let cap2 = 'app_exec';
    if (!findings.some(f => f.assetId === s2.asset.id)) {
      addCveFindingForAsset(s2.asset);
    }
    const f2 = findings.find(f => f.assetId === s2.asset.id);
    if (f2 && (!f2.requiredInterface || f2.requiredInterface === s2.link.protocol)) {
      cap2 = f2.yieldsCapability || 'app_exec';
    } else {
      assignCredentialOnSource(s1.asset, s2.asset, 'authenticate', cap1);
      cap2 = 'account_session';
    }
    s3.link.requiredSourceCapability = cap2;

    // Layer 3 (85% complete path to protected data, 15% stop at Layer 2)
    if (rng() < 0.85) {
      if (!findings.some(f => f.assetId === s3.asset.id) && !addCveFindingForAsset(s3.asset)) {
        assignCredentialOnSource(s2.asset, s3.asset, 'read', cap2);
      } else if (!findings.some(f => f.assetId === s3.asset.id && (!f.requiredInterface || f.requiredInterface === s3.link.protocol))) {
        assignCredentialOnSource(s2.asset, s3.asset, 'read', cap2);
      }
    }

    return route.map(stage => stage.asset.id);
  }

  // A seeded Windows estate branch shared by both attackers. These are deployment
  // assumptions, not incident frequencies. No actor switch adds a vulnerability.
  function addWindowsEstate(seed, assets, relationships, findings, credentials, actionOrder) {
    const chance = (name, threshold) => hashNode(seed, `windows:${name}`, 0x73a916b) < threshold;
    const addAsset = (id, label, layerIdx, interfaces, conditions, y) => {
      const asset = { id, groupId: id, label, layerIdx, interfaces, conditions,
        product: layerIdx === 0 ? 'Windows 11 Enterprise' : 'Windows Server 2022', assumedVersion: 'modeled',
        trustZone: layerIdx === 0 ? 'user-endpoints' : TRUST_ZONES[layerIdx],
        auth: 'domain-account', isExternalEntry: layerIdx === 0,
        icon: layerIdx === 0 ? 'endpoint.png' : 'server-infrastructure.png',
        clusterName: layerIdx === 0 ? 'Workforce & Remote Access' : 'Windows Enterprise',
        variantIdx: 0, x: [0.18,0.4,0.64,0.87][layerIdx], y };
      assets.push(asset); actionOrder.push(id); return asset;
    };
    // This authored attack surface explicitly includes successful user execution.
    // Keep evaluator gates for protected/custom estates; do not randomly close it.
    const desktop = addAsset('windows-desktop', 'Windows Desktop · Phishable User', 0, ['email'], {
      userOpensAttachment: true,
      attachmentExecutionAllowed: true,
      mailFilterBlocksAttachment: false
    }, .84);
    const remote = addAsset('windows-rdp', 'Windows Remote Desktop · Internet Login', 0, ['rdp'], {
      remoteLoginEnabled: chance('remote-login', .9), mfaEnforced: chance('remote-mfa', .4)
    }, .94);
    const admin = addAsset('windows-management', 'Windows Management Server', 1, ['smb','wmi','rdp'], {
      remoteLoginEnabled: true, mfaEnforced: false
    }, .79);
    const fileServer = addAsset('windows-file-server', 'Windows File Server', 2, ['smb','wmi','rdp'], {
      remoteLoginEnabled: true, mfaEnforced: false
    }, .79);
    const records = addAsset('windows-records', 'Confidential Department Share', 3, ['smb'], {}, .79);
    desktop.localUserPermissions = ['write_local_files', ...(chance('desktop-startup-permission', .6) ? ['persist_user'] : [])];
    desktop.conditions.localFilesWritable = true;
    desktop.conditions.startupChangesAllowed = chance('desktop-startup-config', .7);
    for (const host of [remote, admin, fileServer]) host.accessModel = 'windows_remote_service';
    const reference = 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a';
    const base = { provenance: 'synthetic_deployment_assumption', inKev: false,
      sourceUrl: reference, sourceReviewed: '2026-11-20' };
    findings.push({ ...base, id: 'finding-windows-phishing', assetId: desktop.id,
      kind: 'phishing_attachment', technique: 'T1566.001', requiresUserInteraction: true,
      title: 'Phishing attachment · user execution required',
      description: 'Employee opens a delivered malicious attachment and permits execution on their Windows desktop.',
      yieldsCapability: 'app_exec' });
    const remoteFinding = (asset, id, technique, requiredInterface, permission, capability) => {
      findings.push({ ...base, id, assetId: asset.id, kind: 'remote_service', technique,
        requiredInterface, requiredPermission: permission, yieldsCapability: capability,
        title: `${technique} · ${technique === 'T1021.001' ? 'Internal RDP lateral access' : `${requiredInterface.toUpperCase()} authorized access`}`,
        description: `${requiredInterface.toUpperCase()} access to ${asset.label} requires an acquired, unrevoked credential with ${permission} permission.` });
    };
    remoteFinding(remote, 'finding-windows-rdp', 'T1133', 'rdp', 'authenticate', 'account_session');
    for (const host of [admin, fileServer]) {
      remoteFinding(host, `finding-${host.id}-smb`, 'T1021.002', 'smb', 'execute', 'app_exec');
      remoteFinding(host, `finding-${host.id}-wmi`, 'T1047', 'wmi', 'execute', 'app_exec');
      remoteFinding(host, `finding-${host.id}-rdp`, 'T1021.001', 'rdp', 'execute', 'app_exec');
    }
    const credential = (source, target, capability, permissions, startingAccess = false) => {
      credentials.push({ id: `cred-${source.id}-${target.id}`, kind: 'domain_account',
        label: `Scoped Windows account for ${target.label}`,
        scope: permissions[0], permissions, sourceAssetId: source.id,
        requiredSourceCapability: capability, targetAssetIds: [target.id], targetGroupIds: [],
        audience: target.id, revoked: false, expired: false,
        mfaRequired: false, startingAccess });
    };
    // A broker-supplied credential exists only on seeds that explicitly model one.
    if (chance('stolen-remote-account', .65)) credential(remote, remote, 'account_session', ['authenticate'], true);
    if (chance('desktop-admin-credential', .7)) credential(desktop, admin, 'app_exec', ['authenticate','execute','service_execute']);
    if (chance('remote-admin-credential', .65)) credential(remote, admin, 'account_session', ['authenticate','execute','service_execute']);
    if (chance('admin-files-credential', .8)) credential(admin, fileServer, 'app_exec', ['authenticate','execute','service_execute']);
    if (chance('share-read-credential', .8)) credential(fileServer, records, 'app_exec', ['read']);
    const connect = (source, target, protocol, capability) => relationships.push({
      id: `rel-${source.id}-${target.id}-${protocol}`, sourceId: source.id, targetId: target.id,
      protocol, direction: 'outbound', requiredSourceCapability: capability,
      trustBoundary: inferTrustBoundary(source.layerIdx, target.layerIdx),
      purpose: `Assumed permitted ${protocol.toUpperCase()} route; credentials and permissions checked separately` });
    for (const [source, cap] of [[desktop,'app_exec'],[remote,'account_session']]) {
      if (chance(`${source.id}-management-route`, .85)) {
        connect(source, admin, 'smb', cap); connect(source, admin, 'wmi', cap);
        connect(source, admin, 'rdp', cap);
      }
    }
    if (chance('management-files-route', .85)) {
      connect(admin, fileServer, 'smb', 'app_exec'); connect(admin, fileServer, 'wmi', 'app_exec');
      connect(admin, fileServer, 'rdp', 'app_exec');
    }
    connect(fileServer, records, 'smb', 'app_exec');

    const addLocalFindings = asset => {
      findings.push({ ...base, id:`finding-${asset.id}-persistence`, assetId:asset.id,
        kind:'persistence', technique:'T1547.001', title:'Registry startup persistence',
        modeledDurationSec:120, description:'Startup entry established only on executed endpoints with explicit startup-write permission.' });
      findings.push({ ...base, id:`finding-${asset.id}-encryption`, assetId:asset.id,
        kind:'encryption', technique:'T1486', title:'Endpoint file encryption',
        modeledDurationSec:300, description:'Encryption affects only locally writable files on endpoints covered by the acquired execution credential.' });
    };
    addLocalFindings(desktop);
    const fleetRoles = ['Finance','Operations','Engineering'].slice(0, 2 + Number(chance('third-fleet', .5)));
    const fleets = fleetRoles.map((department,index) => {
      const id = `windows-fleet-${department.toLowerCase()}`;
      const count = 12 + Math.floor(hashNode(seed, `${id}:size`, 0x98a31) * 69);
      const fleet = addAsset(id, `${department} Desktop Fleet · ${count} endpoints`, 2, ['smb','wmi','rdp'], {
        remoteLoginEnabled:chance(`${id}-login`, .9), mfaProtocols:chance(`${id}-mfa`, .25) ? ['rdp'] : [],
        localFilesWritable:chance(`${id}-writable`, .85), startupChangesAllowed:chance(`${id}-startup`, .65)
      }, .18 + index * .2);
      fleet.product='Windows 11 Enterprise';fleet.icon='endpoint.png';fleet.accessModel='windows_remote_service';
      fleet.endpointIds=Array.from({length:count},(_,i)=>`${id}-${String(i+1).padStart(3,'0')}`);
      fleet.endpointCount=count;fleet.department=department;
      for (const [protocol,technique] of [['smb','T1021.002'],['wmi','T1047'],['rdp','T1021.001']]) {
        remoteFinding(fleet,`finding-${id}-${protocol}`,technique,protocol,'execute','app_exec');
        connect(admin,fleet,protocol,'app_exec');
      }
      addLocalFindings(fleet);
      return fleet;
    });
    const roles = {
      department_user: ['authenticate','read'],
      helpdesk: ['authenticate','execute'],
      local_admin: ['authenticate','execute','service_execute','write_local_files','persist_user'],
      deployment_service: ['authenticate','execute','service_execute','write_local_files'],
      domain_admin: ['authenticate','execute','service_execute','write_local_files','persist_user']
    };
    const variedCredential = (source,target,role,capability,salt) => {
      const endpointScope = target.endpointIds?.filter(id => chance(`${salt}:${id}`, role === 'domain_admin' ? .9 : role === 'local_admin' ? .25 : .6));
      const status = hashNode(seed, `${salt}:status`, 0x62cd1);
      const sourceEndpointIds = source.endpointIds
        ? [source.endpointIds[Math.floor(hashNode(seed,`${source.id}:${salt}:location`,0x62cd1)*source.endpointIds.length)]] : null;
      credentials.push({ id:`cred-${source.id}-${target.id}-${salt}`, kind:role,
        label:`${role.replaceAll('_',' ')} credential for ${target.label}`,
        provenance:'synthetic_deployment_assumption', scope:role, permissions:[...roles[role]],
        sourceAssetId:source.id, requiredSourceCapability:capability, targetAssetIds:[target.id],
        targetGroupIds:[], audience:target.id, revoked:status < .1, expired:status >= .1 && status < .2,
        mfaRequired:false, ...(endpointScope && {endpointScope}),
        ...(sourceEndpointIds && {sourceEndpointIds}) });
    };
    const roleNames=Object.keys(roles);
    for (const fleet of fleets) {
      const role=roleNames[Math.floor(hashNode(seed,`${fleet.id}:role`,0x15a7)*roleNames.length)];
      variedCredential(admin,fleet,role,'app_exec','fleet-management');
      // Endpoint users can access their actual enterprise application, with a
      // separately stored, scoped account. A fleet does not imply DB access.
      const applications=assets.filter(a=>a.groupId==='app-engine'&&a.interfaces.includes('https'));
      const application=applications[Math.floor(hashNode(seed,`${fleet.id}:app`,0x15a7)*applications.length)];
      if(application) {
        connect(fleet,application,'https','app_exec');
        variedCredential(fleet,application,'department_user','app_exec','business-app');
      }
    }
    // Bridge the Windows management plane to existing identity, application and
    // secret-storage assets. Network permission and credential possession remain separate.
    const bridges=assets.filter(a=>['ad-identity','exchange','vault-creds','app-engine','cust-api'].includes(a.groupId));
    for(const source of bridges) {
      if(!chance(`${source.id}:windows-bridge`,.35))continue;
      for(const protocol of ['smb','wmi','rdp'])connect(source,admin,protocol,'app_exec');
      const role=roleNames[Math.floor(hashNode(seed,`${source.id}:bridge-role`,0x15a7)*roleNames.length)];
      variedCredential(source,admin,role,'app_exec','enterprise-bridge');
    }
    const identity=assets.find(a=>a.groupId==='ad-identity'&&a.interfaces.includes('ad-rpc'));
    if(identity) {
      connect(admin,identity,'ad-rpc','app_exec');
      variedCredential(admin,identity,'helpdesk','app_exec','directory-account');
    }
    // Authored remote-tool opportunities use the existing routes and credential evaluator.
    // Tool availability is an explicit profile assumption; no actual Beacon is installed.
    for(const host of [admin,fileServer,...fleets])for(const method of LATERAL_TOOL_METHODS
    )findings.push({...base,id:`finding-${host.id}-${method.tool==='cobalt_strike'?'cobalt':method.tool}-${method.protocol}`,assetId:host.id,
      kind:'remote_service',tool:method.tool,technique:method.technique,
      requiredInterface:method.protocol,requiredPermission:method.permission,
      requiredSourceCapability:'app_exec',yieldsCapability:'app_exec',
      title:method.label,
      sourceUrl:method.source,
      description:`Modeled ${method.label} requires source execution, configured tool availability and a scoped ${method.permission} credential over the actual ${method.protocol.toUpperCase()} route.`});
  }

  /**
   * Generates a versioned Schema v4 estate.
   * Supports 4 coherent archetypes (`enterprise-identity`, `public-web`, `cloud-saas`, `cicd-secrets`),
   * `generationMode` (`'exploratory' | 'authored_walkthrough'`), and legacy preset options.
   */
  function generateEstate(options = {}) {
    const rawSeed = Number.isInteger(options.estateSeed) ? options.estateSeed : options.seed;
    const seed = Number.isInteger(rawSeed) ? (rawSeed >>> 0) : Math.floor(Math.random() * 4294967296);
    const fullEnterprise = options.archetypeId === 'full-enterprise';
    const preset = fullEnterprise ? 'mixed' : options.preset === 'demo'
      ? 'demo'
      : (options.preset === 'logs' || options.preset === 'credential-in-logs')
        ? 'logs'
        : 'mixed';
    const archetypeId = INFRASTRUCTURE_ARCHETYPES[options.archetypeId]
      ? options.archetypeId
      : preset === 'logs'
        ? 'cloud-saas'
        : 'public-web';
    const archetype = INFRASTRUCTURE_ARCHETYPES[archetypeId];
    const isAuthoredWalkthrough = options.generationMode === 'authored_walkthrough' ||
      (options.generationMode !== 'exploratory' && (preset === 'demo' || preset === 'logs' || !!options.scenarioId || !!options.seedExercise));
    const generationMode = isAuthoredWalkthrough ? 'authored_walkthrough' : 'exploratory';
    const rng = createRng(seed);
    const rand = (min, max) => rng() * (max - min) + min;
    const randInt = (min, max) => Math.floor(rand(min, max + 1));
    const edgePool = Object.keys(EDGE_APPLIANCES);
    const applianceCount = randInt(5, 7);
    const preferredIngress = fullEnterprise ? archetype.preferredIngressGroups[0]
      : options.preferredIngress || (options.archetypeId ? archetype.preferredIngressGroups.find(g => edgePool.includes(g)) : undefined);
    const pinned = fullEnterprise ? archetype.preferredIngressGroups : preset === 'demo' ? ['f5-gateway']
      : preset === 'mixed' && edgePool.includes(preferredIngress) ? [preferredIngress] : [];
    const selectedAppliances = new Set([
      ...pinned,
      ...shuffleWithRng(edgePool.filter(id => !pinned.includes(id)), rng).slice(0, applianceCount - pinned.length)
    ]);
    const ingressBudget = LAYER_FINDING_BUDGETS[0];
    const hasAdditionalOpening = preset === 'mixed' && randInt(ingressBudget.min, ingressBudget.max) === ingressBudget.max;
    const edgeMisconfig = hasAdditionalOpening
      ? EDGE_MISCONFIGURATIONS[randInt(0, EDGE_MISCONFIGURATIONS.length - 1)]
      : null;

    const assets = [];
    LAYER_CONFIG.forEach((layer, layerIdx) => {
      const numClusters = layer.clusters.length;
      layer.clusters.forEach((cluster, clusterIdx) => {
        const targets = cluster.targets.filter(target =>
          (!target.preset || target.preset === preset) &&
          (target.id !== 'external-misconfig' || edgeMisconfig) &&
          (!EDGE_APPLIANCES[target.id] || selectedAppliances.has(target.id)));
        const numTargets = targets.length;
        targets.forEach((targetDef, targetIdx) => {
          if (targetDef.includeChance != null && rng() >= targetDef.includeChance) return;
          const maxVariants = targetDef.variants.length;
          const instanceCount = maxVariants > 1 ? randInt(1, Math.min(targetDef.maxInstances ?? 3, maxVariants)) : 1;
          const variants = targetDef.productPool
            ? shuffleWithRng(Array.from({ length: maxVariants }, (_, idx) => idx), rng).slice(0, instanceCount)
            : Array.from({ length: instanceCount }, (_, idx) => idx);

          for (let slot = 0; slot < instanceCount; slot++) {
            const vIdx = variants[slot];
            const misconfig = targetDef.id === 'external-misconfig' ? edgeMisconfig : null;
            const label = misconfig?.asset || targetDef.variants[vIdx];
            const familyAngle = (targetIdx / numTargets) * Math.PI * 2 - Math.PI / 2 + rand(-0.08, 0.08);
            const clusterCenterX = (layer.xBand[0] + (layer.xBand[1] - layer.xBand[0]) * 0.5) + rand(-0.02, 0.02);
            const clusterCenterY = (clusterIdx + 0.5) / numClusters + rand(-0.025, 0.025);
            const ox = instanceCount === 2 ? (slot === 0 ? -0.015 : 0.015) : instanceCount === 3 ? Math.cos((slot / 3) * Math.PI * 2) * 0.018 : 0;
            const oy = instanceCount === 2 ? (slot === 0 ? -0.02 : 0.02) : instanceCount === 3 ? Math.sin((slot / 3) * Math.PI * 2) * 0.022 : 0;
            const x = Math.max(0.04, Math.min(0.95, clusterCenterX + Math.cos(familyAngle) * 0.045 + ox));
            const y = Math.max(0.05, Math.min(0.95, clusterCenterY + Math.sin(familyAngle) * 0.065 + oy));
            const reviewed = REVIEWED_EXAMPLES[targetDef.id];
            const appliance = EDGE_APPLIANCES[targetDef.id];

            assets.push({
              id: `${targetDef.id}-${vIdx + 1}`,
              groupId: targetDef.id,
              label,
              product: reviewed?.product || label,
              assumedVersion: appliance ? null : reviewed?.version || null,
              conditions: appliance ? {} : { ...reviewed?.conditions },
              ...(appliance && { referenceCve: appliance.cve }),
              layerIdx,
              trustZone: TRUST_ZONES[layerIdx],
              interfaces: [...(misconfig?.interfaces || targetDef.interfaces || ['https'])],
              auth: targetDef.publicExposure || (misconfig && !misconfig.assumedAccount) ? 'none' : 'token',
              isExternalEntry: EXTERNAL_ENTRY_GROUPS.has(targetDef.id),
              isSecurity: !!targetDef.isSecurity,
              isLake: !!targetDef.isLake,
              isDb: !!targetDef.isDb,
              icon: misconfig?.icon || targetDef.icon,
              clusterName: cluster.name,
              variantIdx: vIdx,
              x,
              y
            });
          }
        });
      });
    });

    // Wire directed relationships using ALLOWED_CONNECTIONS
    const relationships = [];
    const relKeys = new Set();
    const addRel = (src, tgt) => {
      const key = `${src.id}->${tgt.id}`;
      if (relKeys.has(key)) return;
      relKeys.add(key);
      relationships.push({
        id: `rel-${src.id}->${tgt.id}`,
        sourceId: src.id,
        targetId: tgt.id,
        protocol: inferConnectionProtocol(src, tgt),
        direction: 'outbound',
        requiredSourceCapability: src.groupId === 'public-gitlab' ? 'code_read' : 'app_exec',
        trustBoundary: inferTrustBoundary(src.layerIdx, tgt.layerIdx),
        purpose: `${src.groupId} to ${tgt.groupId} service flow`
      });
    };

    assets.forEach(source => {
      (ALLOWED_CONNECTIONS[source.groupId] || []).forEach(targetGroup => {
        const candidates = assets.filter(n => n.groupId === targetGroup && n.layerIdx === source.layerIdx + 1);
        if (!candidates.length) return;
        const target = candidates.reduce((a, b) => Math.abs(a.y - source.y) < Math.abs(b.y - source.y) ? a : b);
        addRel(source, target);
      });
    });

    assets.forEach(target => {
      if (relationships.some(r => r.targetId === target.id)) return;
      const candidates = assets.filter(n => n.layerIdx === target.layerIdx - 1 &&
        (ALLOWED_CONNECTIONS[n.groupId] || []).includes(target.groupId));
      if (!candidates.length) return;
      const source = candidates.reduce((a, b) => Math.abs(a.y - target.y) < Math.abs(b.y - target.y) ? a : b);
      addRel(source, target);
    });

    const diagnostics = assets.find(a => a.groupId === 'support-diagnostics');
    const statusApi = assets.find(a => a.groupId === 'staging-status');
    if (diagnostics) {
      const statusRoute = relationships.find(r => r.sourceId === diagnostics.id);
      statusRoute.requiredSourceCapability = 'diagnostic_read';
      statusRoute.purpose = 'Staging status access with a viewer credential';
    }

    if (preset === 'demo') {
      const edge = assets.find(a => a.groupId === 'f5-gateway');
      const gateway = assets.find(a => a.groupId === 'cust-api');
      const app = assets.find(a => a.groupId === 'app-engine');
      const postgres = assets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (edge && gateway) addRel(edge, gateway);
      if (gateway && app) addRel(gateway, app);
      if (app && postgres) addRel(app, postgres);
    } else if (preset === 'logs') {
      const logBucket = assets.find(a => a.groupId === 'public-s3');
      const gateway = assets.find(a => a.groupId === 'cust-api');
      const siblingGw = assets.find(a => a.groupId === 'cust-api' && a.id !== gateway?.id);
      const app = assets.find(a => a.groupId === 'app-engine');
      const postgres = assets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (logBucket && gateway) {
        addRel(logBucket, gateway);
        const rel01 = relationships.find(r => r.sourceId === logBucket.id && r.targetId === gateway.id);
        if (rel01) {
          rel01.protocol = 'https';
          rel01.requiredSourceCapability = 'file_read';
          rel01.purpose = 'Internet access to API gateway using service token recovered from exposed application logs';
        }
      }
      if (logBucket && siblingGw) {
        addRel(logBucket, siblingGw);
        const relSib = relationships.find(r => r.sourceId === logBucket.id && r.targetId === siblingGw.id);
        if (relSib) {
          relSib.protocol = 'https';
          relSib.requiredSourceCapability = 'file_read';
          relSib.purpose = 'Attempted reuse of log-exposed token against sibling API gateway';
        }
      }
      if (gateway && app) {
        addRel(gateway, app);
        const rel12 = relationships.find(r => r.sourceId === gateway.id && r.targetId === app.id);
        if (rel12) {
          rel12.requiredSourceCapability = 'account_session';
          rel12.purpose = 'Authenticated API gateway session calling internal application service';
        }
      }
      if (app && postgres) {
        addRel(app, postgres);
        const rel23 = relationships.find(r => r.sourceId === app.id && r.targetId === postgres.id);
        if (rel23) {
          rel23.requiredSourceCapability = 'account_session';
          rel23.purpose = 'Application service connection to customer database using scoped read credential';
        }
      }
    }

    // Retain only externally reachable assets
    const reachable = new Set(assets.filter(a => a.isExternalEntry).map(a => a.id));
    for (let l = 0; l < 4; l++) {
      relationships.forEach(r => { if (reachable.has(r.sourceId)) reachable.add(r.targetId); });
    }
    const keptAssets = assets.filter(a => reachable.has(a.id));
    const keptRels = relationships.filter(r => reachable.has(r.sourceId) && reachable.has(r.targetId));

    const findings = [];
    const credentials = [];

    const addCveFindingForAsset = (asset) => {
      const info = getTargetDef(asset.groupId);
      const reviewed = REVIEWED_EXAMPLES[asset.groupId];
      if (!reviewed) return false;
      const cveId = info && info.def.kevByVariant ? info.def.kevByVariant[asset.variantIdx] : null;
      if (!cveId || cveId !== reviewed.cve) return false;
      const kev = findKev(asset.layerIdx, cveId);
      if (!kev) return false;
      if (asset.referenceCve) {
        asset.assumedVersion = reviewed.version;
        Object.assign(asset.conditions, reviewed.conditions);
      }
      findings.push({
        id: `finding-${asset.id}-${cveId}`,
        assetId: asset.id,
        kind: 'cve',
        cveId,
        inKev: !!kev.inKev,
        provenance: 'synthetic_deployment_assumption',
        requiredProduct: reviewed.product,
        affectedVersions: [reviewed.version],
        requiredConditions: { ...reviewed.conditions },
        sourceUrl: reviewed.source,
        sourceReviewed: '2026-11-15',
        requiredInterface: kev.reqInterface || asset.interfaces[0],
        requiresAuth: !!kev.requiresAuth,
        technique: kev.tech || 'T1190',
        title: kev.title,
        description: CVE_ATTACK_DESCRIPTIONS[cveId] || kev.title,
        yieldsCapability: kev.yields || (asset.layerIdx === 3 ? 'data_read' : 'app_exec')
      });
      return true;
    };

    const addPublicFindingForAsset = (asset) => {
      const info = getTargetDef(asset.groupId);
      if (!info || !info.def.publicExposure) return false;
      findings.push({
        id: `finding-${asset.id}-public`,
        assetId: asset.id,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        technique: info.def.attackTechnique || 'T1530',
        title: info.def.attackDescription || 'Anonymous public access',
        description: info.def.publicExposure,
        yieldsCapability: asset.groupId.includes('gitlab') || asset.groupId.includes('bitbucket') ? 'code_read' : 'data_read'
      });
      return true;
    };

    const assignCredentialOnSource = (srcAsset, targetAsset, scope = 'read', requiredSourceCapability = 'app_exec') => {
      const credId = `cred-${srcAsset.id}-to-${targetAsset.id}`;
      if (credentials.some(c => c.id === credId)) return;
      const permissions = scope === 'read' ? ['read'] : scope === 'authenticate' ? ['authenticate'] : [scope];
      credentials.push({
        id: credId,
        kind: targetAsset.layerIdx === 3 ? 'db_credential' : 'service_account',
        label: `${scope} credential for ${targetAsset.groupId}`,
        scope,
        permissions,
        targetGroupIds: [],
        targetAssetIds: [targetAsset.id],
        audience: targetAsset.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: srcAsset.id,
        requiredSourceCapability
      });
    };

    if (preset === 'demo') {
      // Intentionally construct one verified 4-layer path + an optional stopped branch
      const l0Candidates = keptAssets.filter(a => a.groupId === 'f5-gateway');
      let chosenChain = null;
      for (const a0 of l0Candidates) {
        const r01 = keptRels.filter(r => r.sourceId === a0.id);
        for (const rel1 of r01) {
          const a1 = keptAssets.find(a => a.id === rel1.targetId);
          if (!a1 || a1.groupId !== 'cust-api') continue;
          const r12 = keptRels.filter(r => r.sourceId === a1.id);
          for (const rel2 of r12) {
            const a2 = keptAssets.find(a => a.id === rel2.targetId);
            if (!a2 || a2.groupId !== 'app-engine') continue;
            const r23 = keptRels.filter(r => {
              const target = keptAssets.find(a => a.id === r.targetId);
              return r.sourceId === a2.id && target?.groupId === 'db-rds' && target.label.includes('Postgres');
            });
            if (r23.length) {
              const a3 = keptAssets.find(a => a.id === r23[0].targetId);
              if (a3) {
                chosenChain = [a0, a1, a2, a3];
                break;
              }
            }
          }
          if (chosenChain) break;
        }
        if (chosenChain) break;
      }

      if (!chosenChain) throw new Error('Unable to construct the reviewed demo topology.');
      if (chosenChain) {
        const [a0, a1, a2, a3] = chosenChain;
        if (!addCveFindingForAsset(a0)) addPublicFindingForAsset(a0);
        if (!addCveFindingForAsset(a1)) assignCredentialOnSource(a0, a1, 'exec');
        if (!addCveFindingForAsset(a2)) assignCredentialOnSource(a1, a2, 'exec');
        // Layer 3: either CVE or scoped credential from L2 (prefer credential to show realistic progression)
        assignCredentialOnSource(a2, a3, 'read');

        // Add one secondary branch that is blocked by MFA/healthy asset for contrast
        const sprayCandidate = keptAssets.find(a => a.layerIdx === 1 && a.id !== a1.id && getTargetDef(a.groupId)?.def.supportsSpray);
        if (sprayCandidate) {
          findings.push({
            id: `finding-${sprayCandidate.id}-spray-mfa`,
            assetId: sprayCandidate.id,
            kind: 'password_spray',
            inKev: false,
            provenance: 'synthetic_assumption',
            mfaProtected: true,
            syntheticAccountUsesSprayedPassword: true,
            rateLimited: false,
            technique: 'T1110.003',
            title: 'Password spray attempt (MFA enforced)',
            description: 'Spray attempt against account; blocked by MFA.',
            yieldsCapability: 'account_session'
          });
        }
      }
    } else if (preset === 'logs') {
      // Dedicated credential-in-logs scenario: readable application logs -> synthetic service token ->
      // authenticated service access (no CVE needed) -> scoped DB credential -> data read.
      const a0 = keptAssets.find(a => a.groupId === 'public-s3');
      const a1 = keptAssets.find(a => a.groupId === 'cust-api');
      const a2 = keptAssets.find(a => a.groupId === 'app-engine');
      const a3 = keptAssets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (!a0 || !a1 || !a2 || !a3) {
        throw new Error('Unable to construct the credential-in-logs topology.');
      }

      findings.push({
        id: `finding-${a0.id}-logs`,
        assetId: a0.id,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        technique: 'T1552.001',
        title: 'Readable application logs expose service token',
        description: 'Log bucket is publicly readable and contains an unrevoked service token.',
        yieldsCapability: 'file_read'
      });

      credentials.push({
        id: `cred-logs-${a0.id}-to-${a1.id}`,
        kind: 'api_token',
        label: 'Service token in application logs',
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [a1.id],
        audience: a1.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a0.id,
        requiredSourceCapability: 'file_read'
      });

      // Expired sibling token in logs for contrast (must not authorize sibling gateway)
      const siblingGw = keptAssets.find(a => a.groupId === 'cust-api' && a.id !== a1.id);
      if (siblingGw) {
        credentials.push({
          id: `cred-logs-${a0.id}-to-${siblingGw.id}-expired`,
          kind: 'api_token',
          label: 'Expired token in application logs',
          scope: 'authenticate',
          permissions: ['authenticate'],
          targetGroupIds: [],
          targetAssetIds: [siblingGw.id],
          audience: siblingGw.id,
          revoked: false,
          expired: true,
          mfaRequired: false,
          sourceAssetId: a0.id,
          requiredSourceCapability: 'file_read'
        });
      }

      credentials.push({
        id: `cred-logs-${a1.id}-to-${a2.id}`,
        kind: 'service_account',
        label: 'Downstream service credential on API gateway',
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [a2.id],
        audience: a2.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a1.id,
        requiredSourceCapability: 'account_session'
      });

      credentials.push({
        id: `cred-logs-${a2.id}-to-${a3.id}`,
        kind: 'db_credential',
        label: 'Read-only DB credential',
        scope: 'read',
        permissions: ['read'],
        targetGroupIds: [],
        targetAssetIds: [a3.id],
        audience: a3.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a2.id,
        requiredSourceCapability: 'account_session'
      });
    } else {
      const opening = MIXED_DIAGNOSTIC_OPENINGS[seed % MIXED_DIAGNOSTIC_OPENINGS.length];
      diagnostics.conditions[opening.requiredCondition] = true;
      findings.push({
        id: `finding-${diagnostics.id}`,
        assetId: diagnostics.id,
        kind: 'diagnostic_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        ...opening
      });
      credentials.push({
        id: 'mixed-diagnostics-viewer',
        kind: 'service_account',
        label: 'Diagnostics viewer',
        scope: 'read diagnostics',
        permissions: ['read_diagnostics'],
        targetAssetIds: [diagnostics.id],
        audience: diagnostics.id,
        sourceAssetId: diagnostics.id,
        startingAccess: true
      }, {
        id: 'mixed-staging-status',
        kind: 'api_token',
        label: 'Staging status credential',
        scope: 'staging status only',
        permissions: ['authenticate'],
        targetAssetIds: [statusApi.id],
        audience: statusApi.id,
        sourceAssetId: diagnostics.id,
        requiredSourceCapability: 'diagnostic_read'
      });

      const edgeAppliances = shuffleWithRng(keptAssets.filter(asset => asset.referenceCve), rng);
      addCveFindingForAsset(edgeAppliances[0]);
      if (edgeMisconfig) {
        const { id } = keptAssets.find(asset => asset.groupId === 'external-misconfig');
        const logToken = edgeMisconfig.illustration === 'git-to-idp';
        findings.push({
          id: `finding-${edgeMisconfig.id}`,
          assetId: id,
          kind: edgeMisconfig.assumedAccount ? 'assumed_edge_account' : 'anonymous_access',
          category: 'external_misconfiguration',
          title: edgeMisconfig.title,
          description: logToken
            ? 'The exposed logs contain a Git token.'
            : 'The scenario records access to the exposed edge service only.',
          ...(logToken && { illustration: edgeMisconfig.illustration }),
          historicalReference: edgeMisconfig.reference,
          sourceUrl: edgeMisconfig.source,
          sourceReviewed: '2026-11-15',
          provenance: 'synthetic_assumption',
          technique: logToken ? 'T1552.001' : edgeMisconfig.assumedAccount ? 'T1078' : null,
          yieldsCapability: logToken ? 'file_read' : 'edge_access'
        });
        if (edgeMisconfig.assumedAccount) {
          credentials.push({
            id: 'mixed-external-example',
            kind: 'account',
            label: 'Edge-only account',
            scope: 'authenticate to this edge service',
            permissions: ['authenticate'],
            targetAssetIds: [id],
            audience: id,
            sourceAssetId: id,
            startingAccess: true
          });
        }
      }

      for (let layerIdx = 1; layerIdx < 4; layerIdx++) {
        const budget = LAYER_FINDING_BUDGETS[layerIdx];
        const targetCount = randInt(budget.min, budget.max);
        const candidates = shuffleWithRng(keptAssets.filter(a => a.layerIdx === layerIdx), rng);
        let assigned = 0;

        for (const asset of candidates) {
          if (assigned >= targetCount) break;
          const info = getTargetDef(asset.groupId);
          if (info?.def.publicExposure) {
            if (addPublicFindingForAsset(asset)) assigned++;
          } else if (layerIdx === 1 && info?.def.supportsSpray && rng() < 0.35) {
            findings.push({
              id: `finding-${asset.id}-spray`,
              assetId: asset.id,
              kind: 'password_spray',
              inKev: false,
              provenance: 'synthetic_assumption',
              mfaProtected: rng() < 0.5,
              syntheticAccountUsesSprayedPassword: true,
              rateLimited: false,
              technique: 'T1110.003',
              title: 'Password spray exposure check',
              description: 'Authentication endpoint evaluated for password spray.',
              yieldsCapability: 'account_session'
            });
            assigned++;
          } else if (addCveFindingForAsset(asset)) {
            assigned++;
          } else if (layerIdx === 3) {
            // Healthy data store may have a scoped credential stored on an upstream L2 service
            const incoming = keptRels.filter(r => r.targetId === asset.id);
            if (incoming.length > 0 && rng() < 0.5) {
              const src = keptAssets.find(a => a.id === incoming[0].sourceId);
              if (src) {
                assignCredentialOnSource(src, asset, 'read');
                assigned++;
              }
            }
          }
        }
      }
    }

    const actionOrder = shuffleWithRng(keptAssets.map(a => a.id), rng);
    if (diagnostics) {
      actionOrder.splice(actionOrder.indexOf(diagnostics.id), 1);
      actionOrder.unshift(diagnostics.id);
    }
    let walkthroughRouteAssetIds = [];
    if (preset === 'mixed' && isAuthoredWalkthrough) {
      const partialContext = {
        estateSeed: seed,
        seed,
        assets: keptAssets,
        relationships: keptRels,
        findings,
        credentials,
        actionOrder
      };
      const scenarioId = options.scenarioId || (options.archetypeId ? archetype.defaultWalkthroughId : 'default-walkthrough') || 'default-walkthrough';
      walkthroughRouteAssetIds = instantiateScenario(scenarioId, partialContext, {
        rng,
        preferredIngress,
        addCveFindingForAsset,
        assignCredentialOnSource,
        validateImmediately: false
      });
    }

    if (preset === 'mixed') {
      addWindowsEstate(seed, keptAssets, keptRels, findings, credentials, actionOrder);
    }

    // Estate-owned defensive visibility & decoy placement (invariant across attacker switches)
    // Independent, reproducible deployment assumptions; actor changes never redraw sensors or response.
    const telemetryLayers = preset === 'mixed'
      ? [0,1,2,3].filter(layer => hashNode(seed, `sensor-layer:${layer}`, 0x9e3779b9) < 0.8)
      : [0,1,2,3];
    const decoys = [];
    const decoyAnchor = (preset === 'demo' && keptAssets.find(a => a.layerIdx === 0 && a.groupId === 'f5-gateway')) ||
      keptAssets.find(a => a.layerIdx === 0 && a.isExternalEntry && findings.some(f => f.assetId === a.id && f.yieldsCapability)) ||
      keptAssets.find(a => a.layerIdx === 1 && a.groupId !== 'staging-status');
    if ((preset === 'mixed' || preset === 'demo') && decoyAnchor) {
      const decoyLayer = decoyAnchor.layerIdx + 1;
      const decoyId = 'canary-decoy-1';
      keptAssets.push({
        id: decoyId,
        groupId: decoyLayer === 3 ? 'lake-cust' : 'comp-registry',
        label: 'Canary Decoy Vault',
        product: 'Instrumented Decoy',
        assumedVersion: '1.0',
        conditions: {},
        layerIdx: decoyLayer,
        trustZone: TRUST_ZONES[decoyLayer],
        interfaces: ['api-https', 'https'],
        auth: 'token',
        isExternalEntry: false,
        isSecurity: true,
        isDecoy: true,
        icon: 'threat-detection.png',
        clusterName: 'Deception Decoys',
        variantIdx: 0,
        x: decoyLayer === 1 ? 0.34 : decoyLayer === 3 ? 0.84 : 0.62,
        y: 0.90
      });
      const anchorCap = findings.find(f => f.assetId === decoyAnchor.id)?.yieldsCapability || 'app_exec';
      const relCap = anchorCap === 'file_read' ? 'account_session' : anchorCap;
      keptRels.push({
        id: `rel-${decoyAnchor.id}->${decoyId}`,
        sourceId: decoyAnchor.id,
        targetId: decoyId,
        protocol: 'api-https',
        direction: 'outbound',
        requiredSourceCapability: relCap,
        trustBoundary: inferTrustBoundary(decoyAnchor.layerIdx, decoyLayer),
        purpose: 'Instrumented canary decoy endpoint'
      });
      findings.push({
        id: `finding-${decoyId}`,
        assetId: decoyId,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_decoy',
        technique: 'T1552',
        title: 'Canary decoy interaction',
        description: 'Instrumented decoy triggers high-confidence deception alert on access.',
        yieldsCapability: 'decoy_alert'
      });
      decoys.push({
        id: decoyId,
        kind: 'decoy_asset',
        assetId: decoyId,
        credentialId: null,
        placement: decoyLayer <= 2 ? 'early' : 'late'
      });
      actionOrder.unshift(decoyId);
    }

    // Estate-owned datasets and egress assumptions are shared across all actors.
    const datasets = [];
    for(const asset of keptAssets) {
      asset.role = asset.isDecoy ? 'decoy' : ['ingress', 'gateway_or_identity', 'service', 'datastore'][asset.layerIdx] || 'service';
      asset.lifecycle = { status: 'active', decommissioned: false, poc: false };
      if (asset.isDecoy) {
        datasets.push({
          id: `dataset-${asset.id}`,
          ownerAssetId: asset.id,
          label: `Decoy lure archive · ${asset.label}`,
          sensitivity: 'decoy',
          records: 0,
          bytes: 0,
          isDecoy: true,
          allowedOperations: ['read']
        });
        continue;
      }
      asset.egress={cloudUploadAllowed:hashNode(seed,`cloud-egress:${asset.id}`,0x531f)>0.2,
        responseExportAllowed:hashNode(seed,`response-egress:${asset.id}`,0x531f)>0.1};
      if(asset.layerIdx===3){
        const records=100+Math.floor(hashNode(seed,`records:${asset.id}`,0x531f)*4900);
        asset.dataHandling={label:`Sensitive records · ${asset.label}`,records,bytes:records*1024};
        asset.datasetSensitivity = 'sensitive';
        datasets.push({
          id: `dataset-${asset.id}`,
          ownerAssetId: asset.id,
          label: asset.dataHandling.label,
          sensitivity: 'sensitive',
          records,
          bytes: records * 1024,
          isDecoy: false,
          allowedOperations: ['read', 'export']
        });
      } else if (['public-s3', 'public-blob'].includes(asset.groupId)) {
        const isLogsObjective = preset === 'logs';
        asset.datasetSensitivity = isLogsObjective ? 'internal_non_sensitive' : 'public';
        datasets.push({
          id: `dataset-${asset.id}`,
          ownerAssetId: asset.id,
          label: isLogsObjective ? `Diagnostic build logs · ${asset.label}` : `Public storage objects · ${asset.label}`,
          sensitivity: asset.datasetSensitivity,
          records: 25,
          bytes: 25 * 1024,
          isDecoy: false,
          allowedOperations: ['read']
        });
      }
    }

    // Schema v4 enforcementPoints, patchRules, routes, sensors, identityRelationships, and responseIntegrations
    const wafAsset = keptAssets.find(a => a.groupId === 'waf-proxy') || keptAssets.find(a => a.layerIdx === 0 && a.interfaces.includes('https'));
    const portalIds = new Set(['forti-vpn', 'pulse-vpn', 'pan-globalprotect']);
    const nonHttpGroups = new Set(['aws-vpn', 'az-net', 'az-branch', 'partner-gw', 'zyxel-atp']);
    const wafCoveredAssetIds = new Set(
      keptAssets.filter(a => {
        const isHttp = a.interfaces.some(i => ['https', 'api-https', 'repo-http', 'storage-s3'].includes(i));
        if (nonHttpGroups.has(a.groupId) || !isHttp) return false;
        return !portalIds.has(a.groupId) || wafPortalCovered(a.id, seed);
      }).map(a => a.id)
    );
    const wafCoveredRouteIds = keptRels
      .filter(r => ['https', 'api-https', 'repo-http', 'storage-s3'].includes(r.protocol) && wafCoveredAssetIds.has(r.targetId))
      .map(r => r.id);

    const patchRules = Object.entries(KEV_MITIGATION_RULES)
      .filter(([, rule]) => rule.waf?.state === 'modeled' && rule.waf?.mitigates)
      .map(([cveId, rule]) => ({
        id: `patch-rule-${cveId}`,
        cveId,
        enforcementPointIds: ['ep-edge-waf'],
        inspectedProtocols: rule.waf.inspectedProtocols || ['https', 'api-https', 'repo-http', 'storage-s3'],
        inspectedFields: ['uri', 'headers', 'query', 'body'],
        ruleStrictness: rule.waf.ruleStrictness || 'strict_virtual_patch',
        coverageState: rule.waf.state,
        action: 'block',
        control: rule.waf.control || 'NIST SI-2 / SC-7',
        reason: rule.waf.reason
      }));

    const enforcementPoints = [
      {
        id: 'ep-edge-waf',
        assetId: wafAsset ? wafAsset.id : null,
        routeIds: wafCoveredRouteIds,
        inspectedProtocols: ['https', 'api-https', 'repo-http', 'storage-s3'],
        inspectedFields: ['uri', 'headers', 'query', 'body'],
        ruleIds: patchRules.map(pr => pr.id),
        enabled: true
      }
    ];

    for (const rel of keptRels) {
      rel.accessibleInterface = rel.protocol;
      rel.policyPredicates = [rel.requiredSourceCapability || 'unauthenticated'];
      rel.enforcementPointIds = wafCoveredRouteIds.includes(rel.id) ? ['ep-edge-waf'] : [];
    }

    for (const f of findings) {
      if (!f.provenanceType) {
        f.provenanceType = f.provenance === 'authored_fixture' ? 'authored_fixture'
          : f.kind === 'cve' ? 'vendor_reference' : 'expert_assumption';
      }
    }

    const identityRelationships = credentials.map(c => ({
      id: `idrel-${c.id}`,
      subjectId: c.sourceAssetId,
      issuerId: keptAssets.find(a => a.groupId === 'iam-idp' || a.groupId === 'ad-identity')?.id || c.sourceAssetId,
      targetScope: c.targetAssetIds?.length ? c.targetAssetIds : c.targetGroupIds || [],
      allowedOperation: (c.permissions || [c.scope || 'authenticate']).join(','),
      delegationConditions: { mfaRequired: !!c.mfaRequired, revoked: !!c.revoked, expired: !!c.expired }
    }));

    const sensors = [0, 1, 2, 3].map(layerIdx => ({
      id: `sensor-layer-${layerIdx}`,
      assetId: keptAssets.find(a => a.layerIdx === layerIdx)?.id || null,
      layerIdx,
      observableActions: ['cve', 'valid_credential', 'password_spray', 'anonymous_access', 'phishing_attachment', 'remote_service', 'persistence', 'encryption', 'data_exfiltration'],
      fieldsCollected: ['sourceId', 'targetId', 'protocol', 'principalId', 'sessionId', 'technique'],
      attributionQuality: telemetryLayers.includes(layerIdx) ? 'session_scoped' : 'unmonitored',
      availability: telemetryLayers.includes(layerIdx),
      lossConditions: telemetryLayers.includes(layerIdx) ? [] : ['layer_telemetry_not_deployed']
    }));

    const responseIntegrations = [
      {
        id: 'integration-iam-session-revocation',
        supportedActions: ['revoke_credential', 'invalidate_session', 'disable_account'],
        authorizedScopes: keptAssets.filter(a => a.isExternalEntry).map(a => a.id),
        sessionSemantics: 'terminate_scoped_session',
        tokenSemantics: 'revoke_token_and_prevent_new_sessions',
        confirmationMechanism: 'synchronous_policy_ack',
        available: hashNode(seed, 'soc-authority', 0x9e3779b9) < 0.95
      },
      {
        id: 'integration-host-isolation',
        supportedActions: ['isolate_host', 'close_public_exposure'],
        authorizedScopes: keptAssets.map(a => a.id),
        sessionSemantics: 'block_host_routes',
        tokenSemantics: 'preserve_unrelated_tokens',
        confirmationMechanism: 'agent_heartbeat_ack',
        available: hashNode(seed, 'soc-enforcement-success', 0x9e3779b9) < 0.95
      }
    ];

    const legitimateWorkflows = keptRels.slice(0, 3).map((r, idx) => ({
      id: `workflow-benign-${idx + 1}`,
      label: `Authorized service traffic (${r.purpose})`,
      actor: 'service_principal_benign',
      routeIds: [r.id],
      expectedOperations: ['authenticate', 'read']
    }));

    const groupsByAsset = fullEnterprise ? new Map(keptAssets.map(asset => [asset.id, asset.groupId])) : null;
    const overviewRoutes = new Map();
    if (fullEnterprise) {
      for (const route of keptRels) {
        if (!FULL_ENTERPRISE_OVERVIEW[groupsByAsset.get(route.sourceId)]?.includes(groupsByAsset.get(route.targetId))) continue;
        const pair = `${route.sourceId}->${route.targetId}`;
        if (!overviewRoutes.has(pair)) overviewRoutes.set(pair, route.id);
      }
    }
    const estate = {
      schemaVersion: SCHEMA_VERSION,
      id: `estate-${archetypeId}-${seed}`,
      ...(fullEnterprise && { overviewRouteIds: [...overviewRoutes.values()] }),
      archetypeId,
      estateSeed: seed,
      seed,
      preset,
      generationMode,
      asOfDate: options.asOfDate ?? null,
      scenarioId: isAuthoredWalkthrough ? (options.scenarioId || archetype.defaultWalkthroughId || 'default-walkthrough') : null,
      walkthroughRouteAssetIds,
      intentionalPathNote: preset === 'demo'
        ? 'DEMO-READY · INTENTIONAL 4-LAYER PATH'
        : preset === 'logs'
          ? 'CREDENTIAL-IN-LOGS · INTENTIONAL 4-LAYER PATH'
          : isAuthoredWalkthrough
            ? `AUTHORED WALKTHROUGH · ${archetype.title.toUpperCase()}`
            : null,
      defensePosture: {
        telemetryLayers,
        socCoverageSeed: seed,
        collectionDelaySec: Math.round(hashNode(seed, 'soc-collection', 0x9e3779b9) * 30),
        decisionDelaySec: 15 + Math.round(hashNode(seed, 'soc-decision', 0x9e3779b9) * 45),
        responseDelaySec: 60 + Math.round(hashNode(seed, 'soc-enforcement-delay', 0x9e3779b9) * 1740),
        responseAuthority: hashNode(seed, 'soc-authority', 0x9e3779b9) < 0.95,
        enforcementSucceeds: hashNode(seed, 'soc-enforcement-success', 0x9e3779b9) < 0.95,
        decoys
      },
      assets: keptAssets,
      routes: keptRels,
      relationships: keptRels,
      identityRelationships,
      weaknesses: findings,
      findings,
      credentials,
      datasets,
      sensors,
      enforcementPoints,
      patchRules,
      decoys,
      responseIntegrations,
      legitimateWorkflows,
      assumptions: CALIBRATION_REGISTER.simulationAssumptions,
      actionOrder
    };

    const validation = validateEstate(estate);
    if (!validation.valid) {
      throw new Error(`Generated invalid estate: ${validation.errors.join('; ')}`);
    }
    return estate;
  }

  function convertLegacySnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
      return { ok: false, legacy: true, reason: 'No snapshot provided.' };
    }
    const unsupportedExerciseFindings = Array.isArray(snapshot.findings)
      ? snapshot.findings.filter(f => f.kind === 'exercise').map(f => f.id || 'exercise')
      : [];
    const missingV4Entities = ['datasets', 'sensors', 'enforcementPoints', 'patchRules', 'responseIntegrations', 'assumptions']
      .filter(key => !Array.isArray(snapshot[key]));
    return {
      ok: false,
      legacy: true,
      schemaVersion: snapshot.schemaVersion ?? null,
      equivalentReplay: false,
      unsupportedExerciseFindings,
      missingV4Entities,
      draftScenario: Array.isArray(snapshot.assets) ? {
        schemaVersion: SCHEMA_VERSION,
        id: `draft-migrated-${snapshot.seed ?? 'unknown'}`,
        archetypeId: 'public-web',
        estateSeed: snapshot.seed ?? 1,
        seed: snapshot.seed ?? 1,
        preset: snapshot.preset || 'mixed',
        generationMode: 'exploratory',
        incompleteDraft: true,
        requiresSuppliedAssumptions: missingV4Entities,
        assets: snapshot.assets,
        routes: snapshot.relationships || [],
        relationships: snapshot.relationships || [],
        weaknesses: (snapshot.findings || []).filter(f => f.kind !== 'exercise'),
        findings: (snapshot.findings || []).filter(f => f.kind !== 'exercise'),
        credentials: snapshot.credentials || [],
        datasets: [],
        sensors: [],
        enforcementPoints: [],
        patchRules: [],
        decoys: [],
        responseIntegrations: [],
        legitimateWorkflows: [],
        assumptions: []
      } : null,
      reason: `Incompatible legacy snapshot (schemaVersion ${snapshot.schemaVersion ?? 'unknown'}): unsupported exercise findings [${unsupportedExerciseFindings.join(', ')}], missing Schema v4 entities [${missingV4Entities.join(', ')}]. Cannot claim equivalent replay.`
    };
  }

  function migrateSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
      return { ok: false, reason: 'No snapshot provided.' };
    }
    if (snapshot.schemaVersion === SCHEMA_VERSION) {
      const validation = validateEstate(snapshot);
      if (!validation.valid) return { ok: false, reason: validation.errors.join('; ') };
      if (snapshot.preset === 'mixed' && Number.isInteger(snapshot.seed) &&
          !snapshot.findings.some(finding => finding.kind === 'diagnostic_access' && finding.openingType)) {
        return { ok: true, estate: generateEstate({ seed: snapshot.seed, preset: 'mixed' }) };
      }
      return { ok: true, estate: snapshot };
    }
    return convertLegacySnapshot(snapshot);
  }

  // Resolve one predeclared service flow for display. Findings and the runner
  // do not use this reference context.
  function referenceServiceFlow(estate, groups) {
    const assets = [];
    const relationships = [];
    const byId = new Map(estate.assets.map(asset => [asset.id, asset]));
    let asset = estate.assets.find(node => node.layerIdx === 0 && node.groupId === groups[0]);
    for (const group of groups.slice(1)) {
      if (!asset) return null;
      assets.push(asset.id);
      const relationship = estate.relationships.find(link => link.sourceId === asset.id &&
        byId.get(link.targetId)?.groupId === group);
      if (!relationship) return null;
      relationships.push(relationship.id);
      asset = byId.get(relationship.targetId);
    }
    if (!asset) return null;
    assets.push(asset.id);
    return { assets, relationships };
  }

  // ---------------------------------------------------------------------------
  // Fixed Comparison Mode: Pre-2023 Human-Led vs ARTEX & Friends
  // ---------------------------------------------------------------------------
  const COMPARISON_PROFILES = {
    pre2023: {
      id: 'pre2023',
      label: 'Pre-2023 human-led',
      shortLabel: 'PRE-2023',
      description: 'Human-led operations using scripts, automation, valid credentials, and operator handoffs.'
    },
    artex: {
      id: 'artex',
      label: 'ARTEX & Friends',
      shortLabel: 'ARTEX',
      description: 'Agentic operations with faster pace, concurrent opportunity review, and context-dependent continuation.'
    }
  };

  const COMPARISON_DEFENSES = {
    baseline: { id: 'baseline', label: 'Baseline', shortLabel: 'BASELINE' },
    patch: { id: 'patch', label: 'Virtual Patching', shortLabel: 'VIRTUAL PATCH' },
    soc: { id: 'soc', label: 'Agentic SOC', shortLabel: 'AGENTIC SOC' },
    canaries: { id: 'canaries', label: 'Canaries', shortLabel: 'CANARIES' },
    combined: { id: 'combined', label: 'Defense in Depth', shortLabel: 'DEFENSE IN DEPTH' }
  };

  function createComparisonEstate() {
    const estate = {
      schemaVersion: SCHEMA_VERSION,
      seed: 20261115,
      preset: 'comparison',
      intentionalPathNote: 'FIXED COMPARISON ESTATE: identical four-layer estate, exposures, access rules, and protected record across all comparison runs.',
      assets: [
        {
          id: 'cmp-edge',
          groupId: 'f5-gateway',
          label: 'Ingress Gateway',
          product: 'F5 BIG-IP',
          assumedVersion: '16.1.0',
          layerIdx: 0,
          trustZone: 'internet-dmz',
          interfaces: ['https'],
          auth: 'token',
          isExternalEntry: true,
          x: 0.14,
          y: 0.48
        },
        {
          id: 'cmp-api',
          groupId: 'cust-api',
          label: 'API Boundary',
          product: 'WSO2 API Manager',
          assumedVersion: '3.2.0',
          layerIdx: 1,
          trustZone: 'identity-edge',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.38,
          y: 0.34
        },
        {
          id: 'cmp-gw2',
          groupId: 'wso2-api',
          label: 'Service Gateway',
          product: 'WSO2 Gateway',
          assumedVersion: '3.2.0',
          layerIdx: 1,
          trustZone: 'identity-edge',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.38,
          y: 0.68
        },
        {
          id: 'cmp-app',
          groupId: 'app-engine',
          label: 'Core App Service',
          product: 'Spring Framework',
          assumedVersion: '5.3.17',
          layerIdx: 2,
          trustZone: 'internal-mesh',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.63,
          y: 0.34
        },
        {
          id: 'cmp-svc',
          groupId: 'spring-svc',
          label: 'Workflow Service',
          product: 'Order Workflow',
          assumedVersion: '5.3.17',
          layerIdx: 2,
          trustZone: 'internal-mesh',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.63,
          y: 0.68
        },
        {
          id: 'cmp-data',
          groupId: 'db-rds',
          label: 'Sensitive Record Store',
          product: 'PostgreSQL RDS',
          assumedVersion: '14.9',
          layerIdx: 3,
          trustZone: 'data-tier',
          interfaces: ['db-pg'],
          auth: 'db_credential',
          isExternalEntry: false,
          isProtectedRecord: true,
          x: 0.86,
          y: 0.34
        },
        {
          id: 'cmp-decoy',
          groupId: 'nosql-doc',
          label: 'Canary Decoy Asset',
          product: 'Decoy Document Store',
          assumedVersion: '1.0',
          layerIdx: 3,
          trustZone: 'data-tier',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          isDecoyAsset: true,
          x: 0.86,
          y: 0.68
        }
      ],
      findings: [
        {
          id: 'cmp-f-edge',
          assetId: 'cmp-edge',
          kind: 'cve',
          cveId: 'CVE-2022-1388',
          requiredProduct: 'F5 BIG-IP',
          affectedVersions: ['16.1.0'],
          requiredConditions: { managementReachable: true },
          sourceUrl: 'https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf',
          sourceReviewed: true,
          requiredInterface: 'https',
          yieldsCapability: 'app_exec'
        },
        {
          id: 'cmp-f-api',
          assetId: 'cmp-api',
          kind: 'cve',
          cveId: 'CVE-2022-29464',
          requiredProduct: 'WSO2 API Manager',
          affectedVersions: ['3.2.0'],
          requiredConditions: { uploadEndpointReachable: true, executableUpload: true },
          sourceUrl: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf',
          sourceReviewed: true,
          requiredInterface: 'api-https',
          yieldsCapability: 'app_exec'
        },
        {
          id: 'cmp-f-app',
          assetId: 'cmp-app',
          kind: 'cve',
          cveId: 'CVE-2022-22965',
          requiredProduct: 'Spring Framework',
          affectedVersions: ['5.3.17'],
          requiredConditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true },
          sourceUrl: 'https://spring.io/security/cve-2022-22965/',
          sourceReviewed: true,
          requiredInterface: 'api-https',
          yieldsCapability: 'app_exec'
        }
      ],
      credentials: [
        {
          id: 'cmp-cred-db',
          kind: 'db_credential',
          label: 'app-db-read',
          scope: 'read',
          targetGroupIds: ['db-rds'],
          targetAssetIds: ['cmp-data'],
          revoked: false,
          expired: false,
          mfaRequired: false,
          sourceAssetId: 'cmp-app',
          requiredSourceCapability: 'app_exec'
        }
      ],
      relationships: [
        { id: 'cmp-r-edge-api', sourceId: 'cmp-edge', targetId: 'cmp-api', protocol: 'api-https', accessibleInterface: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: ['cmp-ep-waf'] },
        { id: 'cmp-r-edge-gw2', sourceId: 'cmp-edge', targetId: 'cmp-gw2', protocol: 'api-https', accessibleInterface: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: ['cmp-ep-waf'] },
        { id: 'cmp-r-api-app', sourceId: 'cmp-api', targetId: 'cmp-app', protocol: 'api-https', accessibleInterface: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: [] },
        { id: 'cmp-r-api-svc', sourceId: 'cmp-api', targetId: 'cmp-svc', protocol: 'api-https', accessibleInterface: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: [] },
        { id: 'cmp-r-app-data', sourceId: 'cmp-app', targetId: 'cmp-data', protocol: 'db-pg', accessibleInterface: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: [] },
        { id: 'cmp-r-svc-decoy', sourceId: 'cmp-svc', targetId: 'cmp-decoy', protocol: 'api-https', accessibleInterface: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec', enforcementPointIds: [] }
      ],
      datasets: [
        { id: 'cmp-ds-data', ownerAssetId: 'cmp-data', label: 'Sensitive Record Store Dataset', sensitivity: 'sensitive', records: 1200, bytes: 1200 * 1024, isDecoy: false, allowedOperations: ['read', 'export'] },
        { id: 'cmp-ds-decoy', ownerAssetId: 'cmp-decoy', label: 'Canary Decoy Dataset', sensitivity: 'decoy', records: 0, bytes: 0, isDecoy: true, allowedOperations: ['read'] }
      ],
      enforcementPoints: [
        { id: 'cmp-ep-waf', assetId: 'cmp-edge', routeIds: ['cmp-r-edge-api', 'cmp-r-edge-gw2'], inspectedProtocols: ['https', 'api-https'], inspectedFields: ['uri', 'headers', 'body'], ruleIds: ['VP-EDGE-01'], enabled: true }
      ],
      patchRules: [
        { id: 'VP-EDGE-01', cveId: 'CVE-2022-1388', enforcementPointIds: ['cmp-ep-waf'], inspectedProtocols: ['https', 'api-https'], inspectedFields: ['uri', 'headers'], ruleStrictness: 'strict_virtual_patch', coverageState: 'modeled', action: 'block', control: 'NIST SC-7', reason: 'WAF drops hop-by-hop Connection header smuggling to /mgmt/shared/authn' }
      ],
      sensors: [0, 1, 2, 3].map(layerIdx => ({
        id: `cmp-sensor-l${layerIdx}`,
        assetId: null,
        layerIdx,
        observableActions: ['cve', 'valid_credential', 'anonymous_access'],
        fieldsCollected: ['sourceId', 'targetId', 'sessionId'],
        attributionQuality: 'session_scoped',
        availability: true,
        lossConditions: []
      })),
      responseIntegrations: [
        { id: 'cmp-ri-iam', supportedActions: ['invalidate_session', 'revoke_credential'], authorizedScopes: ['sess-primary'], sessionSemantics: 'terminate_scoped_session', tokenSemantics: 'revoke_token', confirmationMechanism: 'synchronous_ack', available: true }
      ],
      assumptions: CALIBRATION_REGISTER.simulationAssumptions,
      actionOrder: ['cmp-edge', 'cmp-api', 'cmp-gw2', 'cmp-app', 'cmp-svc', 'cmp-data', 'cmp-decoy']
    };
    estate.id = 'estate-comparison-fixed';
    estate.archetypeId = 'public-web';
    estate.estateSeed = estate.seed;
    estate.generationMode = 'authored_walkthrough';
    estate.routes = estate.relationships;
    estate.weaknesses = estate.findings;
    estate.assets.forEach(a => {
      const td = getTargetDef(a.groupId);
      a.icon = td?.def?.icon || 'application.png';
    });
    return estate;
  }

  function formatDurationSeconds(totalSeconds) {
    if (totalSeconds === null || totalSeconds === undefined || Number.isNaN(totalSeconds)) return 'N/A';
    const secs = Math.max(0, Math.round(totalSeconds));
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  function formatSignedDelta(deltaSeconds) {
    if (deltaSeconds === null || deltaSeconds === undefined || Number.isNaN(deltaSeconds)) return 'Unavailable';
    const sign = deltaSeconds > 0 ? '+' : deltaSeconds < 0 ? '−' : '';
    const abs = Math.abs(Math.round(deltaSeconds));
    if (abs >= 60 && abs % 60 === 0) {
      return `${sign}${abs / 60} min`;
    }
    if (abs >= 120) {
      const mins = Math.floor(abs / 60);
      const rem = abs % 60;
      return rem === 0 ? `${sign}${mins} min` : `${sign}${mins}m ${rem}s`;
    }
    return `${sign}${abs} s`;
  }

  function buildSpeedEvents({
    ingressTime = 0,
    decoyTime = 600,
    boundaryTime = 5400,
    lateralTime = 6300,
    protectedReadTime = 7200,
    patchCovered = false,
    socDetectable = true,
    includeDecoy = true,
    decoyPlacement = 'early',
    includeSecondaryBranch = false
  }) {
    const events = [
      {
        id: 'ev-ingress',
        timeSec: ingressTime,
        layerIdx: 0,
        assetId: 'cmp-edge',
        relationshipId: null,
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'ingress',
        title: 'Ingress edge request',
        detail: patchCovered
          ? 'Edge request matches active virtual patch rule VP-EDGE-01.'
          : 'Edge request uses an unpatched path outside virtual patch rule coverage.',
        ruleCoverage: patchCovered
          ? { covered: true, ruleId: 'VP-EDGE-01', label: 'Active ingress virtual patch' }
          : { covered: false, label: 'Outside virtual patch rule coverage' },
        telemetry: { detectable: false },
        isDecoy: false,
        decoyPlacement: null,
        isBoundaryCrossing: false,
        isProtectedRead: false
      }
    ];

    if (includeDecoy && decoyPlacement === 'early') {
      events.push({
        id: 'ev-decoy',
        timeSec: decoyTime,
        layerIdx: 3,
        assetId: 'cmp-decoy',
        relationshipId: 'cmp-r-svc-decoy',
        prerequisiteIds: ['ev-ingress'],
        identityId: 'sess-primary',
        kind: 'decoy',
        title: 'Early canary decoy interaction',
        detail: 'Session touches instrumented canary decoy, identifying sess-primary.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'early',
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    events.push({
      id: 'ev-boundary',
      timeSec: boundaryTime,
      layerIdx: 1,
      assetId: 'cmp-api',
      relationshipId: 'cmp-r-edge-api',
      prerequisiteIds: ['ev-ingress'],
      identityId: 'sess-primary',
      kind: 'boundary',
      title: 'First boundary crossing',
      detail: 'Cross-boundary session reaches internal API tier.',
      ruleCoverage: { covered: false },
      telemetry: socDetectable
        ? { detectable: true, signalLabel: 'Boundary crossing telemetry (sess-primary)', containableIdentity: 'sess-primary' }
        : { detectable: false, signalLabel: 'No matching SOC telemetry' },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: true,
      isProtectedRead: false
    });

    events.push({
      id: 'ev-lateral',
      timeSec: lateralTime,
      layerIdx: 2,
      assetId: 'cmp-app',
      relationshipId: 'cmp-r-api-app',
      prerequisiteIds: ['ev-boundary'],
      identityId: 'sess-primary',
      kind: 'lateral',
      title: 'Internal service pivot',
      detail: 'Workflow pivots into core application service.',
      ruleCoverage: { covered: false },
      telemetry: { detectable: false },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: false,
      isProtectedRead: false
    });

    events.push({
      id: 'ev-protected-read',
      timeSec: protectedReadTime,
      layerIdx: 3,
      assetId: 'cmp-data',
      relationshipId: 'cmp-r-app-data',
      prerequisiteIds: ['ev-lateral'],
      identityId: 'sess-primary',
      kind: 'protected_read',
      title: 'Protected record read',
      detail: 'First unauthorized read of the designated sensitive record.',
      ruleCoverage: { covered: false },
      telemetry: { detectable: false },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: false,
      isProtectedRead: true
    });

    if (includeDecoy && decoyPlacement === 'late') {
      events.push({
        id: 'ev-decoy',
        timeSec: decoyTime,
        layerIdx: 3,
        assetId: 'cmp-decoy',
        relationshipId: 'cmp-r-svc-decoy',
        prerequisiteIds: ['ev-boundary'],
        identityId: 'sess-primary',
        kind: 'decoy',
        title: 'Late canary decoy interaction',
        detail: 'Session touches backend decoy after sensitive record access.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Late canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'late',
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    if (includeSecondaryBranch) {
      events.push({
        id: 'ev-unrelated',
        timeSec: lateralTime + 15,
        layerIdx: 2,
        assetId: 'cmp-svc',
        relationshipId: 'cmp-r-api-svc',
        prerequisiteIds: [],
        identityId: 'sess-secondary',
        kind: 'lateral',
        title: 'Independent secondary session activity',
        detail: 'Unrelated identity sess-secondary continues outside sess-primary containment scope.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        decoyPlacement: null,
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    events.sort((a, b) => a.timeSec - b.timeSec);
    return events;
  }

  function buildCapabilityEvents(profileId, accessDenied) {
    if (profileId === 'pre2023') {
      return [
        {
          id: 'cap-opp-1',
          timeSec: 15,
          layerIdx: 1,
          assetId: 'cmp-api',
          relationshipId: 'cmp-r-edge-api',
          prerequisiteIds: [],
          identityId: 'sess-primary',
          kind: 'opportunity_review',
          opportunityId: 'opp-1',
          concurrentGroup: null,
          requiresHumanReview: true,
          handoffDurationSec: 45,
          title: 'Opportunity 1 reviewed (scripted check)',
          detail: 'Operator runs scripted check on Opportunity 1 (15 s) and hits context-dependent decision point.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: true, signalLabel: 'Scripted check telemetry (sess-primary)', containableIdentity: 'sess-primary' },
          isDecoy: false,
          isBoundaryCrossing: true,
          isProtectedRead: false
        },
        {
          id: 'cap-handoff-1',
          timeSec: 60,
          layerIdx: 2,
          assetId: 'cmp-app',
          relationshipId: 'cmp-r-api-app',
          prerequisiteIds: ['cap-opp-1'],
          identityId: 'sess-primary',
          kind: 'human_handoff',
          opportunityId: 'opp-1',
          concurrentGroup: null,
          requiresHumanReview: true,
          handoffDurationSec: 45,
          title: 'Human operator handoff (45 s)',
          detail: 'Awaits human review for context-dependent decision (15 s -> 60 s, exceeds 45 s cutoff).',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: false
        },
        {
          id: 'cap-opp-2',
          timeSec: 75,
          layerIdx: 2,
          assetId: 'cmp-svc',
          relationshipId: 'cmp-r-api-svc',
          prerequisiteIds: ['cap-handoff-1'],
          identityId: 'sess-primary',
          kind: 'opportunity_review',
          opportunityId: 'opp-2',
          concurrentGroup: null,
          requiresHumanReview: false,
          handoffDurationSec: null,
          title: 'Opportunity 2 reviewed',
          detail: 'Available only after first human handoff completes.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: false
        },
        {
          id: 'cap-read',
          timeSec: 75,
          layerIdx: 3,
          assetId: 'cmp-data',
          relationshipId: 'cmp-r-app-data',
          prerequisiteIds: ['cap-opp-2'],
          identityId: 'sess-primary',
          kind: 'protected_read',
          opportunityId: 'opp-2',
          concurrentGroup: null,
          requiresHumanReview: false,
          handoffDurationSec: null,
          accessDenied,
          title: accessDenied ? 'Protected record access denied' : 'Protected record read',
          detail: accessDenied ? 'Shared access rules deny read of sensitive record.' : 'Protected read on Opportunity 2.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: true
        }
      ];
    }

    // ARTEX agentic capability trace
    return [
      {
        id: 'cap-opp-1',
        timeSec: 15,
        layerIdx: 1,
        assetId: 'cmp-api',
        relationshipId: 'cmp-r-edge-api',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-1',
        concurrentGroup: 'batch-0',
        requiresHumanReview: true,
        handoffDurationSec: 45,
        title: 'Opportunity 1 reviewed concurrently',
        detail: 'Reviewed in parallel (0-15 s); requires 45 s human review before continuing.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: false
      },
      {
        id: 'cap-opp-2',
        timeSec: 15,
        layerIdx: 1,
        assetId: 'cmp-gw2',
        relationshipId: 'cmp-r-edge-gw2',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-2',
        concurrentGroup: 'batch-0',
        requiresHumanReview: false,
        handoffDurationSec: null,
        title: 'Opportunity 2 reviewed concurrently',
        detail: 'Context-dependent continuation proceeds without human gate (0-15 s).',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Concurrent opportunity telemetry (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: false,
        isBoundaryCrossing: true,
        isProtectedRead: false
      },
      {
        id: 'cap-opp-3',
        timeSec: 15,
        layerIdx: 2,
        assetId: 'cmp-svc',
        relationshipId: 'cmp-r-api-svc',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-3',
        concurrentGroup: 'batch-0',
        requiresHumanReview: false,
        handoffDurationSec: null,
        title: 'Opportunity 3 reviewed concurrently (decoy-adjacent)',
        detail: 'Reviewed in parallel (0-15 s); touches instrumented decoy marker.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'early',
        isBoundaryCrossing: false,
        isProtectedRead: false
      },
      {
        id: 'cap-read',
        timeSec: 30,
        layerIdx: 3,
        assetId: 'cmp-data',
        relationshipId: 'cmp-r-app-data',
        prerequisiteIds: ['cap-opp-2'],
        identityId: 'sess-primary',
        kind: 'protected_read',
        opportunityId: 'opp-2',
        concurrentGroup: null,
        requiresHumanReview: false,
        handoffDurationSec: null,
        accessDenied,
        title: accessDenied ? 'Protected record access denied' : 'Protected record read (30 s)',
        detail: accessDenied
          ? 'Shared access rules deny read of designated sensitive record at 30 s.'
          : 'Context-dependent continuation on Opportunity 2 completes protected read at 30 s.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: true
      },
      {
        id: 'cap-handoff-1',
        timeSec: 60,
        layerIdx: 2,
        assetId: 'cmp-app',
        relationshipId: 'cmp-r-api-app',
        prerequisiteIds: ['cap-opp-1'],
        identityId: 'sess-primary',
        kind: 'human_handoff',
        opportunityId: 'opp-1',
        concurrentGroup: null,
        requiresHumanReview: true,
        handoffDurationSec: 45,
        title: 'Human review on Opportunity 1 completes (60 s)',
        detail: 'Still awaiting human review at the 45 s cutoff.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: false
      }
    ];
  }

  // Fixed timestamps for the authored comparison fixtures below.
  const TIMING_RACE = {
    pre2023: { decoyTime: 10 * 60, boundaryTime: 75 * 60, lateralTime: 90 * 60, protectedReadTime: 105 * 60 },
    artex: { decoyTime: 2 * 60, boundaryTime: 14 * 60 + 45, lateralTime: 15 * 60, protectedReadTime: 15 * 60 + 35 }
  };

  const ATTACKER_PROFILES = {
    pre2023: {
      ...BEHAVIOR_PRESETS.operator_with_tools,
      id: 'pre2023',
      maxConcurrentBranches: 1,
      adaptiveWafEvasion: false,
      allowsUserInteraction: true,
      allowsPersistence: true,
      allowsRansomwareImpact: true
    },
    artex: {
      ...BEHAVIOR_PRESETS.agentic_orchestration,
      id: 'artex',
      maxConcurrentBranches: 3,
      adaptiveWafEvasion: true,
      allowsUserInteraction: false,
      allowsPersistence: false,
      allowsRansomwareImpact: false
    },
    operator_with_tools: {
      ...BEHAVIOR_PRESETS.operator_with_tools
    },
    agentic_orchestration: {
      ...BEHAVIOR_PRESETS.agentic_orchestration
    }
  };

  // Historical Pre-2023 (Pre-LLM) attack patterns & RaaS profiles.
  // Per spec Section 8.1 / R04 / R14, historical identity and incident metadata
  // supply sourced technique context and display labels under the
  // `operator_with_tools` behavior preset; defense deployment and topology
  // come exclusively from the shared estate.
  const PRE2023_ATTACK_PATTERNS = {
    lockbit: {
      id: 'lockbit',
      label: 'LockBit',
      year: 2022,
      actor: 'LockBit (2.0 / 3.0)',
      incident: 'Enterprise RaaS campaigns',
      primaryVector: 'Perimeter appliance & valid-account intrusion with StealBit exfiltration',
      cveIds: ['CVE-2023-4966', 'CVE-2023-3519'],
      techniques: ['T1190', 'T1078', 'T1486'],
      targetGroups: ['citrix-adc', 'iam-idp', 'db-rds'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Most prolific RaaS operation by 2022 (~1/3 of enterprise ransomware incidents globally).',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a'
    },
    conti: {
      id: 'conti',
      label: 'Conti',
      year: 2021,
      actor: 'Conti Syndicate',
      incident: 'Enterprise & healthcare RaaS campaigns',
      primaryVector: 'Phishing loader to Cobalt Strike, Kerberoasting, and AD lateral movement',
      cveIds: ['CVE-2021-26855', 'CVE-2020-1472'],
      techniques: ['T1190', 'T1558.003', 'T1003'],
      targetGroups: ['exchange', 'ad-identity', 'mssql-db'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Dominant syndicate through mid-2022 targeting critical infrastructure and government entities.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a'
    },
    blackcat: {
      id: 'blackcat',
      label: 'BlackCat',
      year: 2022,
      actor: 'BlackCat (ALPHV / Noberus)',
      incident: 'Cross-platform Windows/Linux/ESXi RaaS campaigns',
      primaryVector: 'Exposed VPN/firewall credentials and unpatched edge gateways to hypervisor/data stores',
      cveIds: ['CVE-2024-37085', 'CVE-2018-13379'],
      techniques: ['T1078', 'T1190', 'T1486'],
      targetGroups: ['forti-vpn', 'iam-idp', 'lake-cust'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'First major Rust-based cross-platform RaaS targeting enterprise Windows, Linux, and ESXi estates.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a'
    },
    hive: {
      id: 'hive',
      label: 'Hive',
      year: 2022,
      actor: 'Hive RaaS',
      incident: 'Healthcare & critical infrastructure double-extortion campaigns',
      primaryVector: 'RDP/VPN single-factor logins and ProxyShell/Exchange exploitation with rclone exfiltration',
      cveIds: ['CVE-2021-26855', 'CVE-2019-11510'],
      techniques: ['T1133', 'T1190', 'T1567.002'],
      targetGroups: ['forti-vpn', 'exchange', 'mssql-db'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Compromised over 1,500 victims globally before international law-enforcement disruption in early 2023.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a'
    },
    revil: {
      id: 'revil',
      label: 'REvil · Kaseya VSA',
      year: 2021,
      actor: 'REvil (Sodinokibi)',
      incident: 'Kaseya VSA Supply Chain Ransomware Attack',
      primaryVector: 'Zero-day authentication bypass & SQLi in RMM (CVE-2021-30116)',
      cveIds: ['CVE-2021-30116'],
      techniques: ['T1190', 'T1199', 'T1059.001'],
      targetGroups: ['ivanti-epm', 'weblogic', 'db-rds'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Cascaded ransomware through ~60 MSPs to 1,500+ downstream businesses globally across 17+ countries.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/alerts/2021/07/04/cisa-fbi-guidance-msps-and-their-customers-affected-kaseya-vsa-supply-chain-attack'
    },
    solarwinds: {
      id: 'solarwinds',
      label: 'APT29 · SolarWinds',
      year: 2020,
      actor: 'APT29 (SVR / Nobelium)',
      incident: 'SolarWinds (SUNBURST) Supply Chain Compromise',
      primaryVector: 'CI/CD build pipeline compromise & trojanized Orion software update',
      cveIds: ['CVE-2020-10148', 'CVE-2021-35225'],
      techniques: ['T1195.002', 'T1078', 'T1550.001'],
      targetGroups: ['cicd-runner', 'vuln-scan', 'iam-idp', 'db-rds'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Up to 18,000 organizations trojanized via signed Orion updates; catalyzed Executive Order 14028 and federal SBOM/zero-trust mandates.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise'
    },
    darkside: {
      id: 'darkside',
      label: 'DarkSide · Colonial VPN',
      year: 2021,
      actor: 'DarkSide',
      incident: 'Colonial Pipeline Ransomware Attack',
      primaryVector: 'Compromised legacy VPN credentials (no MFA)',
      cveIds: [],
      openingId: 'legacy-vpn',
      techniques: ['T1078', 'T1133', 'T1486'],
      targetGroups: ['external-misconfig', 'forti-vpn', 'ad-identity', 'mssql-db'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Halted 45% of U.S. East Coast fuel supply for 6 days; triggered mandatory TSA critical infrastructure cybersecurity directives.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.govinfo.gov/content/pkg/CHRG-117hhrg45085/html/CHRG-117hhrg45085.htm'
    },
    log4shell: {
      id: 'log4shell',
      label: 'Log4Shell · Log4j',
      year: 2021,
      actor: 'Nation-states & eCrime',
      incident: 'Log4Shell / Apache Log4j Exploitation (CVE-2021-44228)',
      primaryVector: 'Unauthenticated JNDI injection in Apache Log4j 2',
      cveIds: ['CVE-2021-44228'],
      techniques: ['T1190', 'T1059', 'T1105'],
      targetGroups: ['cust-api', 'log4j-svc', 'iot-hub', 'lake-ops'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Ubiquitous open-source transitive dependency flaw affecting hundreds of millions of enterprise Java instances worldwide.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a'
    },
    cl0p: {
      id: 'cl0p',
      label: 'Cl0p · MOVEit Transfer',
      year: 2023,
      actor: 'Cl0p (TA505)',
      incident: 'MOVEit Transfer Zero-Day Campaign (CVE-2023-34362)',
      primaryVector: 'Zero-day SQL injection & LEMURLOOT web shell in managed file transfer',
      cveIds: ['CVE-2023-34362'],
      techniques: ['T1190', 'T1505.003', 'T1041'],
      targetGroups: ['partner-api', 'moveit-sftp', 'lake-cust'],
      behaviorPreset: 'operator_with_tools',
      systemicImpact: 'Pure-extortion mass exploitation compromising 2,700+ organizations and exposing 93M+ individuals without file encryption.',
      provenanceType: 'historical_source',
      sourceUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a'
    }
  };

  // Gang/pattern identity selects its documented repertoire at spawn. Defense
  // deployment and topology come exclusively from the shared estate.
  const WIRE_ATTACKERS = {
    lockbit: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'lockbit' },
    conti: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'conti' },
    blackcat: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'blackcat' },
    hive: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'hive' },
    revil: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'revil' },
    solarwinds: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'solarwinds' },
    darkside: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'darkside' },
    log4shell: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'log4shell' },
    cl0p: { pace: 'pre2023', behaviorPreset: 'operator_with_tools', patternId: 'cl0p' },
    artex: { pace: 'artex', behaviorPreset: 'agentic_orchestration', patternId: null }
  };

  const WIRE_READ_MINUTES = {
    pre2023: { min: 80, max: 270 },
    artex: { min: 45, max: 75 }
  };

  function wireTiming(seed, pace) {
    const { min, max } = WIRE_READ_MINUTES[pace];
    const readTime = (min + Math.floor(hashNode(seed, `wire-timing:${pace}`, 0x9e3779b9) * (max - min + 1))) * 60;
    // Historical total-duration context is retained. Stage weights are explicit synthetic assumptions.
    const weights = [1, 2, 3].map(layer => 0.15 + hashNode(seed, `stage-weight:${pace}:${layer}`, 0x9e3779b9));
    const total = weights.reduce((a,b) => a+b,0);
    const stageTimes = [0, Math.round(readTime * weights[0]/total), Math.round(readTime * (weights[0]+weights[1])/total), readTime];
    return {stageTimes, actionDurations: stageTimes.map((t,i) => i ? t-stageTimes[i-1] : 0), modeledPathDurationSec: readTime,
      reentryDurationSec:300};
  }

  function classifyRun(result) {
    const encrypted = result.events.filter(e => e.outcome === 'succeeded' && e.actionKind === 'encryption');
    const persisted = result.events.filter(e => e.outcome === 'succeeded' && e.actionKind === 'persistence');
    const exported = result.events.filter(e => e.outcome === 'succeeded' && e.actionKind === 'data_exfiltration');
    const impact = result.summary.dataReached || encrypted.length > 0;
    const incomplete = result.summary.truncated;
    const enforcements = result.controls.filter(e => e.control === 'enforced');
    const reads = result.events.filter(e => e.outcome === 'succeeded' && e.isProtectedRead);
    const effective = enforcements.filter(e => result.events.some(a => a.scope === e.scope && a.outcome === 'succeeded'));
    const activeScopes = new Set(result.events.filter(e => e.scope && e.outcome === 'succeeded').map(e => e.scope));
    const contained = new Set(effective.map(e => e.scope));
    const allContained = activeScopes.size > 0 && [...activeScopes].every(scope => contained.has(scope));
    const late = reads.some(read => effective.some(e => e.scope === read.scope && e.timeSec > read.timeSec));
    const encryptionLate = encrypted.some(event=>effective.some(e=>e.scope===event.scope&&e.timeSec>event.timeSec));
    const label = incomplete ? 'Exploration incomplete' : encrypted.length ? (encryptionLate ? 'Endpoint encryption before containment' : 'Endpoint encryption')
      : exported.length ? 'Data exfiltrated'
      : impact ? (late ? 'Record read before containment' : 'Protected record read')
      : persisted.length ? (allContained ? 'Session contained; persistence was established' : 'Persistence established; no encryption or protected read')
      : allContained ? 'Contained before protected read' : effective.length ? 'Partial session containment'
      : result.events.some(e => e.outcome === 'blocked') ? 'Virtual patch blocked attempts; no protected read'
      : result.controls.some(e => e.control === 'signal') ? 'Alerted; no confirmed containment'
      : 'No protected read established';
    return {impact, incomplete, containedSessions: contained.size, allContained, label,
      style: impact ? 'breached' : !incomplete && allContained ? 'contained' : ''};
  }

  function simulateWireRun(estate, mode, attackerId, options = {}) {
    const attacker = WIRE_ATTACKERS[attackerId];
    if (!attacker) throw new Error(`Unknown Wire attacker: ${attackerId}`);
    const defenseConfig = options.defenseConfig
      ? normalizeDefenseConfig(options.defenseConfig)
      : (() => {
          if (!['baseline','patch','canaries','soc','soc-canary','combined'].includes(mode)) {
            throw new Error(`Unknown Wire defense: ${mode}`);
          }
          return normalizeDefenseConfig(mode);
        })();
    const effectiveMode = options.defenseConfig
      ? (defenseConfig.virtualPatching && defenseConfig.canaries && defenseConfig.responsePolicy !== 'observe_only' ? 'combined'
        : defenseConfig.canaries && defenseConfig.responsePolicy !== 'observe_only' ? 'soc-canary'
        : defenseConfig.responsePolicy !== 'observe_only' ? 'soc'
        : defenseConfig.virtualPatching ? 'patch'
        : defenseConfig.canaries ? 'canaries'
        : 'baseline')
      : mode;
    const attackerProfile = {...ATTACKER_PROFILES[attacker.pace],
      availableTools:[...(COBALT_STRIKE_SOURCES[attackerId]?['cobalt_strike']:[]),...(PSEXEC_SOURCES[attackerId]?['psexec']:[])], ...options.attackerProfile,
      gangId: attacker.pace === 'pre2023' ? attackerId : null};
    const timing = {...wireTiming(estate.seed, attacker.pace), respond: defenseConfig.responsePolicy !== 'observe_only', defenseConfig,
      collectionDelay: estate.defensePosture?.collectionDelaySec ?? 0,
      decisionDelay: estate.defensePosture?.decisionDelaySec ?? 15,
      responseDelay: estate.defensePosture?.responseDelaySec ?? 60,
      responseAuthority: estate.defensePosture?.responseAuthority ?? true,
      enforcementSucceeds: estate.defensePosture?.enforcementSucceeds ?? true,
      ...options, attackerProfile};
    if (!Array.isArray(timing.actionDurations) || timing.actionDurations.length !== 4 || timing.actionDurations.some(t => !Number.isFinite(t) || t < 0)) throw new Error('Expected four nonnegative action durations');
    if (!Number.isInteger(attackerProfile.maxConcurrentBranches) || attackerProfile.maxConcurrentBranches < 1) throw new Error('Worker count must be a positive integer');
    if (timing.explorationLimit != null && (!Number.isInteger(timing.explorationLimit) || timing.explorationLimit < 1)) throw new Error('Exploration limit must be a positive integer');
    for (const key of ['collectionDelay','decisionDelay','responseDelay','reentryDurationSec']) if (!Number.isFinite(timing[key]) || timing[key] < 0) throw new Error(`Invalid ${key}`);
    const result = simulateEstate(estate, effectiveMode, timing);
    result.events.sort((a,b) => a.timeSec-b.timeSec);
    result.controls.sort((a,b) => a.timeSec-b.timeSec);
    const causalScenario = options.includeCausalScenario
      ? simulateScenario({ estate, attackerProfile, defenseConfig, runConfig: options.runConfig })
      : null;
    const projected = projectRun({
      trialSeed: estate.seed,
      attackerProfile,
      defenseConfig,
      events: result.events
    }, { seed: estate.seed, pace: attacker.pace, timingContext: timing });
    const run = {...result, lanes: attackerProfile.maxConcurrentBranches, attackerProfile, defenseConfig,
      nodeStates: projected.nodeStates,
      routeStates: projected.routeStates,
      presentationContext: projected.presentationContext,
      ...(causalScenario && { causalScenario }),
      assumptions: {stageDurationsSec: timing.actionDurations, nominalPathDurationSec: timing.modeledPathDurationSec, responseDelaySec: timing.responseDelay,
        progressionStrategy:attackerProfile.gangId?'Follow a foothold, collect and transfer data, then apply impact':'Parallel access and collection with prompt bulk transfer',
        lateralMethodPreference:attackerProfile.gangId ? {order:GANG_LATERAL_ORDER[attackerId],basis:'authored_order_among_reported_methods'} : null,
        additionalIngressDurationSec:timing.reentryDurationSec,
        postCompromiseTiming: 'Additional synthetic local-action durations from estate findings; not measured ransomware throughput',
        techniquePolicy: attackerProfile.gangId ? { gangId: attackerId, sources: gangCatalogue.sources,
          roots: gangCatalogue.gangs[attackerId]?.roots || [], affiliateSupplement: GANG_SUPPLEMENTS[attackerId],
          interpretation: 'Documented technique filter plus ordinary scoped access after foothold; authored entry ordering. Historical-style operator on a modern estate.' } : null,
        collectionDelaySec: timing.collectionDelay, decisionDelaySec: timing.decisionDelay,
        telemetryLayers: estate.defensePosture?.telemetryLayers ?? null,
        responseAuthority: timing.responseAuthority, enforcementSucceeds: timing.enforcementSucceeds,
        timingBasis: 'Historical-style total duration; synthetic stage allocations, worker queue and response latency'}};
    run.result = classifyRun(run);
    return run;
  }

  const COMPARISON_FIXTURES = {
    'speed-race': {
      id: 'speed-race',
      kind: 'speed',
      title: 'Speed: Timing Race (Out-of-Scope Patch)',
      subtitle: 'Identical ordered attacker activity retimestamped at Pre-2023 vs ARTEX pace. Same 60 s SOC containment wins at Pre-2023 pace and loses at ARTEX pace.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Virtual patch has no matching rule for the ingress path (OUTSIDE RULE COVERAGE).',
        'Regular SOC signal occurs at the first boundary crossing; containment takes 60 modeled seconds.',
        'Early decoy identifies the same containable identity (sess-primary) as the regular SOC signal.',
        'Same response policy, action scope, and 60 s latency across both attacker paces.'
      ],
      traces: {
        pre2023: buildSpeedEvents(TIMING_RACE.pre2023),
        artex: buildSpeedEvents(TIMING_RACE.artex)
      }
    },
    'speed-covered-patch': {
      id: 'speed-covered-patch',
      kind: 'speed',
      title: 'Speed: Covered Virtual Patch',
      subtitle: 'Active ingress virtual patch rule matches the same milestone at both Pre-2023 and ARTEX paces.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Active virtual patch rule VP-EDGE-01 covers the ingress event at both paces.',
        'Blocking at ingress suppresses all dependent downstream milestones.'
      ],
      traces: {
        pre2023: buildSpeedEvents({ ...TIMING_RACE.pre2023, patchCovered: true }),
        artex: buildSpeedEvents({ ...TIMING_RACE.artex, patchCovered: true })
      }
    },
    'capability-45s': {
      id: 'capability-45s',
      kind: 'capability',
      title: 'Capability: 45s Review Window',
      subtitle: 'Common pace and 45 s budget across 3 service opportunities (15 s/review, 45 s human handoff).',
      cutoffSec: 45,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Three abstract service opportunities available to both profiles under identical access rules.',
        '15 s per opportunity review; 45 s duration for any required human handoff.',
        'Human-led trace reviews sequentially and waits at Opportunity 1 handoff; ARTEX reviews all 3 concurrently.'
      ],
      traces: {
        pre2023: buildCapabilityEvents('pre2023', false),
        artex: buildCapabilityEvents('artex', false)
      }
    },
    'capability-denied': {
      id: 'capability-denied',
      kind: 'capability',
      title: 'Capability: Access Denied (45s)',
      subtitle: 'Same 45 s window and workflow traces, with access to the designated sensitive record denied.',
      cutoffSec: 45,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: true,
      assumptions: [
        'Shared access rules deny read access to the designated sensitive record.',
        'Both profiles end without a protected read while still differing in opportunities reviewed.'
      ],
      traces: {
        pre2023: buildCapabilityEvents('pre2023', true),
        artex: buildCapabilityEvents('artex', true)
      }
    },
    'speed-no-signal': {
      id: 'speed-no-signal',
      kind: 'speed',
      title: 'Edge Case: No Matching SOC Signal',
      subtitle: 'Observable telemetry is absent, so Agentic SOC never triggers.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['No matching SOC telemetry is emitted during the trace.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, socDetectable: false, includeDecoy: false }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, socDetectable: false, includeDecoy: false })
      }
    },
    'speed-at-objective': {
      id: 'speed-at-objective',
      kind: 'speed',
      title: 'Edge Case: Same-Timestamp Enforcement Tie',
      subtitle: 'SOC enforcement becomes effective at the exact timestamp of the protected read.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['When enforcement and protected read share a timestamp, objective takes precedence unless enforcementPrecedesOnTie is set.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 7140, lateralTime: 7170, protectedReadTime: 7200 }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 20, lateralTime: 50, protectedReadTime: 80 })
      }
    },
    'speed-late-decoy': {
      id: 'speed-late-decoy',
      kind: 'speed',
      title: 'Edge Case: Late Decoy Placement',
      subtitle: 'Decoy interaction occurs after the protected read.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['Decoy is placed behind the protected record so alert arrives after data access.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 7500, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, decoyPlacement: 'late' }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 100, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, decoyPlacement: 'late' })
      }
    },
    'speed-untouched-decoy': {
      id: 'speed-untouched-decoy',
      kind: 'speed',
      title: 'Edge Case: Untouched Decoy',
      subtitle: 'Attacker trace never interacts with the instrumented decoy.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['An untouched decoy produces no alert.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, includeDecoy: false }),
        artex: buildSpeedEvents({ ingressTime: 0, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, includeDecoy: false })
      }
    },
    'speed-scope-mismatch': {
      id: 'speed-scope-mismatch',
      kind: 'speed',
      title: 'Edge Case: Containment Scope Mismatch',
      subtitle: 'Containment of sess-primary leaves independent sess-secondary activity in progress.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['Containment is scoped to sess-primary; unrelated sess-secondary events continue.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, includeSecondaryBranch: true }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, includeSecondaryBranch: true })
      }
    }
  };

  function evaluateComparisonRun(fixtureId, profileId, defenseId, options = {}) {
    const fixture = COMPARISON_FIXTURES[fixtureId];
    if (!fixture) throw new Error(`Unknown comparison fixture: ${fixtureId}`);
    const profile = COMPARISON_PROFILES[profileId];
    if (!profile) throw new Error(`Unknown comparison profile: ${profileId}`);
    const defense = COMPARISON_DEFENSES[defenseId];
    if (!defense) throw new Error(`Unknown comparison defense: ${defenseId}`);

    const rawEvents = fixture.traces[profileId] || [];
    const cutoffSec = fixture.cutoffSec;
    const useVirtualPatch = defenseId === 'patch' || (defenseId === 'combined' && options.combineVirtualPatch);
    const useSoc = defenseId === 'soc' || defenseId === 'combined';
    const useCanaries = defenseId === 'canaries' || (defenseId === 'combined' && options.useDecoySignal !== false);
    const enforcementPrecedesOnTie = !!options.enforcementPrecedesOnTie;

    const blockedEventIds = new Set();
    const containedIdentities = new Set();
    const trace = [];
    const alerts = [];

    let telemetryTimeSec = null;
    let decisionTimeSec = null;
    let enforcementTimeSec = null;
    let signalSource = null;
    let edgeBlockedTimeSec = null;
    let patchMissed = false;
    let decoyTriggeredTimeSec = null;
    let protectedReadReached = false;
    let protectedReadTimeSec = null;
    let accessDeniedObserved = false;

    const reviewedOpportunities = new Set();
    const concurrentBatchSet = new Set();
    let manualHandoffs = 0;

    let pendingContainment = null;

    function enforceContainment() {
      const { timeSec, identityId, source } = pendingContainment;
      enforcementTimeSec = timeSec;
      containedIdentities.add(identityId);
      trace.push({
        id: `soc-enforce-${identityId}`,
        timeSec,
        layerIdx: 1,
        assetId: 'cmp-api',
        relationshipId: null,
        identityId,
        kind: 'containment',
        outcome: 'enforced',
        title: 'Agentic SOC containment effective',
        detail: `Containment enforced for ${identityId} (signal: ${source}).`,
        reason: protectedReadReached
          ? 'CONTAINMENT EFFECTIVE AFTER DATA ACCESS'
          : 'CONTAINMENT EFFECTIVE'
      });
    }

    for (const ev of rawEvents) {
      if (cutoffSec !== null && ev.timeSec > cutoffSec) {
        continue;
      }

      if (pendingContainment && enforcementTimeSec === null) {
        const arrivesBefore = enforcementPrecedesOnTie
          ? pendingContainment.timeSec <= ev.timeSec
          : pendingContainment.timeSec < ev.timeSec;
        if (arrivesBefore) enforceContainment();
      }

      const prereqBlocked = (ev.prerequisiteIds || []).some(pid => blockedEventIds.has(pid));
      if (prereqBlocked) {
        blockedEventIds.add(ev.id);
        trace.push({
          ...ev,
          outcome: 'suppressed',
          reason: 'PREREQUISITE BLOCKED'
        });
        continue;
      }

      // Check if this event's identity is already contained
      if (containedIdentities.has(ev.identityId)) {
        blockedEventIds.add(ev.id);
        trace.push({
          ...ev,
          outcome: 'suppressed',
          reason: 'CONTAINMENT ACTIVE'
        });
        continue;
      }

      // Track capability review metrics for unblocked events within cutoff
      if (ev.kind === 'opportunity_review' && ev.opportunityId) {
        reviewedOpportunities.add(ev.opportunityId);
        if (ev.concurrentGroup) concurrentBatchSet.add(ev.opportunityId);
        if (ev.requiresHumanReview) manualHandoffs += 1;
      }

      // Virtual Patching check
      if (useVirtualPatch && ev.kind === 'ingress') {
        if (ev.ruleCoverage && ev.ruleCoverage.covered) {
          blockedEventIds.add(ev.id);
          edgeBlockedTimeSec = ev.timeSec;
          alerts.push({ timeSec: ev.timeSec, source: 'virtual_patch', label: ev.ruleCoverage.ruleId || 'RULE MATCH' });
          trace.push({
            ...ev,
            outcome: 'blocked',
            reason: 'RULE MATCH · BLOCKED AT EDGE'
          });
          continue;
        } else {
          patchMissed = true;
        }
      }

      // Canaries check
      if (ev.isDecoy) {
        if (useCanaries) {
          decoyTriggeredTimeSec = decoyTriggeredTimeSec === null ? ev.timeSec : Math.min(decoyTriggeredTimeSec, ev.timeSec);
          alerts.push({ timeSec: ev.timeSec, source: 'canary', label: 'DECOY TRIGGERED' });
        } else if (defenseId === 'canaries') {
          // shouldn't happen since useCanaries is true for canaries
        }
      }

      // Agentic SOC telemetry check (decoy signal only counts if useCanaries is true)
      if (useSoc && ev.telemetry && ev.telemetry.detectable) {
        const isDecoyOnly = ev.isDecoy && !useCanaries;
        if (!isDecoyOnly && !pendingContainment) {
          const sigTime = ev.timeSec;
          const decTime = sigTime + fixture.decisionDelaySec;
          const enfTime = sigTime + fixture.socLatencySec;
          telemetryTimeSec = sigTime;
          decisionTimeSec = decTime;
          signalSource = ev.isDecoy ? 'canary' : 'regular';
          alerts.push({ timeSec: sigTime, source: signalSource, label: ev.telemetry.signalLabel });
          pendingContainment = {
            timeSec: enfTime,
            identityId: ev.telemetry.containableIdentity || ev.identityId,
            source: signalSource
          };
        }
      }

      // Protected read check
      if (ev.isProtectedRead) {
        if (ev.accessDenied) {
          accessDeniedObserved = true;
          trace.push({
            ...ev,
            outcome: 'denied',
            reason: 'ACCESS DENIED'
          });
        } else {
          protectedReadReached = true;
          protectedReadTimeSec = ev.timeSec;
          trace.push({
            ...ev,
            outcome: 'succeeded',
            reason: 'PROTECTED RECORD READ'
          });
        }
        continue;
      }

      trace.push({
        ...ev,
        outcome: ev.isDecoy && useCanaries ? 'alert' : 'succeeded',
        reason: ev.isDecoy && useCanaries
          ? (defenseId === 'canaries' ? 'DECOY TRIGGERED · ALERT ONLY' : 'DECOY TRIGGERED · SIGNAL TO SOC')
          : (useVirtualPatch && ev.kind === 'ingress' ? 'OUTSIDE RULE COVERAGE' : 'OBSERVED')
      });
    }

    if (pendingContainment && enforcementTimeSec === null &&
        (cutoffSec === null || pendingContainment.timeSec <= cutoffSec)) {
      enforceContainment();
    }

    trace.sort((a, b) => a.timeSec - b.timeSec);

    // Determine baseline reference protected read time for margin / lead time calculations
    let baselineProtectedReadSec = null;
    if (defenseId === 'baseline') {
      baselineProtectedReadSec = protectedReadTimeSec;
    } else {
      const baseRun = evaluateComparisonRun(fixtureId, profileId, 'baseline');
      baselineProtectedReadSec = baseRun.protectedReadTimeSec;
    }

    alerts.sort((a, b) => a.timeSec - b.timeSec);
    const firstAlert = alerts.length > 0 ? alerts[0] : null;
    const firstAlertTimeSec = firstAlert ? firstAlert.timeSec : null;
    const firstAlertSource = firstAlert ? firstAlert.source : null;

    // Determine effective control time & reason
    let effectiveControlTimeSec = null;
    let controlReason = 'NO ACTIVE DEFENSES';

    if (defenseId === 'baseline') {
      controlReason = accessDeniedObserved ? 'ACCESS DENIED' : (protectedReadReached ? 'UNMITIGATED · PROTECTED READ' : 'NO PROTECTED READ BY CUTOFF');
    } else if (edgeBlockedTimeSec !== null) {
      effectiveControlTimeSec = edgeBlockedTimeSec;
      controlReason = 'RULE MATCH · BLOCKED AT EDGE';
    } else if (defenseId === 'patch') {
      controlReason = 'OUTSIDE RULE COVERAGE';
    } else if (defenseId === 'canaries') {
      if (decoyTriggeredTimeSec !== null) {
        controlReason = 'DECOY TRIGGERED · ALERT ONLY';
      } else {
        controlReason = 'DECOY UNTOUCHED · NO ALERT';
      }
    } else if (defenseId === 'soc' || defenseId === 'combined') {
      if (!pendingContainment) {
        controlReason = 'NO MATCHING SIGNAL';
      } else if (enforcementTimeSec === null) {
        controlReason = 'CONTAINMENT PENDING AT CUTOFF';
      } else {
        effectiveControlTimeSec = enforcementTimeSec;
        if (protectedReadReached) {
          controlReason = 'CONTAINMENT EFFECTIVE AFTER DATA ACCESS';
        } else {
          controlReason = 'CONTAINED BEFORE DATA ACCESS';
        }
      }
    }

    const responseMarginSec = (baselineProtectedReadSec !== null && effectiveControlTimeSec !== null)
      ? baselineProtectedReadSec - effectiveControlTimeSec
      : null;

    const detectionLeadTimeSec = (baselineProtectedReadSec !== null && firstAlertTimeSec !== null)
      ? baselineProtectedReadSec - firstAlertTimeSec
      : null;

    return {
      fixtureId,
      fixtureKind: fixture.kind,
      fixtureTitle: fixture.title,
      profileId,
      profileLabel: profile.label,
      defenseId,
      defenseLabel: defense.label,
      cutoffSec,
      protectedReadReached,
      protectedReadTimeSec,
      accessDeniedObserved,
      baselineProtectedReadSec,
      firstAlertTimeSec,
      firstAlertSource,
      telemetryTimeSec,
      decisionTimeSec,
      enforcementTimeSec,
      scheduledEnforcementTimeSec: pendingContainment?.timeSec ?? null,
      effectiveControlTimeSec,
      signalSource,
      controlReason,
      responseMarginSec,
      detectionLeadTimeSec,
      patchMissed,
      opportunitiesReviewed: reviewedOpportunities.size,
      concurrentReviews: concurrentBatchSet.size,
      manualHandoffs,
      assumptions: fixture.assumptions,
      trace
    };
  }

  function evaluateComparisonMatrix(fixtureId, options = {}) {
    const profiles = ['pre2023', 'artex'];
    const defenses = ['baseline', 'patch', 'soc', 'canaries', 'combined'];
    const cells = {};
    for (const p of profiles) {
      cells[p] = {};
      for (const d of defenses) {
        cells[p][d] = evaluateComparisonRun(fixtureId, p, d, options);
      }
    }
    return {
      fixture: COMPARISON_FIXTURES[fixtureId],
      estate: createComparisonEstate(),
      cells
    };
  }

  return {
    SCHEMA_VERSION,
    RUN_MANIFEST_VERSION,
    ENGINE_VERSION,
    CALIBRATION_REGISTER,
    BEHAVIOR_PRESETS,
    DEFENSE_CONFIG_PRESETS,
    INFRASTRUCTURE_ARCHETYPES,
    SCENARIO_TEMPLATES,
    SURFACE_COVERAGE_MANIFEST,
    REVIEWED_EXAMPLES,
    REVIEWED_VARIANT_CVES,
    MAX_ONWARD_PER_SOURCE,
    MAX_SUCCESS_PER_LAYER,
    LAYER_FINDING_BUDGETS,
    CVE_ATTACK_DESCRIPTIONS,
    LAYER_KEVS,
    KEV_MITIGATION_RULES,
    LAYER_CONFIG,
    ALLOWED_CONNECTIONS,
    EXTERNAL_ENTRY_GROUPS,
    DEFENSE_SCENARIOS,
    ATTACKER_PROFILES,
    gangTechniqueEvidence,
    classifyRun,
    wireTiming,
    WIRE_ATTACKERS,
    COMPARISON_PROFILES,
    COMPARISON_DEFENSES,
    COMPARISON_FIXTURES,
    PRE2023_ATTACK_PATTERNS,
    createComparisonEstate,
    formatDurationSeconds,
    formatSignedDelta,
    evaluateComparisonRun,
    evaluateComparisonMatrix,
    createRng,
    hashSemanticKey,
    cveTooltip,
    validateCalibrationRegister,
    validateEstate,
    validateRunConfig,
    validateWalkthrough,
    auditSurfaceCoverage,
    isSensitiveDatasetRead,
    instantiateScenario,
    convertLegacySnapshot,
    normalizeDefenseConfig,
    normalizeAttackerProfile,
    evaluateVirtualPatch,
    evaluateDecoyInteraction,
    emitSensorObservations,
    executeScopedResponse,
    createDefaultRunConfig,
    simulateScenario,
    projectRun,
    evaluateComparison,
    exportManifest,
    exportWirePlayback,
    importManifest,
    evaluateAction,
    evaluateDistinctActions,
    evaluateDefense,
    simulateEstate,
    simulateWireRun,
    generateEstate,
    referenceServiceFlow,
    migrateSnapshot
  };
}));
