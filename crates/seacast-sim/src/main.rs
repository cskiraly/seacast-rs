use seacast_sim::{SimConfig, SimSetting, run_simulation};

fn main() {
    let scenarios = [
        ("Tier4", SimConfig { setting: SimSetting::Tier4, ..SimConfig::default() }),
        ("VariantC", SimConfig { setting: SimSetting::VariantC, ..SimConfig::default() }),
        ("Custody", SimConfig {
            setting: SimSetting::Custody,
            withhold_half_columns: true,
            supernodes: 2,
            ..SimConfig::default()
        }),
        ("Rows", SimConfig {
            setting: SimSetting::Rows,
            withhold_half_columns: true,
            supernodes: 1,
            liar_nodes: 2,
            ..SimConfig::default()
        }),
        ("Sampling", SimConfig {
            setting: SimSetting::Sampling,
            samplers: 4,
            ..SimConfig::default()
        }),
    ];

    println!(
        "{:<10} {:>8} {:>9} {:>9} {:>9} {:>8} {:>7} {:>8} {:>9} {:>9}",
        "Setting",
        "Pub",
        "EagerTx",
        "SourceTx",
        "RepairTx",
        "Answers",
        "I3_Err",
        "DutyErr",
        "p50 (ms)",
        "p99 (ms)"
    );
    println!("{}", "-".repeat(95));

    for (name, cfg) in scenarios {
        let report = run_simulation(cfg);
        println!(
            "{:<10} {:>8} {:>9} {:>9} {:>9} {:>8} {:>7} {:>8} {:>9.1} {:>9.1}",
            name,
            report.chunks_published,
            report.eager_pushes,
            report.source_pushes,
            report.repair_pushes,
            report.answers_sent,
            report.violations_i3,
            report.violations_duty_budget,
            report.p50_completion_ms,
            report.p99_completion_ms,
        );
        assert!(report.invariants_hold(), "{} failed invariants: {:?}", name, report);
    }
}
