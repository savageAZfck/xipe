use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;
use xipe::{Constitution, Verdict};

fn unanimous() -> Verdict {
    Verdict {
        decision: "approve".into(),
        mean: 1.0,
        dissent: 0.0,
        unanimous_approve: true,
        summary: "4/4".into(),
        votes: vec![],
    }
}

fn journal_verify(c: &mut Criterion) {
    let dir = std::env::temp_dir().join(format!("xipe-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let con = Constitution::builder(&dir).build().unwrap();
    for i in 0..100 {
        let id = con
            .propose("weight_graft", json!({"i": i}), "dream")
            .unwrap();
        con.record_verdict(&id, &unanimous()).unwrap();
        con.mark_applied(&id, json!({})).unwrap();
    }
    c.bench_function("verify_journal 300 entries", |b| {
        b.iter(|| con.verify_journal().unwrap())
    });
    c.bench_function("verify_all 100 artifacts", |b| {
        b.iter(|| con.verify_all().unwrap())
    });
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, journal_verify);
criterion_main!(benches);
