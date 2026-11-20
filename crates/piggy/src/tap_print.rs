//! One TAP-14 printer for the verbs that account for themselves as points
//! (`card rotate-admin`, `ca verify`): a plan ahead, one `ok`/`not ok` line
//! per point, its diagnostics as the YAML block tap-dancer writes. Plain
//! and deterministic (as `piggy health --format tap`), so a wrapper reads a
//! plan and the lines.

use std::io::Write;

/// One point: its name, whether it passed, and its diagnostics.
pub struct Point<'a> {
    pub name: &'a str,
    pub ok: bool,
    pub diags: Vec<(&'a str, serde_json::Value)>,
}

pub fn print_tap(points: &[Point<'_>]) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    {
        let mut rep =
            tap_dancer::Reporter::Tap(tap_dancer::TapWriterBuilder::new(&mut out).build()?);
        rep.plan_ahead(points.len())?;
        for point in points {
            match (point.ok, point.diags.is_empty()) {
                (true, true) => rep.ok(point.name)?,
                (true, false) => rep.ok_diag(point.name, &point.diags)?,
                (false, _) => rep.not_ok_diag(point.name, &point.diags)?,
            };
        }
        rep.finish()?;
    }
    out.flush()
}
