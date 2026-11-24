import { db, now } from "../db.js";

export default {
  async run(ctx) {
    const rows = db
      .prepare(
        `SELECT rule_id, COUNT(*) AS total, SUM(verified) AS verified,
         SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) AS fp
         FROM findings WHERE scan_id = ? GROUP BY rule_id`,
      )
      .all(ctx.scan.id);
    let adjusted = 0;
    for (const row of rows) {
      if (!row.total) continue;
      const precision = (row.total - row.fp) / row.total;
      const weight = Math.max(0.35, Math.min(1.6, 0.6 + precision * 0.8 + (row.verified ? 0.1 : 0)));
      db.prepare(
        `INSERT INTO rule_stats(rule_id, runs, verified, false_positive, weight, updated_at)
         VALUES(?, ?, ?, ?, ?, ?)
         ON CONFLICT(rule_id) DO UPDATE SET runs = runs + excluded.runs,
         verified = verified + excluded.verified, false_positive = false_positive + excluded.false_positive,
         weight = ROUND((weight * 0.7) + (excluded.weight * 0.3), 3), updated_at = excluded.updated_at`,
      ).run(row.rule_id, row.total, row.verified || 0, row.fp || 0, weight, now());
      adjusted += 1;
    }
    const total = db.prepare("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?").get(ctx.scan.id).n;
    const verified = db.prepare("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND verified = 1").get(ctx.scan.id).n;
    const fp = db.prepare("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND status = 'false_positive'").get(ctx.scan.id).n;
    const precision = total ? Math.round(((total - fp) / total) * 1000) / 10 : 0;
    ctx.emit("info", `Optimizer updated ${adjusted} rule weights · precision ${precision}%`);
    return `${adjusted} rules adjusted · precision ${precision}%`;
  },
};
