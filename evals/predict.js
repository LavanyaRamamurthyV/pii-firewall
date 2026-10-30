// Prints JS-engine predictions for evals/dataset.jsonl as JSON lines (used by evals/run.py).
const fs = require("fs");
const path = require("path");
const { detect } = require("../core/js/pii-core.js");

const lines = fs.readFileSync(path.join(__dirname, "dataset.jsonl"), "utf8").trim().split("\n");
for (const line of lines) {
  const ex = JSON.parse(line);
  const spans = detect(ex.text).map(({ type, start, end }) => ({ type, start, end }));
  process.stdout.write(JSON.stringify({ id: ex.id, spans }) + "\n");
}
