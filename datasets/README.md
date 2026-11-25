# SMS Project datasets

## Folder policy
- `raw/`: original downloaded files; do not edit or overwrite these.
- `processed/`: normalized, deduplicated and label-mapped files (create during preprocessing).
- `splits/`: train/validation/test manifests or exported split files.
- `reports/`: dataset audits, source overlap and quality reports.
- Keep source names and provenance in every processed row.

## Sources
1. UCI SMS Spam Collection
2. IIIT-D SMS Dataset (2011-12)
3. Junioralive India SMS
4. CloveAI India Spam SMS
5. carnageiron Scam/Ham India (pending download)

See `DATASET_MANIFEST.json` for current file status. A file in `_unverified_incoming/` has not been assigned to a source yet.

## Suggested normalized schema
`text, label, source, source_row_id, language, is_synthetic, original_label`

Use `label=0` for ham and `label=1` for spam only after verifying each source's label mapping.
Do not treat `spam` as synonymous with `scam`: preserve the original label and add a separate scam annotation only when supported.
