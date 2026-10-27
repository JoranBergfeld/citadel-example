"""Read the pinned raw ARM regional model catalog, not CLI SDK projections."""


def regional_standard_sku(rows):
    candidates = [row for row in rows if row.get("kind") == "OpenAI"
                  and row.get("model", {}).get("name") == "gpt-4.1-mini"
                  and row["model"].get("version") == "2025-04-14"]
    skus = [sku for row in candidates for sku in row["model"].get("skus", [])
            if sku.get("name") == "Standard"]
    if len(candidates) != 1 or len(skus) != 1:
        raise ValueError("Exact OpenAI regional Standard model SKU required")
    return candidates, skus[0]
