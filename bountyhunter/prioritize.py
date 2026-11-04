from .storage import URLStore
from .urlintel import score_url


def prioritize(store: URLStore) -> int:
    rows = store.rows()
    for row in rows:
        score, reasons = score_url(row["url"])
        store.set_score(row["url"], score, reasons)
    return len(rows)
