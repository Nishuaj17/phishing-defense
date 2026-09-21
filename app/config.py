"""Configuration from environment variables (12-factor style). No secrets live in code."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _f(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass(frozen=True)
class Config:
    url_model_path: str = "models/url_v1.joblib"
    fusion_path: str = "models/fusion_v1.json"
    ti_list_path: str = ""     # optional local blocklist file; empty disables threat intel
    db_path: str = "data/app.db"
    t_low: float = 0.06
    t_high: float = 0.93
    rate_per_minute: int = 20
    rate_burst: int = 8
    trust_proxy: bool = False  # only true behind a proxy you control (uses X-Forwarded-For)
    store_urls: bool = True    # set to 0 to log only hostnames/decisions
    admin_token: str = ""      # empty disables /api/history

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        return cls(
            url_model_path=e("PHISHDEF_URL_MODEL", cls.url_model_path),
            fusion_path=e("PHISHDEF_FUSION", cls.fusion_path),
            ti_list_path=e("PHISHDEF_TI_LIST", cls.ti_list_path),
            db_path=e("PHISHDEF_DB", cls.db_path),
            t_low=_f("PHISHDEF_T_LOW", cls.t_low),
            t_high=_f("PHISHDEF_T_HIGH", cls.t_high),
            rate_per_minute=int(e("PHISHDEF_RATE_PER_MIN", cls.rate_per_minute)),
            rate_burst=int(e("PHISHDEF_RATE_BURST", cls.rate_burst)),
            trust_proxy=e("PHISHDEF_TRUST_PROXY", "0") == "1",
            store_urls=e("PHISHDEF_STORE_URLS", "1") == "1",
            admin_token=e("PHISHDEF_ADMIN_TOKEN", ""),
        )
