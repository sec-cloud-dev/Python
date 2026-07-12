import sys
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.checks.sa_checks import checks_sa_stat_key


@patch("src.checks.sa_checks.sa_get")
@patch("src.checks.sa_checks.access_key_sa")
def test_checks_sa_stat_key_danger_and_never_used(mock_access_key, mock_sa_get):
    now = datetime.now(timezone.utc)
    old_date_str = (now - timedelta(days=100)).isoformat().replace("+00:00", "Z")
    new_date_str = now.isoformat().replace("+00:00", "Z")

    mock_sa_get.return_value = [{"id": "sa-1", "name": "danger-sa"}, {"id": "sa-2", "name": "warning-sa"}]

    mock_access_key.side_effect = [
        [{"keyId": "key-old", "createdAt": old_date_str, "lastUsedAt": new_date_str}],
        [{"keyId": "key-never", "createdAt": new_date_str, "lastUsedAt": None}],
    ]

    result = checks_sa_stat_key("fake-folder-id")

    assert result["status"] == "DANGER"
    assert len(result["report"]) == 2

    assert result["report"][0]["sa_name"] == "danger-sa"
    assert result["report"][0]["risk"] == "DANGER"

    assert result["report"][1]["sa_name"] == "warning-sa"
    assert result["report"][1]["last_used"] == "never"
    assert result["report"][1]["risk"] == "WARNING"