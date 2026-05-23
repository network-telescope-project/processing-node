import os
import clickhouse_connect

_client = None


def get_client():
    global _client
    if _client is None:
        _client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_HTTP_PORT", "8123")),
            username=os.environ.get("CLICKHOUSE_USER", "telescope"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=os.environ.get("CLICKHOUSE_DB", "telescope"),
        )
    return _client
