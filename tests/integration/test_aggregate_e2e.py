"""End-to-end tests for the aggregate POST /mcp endpoint against TWO real FastMCP upstreams
registered simultaneously — proves cross-server namespacing, routing, and policy enforcement
all work through the aggregate layer exactly as they do through /mcp/{slug}."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.models import ServerPolicy
from db.repo import ServerRepo

from .fastmcp_fixture import run_fastmcp_server


@pytest.fixture
async def two_upstreams():
    async with run_fastmcp_server() as a, run_fastmcp_server() as b:
        yield a, b


@pytest.fixture
async def argus_client(tmp_path: Path, two_upstreams):
    upstream_a, upstream_b = two_upstreams
    settings = Settings(data_dir=str(tmp_path), auth_mode="open", health_poll_enabled=False)
    db = Database(tmp_path)
    await db.connect()

    server_repo = ServerRepo(db)
    await server_repo.create(slug="server-a", name="Server A", upstream_url=f"{upstream_a.url}/mcp")
    await server_repo.create(slug="server-b", name="Server B", upstream_url=f"{upstream_b.url}/mcp")

    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://argus.test") as client:
            yield client, server_repo, upstream_a, upstream_b, db

    await db.close()


def _rpc(rpc_method: str, params: dict, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": rpc_method, "params": params}


HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


async def test_aggregate_tools_list_merges_and_namespaces_both_servers(argus_client):
    client, _, _, _, _ = argus_client
    resp = await client.post("/mcp", json=_rpc("tools/list", {}), headers=HEADERS)
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert "server-a__echo" in names
    assert "server-b__echo" in names


async def test_aggregate_tools_call_routes_to_correct_server(argus_client):
    client, _, upstream_a, upstream_b, _ = argus_client
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", {"name": "server-a__echo", "arguments": {"message": "to A"}}),
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["content"][0]["text"] == "to A"
    assert upstream_a.call_counter.get("echo") == 1
    assert upstream_b.call_counter.get("echo") is None  # must NOT cross-fire the other server


async def test_aggregate_tools_call_second_server(argus_client):
    client, _, upstream_a, upstream_b, _ = argus_client
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", {"name": "server-b__echo", "arguments": {"message": "to B"}}),
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert upstream_b.call_counter.get("echo") == 1
    assert upstream_a.call_counter.get("echo") is None


async def test_aggregate_respects_per_server_policy(argus_client):
    client, server_repo, upstream_a, _, _ = argus_client
    server_a = await server_repo.get("server-a")
    await server_repo.set_policy(server_a.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    # write_file is denied on server-a -> must be blocked even through the aggregate.
    resp = await client.post(
        "/mcp",
        json=_rpc("tools/call", {"name": "server-a__write_file", "arguments": {"path": "/x", "content": "y"}}),
        headers=HEADERS,
    )
    assert resp.status_code == 403
    assert upstream_a.call_counter.get("write_file") is None


async def test_aggregate_tools_list_hides_denied_tools(argus_client):
    client, server_repo, _, _, _ = argus_client
    server_a = await server_repo.get("server-a")
    await server_repo.set_policy(server_a.id, ServerPolicy(mode="allowlist", allowed=["echo"]))

    resp = await client.post("/mcp", json=_rpc("tools/list", {}), headers=HEADERS)
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert "server-a__echo" in names
    assert "server-a__write_file" not in names
    assert "server-b__write_file" in names  # server-b is unaffected


async def test_aggregate_excludes_server_not_in_aggregate(argus_client):
    client, server_repo, _, _, _ = argus_client
    await server_repo.update("server-a", in_aggregate=False)

    resp = await client.post("/mcp", json=_rpc("tools/list", {}), headers=HEADERS)
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert not any(n.startswith("server-a__") for n in names)
    assert any(n.startswith("server-b__") for n in names)


async def test_aggregate_tools_call_unknown_namespaced_server_404(argus_client):
    client, _, _, _, _ = argus_client
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", {"name": "no-such-server__echo", "arguments": {}}), headers=HEADERS,
    )
    assert resp.status_code == 404


async def test_aggregate_tools_call_malformed_name_400(argus_client):
    client, _, _, _, _ = argus_client
    resp = await client.post(
        "/mcp", json=_rpc("tools/call", {"name": "not-namespaced", "arguments": {}}), headers=HEADERS,
    )
    assert resp.status_code == 400


async def test_aggregate_server_discover(argus_client):
    client, _, _, _, _ = argus_client
    resp = await client.post("/mcp", json=_rpc("server/discover", {}), headers=HEADERS)
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert set(result["aggregatedServers"]) == {"server-a", "server-b"}
    assert "subscriptions" not in result["capabilities"]


async def test_aggregate_unsupported_method_returns_clean_error(argus_client):
    client, _, _, _, _ = argus_client
    resp = await client.post("/mcp", json=_rpc("subscriptions/listen", {}), headers=HEADERS)
    assert resp.status_code == 501


async def test_per_server_endpoint_still_works_alongside_aggregate(argus_client):
    """Regression: registering 2 servers and hitting /mcp must not break direct /mcp/{slug}."""
    client, _, upstream_a, _, _ = argus_client
    session_init = await client.post(
        "/mcp/server-a",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "c", "version": "1"}}},
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    assert session_init.status_code == 200
    assert upstream_a.call_counter.get("echo") is None  # initialize alone doesn't call any tool
