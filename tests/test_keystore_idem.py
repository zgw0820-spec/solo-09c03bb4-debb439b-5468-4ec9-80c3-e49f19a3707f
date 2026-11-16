"""密钥服务幂等语义：rotate/rewrap/destroy 重放不产生副作用。"""
from conftest import _key_headers, _wait_rotation  # noqa: F401


def test_rotate_idempotency_token_reuses_same_keys(stack):
    kc = stack["key_client"]
    h = {**_key_headers(), "X-Idempotency-Token": "rot-token-1"}
    r1 = kc.post("/internal/master/rotate", headers=h)
    r2 = kc.post("/internal/master/rotate", headers=h)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["new_key_id"] == r2.json()["new_key_id"]
    assert r2.json().get("idempotent") is True
    # 不带令牌的调用会产生新 MK
    r3 = kc.post("/internal/master/rotate", headers=_key_headers())
    assert r3.json()["new_key_id"] != r1.json()["new_key_id"]


def test_rewrap_idempotency_token_returns_same_envelope(stack):
    kc = stack["key_client"]
    h = _key_headers()
    # 先有一把旧 MK 下的 DEK
    rot = kc.post("/internal/master/rotate", headers=h).json()
    old_mk = rot["old_key_id"]
    # 用更老的 MK 视角生成 DEK：直接对旧 MK 无生成接口，改为 rotate 前生成。
    # 这里简化：用当前 MK 生成 DEK，再 rotate，随后 rewrap 验证幂等即可。
    dek1 = kc.post("/internal/dek/generate", headers=h).json()
    rot2 = kc.post("/internal/master/rotate", headers=h).json()
    body = {"key_id": rot2["old_key_id"], "wrapped_dek": dek1["wrapped_dek"]}
    rh = {**h, "X-Idempotency-Token": "rewrap-token-1"}
    a = kc.post("/internal/dek/rewrap", json=body, headers=rh).json()
    b = kc.post("/internal/dek/rewrap", json=body, headers=rh).json()
    assert a["wrapped_dek"] == b["wrapped_dek"]
    assert b.get("idempotent") is True
    assert a["key_id"] == rot2["new_key_id"]
    assert old_mk  # 仅用于引用，确保流程经过至少两次轮换


def test_destroy_is_idempotent_and_rejects_unwrap_afterward(stack):
    kc = stack["key_client"]
    h = _key_headers()
    target = kc.post("/internal/master/rotate", headers=h).json()["old_key_id"]
    d1 = kc.post("/internal/master/destroy",
                 json={"key_id": target}, headers=h)
    d2 = kc.post("/internal/master/destroy",
                 json={"key_id": target}, headers=h)
    assert d1.status_code == d2.status_code == 200
    assert d2.json().get("idempotent") is True
    st = kc.get("/internal/master/status", headers=h).json()
    states = {k["key_id"]: k["state"] for k in st["keys"]}
    assert states[target] == "destroyed"
    # 销毁后解包/改包一律 410
    r = kc.post("/internal/dek/unwrap",
                json={"key_id": target, "wrapped_dek": "00" * 64}, headers=h)
    assert r.status_code == 410
