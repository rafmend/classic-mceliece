from mceliece.toy_verifier import run_toy_verification

def test_toy_verification():
    res = run_toy_verification(verbose=False)
    assert res["status"] == "OK"
    assert res["verified_sections"] == 8
    assert res["K_hex"] == "597f46fbba325c68f0b0b45c6ea984961461eb220d1f24024ed888912b336278"
    assert res["K_rejected_hex"] == "ba1a72ac26b0fcf20c55c108bb681e27aa9c270c60802a821601130b7f1e1494"
