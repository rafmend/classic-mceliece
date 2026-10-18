import sys
import time
from typing import List, Tuple, Dict, Any
import numpy as np
from .params import ParameterSet
from .gf import bits_to_bytes_le

_TORCH = None
_TORCH_LOAD_ATTEMPTED = False


def _get_torch():
    global _TORCH, _TORCH_LOAD_ATTEMPTED
    if not _TORCH_LOAD_ATTEMPTED:
        _TORCH_LOAD_ATTEMPTED = True
        try:
            import torch
            _TORCH = torch
        except ImportError:
            _TORCH = None
    return _TORCH


def get_gpu_info(load_torch: bool = True) -> Dict[str, Any]:
    if not load_torch and "torch" not in sys.modules:
        return {"available": False, "device_name": "CPU (carga GPU diferida, activar con --gpu)"}
    torch = _get_torch()
    if torch is None or not torch.cuda.is_available():
        return {"available": False, "device_name": "CPU (CUDA no disponible)"}
    return {
        "available": True,
        "device_name": torch.cuda.get_device_name(0),
        "device_count": torch.cuda.device_count(),
    }


def encode_cpu(e_bits: List[int], pk_bytes: bytes, params: ParameterSet) -> bytes:
    """Calcula C = (I_mt | T) * e sobre F_2 en CPU."""
    mt = params.mt
    k = params.k
    row_bytes = params.row_bytes
    e_high = np.array(e_bits[:mt], dtype=np.uint8)
    e_low = np.array(e_bits[mt:mt + k], dtype=np.uint8)

    pk_arr = np.frombuffer(pk_bytes, dtype=np.uint8).reshape(mt, row_bytes)
    T_bits = np.unpackbits(pk_arr, axis=1, bitorder="little")[:, :k]
    prod = (T_bits @ e_low.astype(np.uint32)) & 1
    c_bits = (e_high ^ prod.astype(np.uint8)).tolist()
    return bits_to_bytes_le(c_bits)


def encode_gpu(e_bits: List[int], pk_bytes: bytes, params: ParameterSet) -> Tuple[bytes, str]:
    """Calcula C = (I_mt | T) * e sobre F_2 usando PyTorch CUDA si está disponible."""
    info = get_gpu_info()
    if not info["available"]:
        return encode_cpu(e_bits, pk_bytes, params), "CPU (Fallback)"

    torch = _get_torch()
    device = torch.device("cuda:0")
    mt = params.mt
    k = params.k
    row_bytes = params.row_bytes

    pk_arr = np.frombuffer(pk_bytes, dtype=np.uint8).reshape(mt, row_bytes)
    T_bits = np.unpackbits(pk_arr, axis=1, bitorder="little")[:, :k]

    e_high_np = np.array(e_bits[:mt], dtype=np.uint8)
    e_low_np = np.array(e_bits[mt:mt + k], dtype=np.float32)

    T_gpu = torch.from_numpy(T_bits).to(device=device, dtype=torch.float32)
    e_low_gpu = torch.from_numpy(e_low_np).to(device=device)
    e_high_gpu = torch.from_numpy(e_high_np).to(device=device)

    prod_gpu = (torch.mv(T_gpu, e_low_gpu).to(torch.int32) & 1).to(torch.uint8)
    c_gpu = (e_high_gpu ^ prod_gpu).cpu().numpy().tolist()
    return bits_to_bytes_le(c_gpu), info["device_name"]


def benchmark_encode(pk_bytes: bytes, params: ParameterSet, batch_size: int = 256) -> Dict[str, Any]:
    """Compara el rendimiento de codificación por lotes entre CPU y GPU."""
    mt, k, row_bytes = params.mt, params.k, params.row_bytes
    pk_arr = np.frombuffer(pk_bytes, dtype=np.uint8).reshape(mt, row_bytes)
    T_bits = np.unpackbits(pk_arr, axis=1, bitorder="little")[:, :k]

    # NOTA DE SEGURIDAD: np.random se usa EXCLUSIVAMENTE aquí para generar datos sintéticos
    # de benchmarking de throughput matricial. La ruta criptográfica (KEM/DEM) usa os.urandom.
    E_low = np.random.randint(0, 2, size=(k, batch_size), dtype=np.uint32)
    t0 = time.perf_counter()
    _ = (T_bits.astype(np.uint32) @ E_low) & 1
    cpu_ms = (time.perf_counter() - t0) * 1000.0

    gpu_ms = None
    info = get_gpu_info()
    if info["available"]:
        torch = _get_torch()
        device = torch.device("cuda:0")
        T_gpu = torch.from_numpy(T_bits).to(device=device, dtype=torch.float32)
        E_gpu = torch.from_numpy(E_low.astype(np.float32)).to(device=device)
        torch.cuda.synchronize()
        t1 = time.perf_counter()
        _ = torch.matmul(T_gpu, E_gpu).to(torch.int32) & 1
        torch.cuda.synchronize()
        gpu_ms = (time.perf_counter() - t1) * 1000.0

    return {
        "batch_size": batch_size,
        "cpu_ms": cpu_ms,
        "gpu_ms": gpu_ms,
        "device": info["device_name"],
    }
