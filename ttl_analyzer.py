import platform
from typing import Dict, Tuple, Optional

class TTLAnalyzer:
    DEFAULT_TTL_VALUES = {
        64: ["Linux", "macOS", "Android"],
        128: ["Windows"],
        255: ["Cisco IOS", "Solaris"]
    }
    
    @staticmethod
    def detect_os(ttl: int) -> Tuple[str, int]:
        for default_ttl in sorted(TTLAnalyzer.DEFAULT_TTL_VALUES.keys()):
            if ttl <= default_ttl:
                systems = TTLAnalyzer.DEFAULT_TTL_VALUES[default_ttl]
                return (systems[0], default_ttl)
        return ("Unknown", 255)
    
    @staticmethod
    def calculate_hop_count(ttl: int, initial_ttl: Optional[int] = None) -> int:
        if initial_ttl:
            return initial_ttl - ttl
        _, estimated_initial = TTLAnalyzer.detect_os(ttl)
        return estimated_initial - ttl
    
    @staticmethod
    def get_local_ttl() -> int:
        system = platform.system()
        if system == "Windows":
            return 128
        elif system in ["Linux", "Darwin"]:
            return 64
        else:
            return 64