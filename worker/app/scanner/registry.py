from app.scanner.base import BaseScanner
from app.scanner.scanners.api import ApiScanner
from app.scanner.scanners.container import ContainerScanner
from app.scanner.scanners.dns import DNSScanner
from app.scanner.scanners.iac import IacScanner
from app.scanner.scanners.http_fingerprint import HTTPFingerprintScanner
from app.scanner.scanners.nikto import NiktoScanner
from app.scanner.scanners.nmap import NmapScanner
from app.scanner.scanners.nuclei import NucleiScanner
from app.scanner.scanners.sast import SASTScanner
from app.scanner.scanners.sca import SCAScanner
from app.scanner.scanners.secrets import SecretsScanner
from app.scanner.scanners.sqlmap import SQLMapScanner
from app.scanner.scanners.subdomain import SubdomainScanner
from app.scanner.scanners.tls import TLSScanner
from app.scanner.scanners.zap import ZAPScanner


class ScannerRegistry:

    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}

        self._register_builtin_scanners()

    # ---------------------------------------------------------
    # Registration
    # ---------------------------------------------------------

    def _register_builtin_scanners(self):
        self.register(NmapScanner())
        self.register(NucleiScanner())
        self.register(HTTPFingerprintScanner())
        self.register(ZAPScanner())
        self.register(NiktoScanner())
        self.register(TLSScanner())
        self.register(DNSScanner())
        self.register(SubdomainScanner())
        self.register(SCAScanner())
        self.register(SASTScanner())
        self.register(SecretsScanner())
        self.register(ContainerScanner())
        self.register(IacScanner())
        self.register(ApiScanner())
        self.register(SQLMapScanner())

    def register(self, scanner: BaseScanner):
        if not scanner.name:
            raise ValueError(
                "Scanner must define a name."
            )

        if scanner.name in self._scanners:
            raise ValueError(
                f"Scanner '{scanner.name}' is already registered."
            )

        self._scanners[scanner.name] = scanner

    # ---------------------------------------------------------
    # Retrieval
    # ---------------------------------------------------------

    def get(self, name: str) -> BaseScanner:

        scanner = self._scanners.get(name)

        if scanner is None:
            raise ValueError(
                f"Scanner '{name}' is not registered."
            )

        return scanner

    # ---------------------------------------------------------
    # Listing
    # ---------------------------------------------------------

    def list(self) -> list[dict]:

        return [
            scanner.metadata()
            for scanner in self._scanners.values()
        ]