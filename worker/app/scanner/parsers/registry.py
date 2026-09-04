from app.scanner.parsers.base import BaseParser
from app.scanner.parsers.dns_parser import DNSParser
from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nikto_parser import NiktoParser
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.nuclei_parser import NucleiParser
from app.scanner.parsers.api_parser import ApiParser
from app.scanner.parsers.container_parser import ContainerParser
from app.scanner.parsers.iac_parser import IacParser
from app.scanner.parsers.sast_parser import SASTParser
from app.scanner.parsers.sarif_parser import SarifParser
from app.scanner.parsers.sca_parser import SCAParser
from app.scanner.parsers.secrets_parser import SecretsParser
from app.scanner.parsers.subdomain_parser import SubdomainParser
from app.scanner.parsers.tls_parser import TLSParser
from app.scanner.parsers.zap_parser import ZAPParser


class ParserRegistry:

    def __init__(self):
        self._parsers: dict[str, BaseParser] = {}
        self._register_builtin_parsers()

    # ---------------------------------------------------------
    # Registration
    # ---------------------------------------------------------

    def _register_builtin_parsers(self):
        self.register(NmapParser())
        self.register(NucleiParser())
        self.register(HTTPFingerprintParser())
        self.register(ZAPParser())
        self.register(NiktoParser())
        self.register(TLSParser())
        self.register(DNSParser())
        self.register(SubdomainParser())
        self.register(SCAParser())
        self.register(SASTParser())
        self.register(SarifParser())
        self.register(SecretsParser())
        self.register(ContainerParser())
        self.register(IacParser())
        self.register(ApiParser())

    def register(self, parser: BaseParser):
        if not parser.scanner_name:
            raise ValueError(
                "Parser must define a scanner_name."
            )

        if parser.scanner_name in self._parsers:
            raise ValueError(
                f"Parser for scanner "
                f"'{parser.scanner_name}' is already registered."
            )

        self._parsers[parser.scanner_name] = parser

    # ---------------------------------------------------------
    # Retrieval
    # ---------------------------------------------------------

    def get(self, scanner_name: str) -> BaseParser:

        parser = self._parsers.get(scanner_name)

        if parser is None:
            raise ValueError(
                f"No parser registered for scanner "
                f"'{scanner_name}'."
            )

        return parser

    # ---------------------------------------------------------
    # Listing
    # ---------------------------------------------------------

    def list(self) -> list[str]:
        return sorted(
            self._parsers.keys()
        )