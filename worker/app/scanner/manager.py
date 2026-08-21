from app.scanner.scanners.nmap import NmapScanner


class ScannerManager:

    def __init__(self):
        self.scanners = {
            "nmap": NmapScanner(),
        }

    def run(
        self,
        scanner: str,
        target: str,
    ) -> str:

        if scanner not in self.scanners:
            raise ValueError(
                f"Unsupported scanner: {scanner}"
            )

        return self.scanners[scanner].scan(target)