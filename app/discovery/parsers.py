import xml.etree.ElementTree as ET
import re

from app.discovery.errors import ToolExecutionError
from app.domain.discovery import NMAP_PARSER_VERSION, NmapServiceRecord, ToolErrorCode


class NmapParser:
    version = NMAP_PARSER_VERSION

    def __init__(self, *, max_bytes: int = 1_000_000) -> None:
        self.max_bytes = max_bytes

    def parse(self, raw_xml: bytes) -> list[NmapServiceRecord]:
        if len(raw_xml) > self.max_bytes:
            raise ToolExecutionError(
                ToolErrorCode.OUTPUT_TOO_LARGE,
                "Nmap artifact exceeds the parser input bound",
            )
        upper_xml = raw_xml.upper()
        doctypes = re.findall(rb"<!DOCTYPE[^>]*>", upper_xml)
        if b"<!ENTITY" in upper_xml or any(
            re.fullmatch(rb"<!DOCTYPE\s+NMAPRUN\s*>", declaration) is None
            for declaration in doctypes
        ):
            raise ToolExecutionError(
                ToolErrorCode.PARSER_FAILED, "Nmap XML declarations are not allowed"
            )
        try:
            root = ET.fromstring(raw_xml)
        except (ET.ParseError, ValueError) as error:
            raise ToolExecutionError(
                ToolErrorCode.PARSER_FAILED, "Nmap artifact is malformed XML"
            ) from error
        if root.tag != "nmaprun":
            raise ToolExecutionError(
                ToolErrorCode.ARTIFACT_INVALID,
                "Nmap artifact has an unexpected root element",
            )
        records: list[NmapServiceRecord] = []
        for host in root.findall("host"):
            address_node = host.find("address")
            address = address_node.get("addr") if address_node is not None else None
            hostname_node = host.find("hostnames/hostname")
            hostname = hostname_node.get("name") if hostname_node is not None else None
            if not address:
                continue
            for port in host.findall("ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state_node = port.find("state")
                if not port_id or not protocol or state_node is None:
                    continue
                try:
                    parsed_port = int(port_id)
                except ValueError:
                    continue
                service = port.find("service")
                records.append(
                    NmapServiceRecord(
                        host=hostname or address,
                        address=address,
                        port=parsed_port,
                        protocol=protocol,
                        state=state_node.get("state", "unknown"),
                        service_name=service.get("name") if service is not None else None,
                        product=service.get("product") if service is not None else None,
                        version=service.get("version") if service is not None else None,
                        extra_info=service.get("extrainfo") if service is not None else None,
                    )
                )
        return sorted(records, key=lambda item: (item.address, item.protocol, item.port))
