"""Build a Common Cartridge of LTI 1.1 links for the browser RDP pilot.

Brightspace offers no Deep Linking, so an instructor cannot add the pilot's
links from a picker. This script emits a Common Cartridge 1.3.0 package that
imports them in one action.

Two differences from the broker's cartridge generator, which this borrows its
XML shapes from:

The pilot reads only standard LTI parameters, so no link carries a custom
property. The broker's cartridge carries a `route` property because the broker
resolves a route from it. Adding one here would be inert at best.

Every link uses the same launch URL. The pilot distinguishes one link from
another by `resource_link_id`, which Brightspace assigns per link on import,
so the URL does not need to vary.

The point value travels as a Desire2Learn extension only. There is no portable
Common Cartridge mechanism that forces a graded item to a point value on
import, so the operator verifies the grade maximum in Brightspace afterwards.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.dom import minidom
from xml.etree import ElementTree as ET

BLTI_NS = "http://www.imsglobal.org/xsd/imsbasiclti_v1p0"
LTICM_NS = "http://www.imsglobal.org/xsd/imslticm_v1p0"
LTICP_NS = "http://www.imsglobal.org/xsd/imslticp_v1p0"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
CC_NS = "http://www.imsglobal.org/xsd/imsccv1p3/imscp_v1p1"
LOMIMSCC_NS = "http://ltsc.ieee.org/xsd/imsccv1p3/LOM/manifest"

DEFAULT_LAUNCH_URL = "https://lti.labsconnect.dev/lti/launch"
MODULE_TITLE = "Linux Lab Pilot"

VERIFY_AFTER_IMPORT = (
    "After import, confirm in Brightspace that the graded link is associated "
    "with a numeric grade item. The pilot returns scores over LTI 1.1 Basic "
    "Outcomes, which requires lis_outcome_service_url and "
    "lis_result_sourcedid in the launch, and Brightspace sends those only for "
    "a link tied to a grade item. The point value in this cartridge is an "
    "extension hint and is not guaranteed to survive import."
)


@dataclass(frozen=True)
class Link:
    identifier: str
    title: str
    description: str
    points: float | None


LINKS = (
    Link(
        identifier="pilot_open_lab",
        title="Open Linux Lab",
        description=(
            "Provisions the student's virtual machine and offers a browser "
            "terminal and a browser desktop."
        ),
        points=None,
    ),
    Link(
        identifier="pilot_graded_lab",
        title="Linux Lab (Graded)",
        description=(
            "The same lab, associated with a grade item so lab results can be "
            "returned to the gradebook."
        ),
        points=100.0,
    ),
)


def prettify(element: ET.Element) -> str:
    raw = ET.tostring(element, encoding="utf-8")
    return minidom.parseString(raw).toprettyxml(indent="  ", encoding="utf-8").decode()


def _points(value: float) -> str:
    return str(int(value)) if value == int(value) else str(value)


def link_xml(link: Link, launch_url: str) -> str:
    root = ET.Element("cartridge_basiclti_link")
    root.set("xmlns", BLTI_NS)
    root.set("xmlns:blti", BLTI_NS)
    root.set("xmlns:lticm", LTICM_NS)
    root.set("xmlns:lticp", LTICP_NS)
    root.set("xmlns:xsi", XSI_NS)
    root.set(
        "xsi:schemaLocation",
        f"{BLTI_NS} http://www.imsglobal.org/xsd/lti/ltiv1p0/imsbasiclti_v1p0.xsd",
    )
    ET.SubElement(root, "blti:title").text = link.title
    ET.SubElement(root, "blti:description").text = link.description
    ET.SubElement(root, "blti:launch_url").text = launch_url
    ET.SubElement(root, "blti:secure_launch_url").text = launch_url
    if link.points is not None:
        extensions = ET.SubElement(root, "blti:extensions")
        extensions.set("platform", "desire2learn.com")
        prop = ET.SubElement(extensions, "lticm:property")
        prop.set("name", "points_possible")
        prop.text = _points(link.points)
    return prettify(root)


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def manifest_xml() -> str:
    items = "".join(
        f'        <item identifier="item_{link.identifier}" '
        f'identifierref="res_{link.identifier}">\n'
        f"          <title>{_escape(link.title)}</title>\n"
        f"        </item>\n"
        for link in LINKS
    )
    resources = "".join(
        f'    <resource identifier="res_{link.identifier}" '
        f'type="imsbasiclti_xmlv1p3" href="{link.identifier}.xml">\n'
        f'      <file href="{link.identifier}.xml"/>\n'
        f"    </resource>\n"
        for link in LINKS
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<manifest identifier="labsconnect_pilot_cartridge"
          xmlns="{CC_NS}"
          xmlns:lomimscc="{LOMIMSCC_NS}"
          xmlns:xsi="{XSI_NS}">
  <metadata>
    <schema>IMS Common Cartridge</schema>
    <schemaversion>1.3.0</schemaversion>
    <lomimscc:lom>
      <lomimscc:general>
        <lomimscc:title>
          <lomimscc:string language="en-US">{_escape(MODULE_TITLE)}</lomimscc:string>
        </lomimscc:title>
      </lomimscc:general>
    </lomimscc:lom>
  </metadata>
  <organizations>
    <organization identifier="org_1" structure="rooted-hierarchy">
      <item identifier="root">
        <item identifier="module_pilot">
          <title>{_escape(MODULE_TITLE)}</title>
{items}        </item>
      </item>
    </organization>
  </organizations>
  <resources>
{resources}  </resources>
</manifest>
"""


def build(destination: Path, launch_url: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("imsmanifest.xml", manifest_xml())
        for link in LINKS:
            archive.writestr(f"{link.identifier}.xml", link_xml(link, launch_url))
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--launch-url", default=DEFAULT_LAUNCH_URL)
    arguments = parser.parse_args(argv)
    written = build(arguments.output, arguments.launch_url)
    print(f"wrote {written}")
    print(f"launch url: {arguments.launch_url}")
    for link in LINKS:
        points = "ungraded" if link.points is None else f"{_points(link.points)} points"
        print(f"  {link.title} ({points})")
    print()
    print(VERIFY_AFTER_IMPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
