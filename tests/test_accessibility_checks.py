from html.parser import HTMLParser

from fastapi.testclient import TestClient

import app
from database import AuditEvent, Scan, SessionLocal, init_db


class LandmarkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.main_count = 0
        self.ids: dict[str, tuple[str, dict[str, str]]] = {}
        self.forms: list[dict[str, str]] = []
        self.buttons: dict[str, dict[str, str]] = {}
        self.links: list[dict[str, str]] = []
        self.inputs: list[dict[str, str]] = []
        self.live_regions: dict[str, dict[str, str]] = {}
        self.skip_links: list[dict[str, str]] = []
        self.alert_regions: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attr_map = {k: v for k, v in attrs if k}
        if tag == "main":
            self.main_count += 1
        if "id" in attr_map:
            self.ids[attr_map["id"]] = (tag, attr_map)
        if tag == "form":
            self.forms.append(attr_map)
        if tag == "button":
            button_id = attr_map.get("id")
            if button_id:
                self.buttons[button_id] = attr_map
        if tag == "a":
            self.links.append(attr_map)
            if attr_map.get("href", "").startswith("#"):
                classes = attr_map.get("class", "")
                if "sr-only" in classes:
                    self.skip_links.append(attr_map)
        if tag == "input":
            self.inputs.append(attr_map)
        if attr_map.get("aria-live"):
            self.live_regions[attr_map.get("id", f"anon-{len(self.live_regions)}")] = attr_map
        if attr_map.get("role") == "alert":
            self.alert_regions.append(attr_map)


def _clear_scans() -> None:
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.query(AuditEvent).delete()
        session.commit()


def _parse_html(response_text: str) -> LandmarkParser:
    parser = LandmarkParser()
    parser.feed(response_text)
    return parser


def test_homepage_has_core_accessibility_landmarks_and_keyboard_controls():
    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    parser = _parse_html(response.text)

    assert parser.main_count == 1
    assert "dashboard-kpi-title" in parser.ids
    assert "new-scan-title" in parser.ids

    guided_form = parser.ids.get("guided-scan-form")
    assert guided_form is not None

    csrf_inputs = [
        field
        for field in parser.inputs
        if field.get("name") == "csrf_token" and field.get("type") == "hidden"
    ]
    assert csrf_inputs, "Il form deve includere un CSRF token nascosto."

    next_button = parser.buttons.get("scan-step-next")
    prev_button = parser.buttons.get("scan-step-prev")
    assert next_button is not None and next_button.get("type") == "button"
    assert prev_button is not None and prev_button.get("type") == "button"

    compare_toggle = parser.buttons.get("scan-compare-toggle")
    assert compare_toggle is not None
    assert compare_toggle.get("aria-controls") == "scan-compare-content"
    assert compare_toggle.get("aria-expanded") in {"true", "false"}
    assert any(link.get("href") == "#new-scan-title" for link in parser.skip_links)


def test_scan_detail_has_live_regions_and_single_main_landmark():
    _clear_scans()
    with SessionLocal() as session:
        scan = Scan(
            target="example.com",
            scan_type="full",
            status="running",
            data_classification="internal",
            logs_json="[]",
            findings_json="[]",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    with TestClient(app.app) as client:
        response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    parser = _parse_html(response.text)

    assert parser.main_count == 1

    logs_region = parser.ids.get("scan-logs")
    notifications_region = parser.ids.get("scan-notifications")
    assert logs_region is not None
    assert notifications_region is not None

    assert logs_region[1].get("role") == "log"
    assert logs_region[1].get("aria-live") == "polite"
    assert notifications_region[1].get("role") == "status"
    assert notifications_region[1].get("aria-live") == "assertive"
    assert any(link.get("href") == "#scan-status" for link in parser.skip_links)
