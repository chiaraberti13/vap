"""Catalogo didattico dei tipi di scansione supportati da VAP."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class ScanCatalogEntry:
    id: str
    display_name: str
    category: str
    level: str
    learning_objective: str
    when_to_use: str
    when_not_to_use: str
    owasp_tags: List[str]
    mitre_tags: List[str]
    expected_duration: str
    invasiveness: str
    noise_level: str
    required_permissions: str
    legal_notice: str
    common_false_positives: List[str]
    interpretation_guide: str
    next_learning_step: str


def _entry(
    *,
    id: str,
    display_name: str,
    category: str,
    level: str,
    learning_objective: str,
    when_to_use: str,
    when_not_to_use: str,
    owasp_tags: List[str],
    mitre_tags: List[str],
    expected_duration: str,
    invasiveness: str,
    noise_level: str,
    required_permissions: str,
    legal_notice: str,
    common_false_positives: List[str],
    interpretation_guide: str,
    next_learning_step: str,
) -> ScanCatalogEntry:
    return ScanCatalogEntry(
        id=id,
        display_name=display_name,
        category=category,
        level=level,
        learning_objective=learning_objective,
        when_to_use=when_to_use,
        when_not_to_use=when_not_to_use,
        owasp_tags=owasp_tags,
        mitre_tags=mitre_tags,
        expected_duration=expected_duration,
        invasiveness=invasiveness,
        noise_level=noise_level,
        required_permissions=required_permissions,
        legal_notice=legal_notice,
        common_false_positives=common_false_positives,
        interpretation_guide=interpretation_guide,
        next_learning_step=next_learning_step,
    )


SCAN_CATALOG: Dict[str, ScanCatalogEntry] = {
    "full": _entry(
        id="full",
        display_name="Full Stack Assessment",
        category="Orchestrated",
        level="intermediate",
        learning_objective="Comprendere una valutazione completa multi-tool end-to-end.",
        when_to_use="Assessment iniziale o prima di una release importante.",
        when_not_to_use="Quando hai finestre temporali molto ridotte o scope non autorizzato.",
        owasp_tags=["A01", "A03", "A05", "A06", "A09"],
        mitre_tags=["TA0001", "TA0007", "TA0009"],
        expected_duration="30-120 min",
        invasiveness="medium",
        noise_level="high",
        required_permissions="Autorizzazione esplicita del proprietario del target.",
        legal_notice="Esegui solo su sistemi di tua proprietà o con consenso scritto.",
        common_false_positives=["Header mancanti non applicabili", "Fingerprinting incompleto"],
        interpretation_guide="Parti dai finding critical/high e valida i falsi positivi con verifica manuale.",
        next_learning_step="Studiare prioritizzazione remediation basata su impatto business.",
    ),
    "light": _entry(
        id="light",
        display_name="Light Baseline Scan",
        category="Orchestrated",
        level="beginner",
        learning_objective="Eseguire una baseline rapida con basso impatto operativo.",
        when_to_use="Health-check periodico e triage iniziale di un asset.",
        when_not_to_use="Audit approfonditi o validazioni pre-pen-test.",
        owasp_tags=["A05", "A06", "A09"],
        mitre_tags=["TA0007"],
        expected_duration="5-20 min",
        invasiveness="low",
        noise_level="low",
        required_permissions="Permesso di scansione base sul dominio/host.",
        legal_notice="Mantieni la frequenza di scansione entro policy del cliente.",
        common_false_positives=["Tecnologia rilevata ma non esposta", "Porta filtrata come closed"],
        interpretation_guide="Usa i risultati per decidere se passare a scan full o verticali.",
        next_learning_step="Approfondire differenze tra passive e active recon.",
    ),
    "wordpress": _entry(
        id="wordpress",
        display_name="WordPress Focused Assessment",
        category="CMS",
        level="intermediate",
        learning_objective="Analizzare rischi tipici di stack WordPress (core/plugin/theme).",
        when_to_use="Siti WordPress in produzione o staging con plugin di terze parti.",
        when_not_to_use="Target non WordPress o con WAF che blocca scansioni aggressive.",
        owasp_tags=["A03", "A06", "A08"],
        mitre_tags=["TA0001", "TA0007"],
        expected_duration="20-60 min",
        invasiveness="medium",
        noise_level="medium",
        required_permissions="Consenso esplicito per test su CMS e plugin.",
        legal_notice="Rispetta ToS hosting e limiti del provider.",
        common_false_positives=["Plugin enumerati ma non attivi", "Versioni plugin stimate"],
        interpretation_guide="Conferma manualmente versioni e vettori exploit prima di remediation.",
        next_learning_step="Studiare hardening WordPress (least privilege, update policy, WAF).",
    ),
}


_TOOL_VARIANTS = {
    "nuclei": ("Nuclei", "Web", "Template signatures dipendenti da versione applicativa."),
    "nmap": ("Nmap", "Infra", "Servizi filtrati o banner obfuscati possono alterare risultati."),
    "whatweb": ("WhatWeb", "Recon", "Fingerprinting euristico suscettibile a header custom."),
    "subfinder": ("Subfinder", "Recon", "Dati OSINT non sempre aggiornati o completi."),
    "wpscan": ("WPScan", "CMS", "Enumerazione plugin/tema può rilevare componenti non realmente attivi."),
    "wafw00f": ("wafw00f", "Recon", "Rilevamento WAF basato su signature può essere ambiguo."),
    "testssl": ("testssl.sh", "Infra", "Cipher legacy segnalati anche quando mitigati da policy applicative."),
    "theharvester": ("theHarvester", "Recon", "Le fonti OSINT possono restituire asset obsoleti o rumorosi."),
    "nikto": ("Nikto", "Web", "Check storici non sempre rilevanti per stack moderni."),
    "dirsearch": ("Dirsearch", "Web", "Path protetti possono risultare come falsi negativi."),
    "arjun": ("Arjun", "App", "Parametri candidati non sempre corrispondono a input realmente processati."),
    "sqlmap": ("SQLMap", "App", "Parametri non exploitabili possono essere marcati come sospetti."),
    "dalfox": ("Dalfox", "App", "Payload XSS riflessi possono non essere sfruttabili in contesto reale."),
    "xsstrike": ("XSStrike", "App", "Payload riflessi non necessariamente sfruttabili."),
    "zap": ("OWASP ZAP", "App", "Regole passive possono produrre warning informativi."),
    "burp": ("Burp Scanner", "App", "Scanner automatico richiede sempre validazione manuale."),
    "wapiti": ("Wapiti", "App", "Coverage limitata da crawling incompleto."),
    "commix": ("Commix", "App", "Comandi filtrati lato server possono mascherare vulnerabilità reali."),
    "httpx": ("httpx", "Recon", "Servizi intermittenti possono generare risultati non deterministici."),
    "katana": ("Katana", "Recon", "Crawler può perdere route protette da autenticazione o feature flag."),
    "nosqlmap": ("NoSQLMap", "App", "Endpoint non vulnerabili possono apparire sospetti in assenza di contesto."),
    "acunetix": ("Acunetix", "App", "Euristiche proprietarie possono richiedere tuning per ridurre rumore."),
    "nessus": ("Nessus", "Infra", "Plugin feed e credenziali influenzano profondità e accuratezza."),
}

_TOOL_COPYWRITING_OVERRIDES = {
    "nuclei": {
        "learning_objective": "Rilevare rapidamente misconfigurazioni e CVE note tramite template versionati.",
        "when_to_use": "Triage veloce pre-release e verifica continua dopo patching applicativo.",
        "when_not_to_use": "Quando il target blocca traffico scannerizzato e non hai una finestra di whitelisting.",
        "owasp_tags": ["A05", "A06", "A09"],
        "mitre_tags": ["TA0001", "TA0007"],
        "expected_duration": "8-25 min",
        "invasiveness": "low",
        "noise_level": "medium",
        "interpretation_guide": "Conferma severità e template match con evidenze HTTP reali prima di aprire incident.",
        "next_learning_step": "Studiare gestione dei template nuclei (severity, tag, esclusioni contestuali).",
    },
    "nmap": {
        "learning_objective": "Mappare superficie di attacco network (porte/servizi/versioni) per prioritizzare hardening.",
        "when_to_use": "Asset discovery iniziale o verifica esposizione prima di penetration test esterni.",
        "when_not_to_use": "Sistemi sensibili in produzione senza maintenance window concordata.",
        "owasp_tags": ["A05", "A06", "A09"],
        "mitre_tags": ["TA0007", "TA0009"],
        "expected_duration": "10-40 min",
        "invasiveness": "medium",
        "noise_level": "high",
        "interpretation_guide": "Valuta porte aperte insieme a owner del servizio e conferma versioni con inventory CMDB.",
        "next_learning_step": "Approfondire differenza tra scan SYN/Version/Script e relativo impatto operativo.",
    },
    "zap": {
        "learning_objective": "Identificare vulnerabilità web OWASP comuni combinando passive e active scan.",
        "when_to_use": "Applicazioni web in staging con autenticazione test e casi d'uso riproducibili.",
        "when_not_to_use": "Produzione senza account dedicati e senza esclusioni anti-DOS configurate.",
        "owasp_tags": ["A01", "A03", "A05", "A07"],
        "mitre_tags": ["TA0001", "TA0007"],
        "expected_duration": "15-60 min",
        "invasiveness": "medium",
        "noise_level": "medium",
        "interpretation_guide": "Separa alert high-confidence da warning informativi e valida i path con replay manuale.",
        "next_learning_step": "Imparare policy di scan context-aware (auth scope, exclude regex, rate limits).",
    },
    "sqlmap": {
        "learning_objective": "Validare rischi di SQL Injection su endpoint e parametri ad alto impatto dati.",
        "when_to_use": "Endpoint con input utente e query dinamiche sospette già emerse da recon/app scan.",
        "when_not_to_use": "Database critici senza backup recente o senza approvazione esplicita del data owner.",
        "owasp_tags": ["A03"],
        "mitre_tags": ["TA0001", "TA0009"],
        "expected_duration": "12-50 min",
        "invasiveness": "high",
        "noise_level": "high",
        "interpretation_guide": "Esegui sempre conferma manuale dell'injection e stima impatto su confidenzialità/integrità.",
        "next_learning_step": "Studiare tecniche di parameterized query e validazione server-side anti-injection.",
    },
    "wpscan": {
        "learning_objective": "Ridurre rischio WordPress identificando versioni deboli, plugin e utenti esposti.",
        "when_to_use": "Portali WordPress con ecosistema plugin ampio o governance update non strutturata.",
        "when_not_to_use": "Target non WordPress o installazioni protette da policy anti-enumerazione non autorizzate.",
        "owasp_tags": ["A03", "A06", "A07"],
        "mitre_tags": ["TA0001", "TA0007"],
        "expected_duration": "10-35 min",
        "invasiveness": "medium",
        "noise_level": "medium",
        "interpretation_guide": "Verifica stato reale plugin/temi dal pannello admin prima di pianificare remediation.",
        "next_learning_step": "Applicare hardening WordPress: MFA admin, policy update, riduzione plugin inutilizzati.",
    },
}

for scan_id, (display_name, category, fp_note) in _TOOL_VARIANTS.items():
    override = _TOOL_COPYWRITING_OVERRIDES.get(scan_id, {})
    SCAN_CATALOG[scan_id] = _entry(
        id=scan_id,
        display_name=display_name,
        category=category,
        level="intermediate",
        learning_objective=override.get(
            "learning_objective",
            f"Comprendere output operativo dello scanner {display_name}.",
        ),
        when_to_use=override.get("when_to_use", f"Quando serve un'analisi mirata con {display_name}."),
        when_not_to_use=override.get(
            "when_not_to_use",
            "Quando manca autorizzazione formale o scope tecnico definito.",
        ),
        owasp_tags=override.get("owasp_tags", ["A05", "A06"]),
        mitre_tags=override.get("mitre_tags", ["TA0007"]),
        expected_duration=override.get("expected_duration", "10-45 min"),
        invasiveness=override.get("invasiveness", "medium"),
        noise_level=override.get("noise_level", "medium"),
        required_permissions="Scope tecnico approvato + consenso del proprietario del sistema.",
        legal_notice="Non usare su target di terzi senza autorizzazione tracciabile.",
        common_false_positives=[fp_note],
        interpretation_guide=override.get(
            "interpretation_guide",
            "Correla i finding con evidenze (request/response/log) prima di escalation.",
        ),
        next_learning_step=override.get(
            "next_learning_step",
            "Allenarsi su validazione manuale e prioritizzazione CVSS/business impact.",
        ),
    )


def get_scan_catalog() -> List[Dict[str, Any]]:
    """Restituisce il catalogo scansioni in formato serializzabile."""
    return [asdict(SCAN_CATALOG[key]) for key in sorted(SCAN_CATALOG.keys())]
