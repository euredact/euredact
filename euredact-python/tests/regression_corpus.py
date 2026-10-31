"""Regression records for the corpus: the layouts the generated corpus lacked.

Every fix in rules-engine#82, #90, #91, #93 and #94 (and later #100-#103) left the 152,300-document
corpus exactly as it was, before and after. Not because the fixes did nothing --
the pipeline documents gained 1,800 masked values from them -- but because the
corpus contained none of the layouts involved: no AVS number with a bad check
digit, no KRS, no Polish domestic account number or personal NIP grouping, and
no identifier sitting above a bulleted line. A regression in any of them would
have passed `make eval`, `make sweep` and `make parity` in silence.

This module writes those layouts as corpus records, deterministically, in the
corpus's own format (`source_text` plus `PII`), so all three corpus tools see
them once the file is in `EUREDACT_CORPUS`. Two extra keys ride along and are
ignored by the corpus tools: `regression`, the issue a record guards, and
`must_not_detect`, values that must stay unmasked. Each negative sits in a
record that also carries real PII, because `make eval` skips a record with
none, and only then does a wrong detection count as a false positive.

The same records are a hard gate here: `check()` fails on any value not masked
whole with an accepted type, and on any detection touching a `must_not_detect`
value, in both of the modes `make eval` runs (with and without country hints).
A few hundred records in a corpus of 152,000 move the aggregate recall by
less than its rounding, so the aggregate alone would not catch a regression.

    python tests/regression_corpus.py --check            # gate, exit 1 on failure
    python tests/regression_corpus.py --write "$EUREDACT_CORPUS"
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import euredact  # noqa: E402
from euredact.rules.validators import VALIDATORS  # noqa: E402
from eval_full import CATEGORY_MAP, _recall_outcome  # noqa: E402

FILENAME = "euromask_regressions.json"
SEED = 20261007
#: Variants generated per template. Small, because each template already pins
#: one layout; the variants only vary the digits, names and surrounding words.
PER_TEMPLATE = 6


# ── Values ──────────────────────────────────────────────────────────────


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def _sample(rng: random.Random, make, validator: str):
    """Draw from *make* until the engine's own validator accepts it."""
    check = VALIDATORS[validator]
    while True:
        value = make(rng)
        if check(value):
            return value


def ahv(rng: random.Random, *, valid: bool) -> str:
    """A 13-digit AHV, compact. *valid* chooses whether its EAN-13 digit holds."""
    good = _sample(rng, lambda r: "756" + _digits(r, 10), "swiss_ahv")
    if valid:
        return good
    return good[:-1] + str((int(good[-1]) + 1 + rng.randrange(9)) % 10)


def dotted_ahv(compact: str) -> str:
    return f"{compact[:3]}.{compact[3:7]}.{compact[7:11]}.{compact[11:]}"


def krs(rng: random.Random) -> str:
    return "0000" + _digits(rng, 6)


def regon(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 9), "polish_regon")


def nip(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 10), "polish_nip")


def nip_company(n: str) -> str:
    return f"{n[:3]}-{n[3:6]}-{n[6:8]}-{n[8:]}"


def nip_personal(n: str) -> str:
    return f"{n[:3]}-{n[3:5]}-{n[5:7]}-{n[7:]}"


def nrb(rng: random.Random, *, valid: bool = True) -> str:
    """A Polish NRB: the PL IBAN's check digits and 24-digit BBAN, no "PL"."""
    bban = _digits(rng, 24)
    check = 98 - int(bban + "252100") % 97
    if not valid:
        check = (check + 1 + rng.randrange(90)) % 100
    return f"{check:02d}{bban}"


def nrb_spaced(n: str) -> str:
    return " ".join([n[:2]] + [n[i:i + 4] for i in range(2, 26, 4)])


def bsn(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 9), "bsn")


def belgian_nn(rng: random.Random) -> str:
    yy, mm, dd = rng.randrange(50, 99), rng.randrange(1, 13), rng.randrange(1, 29)
    seq = rng.randrange(1, 998)
    first = f"{yy:02d}{mm:02d}{dd:02d}{seq:03d}"
    check = 97 - int(first) % 97
    return f"{first[:2]}.{first[2:4]}.{first[4:6]}-{first[6:]}.{check:02d}"


def nl_mobile(rng: random.Random) -> str:
    return f"06 {_digits(rng, 8)}"


def at_mobile(rng: random.Random) -> str:
    return f"+43 664 {rng.randrange(1, 10)}{_digits(rng, 6)}"


def uk_mobile(rng: random.Random) -> str:
    return f"+44 7{_digits(rng, 3)} {_digits(rng, 6)}"


_FIRST = ["anna", "lukas", "marta", "piotr", "sophie", "jan", "elena", "noah", "chiara", "tomasz"]
_LAST = ["meier", "kowalski", "de-vries", "peeters", "nowak", "brunner", "rossi", "janssen"]
_DOMAINS = ["example.ch", "example.pl", "example.nl", "example.be", "example.at", "example.co.uk"]


def email(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}@{rng.choice(_DOMAINS)}"


def pii(value: str, category: str, country: str) -> dict:
    return {"PII_identifier": value, "PII_category": category, "PII_country": country}


# ── Templates ───────────────────────────────────────────────────────────
#
# Each returns (source_text, PII, must_not_detect). One template, one layout.


def _avs(label_and_value: str, valid: bool, compact: bool = False):
    def build(rng):
        a = ahv(rng, valid=valid)
        v = a if compact else dotted_ahv(a)
        e = email(rng)
        text = label_and_value.format(v=v) + f" Kontakt: {e}"
        return text, [pii(v, "NATIONAL_ID", "CH"), pii(e, "EMAIL", "CH")], []
    return build


def _avs_unlabelled(rng):
    v = dotted_ahv(ahv(rng, valid=False))
    e = email(rng)
    return f"Referenz {v} im Archiv. Kontakt: {e}", [pii(e, "EMAIL", "CH")], [v]


def _krs(template: str):
    def build(rng):
        k, r, n = krs(rng), regon(rng), nip(rng)
        text = template.format(krs=k, regon=r, nip=nip_company(n))
        found = [pii(k, "CHAMBER_OF_COMMERCE", "PL")]
        if "{regon}" in template:
            found.append(pii(r, "CHAMBER_OF_COMMERCE", "PL"))
        if "{nip}" in template:
            found.append(pii(nip_company(n), "TAX_ID", "PL"))
        return text, found, []
    return build


def _nrb(label: str, spaced: bool):
    def build(rng):
        n = nrb(rng)
        v = nrb_spaced(n) if spaced else n
        return f"{label}{v}. Tytuł przelewu: faktura 14/2026.", [pii(v, "BANK_ACCOUNT", "PL")], []
    return build


def _nrb_bad_check(rng):
    v = nrb_spaced(nrb(rng, valid=False))
    e = email(rng)
    return (f"Nr rachunku: {v}\nKontakt: {e}", [pii(e, "EMAIL", "PL")], [v])


def _nip(label: str, personal: bool):
    def build(rng):
        n = nip(rng)
        v = nip_personal(n) if personal else nip_company(n)
        return f"{label}{v}, podatnik VAT czynny.", [pii(v, "TAX_ID", "PL")], []
    return build


def _bullets(rows, country: str):
    """A bulleted block: each row is (label, value-maker, category)."""
    def build(rng):
        lines, found = [], []
        for label, make, category in rows:
            v = make(rng)
            lines.append(f"- {label}: {v}")
            found.append(pii(v, category, country))
        lines.append("- Notitie: terugbellen na 14:00")
        return "Gegevens\n" + "\n".join(lines), found, []
    return build


def _rule_after(label: str, make, category: str, country: str):
    def build(rng):
        v = make(rng)
        return (f"{label}: {v}\n\n---\n\nBeschreibung des Vorgangs folgt.",
                [pii(v, category, country)], [])
    return build


def _asterisk_after(rng):
    v = belgian_nn(rng)
    return (f"Rijksregisternummer: {v}\n* volgende punt: adreswijziging",
            [pii(v, "NATIONAL_ID", "BE")], [])


def _timeline(rng):
    """Bulleted timeline dates are not phones: guards against widening #91."""
    e = email(rng)
    d1 = f"{rng.randrange(1, 28):02d}.0{rng.randrange(1, 9)}.2026 {rng.randrange(10, 23)}:{rng.randrange(10, 59)}"
    d2 = f"{rng.randrange(1, 28):02d}.0{rng.randrange(1, 9)}.2026 0{rng.randrange(1, 9)}:{rng.randrange(10, 59)}"
    text = (f"## Zeitachse\n\n- {d1} — Push nach öffentlichem Repo\n"
            f"- {d2} — Schlüssel rotiert\n\nMeldung an {e}")
    return text, [pii(e, "EMAIL", "DE")], [d1, d2]


def _references(rng):
    """Hyphenated references are not phones: guards against widening #91."""
    e = email(rng)
    r1 = f"V-20{rng.randrange(10, 27)}-{_digits(rng, 7)}"
    r2 = f"PV-LS-2026-{_digits(rng, 6)}"
    text = f"IND-referentie {r1} (verleend), proces-verbaal {r2}. Contact: {e}"
    return text, [pii(e, "EMAIL", "NL")], [r1, r2]


def _date(rng: random.Random, years: tuple[int, int]) -> str:
    return (f"{rng.randrange(1, 29):02d}.{rng.randrange(1, 13):02d}."
            f"{rng.randrange(*years)}")


def _event_date(lead: str):
    """A decision or proceeding date is not personal data (rules-engine#100)."""
    def build(rng):
        d, e = _date(rng, (2020, 2027)), email(rng)
        text = f"{lead.format(d=d)} Kontakt: {e}"
        return text, [pii(e, "EMAIL", "PL")], [d]
    return build


def _call_up_and_birth(rng):
    """'DOB' inside 'dobrowolnej' made a call-up date a date of birth (#100)."""
    born, called = _date(rng, (1960, 2005)), _date(rng, (2020, 2027))
    text = (f"Data urodzenia: {born}\n"
            f"Data powołania do dobrowolnej zasadniczej służby wojskowej: {called}")
    return text, [pii(born, "DOB", "PL")], [called]


def _timestamp(rng):
    """A date-time stamp is not a phone number (rules-engine#101)."""
    stamp = f"{_date(rng, (2024, 2027))} {rng.randrange(0, 24):02d}:{rng.randrange(0, 60):02d}"
    e = email(rng)
    return f"Data eksportu: {stamp}\nOperator: {e}", [pii(e, "EMAIL", "PL")], [stamp]


def _booklet(label: str, letters: int = 3, joint: str = " "):
    """A military booklet number is one INTERNAL_ID, series included (#102)."""
    def build(rng):
        series = "".join(rng.choice("ABCDEFGHJKLMNPRSTUWZ") for _ in range(letters))
        v = f"{series}{joint}{_digits(rng, 7)}"
        return f"{label}{v}.", [pii(v, "INTERNAL_ID", "PL")], []
    return build


def _residence(label: str):
    """A visa sticker or residence card is a RESIDENCE_PERMIT (#103)."""
    def build(rng):
        v = "".join(rng.choice("ABCDEFGHJKLMNPRSTUWZ") for _ in range(2)) + _digits(rng, 7)
        return f"{label}{v}.", [pii(v, "RESIDENCE_PERMIT", "PL")], []
    return build


def _case_reference(label: str):
    """A znak-sprawy reference is one INTERNAL_ID, not a dotted MAC (#105)."""
    def build(rng):
        prefix = rng.choice(["WSO-II", "MOPS", "SO-III", "WOA", "UM-WA"])
        v = f"{prefix}.{rng.randrange(1000, 9999)}.{rng.randrange(1, 9999)}.{rng.randrange(2018, 2027)}"
        return f"{label}{v}.", [pii(v, "INTERNAL_ID", "PL")], []
    return build


def _account_with_bad_check(rng):
    """No card is carved out of an account number, valid or not (#106)."""
    v = nrb_spaced(nrb(rng, valid=False))
    e = email(rng)
    return f"Nr rachunku: {v}\nKontakt: {e}", [pii(e, "EMAIL", "PL")], [v]


def _date_before_masked_birth(rng):
    """On masked text a birth label is the masked date's (#111)."""
    d = _date(rng, (2024, 2030))
    e = email(rng)
    return (f"Titre de séjour valable jusqu'au {d}, né le [DOB]. Contact: {e}",
            [pii(e, "EMAIL", "FR")], [d])


def _written_birth_year(lead: str, months: list[str], country: str):
    """The year of a written birth date is not a postcode (#111)."""
    def build(rng):
        y = str(rng.randrange(1925, 1950))
        pc = str(rng.randrange(10000, 99999))
        text = (f"{lead} {rng.randrange(1, 28)}. {rng.choice(months)} {y}\n"
                f"Anschrift: Lindenweg {rng.randrange(1, 90)}, {pc} München")
        date = text.split(lead + " ", 1)[1].split("\n", 1)[0]
        return text, [pii(pc, "POSTAL_CODE", country), pii(date, "DOB", country)], []
    return build


def _prefixed_reference(rng):
    """A letter-prefixed number is not a country-prefixed postcode (#111)."""
    pc = str(rng.randrange(1000, 9999))
    ref = f"{rng.choice(['K', 'LX', 'B', 'Q'])}-{rng.randrange(10000, 99999)}"
    text = f"Adresse: Hauptstraße 12, {pc} Linz\nKundennummer: {ref}"
    return text, [pii(pc, "POSTAL_CODE", "AT")], [ref]


def _year_beside_masked_postcode(rng):
    """A placeholder is no address word: "2013 — [POSTAL_CODE]" in a CV (#111)."""
    pc, y = str(rng.randrange(3000, 9999)), str(rng.randrange(2005, 2019))
    text = (f"Adresse: Bahnhofstrasse {rng.randrange(1, 90)}, {pc} Zürich\n\n"
            f"=== AUSBILDUNG ===\n\n{y} — [POSTAL_CODE]\nMaster of Science (ETH)")
    return text, [pii(pc, "POSTAL_CODE", "CH")], [y]


def _amount_and_headcount(rng):
    """A thousands group and a head count are not postcodes (#111)."""
    amount = f"£{rng.randrange(10, 99)},{rng.randrange(100, 999)},000"
    count = f"Employees: {rng.randrange(100, 999)}"
    text = f"Annual Revenue: {amount}\n{count}\nAddress: 1 King Street, London EC2V 8AU"
    return text, [pii("EC2V 8AU", "POSTAL_CODE", "UK")], [amount, count]


def _nl_spaced_landline(rng):
    """"020 - 638 4455" is one phone number, not a phone and a postcode (#111)."""
    phone = f"020 - {rng.randrange(200, 999)} {rng.randrange(1000, 9999)}"
    text = (f"Correspondentieadres: Haarlemmerdijk {rng.randrange(1, 200)}, 1013 KH Amsterdam\n"
            f"Telefoon: {phone}")
    return text, [pii(phone, "PHONE", "NL"), pii("1013 KH", "POSTAL_CODE", "NL")], []


def _collar_number(rng):
    """A garda's collar number is an INTERNAL_ID, not a postcode (#111)."""
    n = str(rng.randrange(10000, 99999))
    text = (f"Station: Pearse Street, Dublin 2\nSupervisor on duty: Sgt. B. Fahy (collar {n})\n"
            f"Address of incident: 4 Main Street")
    return text, [pii(n, "INTERNAL_ID", "IE")], []


def _abbreviated_death_date(rng):
    """"8 déc. 2025": an abbreviated French month is a month (#111)."""
    date = f"{rng.randrange(1, 28)} {rng.choice(['déc.', 'janv.', 'févr.', 'avr.', 'juil.'])} {rng.randrange(2020, 2026)}"
    text = f"Il s'agit de ma mère (décédée le {date}), domiciliée 14 rue des Tanneurs, 69007 Lyon."
    return text, [pii(date, "DATE_OF_DEATH", "FR"), pii("69007", "POSTAL_CODE", "FR")], []


def _imei_form(label: str, form: str):
    """IMEI forms behind their label (rules-engine#110)."""
    def build(rng):
        good = _sample(rng, lambda r: "35" + _digits(r, 13), "imei")
        v = {"14": good[:14], "sv": good[:14] + _digits(rng, 2),
             "bad": good[:14] + str((int(good[14]) + 1 + rng.randrange(9)) % 10)}[form]
        return f"{label}{v}.", [pii(v, "IMEI", "DE")], []
    return build


def _vin_form(label: str, form: str):
    """VIN forms behind their label (rules-engine#110)."""
    def build(rng):
        chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
        v = "".join(rng.choice(chars) for _ in range(13)) + _digits(rng, 4)
        v = v.lower() if form == "lower" else f"{v[:3]}-{v[3:9]}-{v[9:]}"
        return f"{label}{v}.", [pii(v, "VIN", "DE")], []
    return build


def _ssn_label(label: str, make, country: str):
    """A separate social-security number is SSN (rules-engine#111)."""
    def build(rng):
        v = make(rng)
        return f"{label}{v}.", [pii(v, "SSN", country)], []
    return build


def _provider(label: str, digits: int, country: str):
    """A provider registration number is HEALTHCARE_PROVIDER (#111)."""
    def build(rng):
        v = str(rng.randrange(1, 10)) + _digits(rng, digits - 1)
        return f"{label}{v}.", [pii(v, "HEALTHCARE_PROVIDER", country)], []
    return build


def _pps(rng):
    return _sample(rng, lambda r: _digits(r, 7) + r.choice("ABCDEFGHIJKLMNOPQRSTUVW")
                   + r.choice(["", "A", "W"]), "irish_pps")


def _svnr(rng):
    v = _sample(rng, lambda r: _digits(r, 10), "austrian_svnr")
    return f"{v[:4]} {v[4:]}"


def _leave_table(rng):
    """Dates under "von" and "bis" are leave dates, not birth dates (#126)."""
    rows, absent, found = [], [], []
    for _ in range(3):
        a, b = _date(rng, (2025, 2027)), _date(rng, (2025, 2027))
        e = email(rng)
        rows.append(f"{rng.choice(_LAST)};{e};Urlaub;{a};{b}")
        absent += [a, b]
        found.append(pii(e, "EMAIL", "DE"))
    text = "Name;E-Mail;Art;von;bis\n" + "\n".join(rows)
    return text, found, list(dict.fromkeys(absent))


def _syslog_ports(rng):
    """A process id and a port are not postcodes; the host and the address
    line are what stays (#126)."""
    pid, port = str(rng.randrange(10000, 99999)), str(rng.randrange(20000, 65000))
    ip = f"192.168.{rng.randrange(1, 254)}.{rng.randrange(1, 254)}"
    pc = str(rng.randrange(10000, 99999))
    text = (f"Oct 23 06:41:12 bastion01 sshd[{pid}]: Accepted publickey for jan "
            f"from {ip} port {port} ssh2\nAdresse: Hauptstraße 5, {pc} Berlin")
    return text, [pii(ip, "IP_ADDRESS", "DE"), pii(pc, "POSTAL_CODE", "DE")], [f"[{pid}]", f"port {port}"]


def _compose_env(rng):
    """A ${VAR} reference is where a secret is kept; the quoted value is the
    secret, without its quotes (#126)."""
    secret = f"Zomer{rng.randrange(1000, 9999)}${rng.choice('xyzq')}"
    text = ("environment:\n  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}\n"
            f"  SMTP_PASSWORD: \"{secret}\"")
    return text, [pii(secret, "SECRET", "NL")], ["${POSTGRES_PASSWORD:-changeme}"]


def _terraform_cidrs(rng):
    """A network address with its prefix names no host; a host address does (#126)."""
    a = rng.randrange(10, 99)
    host = f"10.{a}.1.{rng.randrange(2, 254)}"
    text = (f'vpc_cidr = "10.{a}.0.0/16"\nprivate_subnets = ["10.{a}.10.0/24"]\n'
            f'bastion_ip = "{host}"')
    return text, [pii(host, "IP_ADDRESS", "UK")], [f"10.{a}.0.0", f"10.{a}.10.0"]


def _asset_tags(rng):
    """An asset tag numbered from 0 is not a German plate (#126). The owner's
    address in the same row stays masked."""
    tags = [f"GR-{t}-0{rng.randrange(1, 999)}" for t in ("NB", "SW", "AP")]
    e = email(rng)
    text = ("inventarnr;typ;besitzer\n" + f"{tags[0]};Notebook;{e}\n"
            + f"{tags[1]};Switch;IT\n{tags[2]};Access Point;IT")
    return text, [pii(e, "EMAIL", "DE")], tags


def _signature_date(rng):
    """"née le" inside "signée le" labels no birth date; a real one still does (#126)."""
    signed = _date(rng, (2025, 2027)).replace(".", "/")
    born = _date(rng, (1940, 1990)).replace(".", "/")
    text = f"Patiente née le {born} à Lyon. Conclusion signée le {signed}."
    return text, [pii(born, "DOB", "FR")], [signed]


def _newborn_screening(rng):
    """"born" inside "Newborn" is no birth label (#126)."""
    day = f"{rng.randrange(1, 28)} November 2026"
    e = email(rng)
    text = f"Antenatal and Newborn Screening, London\n{day}\nQuestions: {e}"
    return text, [pii(e, "EMAIL", "UK")], [day]


def _commented_header(rng):
    """A "# Spalten:" header names the columns; its dates are leave dates (#126)."""
    a, b = _date(rng, (2025, 2027)), _date(rng, (2025, 2027))
    e = email(rng)
    text = f"# Spalten: Name;E-Mail;Art;von;bis\n{rng.choice(_LAST)};{e};AU;{a};{b}"
    return text, [pii(e, "EMAIL", "DE")], list(dict.fromkeys([a, b]))


def _quoted_password(rng):
    """A quoted secret is what the quotes hold, closing "!" included (#126)."""
    pw = f"Hiver{rng.randrange(100, 999)}!"
    text = f"Contrôle : mot de passe en clair ($pwd = \"{pw}\") dans le script."
    return text, [pii(pw, "SECRET", "FR")], []


def _names_not_secrets(rng):
    """Identifiers, image tags and compounds after a "=" are names, not
    secrets; a real token beside them still is (#126)."""
    token = "ghp_" + "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(36))
    text = ("secret_name: AWS_SECRET_ACCESS_KEY\ncredentials_user = svc_terraform\n"
            "image: postgres:16-alpine\nPasswort-Richtlinie: Multi-Faktor-Authentifizierung\n"
            f'GH_TOKEN = "{token}"')
    return text, [pii(token, "SECRET", "DE")], [
        "AWS_SECRET_ACCESS_KEY", "svc_terraform", "postgres:16-alpine",
        "Multi-Faktor-Authentifizierung"]


def _connection_string(rng):
    """A connection string stops at its closing quote (#126)."""
    pw = "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(10))
    url = f"postgresql://etl:{pw}@db5.internal:5432/hr"
    text = f'DB_URL = "{url}"'
    return text, [pii(url, "SECRET", "UK")], []


def _placeholder_inside(rng):
    """On text masked once, no span runs across a [TYPE] placeholder (#126)."""
    e = email(rng)
    text = f"api_key = abc[EMAIL]def{rng.randrange(1, 9)}\nContact: {e}"
    return text, [pii(e, "EMAIL", "UK")], ["abc[EMAIL]"]


def _units_and_builds(rng):
    """A build, a duration, a lease and a count are not postcodes (#126)."""
    build, ms, lease, rows = (str(rng.randrange(1000, 9999)) for _ in range(4))
    pc = str(rng.randrange(10000, 99999))
    text = (f"Firmware 7.4.5 build {build}, Timeout nach {ms} ms, Lease {lease} seconds, "
            f"{rows} Datensätze. Adresse: Hauptstraße 5, {pc} Berlin")
    return text, [pii(pc, "POSTAL_CODE", "DE")], [f"build {build}", f"{ms} ms", f"{lease} seconds", f"{rows} Datensätze"]


def _ports_and_ids(rng):
    """Ports and id fields are not postcodes (#126)."""
    port, app, pid_, db = "8080", str(rng.randrange(3000, 3999)), str(rng.randrange(1000, 9999)), "5432"
    pc = str(rng.randrange(10000, 99999))
    text = (f'ports: ["{port}:{port}"]\nAPP_URL=http://localhost:{app}\n'
            f'"parent_id": {pid_}, DB_PORT: "{db}"\nAdresse: Hauptstraße 5, {pc} Berlin')
    return text, [pii(pc, "POSTAL_CODE", "DE")], [f'"{port}:{port}"', f"localhost:{app}", f'"parent_id": {pid_}', f'"{db}"']


def _year_range_and_hour(rng):
    """A year opening or closing a range, and the hour after a date, are not
    postcodes (#126)."""
    pc = str(rng.randrange(10000, 99999))
    text = ("Lebenslauf: 1998–2011 Fernverkehr, 2012–2026 Baustellen. "
            f"Erstbefund 03.10.2026 23:50. Adresse: Hauptstraße 5, {pc} Berlin")
    return text, [pii(pc, "POSTAL_CODE", "DE")], ["1998–2011", "2012–2026", "2026 23"]


def _facture_reference(rng):
    """"Facture 2026-014" has the Portuguese postcode shape and is a reference (#126)."""
    ref = f"2026-0{rng.randrange(10, 99)}"
    text = f"Objet : Facture {ref} – mission API\nAdresse : Rua Augusta 10, 1100-053 Lisboa"
    return text, [pii("1100-053", "POSTAL_CODE", "PT")], [ref]


def _lab_ranges(rng):
    """A lab reference range is not a Polish postcode (#126)."""
    pc = str(rng.randrange(10000, 99999))
    text = ("Ferritine 1 180 µg/L (N : 30-400)\nOBX|4|NM|MCV^Gemiddeld celvolume^L||84|fl|80-100|N\n"
            f"Adresse : 12 rue de la Paix, {pc} Paris")
    return text, [pii(pc, "POSTAL_CODE", "FR")], ["30-400", "80-100"]


def _ip_not_a_host(rng):
    """A documentation address, a version and an OID are not hosts; a host is (#126)."""
    host = f"10.{rng.randrange(10, 99)}.1.{rng.randrange(2, 254)}"
    text = (f"documentation 192.0.2.{rng.randrange(1, 254)}, HANA-Revision 2.00.079.01, "
            f"urn:oid:1.2.250.1.71.4.2.1, host {host}")
    return text, [pii(host, "IP_ADDRESS", "DE")], ["192.0.2.", "2.00.079.01", "1.2.250.1.71.4.2.1"]


def _words_not_passports(rng):
    """A word without a digit is not a passport (#126)."""
    e = email(rng)
    text = (f"Kopie paspoort ontvangen.\nDEEL C — SCREENING (in te vullen door HR)\n"
            f"Paszport sprawdzony. Wynik: POZYTYWNY\nContact: {e}")
    return text, [pii(e, "EMAIL", "NL")], ["SCREENING", "POZYTYWNY"]


def _not_plates(rng):
    """Algorithm names and a law citation are not plates (#126)."""
    e = email(rng)
    text = (f"Accepted publickey for jan port {rng.randrange(20000, 65000)} ssh2: ED25519 "
            f"SHA256:q1Xb. Antrag nach § 1666 BGB. Kontakt: {e}")
    return text, [pii(e, "EMAIL", "DE")], ["ED25519", "SHA256", "1666 BGB"]


def _specimen_and_date(rng):
    """A form's specimen and a dotted date are not national ids (#126)."""
    e = email(rng)
    text = f"Im Formular stand zunächst das Muster „C01X00T47“. Termin najpóźniej 24.11.2026. {e}"
    return text, [pii(e, "EMAIL", "DE")], ["C01X00T47", "24.11.2026"]


def _dummy_values(rng):
    """Placeholder values are nothing; the test BSN beside them is still one (#126)."""
    text = ("NHS number: e.g. 999 999 9999; passport XX0000000; MAC aa:bb:cc:dd:ee:ff\n"
            "BSN: 111222333")
    return text, [pii("111222333", "NATIONAL_ID", "NL")], ["999 999 9999", "XX0000000", "aa:bb:cc:dd:ee:ff"]


def _sort_code(rng):
    """A UK sort code behind its label is a bank account (#126)."""
    code = f"{rng.randrange(10, 99)}-{rng.randrange(10, 99)}-{rng.randrange(10, 99)}"
    text = f"Please pay to sort code {code}, reference INV-{rng.randrange(1000, 9999)}."
    return text, [pii(code, "IBAN", "UK")], []


_PROSE_FR = ("Merci de créer des accès temporaires en lecture seule pour les auditeurs "
             "externes ci-dessous. Périmètre : SAP FI (rôle Z_AUD_RO), partage "
             "\\\\fs02\\Finance (lecture), Power BI espace « Contrôle de gestion ». "
             "Aucun accès VPN : le travail se fera depuis la salle de réunion.\n\n")


def _markdown_birth_table(rng):
    """Dates under a "Date de naissance" column, below a |---| rule row (#130)."""
    dates = [_date(rng, (1950, 2000)).replace(".", "/") for _ in range(3)]
    rows = "\n".join(f"| {rng.choice(_LAST)} | EXT-{rng.randrange(10000, 99999)} | "
                     f"{rng.choice(_LAST).lower()} | {d} |" for d in dates)
    text = (_PROSE_FR + "| Auditeur | Matricule tiers | Identifiant souhaité | Date de naissance |\n"
            "|---|---|---|---|\n" + rows)
    return text, [pii(d, "DOB", "FR") for d in dict.fromkeys(dates)], []


def _psql_birth_table(rng):
    """Dates under a "dob" column, below a ----+---- rule line (#130)."""
    dates = [f"{rng.randrange(1950, 2000)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
             for _ in range(3)]
    rows = "\n".join(f"   {rng.choice(_LAST).lower():<12}| {rng.choice(_LAST):<16}| {d} | NONE       | card only"
                     for d in dates)
    text = ("hr=# SELECT emp_login, full_name, dob, union_code, door_auth FROM staff LIMIT 3;\n"
            "   emp_login   | full_name       | dob        | union_code | door_auth\n"
            "  -------------+-----------------+------------+------------+-----------\n" + rows)
    return text, [pii(d, "DOB", "UK") for d in dict.fromkeys(dates)], []


def _passport_column(rng):
    """Passport numbers under a "Passport" column, rows below the header (#130)."""
    passports = [f"{rng.choice('ABCDEFGHJKLMNPRSTUVWXYZ')}{rng.choice('ABCDEFGHJKLMNPRSTUVWXYZ')}"
                 f"{rng.randrange(1000000, 9999999)}" for _ in range(4)]
    rows = "\n".join(f"104-0{10 + k} | {rng.choice(_LAST)} | {_date(rng, (1940, 2000)).replace('.', '/')} | "
                     f"{pn} | White Irish | flights EUR {rng.randrange(100, 300)}, taxi EUR 38, meals EUR 22"
                     for k, pn in enumerate(passports))
    text = "Subject | Name | DOB | Passport | Ethnicity | Claimed\n" + rows
    return text, [pii(pn, "PASSPORT", "UK") for pn in passports], []


def _polish_ur(rng):
    """"ur." is the usual abbreviation of urodzony (#130)."""
    born = _date(rng, (1950, 2000))
    text = f"{rng.choice(_LAST)} Jabłecki, ur. {born} · nr P/{rng.randrange(100000, 999999)} · pobyt 15.10–13.11.2026"
    return text, [pii(born, "DOB", "PL")], []


def _log_loopback(rng):
    """Loopback and unspecified addresses in a service log name no host; a
    client's address does (#136)."""
    host = f"192.168.{rng.randrange(0, 255)}.{rng.randrange(2, 254)}"
    text = (f"INFO Starting vLLM server on http://0.0.0.0:{rng.randrange(8000, 8999)}\n"
            f"INFO metrics on http://127.0.0.1:{rng.randrange(9000, 9999)}/metrics\n"
            f"INFO client {host}:{rng.randrange(40000, 65000)} connected")
    return text, [pii(host, "IP_ADDRESS", "BE")], ["0.0.0.0", "127.0.0.1"]


def _byte_count(rng):
    """A number followed by "bytes" is a size, not a phone (#136)."""
    size = str(rng.randrange(10_000_000, 99_999_999))
    text = (f"collected artifacts: {rng.randrange(10, 99)} entries, {rng.randrange(2, 30)} artifacts, "
            f"{size} bytes total\nnotify: {email(rng)}")
    return text, [pii(text.rsplit(" ", 1)[1], "EMAIL", "NL")], [size]


def _config_key_values(rng):
    """A config value is a credential when its key names one (#136)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    secret = "".join(rng.choice(alphabet) for _ in range(7)) + "!" + "".join(rng.choice(alphabet) for _ in range(7))
    bundle = f"/var/lib/euredact/bundles/2026-10-{rng.randrange(10, 29)}T{rng.randrange(1000, 2359)}Z"
    text = (f"with config: model='{bundle}', tokenizer_mode='auto', seed=0\n"
            f"DB_PASSWORD={secret}")
    return text, [pii(secret, "SECRET", "DE")], [bundle]


def _json_id_near_bearer(rng):
    """On text masked once, a JSON record's id is not a credential because a
    Bearer header sits above it (#136)."""
    cid = f"KD-{rng.randrange(1_000_000, 9_999_999)}"
    mail = email(rng)
    text = (f'Authorization: Bearer [SECRET]\nAccept: application/json\n\n'
            f'{{\n  "id": "{cid}",\n  "email": "{mail}"\n}}')
    return text, [pii(mail, "EMAIL", "DE")], [cid]


def _mail_header_near_password_word(rng):
    """The sender of a mail is no credential because "wachtwoord" is nearby (#136)."""
    mail = email(rng)
    sender = f"{rng.choice(['Ann-Sophie', 'Marie-Claire', 'Jan-Willem'])} {rng.choice(_LAST).capitalize()}"
    text = f"Ik stuur het wachtwoordmailtje morgen.\n\nVan: {sender} <{mail}>\nOnderwerp: toegang"
    return text, [pii(mail, "EMAIL", "NL")], [sender.split()[0]]


def utr(rng: random.Random, *, valid: bool) -> str:
    """A UK Unique Taxpayer Reference. *valid* chooses whether its check digit holds."""
    good = _sample(rng, lambda r: str(r.randrange(1, 10)) + _digits(r, 9), "uk_utr")
    if valid:
        return good
    return rng.choice([d for d in "0123456789" if d != good[0]]) + good[1:]


def _utr(label: str, valid: bool, spaced: bool):
    """A UTR behind its label, with or without a passing check digit (#137)."""
    def build(rng):
        v = utr(rng, valid=valid)
        if spaced:
            v = f"{v[:5]} {v[5:]}"
        return label.format(v=v), [pii(v, "TAX_ID", "UK")], []
    return build


def _wrapped_iban(indent: str):
    """An IBAN wrapped over a line break between groups (#138)."""
    def build(rng):
        n = nrb(rng)
        groups = ["PL" + n[:2]] + [n[i:i + 4] for i in range(2, 26, 4)]
        v = " ".join(groups[:3]) + "\n" + indent + " ".join(groups[3:])
        text = f"Prosimy o wpłatę na rachunek:\n{indent}{v}\nDziękujemy."
        return text, [pii(v, "BANK_ACCOUNT", "PL")], []
    return build


TEMPLATES: list[tuple[str, object]] = [
    # #82: AVS/AHV with a bad check digit, named as such.
    ("rules-engine#82: label touching", _avs("Numéro AVS {v}.", valid=False)),
    ("rules-engine#82: AHV-Nr.", _avs("AHV-Nr. {v}.", valid=False)),
    ("rules-engine#82: AHV-Nummer, compact", _avs("AHV-Nummer: {v}.", valid=False, compact=True)),
    ("rules-engine#82: n° AVS", _avs("n° AVS: {v}.", valid=False)),
    ("rules-engine#82: in parentheses", _avs("Numéro AVS ({v}), adresse inchangée.", valid=False)),
    ("rules-engine#82: in backticks", _avs("Bitte die AHV-Nummer `{v}` abfragen.", valid=False)),
    ("rules-engine#82: after a phrase", _avs("Le numéro AVS de l'assurée : {v}.", valid=False)),
    ("rules-engine#82: valid, behind its label", _avs("Numéro AVS {v}.", valid=True)),
    ("rules-engine#82: unlabelled bad number stays unmasked", _avs_unlabelled),
    # #90: KRS is a register number, not a phone.
    ("rules-engine#90: KRS label", _krs("KRS: {krs}.")),
    ("rules-engine#90: KRS in prose", _krs("Spółka wpisana do rejestru przedsiębiorców pod numerem KRS {krs}.")),
    ("rules-engine#90: KYC paragraph", _krs("NIP: {nip}. REGON: {regon}. KRS: {krs}.")),
    # #91: a bullet or rule on the next line is not arithmetic.
    ("rules-engine#91: NL bullets", _bullets([("BSN", bsn, "NATIONAL_ID"), ("Telefoon", nl_mobile, "PHONE")], "NL")),
    ("rules-engine#91: NL phone then bullet", _bullets([("Telefoon", nl_mobile, "PHONE")], "NL")),
    ("rules-engine#91: AHV then bullet", _bullets([("AHV-Nummer", lambda r: dotted_ahv(ahv(r, valid=True)), "NATIONAL_ID")], "CH")),
    ("rules-engine#91: AT phone before a rule", _rule_after("Kontakt", at_mobile, "PHONE", "AT")),
    ("rules-engine#91: UK phone before a rule", _rule_after("Tel", uk_mobile, "PHONE", "UK")),
    ("rules-engine#91: BE number before an asterisk", _asterisk_after),
    ("rules-engine#91: timeline dates stay unmasked", _timeline),
    ("rules-engine#91: references stay unmasked", _references),
    # #93: the Polish domestic account number.
    ("rules-engine#93: Nr rachunku, spaced", _nrb("Nr rachunku: ", spaced=True)),
    ("rules-engine#93: Numer konta, compact", _nrb("Numer konta: ", spaced=False)),
    ("rules-engine#93: payment request, spaced", _nrb("Proszę o wpłatę na konto ", spaced=True)),
    ("rules-engine#93: Rachunek bankowy nr, compact", _nrb("Rachunek bankowy nr ", spaced=False)),
    ("rules-engine#93: bad check digits stay unmasked", _nrb_bad_check),
    # #94: the NIP in both groupings.
    ("rules-engine#94: personal grouping", _nip("NIP: ", personal=True)),
    ("rules-engine#94: personal grouping, in prose", _nip("numer NIP podatnika ", personal=True)),
    ("rules-engine#94: company grouping", _nip("NIP: ", personal=False)),
    # #100: event dates after "z dnia" / "dnia" / "w dniu", and a call-up date.
    ("rules-engine#100: z dnia", _event_date("Orzeczenie nr WKL/P/2026/2214 z dnia {d}.")),
    ("rules-engine#100: dnia", _event_date("Postępowanie umorzone dnia {d}.")),
    ("rules-engine#100: w dniu", _event_date("Spotkanie odbyło się w dniu {d} w Warszawie.")),
    ("rules-engine#100: call-up date beside a birth date", _call_up_and_birth),
    # #101: a timestamp stays unmasked.
    ("rules-engine#101: timestamp", _timestamp),
    # #102: the military booklet.
    ("rules-engine#102: booklet, nominative", _booklet("książeczka wojskowa nr ")),
    ("rules-engine#102: booklet, genitive", _booklet("Seria i nr książeczki wojskowej: ")),
    ("rules-engine#102: booklet, two-letter series", _booklet("książeczka wojskowa nr ", letters=2)),
    ("rules-engine#102: booklet, unspaced", _booklet("Książeczka wojskowa: ", letters=2, joint="")),
    ("rules-engine#102: booklet, seria ... nr", _booklet("książeczka wojskowa seria ", letters=2, joint=" nr ")),
    # #105: case references.
    ("rules-engine#105: znak sprawy", _case_reference("Znak sprawy: ")),
    ("rules-engine#105: after decyzja", _case_reference("zgodnie z decyzją nr ")),
    # #106: no card inside an account number.
    ("rules-engine#106: account number with a bad check", _account_with_bad_check),
    # #111: dates and postcodes.
    ("rules-engine#111: date before a masked birth date", _date_before_masked_birth),
    ("rules-engine#111: written birth year (de)", _written_birth_year(
        "Geburtsdatum:", ["Januar", "März", "Juli", "Oktober"], "DE")),
    ("rules-engine#111: prefixed reference beside an address", _prefixed_reference),
    ("rules-engine#111: year beside a masked postcode", _year_beside_masked_postcode),
    ("rules-engine#111: amount and head count", _amount_and_headcount),
    ("rules-engine#111: NL landline with a spaced hyphen", _nl_spaced_landline),
    ("rules-engine#111: garda collar number", _collar_number),
    ("rules-engine#111: abbreviated French death date", _abbreviated_death_date),
    # #110: IMEI and VIN forms.
    ("rules-engine#110: IMEI, 14 digits", _imei_form("IMEI/SV: ", "14")),
    ("rules-engine#110: IMEISV, 16 digits", _imei_form("IMEISV ", "sv")),
    ("rules-engine#110: IMEI, bad check digit", _imei_form("IMEI: ", "bad")),
    ("rules-engine#110: VIN, lower case", _vin_form("VIN: ", "lower")),
    ("rules-engine#110: VIN, in sections", _vin_form("Fahrgestellnummer ", "sections")),
    # #111: SSN and healthcare-provider numbers.
    ("rules-engine#111: Irish PPSN", _ssn_label("PPSN: ", _pps, "IE")),
    ("rules-engine#111: Austrian SVNr", _ssn_label("SVNR: ", _svnr, "AT")),
    ("rules-engine#111: Dutch BIG", _provider("BIG-registratienummer: ", 11, "NL")),
    ("rules-engine#111: German LANR", _provider("Lebenslange Arztnummer: ", 9, "DE")),
    ("rules-engine#111: German BSNR", _provider("BSNR ", 9, "DE")),
    ("rules-engine#111: UK GMC", _provider("GMC number ", 7, "UK")),
    # #126: the IT/HR/MED benchmark's over-redaction.
    ("rules-engine#126: leave table", _leave_table),
    ("rules-engine#126: syslog with a process id and a port", _syslog_ports),
    ("rules-engine#126: compose environment", _compose_env),
    ("rules-engine#126: terraform CIDRs and a host", _terraform_cidrs),
    ("rules-engine#126: asset tags", _asset_tags),
    ("rules-engine#126: signature date", _signature_date),
    ("rules-engine#126: newborn screening date", _newborn_screening),
    ("rules-engine#126: commented table header", _commented_header),
    ("rules-engine#126: quoted password", _quoted_password),
    ("rules-engine#126: names that are not secrets", _names_not_secrets),
    ("rules-engine#126: connection string in quotes", _connection_string),
    ("rules-engine#126: span across a placeholder", _placeholder_inside),
    ("rules-engine#126: builds, durations and counts", _units_and_builds),
    ("rules-engine#126: ports and id fields", _ports_and_ids),
    ("rules-engine#126: year ranges and an hour", _year_range_and_hour),
    ("rules-engine#126: invoice reference", _facture_reference),
    ("rules-engine#126: lab reference ranges", _lab_ranges),
    ("rules-engine#126: IPs that name no host", _ip_not_a_host),
    ("rules-engine#126: words that are not passports", _words_not_passports),
    ("rules-engine#126: algorithms and a law citation", _not_plates),
    ("rules-engine#126: specimen and dotted date", _specimen_and_date),
    ("rules-engine#126: dummy values", _dummy_values),
    ("rules-engine#126: UK sort code", _sort_code),
    # #130: values in tables only the gateway's 0.6.0 pass caught.
    ("rules-engine#130: markdown table, birth column", _markdown_birth_table),
    ("rules-engine#130: psql table, dob column", _psql_birth_table),
    ("rules-engine#130: passport column", _passport_column),
    ("rules-engine#130: Polish ur.", _polish_ur),
    # #136: service logs and text masked once.
    ("rules-engine#136: loopback and unspecified addresses", _log_loopback),
    ("rules-engine#136: byte count", _byte_count),
    ("rules-engine#136: config keys", _config_key_values),
    ("rules-engine#136: JSON id near a Bearer header", _json_id_near_bearer),
    ("rules-engine#136: mail header near a password word", _mail_header_near_password_word),
    # #137: the UK UTR behind its label.
    ("rules-engine#137: UTR label, spaced", _utr("Supplier UTR: {v}, registered in Leeds.", valid=True, spaced=True)),
    ("rules-engine#137: UTR label, bad check digit", _utr("Supplier UTR: {v}, registered in Leeds.", valid=False, spaced=False)),
    ("rules-engine#137: UTR field", _utr("self_assessment_utr: {v}", valid=False, spaced=False)),
    ("rules-engine#137: UTR in prose", _utr("Payment checked against UTR {v} before release.", valid=True, spaced=False)),
    ("rules-engine#137: Unique Taxpayer Reference", _utr("Your Unique Taxpayer Reference is {v}.", valid=False, spaced=True)),
    # #138: an IBAN wrapped over a line break.
    ("rules-engine#138: wrapped IBAN, indented", _wrapped_iban("  ")),
    ("rules-engine#138: wrapped IBAN", _wrapped_iban("")),
    # #103: residence card and visa sticker.
    ("rules-engine#103: karta pobytu CUKR", _residence("karta pobytu CUKR nr ")),
    ("rules-engine#103: visa sticker", _residence("wiza krajowa typu D, naklejka wizowa nr ")),
]


def build(per_template: int = PER_TEMPLATE) -> list[dict]:
    rng = random.Random(SEED)
    records = []
    for name, template in TEMPLATES:
        for _ in range(per_template):
            text, found, absent = template(rng)
            records.append({"source_text": text, "PII": found,
                            "regression": name, "must_not_detect": absent})
    return records


# ── Gate ────────────────────────────────────────────────────────────────


def check(records: list[dict]) -> list[str]:
    """Every failure, as a readable line; empty when the engine holds."""
    failures = []
    for rec in records:
        text = rec["source_text"]
        countries = sorted({p["PII_country"] for p in rec["PII"]})
        for hint in (countries, None):
            dets = euredact.redact(text, countries=hint, detect_dates=True, cache=False).detections
            mode = "hints" if hint else "blind"
            for p in rec["PII"]:
                acceptable = CATEGORY_MAP.get(p["PII_category"], {p["PII_category"]})
                outcome = _recall_outcome(text, dets, p["PII_identifier"], acceptable)
                if outcome != "hit":
                    failures.append(f"{rec['regression']} [{mode}]: {p['PII_category']} "
                                    f"{p['PII_identifier']!r} {outcome} in {text!r}")
            for value in rec["must_not_detect"]:
                start = text.find(value)
                end = start + len(value)
                for d in dets:
                    if d.start < end and d.end > start:
                        failures.append(f"{rec['regression']} [{mode}]: {d.entity_type.value} "
                                        f"{d.text!r} detected inside {value!r}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", metavar="DIR", help=f"write {FILENAME} into DIR")
    ap.add_argument("--check", action="store_true", help="fail on any regression")
    args = ap.parse_args()
    records = build()
    if args.write:
        path = Path(args.write) / FILENAME
        path.write_text(json.dumps(records, indent=1, ensure_ascii=False) + "\n")
        print(f"wrote {len(records)} records to {path}")
    if args.check or not args.write:
        failures = check(records)
        for line in failures:
            print(line)
        print(f"{len(records)} regression records, {len(failures)} failures")
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
