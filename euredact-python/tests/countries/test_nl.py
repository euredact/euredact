"""Netherlands-specific pattern tests."""

import euredact
from euredact.types import EntityType


class TestNLBSN:
    def test_valid_bsn(self):
        result = euredact.redact("Mijn BSN is 111222333.", countries=["NL"])
        assert any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)

    def test_invalid_checksum(self):
        result = euredact.redact("Reference number: 123456789.", countries=["NL"])
        assert not any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)

    def test_bsn_with_dots(self):
        result = euredact.redact("BSN: 111.222.333", countries=["NL"])
        assert any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)

    def test_bsn_redacted(self):
        result = euredact.redact("Mijn BSN is 111222333.", countries=["NL"])
        assert "[NATIONAL_ID]" in result.redacted_text
        assert "111222333" not in result.redacted_text


class TestNLIBAN:
    def test_valid_iban(self):
        result = euredact.redact(
            "Rekeningnummer: NL91ABNA0417164300", countries=["NL"]
        )
        assert any(d.entity_type == EntityType.IBAN for d in result.detections)

    def test_valid_iban_with_spaces(self):
        result = euredact.redact(
            "IBAN: NL91 ABNA 0417 1643 00", countries=["NL"]
        )
        assert any(d.entity_type == EntityType.IBAN for d in result.detections)

    def test_invalid_iban(self):
        result = euredact.redact(
            "IBAN: NL00ABNA0417164300", countries=["NL"]
        )
        assert not any(d.entity_type == EntityType.IBAN for d in result.detections)


class TestNLPhone:
    def test_mobile(self):
        result = euredact.redact("Bel 06-12345678.", countries=["NL"])
        assert any(d.entity_type == EntityType.PHONE for d in result.detections)

    def test_international(self):
        result = euredact.redact("Phone: +31 6 12345678.", countries=["NL"])
        assert any(d.entity_type == EntityType.PHONE for d in result.detections)


class TestNLPostalCode:
    def test_valid_postal_code(self):
        result = euredact.redact("Adres: 1234 AB Amsterdam.", countries=["NL"])
        assert any(d.entity_type == EntityType.POSTAL_CODE for d in result.detections)


class TestNLLicensePlate:
    def test_plate_format(self):
        result = euredact.redact("Kenteken: AB-123-C.", countries=["NL"])
        assert any(d.entity_type == EntityType.LICENSE_PLATE for d in result.detections)


class TestNLVAT:
    def test_vat(self):
        result = euredact.redact("BTW: NL123456789B01.", countries=["NL"])
        assert any(d.entity_type == EntityType.VAT for d in result.detections)
