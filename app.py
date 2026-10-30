
import os
import re
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string, request, Response


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

SSL_LABS_API = "https://api.ssllabs.com/api/v4"
SSL_LABS_EMAIL = os.getenv("SSLLABS_EMAIL", "").strip()

REQUEST_TIMEOUT = 45

http = requests.Session()
http.headers.update({
    "User-Agent": "QuantumGuard-CBOM-Analyzer/3.0"
})


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def normalize_host(value):
    value = str(value or "").strip()

    if not value:
        raise ValueError("Enter a hostname.")

    if "://" in value:
        parsed = urlsplit(value)

        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS URLs are accepted.")

        if parsed.username or parsed.password:
            raise ValueError("URL credentials are not accepted.")

        if parsed.port not in (None, 443):
            raise ValueError("Only port 443 is supported.")

        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Enter only the hostname.")

        value = parsed.hostname or ""

    elif any(c in value for c in "/\\@?#:"):
        raise ValueError("Enter a hostname, not a URL or IP:port.")

    value = value.rstrip(".").lower()

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid hostname.") from exc

    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        value
    ):
        raise ValueError("Enter a valid public hostname, e.g. example.com.")

    return value


# ============================================================
# SSL LABS API
# ============================================================

def ssl_request(endpoint, params=None):
    if not SSL_LABS_EMAIL:
        raise RuntimeError(
            "Set SSLLABS_EMAIL in your environment before scanning."
        )

    started = datetime.now(timezone.utc)

    try:
        response = http.get(
            SSL_LABS_API + endpoint,
            params=params,
            headers={"email": SSL_LABS_EMAIL},
            timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"SSL Labs connection failed: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        data = {}

    if not response.ok:
        errors = data.get("errors", [])
        message = "; ".join(
            str(x.get("message", x)) if isinstance(x, dict) else str(x)
            for x in errors
        )
        message = message or data.get("message") or response.text[:500]
        raise RuntimeError(f"SSL Labs API error {response.status_code}: {message}")

    if not isinstance(data, dict):
        raise RuntimeError("Invalid SSL Labs response.")

    data["_quantumguard"] = {
        "requestTime": started.isoformat(),
        "httpStatus": response.status_code
    }

    return data


# ============================================================
# DATA EXTRACTION
# ============================================================

def endpoints(report):
    return report.get("endpoints") or []


def details(endpoint):
    return endpoint.get("details") or {}


def protocols(endpoint):
    return details(endpoint).get("protocols") or []


def protocol_name(item):
    name = str(item.get("name") or "TLS").upper()
    version = str(item.get("version") or "")
    return f"{name} {version}".strip()


def named_groups(endpoint):
    groups = details(endpoint).get("namedGroups") or {}
    return groups.get("list") or []


def suite_groups(endpoint):
    return details(endpoint).get("suites") or []


def cipher_suites(endpoint):
    result = []

    for group in suite_groups(endpoint):
        for suite in group.get("list") or []:
            item = dict(suite)
            item["protocol"] = group.get("protocol") or "Unknown"
            result.append(item)

    return result


def all_certificates(report):
    return report.get("certs") or []


def certificate_for_endpoint(endpoint, report):
    certs = all_certificates(report)
    detail = details(endpoint)

    cert_info = detail.get("cert") or {}
    cert_id = cert_info.get("id")

    if cert_id:
        for cert in certs:
            if cert.get("id") == cert_id:
                return cert

    # Fallback to first certificate in the first chain.
    chains = detail.get("certChains") or []

    if chains:
        ids = chains[0].get("certIds") or []

        if ids:
            for cert in certs:
                if cert.get("id") == ids[0]:
                    return cert

    return None


def certificate_chain(endpoint, report):
    certs = all_certificates(report)
    chains = details(endpoint).get("certChains") or []

    if not chains:
        cert = certificate_for_endpoint(endpoint, report)
        return [cert] if cert else []

    ids = chains[0].get("certIds") or []
    result = []

    for cert_id in ids:
        cert = next(
            (x for x in certs if x.get("id") == cert_id),
            None
        )
        if cert:
            result.append(cert)

    return result


def is_pqc_group(group):
    name = str(group.get("name") or "").upper()
    group_type = str(group.get("namedGroupType") or "").upper()

    return (
        "PQC" in group_type
        or "MLKEM" in name
        or "KYBER" in name
    )


def is_hybrid_group(group):
    name = str(group.get("name") or "").upper()

    # Conservative recognition only.
    # Keep this allow-list aligned with actual SSL Labs group names.
    return bool(
        re.search(
            r"(MLKEM|KYBER).*(X25519|SECP|P256|P384)"
            r"|(X25519|SECP|P256|P384).*(MLKEM|KYBER)",
            name
        )
    )


def is_legacy_protocol(name):
    name = str(name).upper().replace("V", " ")

    return any(
        x in name
        for x in ["SSL 2", "SSL 3", "TLS 1.0", "TLS 1.1"]
    )


# ============================================================
# ALGORITHM CLASSIFICATION
# ============================================================

def classify_public_key(value):
    name = str(value or "").upper()

    if "RSA" in name:
        return "RSA", "pke", "classical"

    if "ECDSA" in name or "EC" in name:
        return "ECDSA", "signature", "classical"

    if "ED25519" in name or "ED448" in name:
        return "EdDSA", "signature", "classical"

    if "ML-DSA" in name or "DILITHIUM" in name:
        return "ML-DSA", "signature", "pqc"

    if "SLH-DSA" in name or "SPHINCS" in name:
        return "SLH-DSA", "signature", "pqc"

    if "ML-KEM" in name or "KYBER" in name:
        return "ML-KEM", "kem", "pqc"

    return name or "Unknown", "unknown", "unknown"


def classify_signature(value):
    name = str(value or "").upper()

    if "SHA1" in name or "SHA-1" in name or "MD5" in name:
        return "weak"

    if "ML-DSA" in name or "SLH-DSA" in name:
        return "pqc"

    if "RSA" in name or "ECDSA" in name or "ED25519" in name:
        return "classical"

    return "unknown"


def classify_suite(suite):
    name = str(suite.get("name") or "").upper()
    kx = str(suite.get("kxType") or "").upper()

    result = {
        "cipher": None,
        "keyExchange": kx or None,
        "hash": None,
        "mac": None,
        "classicalKeyExchange": False,
        "pqcKeyExchange": False,
        "hybridKeyExchange": False,
        "weak": False
    }

    if "AES_128" in name:
        result["cipher"] = "AES-128"
    elif "AES_256" in name:
        result["cipher"] = "AES-256"
    elif "CHACHA20" in name:
        result["cipher"] = "ChaCha20-Poly1305"
    elif "3DES" in name or "DES_" in name:
        result["cipher"] = "3DES"
        result["weak"] = True
    elif "RC4" in name:
        result["cipher"] = "RC4"
        result["weak"] = True

    if "SHA384" in name:
        result["hash"] = "SHA-384"
    elif "SHA256" in name:
        result["hash"] = "SHA-256"
    elif "SHA1" in name:
        result["hash"] = "SHA-1"
        result["weak"] = True

    if any(x in kx for x in ["ECDHE", "DHE", "ECDH", "DH", "RSA"]):
        result["classicalKeyExchange"] = True

    if "MLKEM" in name or "KYBER" in name:
        result["pqcKeyExchange"] = True

    if is_hybrid_group({"name": name}):
        result["hybridKeyExchange"] = True

    return result


# ============================================================
# RISK AND READINESS ANALYSIS
# ============================================================

def analyze_report(report):
    eps = endpoints(report)

    rows = []
    certs_seen = set()
    all_suite_names = set()
    all_protocols = set()

    pqc_count = 0
    hybrid_count = 0
    legacy_count = 0
    classical_cert_count = 0
    weak_cert_count = 0
    classical_kx_count = 0
    weak_suite_count = 0
    tls13_count = 0
    evidence_count = 0

    for endpoint in eps:
        d = details(endpoint)

        groups = named_groups(endpoint)
        suites = cipher_suites(endpoint)
        protos = protocols(endpoint)

        cert = certificate_for_endpoint(endpoint, report)

        group_evidence = bool(groups)
        protocol_evidence = bool(protos)
        suite_evidence = bool(suites)
        cert_evidence = bool(cert)

        if group_evidence or protocol_evidence or suite_evidence or cert_evidence:
            evidence_count += 1

        pqc_groups = [g for g in groups if is_pqc_group(g)]
        hybrid_groups = [g for g in groups if is_hybrid_group(g)]

        endpoint_pqc = bool(pqc_groups)
        endpoint_hybrid = bool(hybrid_groups)

        if endpoint_pqc:
            pqc_count += 1

        if endpoint_hybrid:
            hybrid_count += 1

        proto_names = [protocol_name(p) for p in protos]

        legacy = any(is_legacy_protocol(p) for p in proto_names)

        if legacy:
            legacy_count += 1

        if any("TLS 1.3" in p for p in proto_names):
            tls13_count += 1

        suite_names = []
        suite_details = []

        for suite in suites:
            suite_names.append(suite.get("name") or "Unknown")
            all_suite_names.add(suite.get("name") or "Unknown")

            classification = classify_suite(suite)

            if classification["weak"]:
                weak_suite_count += 1

            if classification["classicalKeyExchange"]:
                classical_kx_count += 1

            suite_details.append({
                "name": suite.get("name"),
                "protocol": suite.get("protocol"),
                "id": suite.get("id"),
                "kxType": suite.get("kxType"),
                "namedGroupName": suite.get("namedGroupName"),
                "kxStrength": suite.get("kxStrength"),
                "cipherStrength": suite.get("cipherStrength"),
                "classification": classification
            })

        all_protocols.update(proto_names)

        cert_data = None

        if cert:
            cert_key = cert.get("sha256Hash") or cert.get("id")

            if cert_key not in certs_seen:
                certs_seen.add(cert_key)

            key_alg = cert.get("keyAlg") or "Unknown"
            sig_alg = cert.get("sigAlg") or "Unknown"

            key_class, _, key_type = classify_public_key(key_alg)
            signature_type = classify_signature(sig_alg)

            if key_type == "classical" or signature_type == "classical":
                classical_cert_count += 1

            key_size = cert.get("keySize")

            weak_key = (
                "RSA" in str(key_alg).upper()
                and isinstance(key_size, (int, float))
                and key_size < 2048
            )

            weak_signature = signature_type == "weak"

            if weak_key or weak_signature:
                weak_cert_count += 1

            cert_data = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuerSubject"),
                "keyAlgorithm": key_alg,
                "keySize": key_size,
                "signatureAlgorithm": sig_alg,
                "signatureClassification": signature_type,
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "sha256": cert.get("sha256Hash"),
                "serialNumber": cert.get("serialNumber"),
                "weakKey": weak_key,
                "weakSignature": weak_signature
            }

        rows.append({
            "ip": endpoint.get("ipAddress"),
            "serverName": endpoint.get("serverName"),
            "statusMessage": endpoint.get("statusMessage"),
            "protocols": proto_names,
            "legacy": legacy,
            "tls13": any("TLS 1.3" in p for p in proto_names),
            "groups": [
                {
                    "name": g.get("name"),
                    "type": g.get("namedGroupType")
                }
                for g in groups
            ],
            "pqcGroups": [g.get("name") for g in pqc_groups],
            "hybridGroups": [g.get("name") for g in hybrid_groups],
            "pqc": endpoint_pqc,
            "hybrid": endpoint_hybrid,
            "suites": suite_details,
            "certificate": cert_data,
            "evidence": {
                "namedGroups": group_evidence,
                "protocols": protocol_evidence,
                "cipherSuites": suite_evidence,
                "certificate": cert_evidence
            }
        })

    total = len(eps)

    # Risk and readiness are deliberately separate.
    # These are directional indicators, not certifications.

    def ratio(n, d):
        return n / d if d else None

    pqc_ratio = ratio(pqc_count, total)
    hybrid_ratio = ratio(hybrid_count, total)
    legacy_ratio = ratio(legacy_count, total)
    classical_cert_ratio = ratio(classical_cert_count, total)
    weak_cert_ratio = ratio(weak_cert_count, total)
    tls13_ratio = ratio(tls13_count, total)

    readiness_inputs = [
        (pqc_ratio, 25),
        (hybrid_ratio, 25),
        (tls13_ratio, 15),
        (1 - legacy_ratio if legacy_ratio is not None else None, 15),
        (1 - classical_cert_ratio if classical_cert_ratio is not None else None, 10),
        (1 - weak_cert_ratio if weak_cert_ratio is not None else None, 10)
    ]

    weighted = [
        (value, weight)
        for value, weight in readiness_inputs
        if value is not None
    ]

    readiness = None
    if weighted:
        readiness = round(
            sum(v * w for v, w in weighted) /
            sum(w for _, w in weighted) * 100
        )

    risk_inputs = [
        (legacy_ratio, 20),
        (classical_cert_ratio, 25),
        (weak_cert_ratio, 15),
        (1 - (pqc_ratio or 0), 20),
        (1 - (hybrid_ratio or 0), 20)
    ]

    risk = round(
        sum(v * w for v, w in risk_inputs if v is not None) /
        sum(w for v, w in risk_inputs if v is not None) * 100
    ) if total else None

    return {
        "host": report.get("host"),
        "status": report.get("status"),
        "grade": max(
            [e.get("grade", 0) or 0 for e in eps],
            default=None
        ),
        "totalEndpoints": total,
        "readiness": readiness,
        "quantumRisk": risk,
        "pqcEndpoints": pqc_count,
        "hybridEndpoints": hybrid_count,
        "legacyEndpoints": legacy_count,
        "tls13Endpoints": tls13_count,
        "classicalCertificateEndpoints": classical_cert_count,
        "weakCertificateEndpoints": weak_cert_count,
        "classicalKeyExchangeSuiteCount": classical_kx_count,
        "weakCipherSuiteCount": weak_suite_count,
        "uniqueCertificates": len(certs_seen),
        "uniqueCipherSuites": len(all_suite_names),
        "uniqueProtocols": sorted(all_protocols),
        "inventoryCoverage": round(evidence_count / total * 100) if total else 0,
        "endpoints": rows
    }


# ============================================================
# CYCLONEDX 1.6 CBOM GENERATOR
# ============================================================

def stable_ref(kind, value):
    digest = hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()[:20]

    return f"urn:quantumguard:{kind}:{digest}"


def add_property(properties, name, value):
    if value is not None and value != "":
        properties.append({
            "name": name,
            "value": str(value)
        })


def add_algorithm(components, cache, name, primitive,
                  family=None, parameter=None,
                  source="SSL Labs observation"):

    name = str(name or "").strip()

    if not name or name.lower() == "unknown":
        return None

    key = (name.lower(), primitive)

    if key in cache:
        return cache[key]

    ref = stable_ref("algorithm", key)

    props = {
        "primitive": primitive
    }

    if family:
        props["algorithmFamily"] = family

    if parameter:
        props["parameterSetIdentifier"] = str(parameter)

    component = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": props
        },
        "properties": [
            {
                "name": "quantumguard:evidence-source",
                "value": source
            }
        ]
    }

    components.append(component)
    cache[key] = ref

    return ref


def timestamp_from_ssl(value):
    if not isinstance(value, (int, float)):
        return None

    try:
        # SSL Labs certificate timestamps are milliseconds.
        return datetime.fromtimestamp(
            value / 1000,
            timezone.utc
        ).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def build_cbom(report):
    analyzed = analyze_report(report)

    components = []
    dependencies = []
    algorithm_cache = {}
    cert_cache = {}
    protocol_cache = {}

    host = report.get("host") or "unknown-host"

    application_ref = stable_ref("application", host)

    root_component = {
        "type": "application",
        "bom-ref": application_ref,
        "name": host,
        "version": "observed-public-endpoint",
        "description": (
            "Public TLS cryptographic inventory observed through "
            "Qualys SSL Labs API."
        )
    }

    components.append(root_component)

    root_dependencies = set()

    # --------------------------------------------------------
    # Certificates and certificate algorithms
    # --------------------------------------------------------

    for endpoint in endpoints(report):
        endpoint_id = endpoint.get("ipAddress") or "unknown-endpoint"

        for cert in certificate_chain(endpoint, report):
            fingerprint = cert.get("sha256Hash") or cert.get("id")

            if not fingerprint:
                continue

            if fingerprint in cert_cache:
                cert_ref = cert_cache[fingerprint]
                root_dependencies.add(cert_ref)
                continue

            key_alg = cert.get("keyAlg") or "Unknown"
            sig_alg = cert.get("sigAlg") or "Unknown"
            key_size = cert.get("keySize")

            key_family, key_primitive, _ = classify_public_key(key_alg)

            key_ref = add_algorithm(
                components,
                algorithm_cache,
                key_alg,
                key_primitive,
                family=key_family,
                parameter=key_size
            )

            sig_family, sig_primitive, _ = classify_public_key(sig_alg)

            if sig_primitive == "pke":
                sig_primitive = "signature"

            sig_ref = add_algorithm(
                components,
                algorithm_cache,
                sig_alg,
                sig_primitive,
                family=sig_family
            )

            cert_ref = stable_ref("certificate", fingerprint)

            cert_properties = {
                "certificateFormat": "X.509",
                "subjectName": cert.get("subject") or "Unknown",
                "issuerName": cert.get("issuerSubject") or "Unknown"
            }

            before = timestamp_from_ssl(cert.get("notBefore"))
            after = timestamp_from_ssl(cert.get("notAfter"))

            if before:
                cert_properties["notValidBefore"] = before

            if after:
                cert_properties["notValidAfter"] = after

            if sig_ref:
                cert_properties["signatureAlgorithmRef"] = sig_ref

            if key_ref:
                cert_properties["subjectPublicKeyRef"] = key_ref

            properties = []

            add_property(properties, "quantumguard:sha256", cert.get("sha256Hash"))
            add_property(properties, "quantumguard:serial-number", cert.get("serialNumber"))
            add_property(properties, "quantumguard:key-algorithm", key_alg)
            add_property(properties, "quantumguard:key-size-bits", key_size)
            add_property(properties, "quantumguard:signature-algorithm", sig_alg)
            add_property(properties, "quantumguard:evidence-source", "Qualys SSL Labs certificate response")
            add_property(properties, "quantumguard:observed-endpoint", endpoint_id)

            components.append({
                "type": "cryptographic-asset",
                "bom-ref": cert_ref,
                "name": cert.get("subject") or "TLS Certificate",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": cert_properties
                },
                "properties": properties
            })

            cert_cache[fingerprint] = cert_ref
            root_dependencies.add(cert_ref)

        # ----------------------------------------------------
        # Protocol assets and cipher suites
        # ----------------------------------------------------

        for protocol in protocols(endpoint):
            version = str(protocol.get("version") or "unknown")
            pname = str(protocol.get("name") or "TLS")

            if "TLS" not in pname.upper() and "SSL" not in pname.upper():
                continue

            proto_key = (pname.lower(), version)
            proto_ref = protocol_cache.get(proto_key)

            if not proto_ref:
                proto_ref = stable_ref("protocol", proto_key)
                protocol_cache[proto_key] = proto_ref

                components.append({
                    "type": "cryptographic-asset",
                    "bom-ref": proto_ref,
                    "name": f"{pname} {version}",
                    "cryptoProperties": {
                        "assetType": "protocol",
                        "protocolProperties": {
                            "type": "tls",
                            "version": version,
                            "cipherSuites": [],
                            "cryptoRefArray": []
                        }
                    },
                    "properties": [{
                        "name": "quantumguard:evidence-source",
                        "value": "Qualys SSL Labs protocol response"
                    }]
                })

            root_dependencies.add(proto_ref)

            suite_component = next(
                c for c in components if c["bom-ref"] == proto_ref
            )

            suite_target = suite_component["cryptoProperties"]["protocolProperties"]

            for suite in cipher_suites(endpoint):
                if suite.get("protocol") not in (version, f"{pname} {version}"):
                    # Keep the suite only when its group matches this protocol.
                    group_version = str(suite.get("protocol") or "")
                    if group_version and version not in group_version:
                        continue

                suite_name = suite.get("name")

                if not suite_name:
                    continue

                classification = classify_suite(suite)

                algorithm_refs = []

                cipher = classification.get("cipher")
                if cipher:
                    primitive = "ae" if "GCM" in suite_name.upper() or "POLY1305" in suite_name.upper() else "blockcipher"

                    ref = add_algorithm(
                        components,
                        algorithm_cache,
                        cipher,
                        primitive,
                        family=cipher
                    )
                    if ref:
                        algorithm_refs.append(ref)

                kx = classification.get("keyExchange")
                if kx:
                    ref = add_algorithm(
                        components,
                        algorithm_cache,
                        kx,
                        "key-agreement",
                        family=kx
                    )
                    if ref:
                        algorithm_refs.append(ref)

                hash_name = classification.get("hash")
                if hash_name:
                    ref = add_algorithm(
                        components,
                        algorithm_cache,
                        hash_name,
                        "hash",
                        family=hash_name
                    )
                    if ref:
                        algorithm_refs.append(ref)

                identifier = suite.get("id")
                identifiers = []

                if isinstance(identifier, int):
                    identifiers = [f"0x{identifier:04X}"]

                suite_entry = {
                    "name": suite_name,
                    "algorithms": sorted(set(algorithm_refs)),
                    "identifiers": identifiers
                }

                if suite_entry not in suite_target["cipherSuites"]:
                    suite_target["cipherSuites"].append(suite_entry)

                suite_target["cryptoRefArray"] = sorted(
                    set(suite_target["cryptoRefArray"]) |
                    set(algorithm_refs)
                )

    dependencies.append({
        "ref": application_ref,
        "dependsOn": sorted(root_dependencies)
    })

    for component in components:
        if component["type"] == "cryptographic-asset":
            dependencies.append({
                "ref": component["bom-ref"],
                "dependsOn": []
            })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "component": root_component
        },
        "components": components,
        "dependencies": dependencies,
        "properties": [
            {
                "name": "quantumguard:scan-provider",
                "value": "Qualys SSL Labs API"
            },
            {
                "name": "quantumguard:scan-host",
                "value": host
            },
            {
                "name": "quantumguard:scan-status",
                "value": str(report.get("status") or "Unknown")
            },
            {
                "name": "quantumguard:inventory-coverage-percent",
                "value": str(analyzed["inventoryCoverage"])
            },
            {
                "name": "quantumguard:assessment-limitation",
                "value": "Public TLS observations only; not a complete internal application cryptographic inventory."
            }
        ]
    }

    return bom


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def index():
    return render_template_string(HTML)


@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True) or {}

    try:
        host = normalize_host(body.get("host"))

        report = ssl_request(
            "/analyze",
            params={
                "host": host,
                "publish": "off",
                "startNew": "on",
                "all": "done"
            }
        )

        return jsonify(report)

    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    except Exception as exc:
        app.logger.exception("Start scan failed")
        return jsonify(error=str(exc)), 502


@app.get("/api/scan/<path:host>")
def poll_scan(host):
    try:
        host = normalize_host(host)

        report = ssl_request(
            "/analyze",
            params={
                "host": host,
                "publish": "off",
                "all": "done"
            }
        )

        return jsonify(report)

    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    except Exception as exc:
        app.logger.exception("Polling failed")
        return jsonify(error=str(exc)), 502


@app.post("/api/cbom")
def export_cbom():
    report = request.get_json(silent=True)

    if not isinstance(report, dict):
        return jsonify(error="A completed SSL Labs report is required."), 400

    if report.get("status") != "READY":
        return jsonify(error="Complete the SSL Labs assessment before exporting."), 400

    try:
        bom = build_cbom(report)

        filename = re.sub(
            r"[^a-zA-Z0-9.-]",
            "_",
            report.get("host") or "tls-assessment"
        )

        return Response(
            json.dumps(bom, indent=2),
            mimetype="application/vnd.cyclonedx+json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{filename}-cbom.cdx.json"'
            }
        )

    except Exception as exc:
        app.logger.exception("CBOM generation failed")
        return jsonify(error=str(exc)), 500


# ============================================================
# DASHBOARD
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QuantumGuard | Crypto Readiness</title>

<style>
:root {
    --bg:#f3f6fa; --surface:#fff; --border:#e1e8f0;
    --text:#172033; --muted:#64748b; --green:#08785e;
    --blue:#2563eb; --yellow:#a16207; --red:#b91c1c;
}

* {box-sizing:border-box}
body {
    margin:0;background:var(--bg);color:var(--text);
    font-family:Inter,system-ui,Arial,sans-serif;font-size:14px
}
header {
    background:#fff;border-bottom:1px solid var(--border);
    padding:18px 4%;display:flex;align-items:center;
    justify-content:space-between;gap:15px;flex-wrap:wrap
}
.brand {font-size:22px;font-weight:900}
.brand span {color:var(--green)}
main {max-width:1500px;margin:auto;padding:25px 4%}
h1 {font-size:27px;margin:0 0 5px}
h2 {font-size:17px;margin:0 0 14px}
h3 {font-size:14px;margin:0 0 10px}
p {line-height:1.5}
.muted {color:var(--muted)}
.scan-form {display:flex;gap:8px;flex-wrap:wrap}
input {
    min-width:260px;padding:12px;border:1px solid var(--border);
    border-radius:9px;font-size:14px
}
button {
    border:0;background:var(--green);color:white;
    padding:11px 17px;border-radius:9px;font-weight:800;cursor:pointer
}
button:disabled {opacity:.5;cursor:wait}
.panel {
    background:#fff;border:1px solid var(--border);
    border-radius:14px;padding:19px;margin-top:17px;min-width:0
}
.grid {
    display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px
}
.two {
    display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px
}
.metric {
    border:1px solid var(--border);padding:15px;border-radius:11px
}
.metric-label {
    font-size:10px;text-transform:uppercase;letter-spacing:.5px;
    font-weight:850;color:var(--muted)
}
.metric-value {font-size:27px;font-weight:900;margin:7px 0}
.metric-note {font-size:11px;color:var(--muted);line-height:1.5}
.hero {
    display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:center
}
.score-row {display:flex;gap:18px;flex-wrap:wrap}
.score {
    border:7px solid #dbe5ef;border-radius:50%;width:95px;height:95px;
    display:grid;place-items:center;font-size:25px;font-weight:900
}
.score.good {border-color:#10b981;color:var(--green)}
.score.warn {border-color:#f59e0b;color:var(--yellow)}
.score.bad {border-color:#ef4444;color:var(--red)}
.status {
    display:inline-block;border-radius:20px;padding:5px 9px;
    font-size:10px;font-weight:850
}
.good {background:#e8f8f1;color:var(--green)}
.warn {background:#fff7e6;color:var(--yellow)}
.bad {background:#fff0f0;color:var(--red)}
.neutral {background:#f1f5f9;color:#475569}
.row {
    border:1px solid var(--border);border-radius:9px;padding:11px;
    margin:8px 0;display:flex;justify-content:space-between;
    align-items:center;gap:10px
}
.protocol {
    display:inline-block;padding:6px 9px;margin:3px;
    border-radius:7px;background:#e8f8f1;color:var(--green);
    font-size:11px;font-weight:800
}
.protocol.legacy {background:#fff0f0;color:var(--red)}
table {width:100%;border-collapse:collapse;font-size:12px}
th,td {padding:10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th {color:var(--muted);white-space:nowrap}
.table-wrap {overflow:auto;max-width:100%}
.trace-box {
    height:260px;max-height:260px;overflow-y:auto;
    overscroll-behavior:contain;border:1px solid var(--border);
    border-radius:9px;padding:10px;background:#fbfdff
}
.trace-item {
    display:grid;grid-template-columns:10px 1fr auto;gap:9px;
    padding:10px 2px;border-bottom:1px solid var(--border)
}
.dot {width:8px;height:8px;border-radius:50%;background:#10b981;margin-top:4px}
.dot.active {background:var(--blue)}
.dot.error {background:var(--red)}
.trace-title {font-weight:800;font-size:11px}
.trace-detail,.trace-time {font-size:10px;color:var(--muted)}
.progress {height:7px;background:#e2e8f0;border-radius:10px;overflow:hidden;margin:12px 0}
.progress-fill {height:100%;width:0;background:var(--blue);transition:width .3s}
.export {
    display:flex;justify-content:space-between;align-items:center;
    gap:15px;flex-wrap:wrap
}
.export button {background:#172033;padding:13px 20px}
.hidden {display:none}
details summary {cursor:pointer;font-weight:800}
pre {
    white-space:pre-wrap;overflow:auto;max-height:300px;
    background:#f7f9fc;padding:12px;border-radius:8px;font-size:11px
}
@media(max-width:900px) {
    .grid {grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:650px) {
    .grid,.two,.hero {grid-template-columns:1fr}
    input {min-width:100%}
}
</style>
</head>

<body>
<header>
    <div>
        <div class="brand">◈ Quantum<span>Guard</span></div>
        <div class="muted">PQC Readiness · Cryptographic Inventory · CBOM</div>
    </div>
    <form class="scan-form" id="scanForm">
        <input id="host" placeholder="example.com" required>
        <button id="scanBtn">Analyze domain</button>
    </form>
</header>

<main>
    <h1>Quantum Risk & Cryptographic Readiness</h1>
    <p class="muted">
        Public TLS cryptographic exposure and post-quantum migration indicators.
    </p>

    <div id="notice" class="panel hidden"></div>

    <section class="panel hero">
        <div>
            <div class="metric-label">Executive assessment</div>
            <h2 id="verdict">Awaiting scan</h2>
            <p id="summary" class="muted">
                Enter a public hostname to begin the assessment.
            </p>
            <span id="evidence" class="status neutral">No evidence yet</span>
            <p class="metric-note">
                Readiness and risk are directional indicators based on observed
                public TLS data. They are not compliance or certification scores.
            </p>
        </div>
        <div class="score-row">
            <div>
                <div class="metric-label">Quantum readiness</div>
                <div id="readiness" class="score">—</div>
            </div>
            <div>
                <div class="metric-label">Quantum risk</div>
                <div id="risk" class="score">—</div>
            </div>
        </div>
    </section>

    <section class="grid">
        <div class="panel metric">
            <div class="metric-label">PQC endpoints</div>
            <div id="pqc" class="metric-value">—</div>
            <div class="metric-note">Recognized PQC group evidence</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Hybrid endpoints</div>
            <div id="hybrid" class="metric-value">—</div>
            <div class="metric-note">Recognized hybrid group evidence</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Classical certificate exposure</div>
            <div id="classicalCert" class="metric-value">—</div>
            <div class="metric-note">RSA, ECDSA or other classical certificate algorithms</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Legacy TLS endpoints</div>
            <div id="legacy" class="metric-value">—</div>
            <div class="metric-note">SSLv2, SSLv3, TLS 1.0 or TLS 1.1</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">TLS 1.3 endpoints</div>
            <div id="tls13" class="metric-value">—</div>
            <div class="metric-note">Modern TLS availability</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Weak certificate endpoints</div>
            <div id="weakCert" class="metric-value">—</div>
            <div class="metric-note">Weak RSA key size or SHA-1/MD5 signature</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Weak cipher suites</div>
            <div id="weakSuites" class="metric-value">—</div>
            <div class="metric-note">Recognized weak suite indicators</div>
        </div>
        <div class="panel metric">
            <div class="metric-label">Inventory coverage</div>
            <div id="coverage" class="metric-value">—</div>
            <div class="metric-note">Endpoints with at least one crypto evidence category</div>
        </div>
    </section>

    <section class="two">
        <div class="panel">
            <h2>Cryptographic algorithms & certificates</h2>
            <div id="certificates" class="muted">No certificate information.</div>
        </div>
        <div class="panel">
            <h2>TLS protocols & key exchange</h2>
            <div id="protocols" class="muted">No protocol information.</div>
            <div id="groups" style="margin-top:12px"></div>
        </div>
    </section>

    <section class="panel">
        <h2>Cipher suite inventory</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Protocol</th>
                        <th>Cipher suite</th>
                        <th>Key exchange</th>
                        <th>Named group</th>
                        <th>Cipher strength</th>
                        <th>KX strength</th>
                        <th>Assessment</th>
                    </tr>
                </thead>
                <tbody id="suiteTable">
                    <tr><td colspan="8">No data yet.</td></tr>
                </tbody>
            </table>
        </div>
    </section>

    <section class="panel">
        <h2>Certificate inventory</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Subject</th>
                        <th>Issuer</th>
                        <th>Public-key algorithm</th>
                        <th>Key size</th>
                        <th>Signature algorithm</th>
                        <th>Valid until</th>
                    </tr>
                </thead>
                <tbody id="certTable">
                    <tr><td colspan="7">No certificate data yet.</td></tr>
                </tbody>
            </table>
        </div>
    </section>

    <section class="two">
        <div class="panel">
            <h2>Priority actions</h2>
            <div id="actions">Actions appear after assessment.</div>
        </div>

        <div class="panel">
            <h2>Live assessment activity</h2>
            <div id="traceStatus" class="metric-note">Waiting for scan</div>
            <div class="progress"><div id="progress" class="progress-fill"></div></div>
            <div id="trace" class="trace-box"></div>
        </div>
    </section>

    <section class="panel">
        <h2>Endpoint cryptographic inventory</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>IP address</th>
                        <th>PQC</th>
                        <th>Hybrid</th>
                        <th>Protocols</th>
                        <th>Legacy</th>
                        <th>Certificate</th>
                        <th>Named groups</th>
                    </tr>
                </thead>
                <tbody id="endpointTable">
                    <tr><td colspan="7">No endpoint data yet.</td></tr>
                </tbody>
            </table>
        </div>
    </section>

    <section class="panel export">
        <div>
            <h2>Export cryptographic inventory</h2>
            <p class="muted">
                Generate a CycloneDX 1.6 CBOM from the completed SSL Labs findings.
                The file includes cryptographic assets, protocols, certificates,
                cipher-suite references and evidence properties.
            </p>
        </div>
        <button id="cbomBtn" disabled>Extract to CBOM ↓</button>
    </section>

    <section class="panel">
        <details>
            <summary>View raw SSL Labs JSON response</summary>
            <pre id="raw">No report loaded.</pre>
        </details>
    </section>
</main>

<script>
const $ = id => document.getElementById(id);

let currentReport = null;
let scanBusy = false;
let traceItems = [];
let startTime = null;
let pollCount = 0;

function esc(value) {
    return String(value ?? "—").replace(/[&<>"']/g, c => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;",
        '"':"&quot;", "'":"&#39;"
    })[c]);
}

function showNotice(message, kind="neutral") {
    $("notice").className = "panel " + kind;
    $("notice").textContent = message;
    $("notice").classList.remove("hidden");
}

function trace(title, detail, state="done") {
    traceItems.push({
        title, detail, state,
        time: new Date().toLocaleTimeString()
    });

    if (traceItems.length > 100) traceItems.shift();

    $("trace").innerHTML = traceItems.map(item => `
        <div class="trace-item">
            <div class="dot ${item.state}"></div>
            <div>
                <div class="trace-title">${esc(item.title)}</div>
                <div class="trace-detail">${esc(item.detail)}</div>
            </div>
            <div class="trace-time">${esc(item.time)}</div>
        </div>
    `).join("");

    // Keep the activity panel at a fixed height and scroll to newest event.
    $("trace").scrollTop = $("trace").scrollHeight;
}

function traceStatus(status) {
    const seconds = Math.round((Date.now() - startTime) / 1000);

    $("traceStatus").textContent =
        `${seconds}s elapsed · ${pollCount} checks · SSL Labs: ${status}`;

    const width = {
        DNS: 15,
        IN_PROGRESS: 55,
        READY: 100,
        ERROR: 100
    }[status] || 25;

    $("progress").style.width = width + "%";
}

async function api(url, options={}) {
    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}

function protocolName(p) {
    return `${p.name || "TLS"} ${p.version || ""}`.trim();
}

function isLegacy(name) {
    const x = String(name).toUpperCase();
    return x.includes("SSL 2") || x.includes("SSL 3") ||
        x.includes("TLS 1.0") || x.includes("TLS 1.1");
}

function getGroups(ep) {
    return ep?.details?.namedGroups?.list || [];
}

function getSuites(ep) {
    const output = [];

    for (const group of (ep?.details?.suites || [])) {
        for (const suite of (group.list || [])) {
            output.push({
                ...suite,
                protocol: group.protocol || "Unknown"
            });
        }
    }

    return output;
}

function getCerts(report) {
    return report?.certs || [];
}

function getCertForEndpoint(ep, report) {
    const certs = getCerts(report);
    const id = ep?.details?.cert?.id;

    if (id) return certs.find(c => c.id === id) || null;

    const chain = ep?.details?.certChains?.[0]?.certIds || [];
    if (chain.length) {
        return certs.find(c => c.id === chain[0]) || null;
    }

    return null;
}

function pct(n, d) {
    return d ? Math.round(n / d * 100) + "%" : "Unknown";
}

function renderReport(report) {
    currentReport = report;

    const eps = report.endpoints || [];

    if (!eps.length) {
        $("summary").textContent =
            report.statusMessage || `SSL Labs status: ${report.status}`;
        return;
    }

    const pqc = eps.filter(ep =>
        getGroups(ep).some(g =>
            String(g.namedGroupType || "").toUpperCase().includes("PQC") ||
            /MLKEM|KYBER/i.test(g.name || "")
        )
    ).length;

    const hybrid = eps.filter(ep =>
        getGroups(ep).some(g =>
            /(MLKEM|KYBER).*(X25519|SECP|P256|P384)|(X25519|SECP|P256|P384).*(MLKEM|KYBER)/i
                .test(g.name || "")
        )
    ).length;

    const legacy = eps.filter(ep =>
        (ep.details?.protocols || []).some(p => isLegacy(protocolName(p)))
    ).length;

    const tls13 = eps.filter(ep =>
        (ep.details?.protocols || []).some(p => protocolName(p).includes("1.3"))
    ).length;

    const certs = eps.map(ep => getCertForEndpoint(ep, report)).filter(Boolean);

    const classicalCert = certs.filter(c =>
        /RSA|ECDSA|EC|ED25519|ED448/i.test(
            (c.keyAlg || "") + " " + (c.sigAlg || "")
        )
    ).length;

    const weakCert = certs.filter(c =>
        (/RSA/i.test(c.keyAlg || "") && Number(c.keySize || 0) < 2048) ||
        /SHA1|SHA-1|MD5/i.test(c.sigAlg || "")
    ).length;

    let allSuites = [];
    eps.forEach(ep => allSuites.push(...getSuites(ep)));

    const weakSuites = allSuites.filter(s =>
        /RC4|3DES|DES_|NULL|EXPORT/i.test(s.name || "")
    ).length;

    const evidenceCount = eps.filter(ep =>
        getGroups(ep).length ||
        (ep.details?.protocols || []).length ||
        getSuites(ep).length ||
        getCertForEndpoint(ep, report)
    ).length;

    const readiness =
        Math.round(
            (pqc / eps.length * 25) +
            (hybrid / eps.length * 25) +
            (tls13 / eps.length * 15) +
            ((1 - legacy / eps.length) * 15) +
            ((1 - classicalCert / eps.length) * 10) +
            ((1 - weakCert / eps.length) * 10)
        );

    const risk =
        Math.round(
            (legacy / eps.length * 20) +
            (classicalCert / eps.length * 25) +
            (weakCert / eps.length * 15) +
            ((1 - pqc / eps.length) * 20) +
            ((1 - hybrid / eps.length) * 20)
        );

    $("readiness").textContent = readiness;
    $("risk").textContent = risk;

    $("readiness").className =
        "score " + (readiness >= 70 ? "good" : readiness >= 40 ? "warn" : "bad");

    $("risk").className =
        "score " + (risk <= 30 ? "good" : risk <= 60 ? "warn" : "bad");

    $("verdict").textContent =
        risk >= 70 ? "High quantum transition priority" :
        risk >= 40 ? "Quantum migration work required" :
        "Lower observed quantum exposure";

    $("summary").textContent =
        `${eps.length} endpoints assessed. ${pqc} with PQC evidence, ` +
        `${hybrid} with hybrid evidence, ${classicalCert} with classical certificate algorithms, ` +
        `${legacy} exposing legacy TLS.`;

    $("evidence").textContent =
        `Inventory evidence: ${pct(evidenceCount, eps.length)}`;

    $("evidence").className =
        "status " + (evidenceCount ? "good" : "warn");

    $("pqc").textContent = pct(pqc, eps.length);
    $("hybrid").textContent = pct(hybrid, eps.length);
    $("classicalCert").textContent = classicalCert;
    $("legacy").textContent = legacy;
    $("tls13").textContent = tls13;
    $("weakCert").textContent = weakCert;
    $("weakSuites").textContent = weakSuites;
    $("coverage").textContent = pct(evidenceCount, eps.length);

    renderCertificates(eps, report);
    renderProtocols(eps);
    renderSuiteTable(eps);
    renderEndpointTable(eps, report);
    renderActions({
        legacy, pqc, hybrid, classicalCert, weakCert,
        weakSuites, tls13, total: eps.length
    });

    $("raw").textContent = JSON.stringify(report, null, 2);
    $("cbomBtn").disabled = report.status !== "READY";
}

function renderCertificates(eps, report) {
    const rows = [];

    eps.forEach(ep => {
        const cert = getCertForEndpoint(ep, report);
        if (!cert) return;

        rows.push(`
            <tr>
                <td>${esc(ep.ipAddress)}</td>
                <td>${esc(cert.subject)}</td>
                <td>${esc(cert.issuerSubject)}</td>
                <td>${esc(cert.keyAlg)}</td>
                <td>${esc(cert.keySize)} bits</td>
                <td>${esc(cert.sigAlg)}</td>
                <td>${cert.notAfter ? new Date(cert.notAfter).toLocaleDateString() : "Unknown"}</td>
            </tr>
        `);
    });

    $("certTable").innerHTML = rows.length
        ? rows.join("")
        : '<tr><td colspan="7">No certificate evidence returned.</td></tr>';

    const unique = new Map();

    eps.forEach(ep => {
        const cert = getCertForEndpoint(ep, report);
        if (cert) unique.set(cert.sha256Hash || cert.id, cert);
    });

    $("certificates").innerHTML = unique.size
        ? [...unique.values()].map(c => `
            <div class="row">
                <div>
                    <strong>${esc(c.subject)}</strong>
                    <div class="metric-note">
                        ${esc(c.keyAlg)} ${esc(c.keySize)} bits · ${esc(c.sigAlg)}
                    </div>
                    <div class="metric-note">Issuer: ${esc(c.issuerSubject)}</div>
                    <div class="metric-note">SHA-256: ${esc(c.sha256Hash)}</div>
                    <div class="metric-note">
                        Valid until: ${c.notAfter ? new Date(c.notAfter).toLocaleString() : "Unknown"}
                    </div>
                </div>
                <span class="status neutral">X.509</span>
            </div>
        `).join("")
        : "No certificate evidence returned.";
}

function renderProtocols(eps) {
    const unique = new Set();
    const groups = new Set();

    eps.forEach(ep => {
        (ep.details?.protocols || []).forEach(p => unique.add(protocolName(p)));
        getGroups(ep).forEach(g => groups.add(g.name || "Unknown"));
    });

    $("protocols").innerHTML = unique.size
        ? [...unique].sort().map(p =>
            `<span class="protocol ${isLegacy(p) ? "legacy" : ""}">${esc(p)}</span>`
        ).join("")
        : "No protocol evidence returned.";

    $("groups").innerHTML =
        "<strong>Named groups</strong><br>" +
        ([...groups].map(g => `<span class="protocol">${esc(g)}</span>`).join("") ||
            '<span class="muted">No named groups returned.</span>');
}

function renderSuiteTable(eps) {
    const rows = [];

    eps.forEach(ep => {
        getSuites(ep).forEach(s => {
            const weak = /RC4|3DES|DES_|NULL|EXPORT/i.test(s.name || "");

            rows.push(`
                <tr>
                    <td>${esc(ep.ipAddress)}</td>
                    <td>${esc(s.protocol)}</td>
                    <td>${esc(s.name)}</td>
                    <td>${esc(s.kxType)}</td>
                    <td>${esc(s.namedGroupName)}</td>
                    <td>${esc(s.cipherStrength)} bits</td>
                    <td>${esc(s.kxStrength)} bits</td>
                    <td><span class="status ${weak ? "bad" : "neutral"}">${weak ? "Review" : "Observed"}</span></td>
                </tr>
            `);
        });
    });

    $("suiteTable").innerHTML = rows.length
        ? rows.join("")
        : '<tr><td colspan="8">No cipher suite evidence returned.</td></tr>';
}

function renderEndpointTable(eps, report) {
    $("endpointTable").innerHTML = eps.map(ep => {
        const groups = getGroups(ep);
        const protocols = (ep.details?.protocols || []).map(protocolName);
        const cert = getCertForEndpoint(ep, report);

        const pqc = groups.some(g =>
            /PQC/i.test(g.namedGroupType || "") || /MLKEM|KYBER/i.test(g.name || "")
        );

        const hybrid = groups.some(g =>
            /(MLKEM|KYBER).*(X25519|SECP|P256|P384)|(X25519|SECP|P256|P384).*(MLKEM|KYBER)/i
                .test(g.name || "")
        );

        return `
            <tr>
                <td>${esc(ep.ipAddress)}</td>
                <td>${pqc ? "PQC evidence" : groups.length ? "Not identified" : "Unknown"}</td>
                <td>${hybrid ? "Hybrid evidence" : groups.length ? "Not identified" : "Unknown"}</td>
                <td>${esc(protocols.join(", ") || "Unknown")}</td>
                <td>${protocols.some(isLegacy) ? "Yes" : protocols.length ? "No" : "Unknown"}</td>
                <td>${cert ? esc(cert.keyAlg + " / " + cert.sigAlg) : "Unknown"}</td>
                <td>${esc(groups.map(g => g.name).join(", ") || "Unknown")}</td>
            </tr>
        `;
    }).join("");
}

function renderActions(k) {
    const actions = [];

    if (k.legacy) {
        actions.push([
            "Critical · Retire legacy TLS",
            `${k.legacy} endpoint(s) expose legacy protocol versions.`
        ]);
    }

    if (k.classicalCert) {
        actions.push([
            "High · Plan certificate cryptographic transition",
            `${k.classicalCert} endpoint(s) use classical certificate algorithms.`
        ]);
    }

    if (k.weakCert) {
        actions.push([
            "High · Remediate weak certificates",
            `${k.weakCert} endpoint(s) have weak key-size or signature indicators.`
        ]);
    }

    if (k.pqc < k.total) {
        actions.push([
            "High · Evaluate PQC key exchange",
            `${k.total - k.pqc} endpoint(s) do not show recognized PQC group evidence.`
        ]);
    }

    if (k.hybrid < k.total) {
        actions.push([
            "High · Evaluate hybrid key exchange",
            `${k.total - k.hybrid} endpoint(s) do not show recognized hybrid group evidence.`
        ]);
    }

    if (k.weakSuites) {
        actions.push([
            "Medium · Review cipher suites",
            `${k.weakSuites} weak cipher suite observations require review.`
        ]);
    }

    if (!actions.length) {
        actions.push([
            "Continue cryptographic governance",
            "No immediate issues were identified by the indicators in this scan."
        ]);
    }

    $("actions").innerHTML = actions.map(a => `
        <div class="row">
            <div>
                <strong>${esc(a[0])}</strong>
                <div class="metric-note">${esc(a[1])}</div>
            </div>
        </div>
    `).join("");
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runScan(host) {
    if (scanBusy) return;

    scanBusy = true;
    startTime = Date.now();
    pollCount = 0;
    traceItems = [];

    $("scanBtn").disabled = true;
    $("scanBtn").textContent = "Analyzing…";
    $("cbomBtn").disabled = true;

    trace("Assessment requested", `Preparing scan for ${host}.`);
    showNotice(`Starting assessment for ${host}.`);

    try {
        trace("Connecting to SSL Labs", "Submitting initial assessment request.", "active");

        let report = await api("/api/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({host})
        });

        renderReport(report);
        trace("Initial response received", `Status: ${report.status}`);
        traceStatus(report.status);

        const deadline = Date.now() + 15 * 60 * 1000;

        while (!["READY", "ERROR"].includes(report.status)) {
            if (Date.now() > deadline) {
                throw new Error("Assessment polling timed out. Try again later.");
            }

            const wait = report.status === "DNS" ? 5000 : 10000;

            trace("Assessment processing", `Waiting ${wait / 1000}s before checking status.`, "active");
            await sleep(wait);

            pollCount++;
            trace("Polling SSL Labs", `Status check ${pollCount}.`);

            report = await api("/api/scan/" + encodeURIComponent(host));

            renderReport(report);
            traceStatus(report.status);
        }

        if (report.status === "READY") {
            trace("Assessment completed", "Endpoint and cryptographic evidence received.");
            showNotice("Assessment completed successfully.", "good");
        } else {
            trace("Assessment error", report.statusMessage || "SSL Labs reported an error.", "error");
            showNotice(report.statusMessage || "Assessment failed.", "bad");
        }

    } catch (error) {
        trace("Assessment failed", error.message, "error");
        showNotice(error.message, "bad");

    } finally {
        scanBusy = false;
        $("scanBtn").disabled = false;
        $("scanBtn").textContent = "Analyze domain";
    }
}

async function exportCbom() {
    if (!currentReport || currentReport.status !== "READY") {
        showNotice("Complete an assessment before generating a CBOM.", "warn");
        return;
    }

    $("cbomBtn").disabled = true;
    $("cbomBtn").textContent = "Generating…";

    try {
        const response = await fetch("/api/cbom", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(currentReport)
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || "CBOM generation failed.");
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");
        link.href = url;
        link.download = (currentReport.host || "assessment") + "-cbom.cdx.json";

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);

        showNotice("CycloneDX 1.6 CBOM generated and downloaded.", "good");
        trace("CBOM exported", "CycloneDX 1.6 JSON downloaded.");

    } catch (error) {
        showNotice(error.message, "bad");
        trace("CBOM export failed", error.message, "error");

    } finally {
        $("cbomBtn").disabled = false;
        $("cbomBtn").textContent = "Extract to CBOM ↓";
    }
}

$("scanForm").addEventListener("submit", event => {
    event.preventDefault();
    const host = $("host").value.trim();
    if (host) runScan(host);
});

$("cbomBtn").addEventListener("click", exportCbom);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
