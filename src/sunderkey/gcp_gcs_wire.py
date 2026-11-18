"""Inert current-live GCS JSON API descriptions and unsigned response decoding."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from urllib.parse import quote, urlencode

from .candidate_enrollment_production_custody_contract import LedgerObjectDescriptor
from .gcp_gcs_custody import (
    ENVIRONMENT_CLASS,
    MAXIMUM_HEAD_BYTES,
    MAXIMUM_OBJECT_BYTES,
    GCSAmbiguousWrite,
    GCSBucketProfile,
    GCSCustodyError,
    GCSObjectMetadata,
    GCSObjectRead,
    GCSPreconditionFailed,
    GCSReadRequest,
    GCSWriteRequest,
    _generation,
    _instant,
    _object_name,
    _rebuild,
)
from .qualification import _canonical_json

ORIGIN = "https://storage.googleapis.com"
DESCRIPTOR_METADATA_KEY = "sunderkey-ledger-object-descriptor-v1"
MAXIMUM_JSON_BYTES = 16_384
MAXIMUM_DESCRIPTOR_BYTES = 8_192
MAXIMUM_MULTIPART_BYTES = MAXIMUM_OBJECT_BYTES + MAXIMUM_JSON_BYTES + 1024
BUCKET_FIELDS = (
    "name,metageneration,versioning(enabled),retentionPolicy(retentionPeriod,isLocked),"
    "objectRetention(mode),defaultEventBasedHold,softDeleteTime,hardDeleteTime"
)
OBJECT_FIELDS = (
    "bucket,name,generation,metageneration,size,contentType,contentEncoding,crc32c,"
    "retentionExpirationTime,retention(mode,retainUntilTime),temporaryHold,eventBasedHold,"
    "timeDeleted,softDeleteTime,hardDeleteTime,metadata"
)
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
_OPERATIONS = {"bucket_lookup", "live_metadata", "pinned_live_media", "conditional_write"}


class GCSWireError(GCSCustodyError):
    """Unsupported or unconfirmed wire material, never a policy rejection."""


def _fail(message: str) -> None:
    raise GCSWireError(message)


def _bounded_json(value: object) -> bytes:
    charged = 0
    nodes = 0

    def charge(count: int) -> None:
        nonlocal charged
        charged += count
        if charged > MAXIMUM_JSON_BYTES:
            _fail("JSON exceeds the aggregate byte bound")

    def visit(item, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 256:
            _fail("JSON structure exceeds its bound")
        kind = type(item)
        if kind is dict:
            if len(item) > 32 or any(type(key) is not str for key in item):
                _fail("Native bounded JSON keys are required")
            charge(2 + len(item) + max(0, len(item) - 1))
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif kind is str:
            if len(item) > MAXIMUM_DESCRIPTOR_BYTES:
                _fail("JSON string exceeds its bound")
            charge(len(item) + 2)
            if not item.isascii():
                _fail("JSON strings must be printable ASCII")
            for char in item:
                if not 32 <= ord(char) <= 126:
                    _fail("JSON strings must be printable ASCII")
                if char in {'"', "\\"}:
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                _fail("JSON integers exceed the supported native signed-long range")
            charge(len(str(item)))
        elif kind is type(None):
            charge(4)
        else:
            _fail("Unsupported JSON primitive or container")

    visit(value, 0)
    return _canonical_json(value).encode("ascii")


def _decode(raw: bytes, maximum: int = MAXIMUM_JSON_BYTES) -> dict:
    if type(raw) is not bytes or len(raw) > maximum:
        _fail("Native response bytes exceed the pre-decode bound")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("Duplicate JSON keys are unsupported")
            result[key] = value
        return result

    def reject_number(_):
        _fail("Floating or nonfinite JSON numbers are unsupported")

    def integer(text):
        if len(text) > 20:
            _fail("JSON integer text exceeds its bound")
        value = int(text)
        if not -(2**63) <= value < 2**63:
            _fail("JSON integer exceeds its bound")
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
            parse_int=integer,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GCSWireError("Response is not bounded strict UTF-8 JSON") from exc
    if type(value) is not dict:
        _fail("A selected JSON object is required")
    _bounded_json(value)
    return value


def _exact(raw: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    if type(raw) is not dict or any(type(key) is not str for key in raw):
        _fail("Exact native JSON fields are required")
    if not required <= set(raw) or set(raw) - required - optional:
        _fail("Selected response fields are missing or unsupported")


def _decimal(value: object, *, maximum: int, zero: bool = False) -> int:
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        _fail("Provider counters must be canonical native decimal strings")
    parsed = int(value)
    if parsed > maximum or (not zero and parsed == 0):
        _fail("Provider counter exceeds the supported bound")
    return parsed


def _profile(value: GCSBucketProfile) -> GCSBucketProfile:
    captured = _rebuild(value, GCSBucketProfile)
    if (
        captured.versioning_enabled
        or (
            captured.retention_policy_locked
            and not 1 <= captured.retention_period_seconds < 3_155_760_000
        )
        or (not captured.retention_policy_locked and captured.retention_period_seconds != 0)
    ):
        _fail("Unsupported declared bucket profile")
    return captured


def _descriptor(raw: dict) -> LedgerObjectDescriptor:
    _exact(
        raw,
        {
            "object_id",
            "sha256",
            "size_bytes",
            "retention_until",
            "namespace_id",
            "failure_domain_id",
        },
    )
    try:
        return _rebuild(LedgerObjectDescriptor(**raw), LedgerObjectDescriptor)
    except (TypeError, ValueError) as exc:
        raise GCSWireError("Local ledger descriptor does not reconstruct") from exc


def _crc(value: str | None) -> str | None:
    if value is None:
        return None
    if type(value) is not str or len(value) != 8:
        _fail("CRC32C must be a canonical four-byte base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise GCSWireError("CRC32C encoding is invalid") from exc
    if len(raw) != 4 or base64.b64encode(raw).decode("ascii") != value:
        _fail("CRC32C encoding is noncanonical")
    return value


def _crc_entry(value: int) -> int:
    for _ in range(8):
        value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value


_CRC_TABLE = tuple(_crc_entry(value) for value in range(256))


def crc32c_base64(payload: bytes) -> str:
    """Bounded local data checksum, not provider or custody authentication."""
    if type(payload) is not bytes or len(payload) > MAXIMUM_OBJECT_BYTES:
        _fail("Checksum payload exceeds its native byte bound")
    checksum = 0xFFFFFFFF
    for value in payload:
        checksum = (checksum >> 8) ^ _CRC_TABLE[(checksum ^ value) & 0xFF]
    return base64.b64encode((checksum ^ 0xFFFFFFFF).to_bytes(4, "big")).decode("ascii")


@dataclass(frozen=True)
class GCSBucketObservation:
    """Unsigned returned facts only, with no logical namespace or failure-domain claim."""

    bucket: str
    metageneration: str
    versioning_enabled: bool
    retention_policy_locked: bool
    retention_period_seconds: int


@dataclass(frozen=True)
class GCSWireObjectObservation:
    """Selected live-object facts and optional CRC32C, not a signed custody receipt."""

    metadata: GCSObjectMetadata
    crc32c: str | None

    def __post_init__(self) -> None:
        _rebuild(self.metadata, GCSObjectMetadata)
        _crc(self.crc32c)


def _metadata(profile: GCSBucketProfile, name: str, raw: dict) -> GCSWireObjectObservation:
    required = {"bucket", "name", "generation", "metageneration", "size", "contentType"}
    optional = {
        "contentEncoding",
        "crc32c",
        "retentionExpirationTime",
        "retention",
        "temporaryHold",
        "eventBasedHold",
        "timeDeleted",
        "softDeleteTime",
        "hardDeleteTime",
        "metadata",
    }
    _exact(raw, required, optional)
    if raw["bucket"] != profile.bucket or raw["name"] != name:
        _fail("Object response substitutes requested coordinates")
    if raw["contentType"] != "application/octet-stream" or raw.get("contentEncoding") not in (
        None,
        "identity",
    ):
        _fail("Unsupported object media type or stored content encoding")
    for key in ("temporaryHold", "eventBasedHold"):
        if key in raw and (type(raw[key]) is not bool or raw[key]):
            _fail("Object holds are outside the supported retention mapping")
    if "retention" in raw or any(
        key in raw for key in ("timeDeleted", "softDeleteTime", "hardDeleteTime")
    ):
        _fail(
            "Object retention configurations, noncurrent versions "
            "and deleted objects are unsupported"
        )
    _generation(raw["generation"])
    _generation(raw["metageneration"])
    maximum = MAXIMUM_HEAD_BYTES if name.startswith("heads/") else MAXIMUM_OBJECT_BYTES
    size = _decimal(raw["size"], maximum=maximum, zero=True)
    custom = raw.get("metadata", {})
    if type(custom) is not dict or any(
        type(key) is not str or type(value) is not str for key, value in custom.items()
    ):
        _fail("Custom metadata must use native string keys and values")
    descriptor = None
    retention = raw.get("retentionExpirationTime")
    if name.startswith("ledger/"):
        if not profile.retention_policy_locked:
            _fail("Ledger metadata requires the declared locked bucket")
        _exact(custom, {DESCRIPTOR_METADATA_KEY})
        descriptor_text = custom[DESCRIPTOR_METADATA_KEY]
        descriptor_bytes = descriptor_text.encode("ascii")
        descriptor_raw = _decode(descriptor_bytes, MAXIMUM_DESCRIPTOR_BYTES)
        descriptor = _descriptor(descriptor_raw)
        if descriptor_bytes != _bounded_json(asdict(descriptor)):
            _fail("Descriptor metadata must contain the exact local canonical bytes")
        if (
            name != "ledger/" + descriptor.object_id
            or size != descriptor.size_bytes
            or descriptor.namespace_id != profile.namespace_id
            or descriptor.failure_domain_id != profile.failure_domain_id
            or retention is None
            or _instant(retention) < _instant(descriptor.retention_until)
        ):
            _fail("Ledger descriptor or retention differs from the declared local mapping")
    elif profile.retention_policy_locked or custom or retention is not None:
        _fail("Head metadata cannot acquire ledger descriptor or retention policy")
    return GCSWireObjectObservation(
        GCSObjectMetadata(
            profile.bucket,
            name,
            raw["generation"],
            raw["metageneration"],
            size,
            retention,
            descriptor,
            True,
        ),
        _crc(raw.get("crc32c")),
    )


def _captured_source(
    operation: str, source: dict, payload: bytes
) -> tuple[GCSBucketProfile, object]:
    _exact(source, {"profile", "object_name", "request", "observation"})
    try:
        _exact(
            source["profile"],
            {
                "bucket",
                "namespace_id",
                "failure_domain_id",
                "versioning_enabled",
                "retention_policy_locked",
                "retention_period_seconds",
            },
        )
        profile = _profile(GCSBucketProfile(**source["profile"]))
        name = source["object_name"]
        if operation == "bucket_lookup":
            if (
                name is not None
                or source["request"] is not None
                or source["observation"] is not None
                or payload
            ):
                _fail("Bucket description source fields are invalid")
            return profile, None
        _object_name(name)
        if name.startswith("ledger/") != profile.retention_policy_locked:
            _fail("Object class differs from the declared bucket role")
        if operation == "live_metadata":
            if source["request"] is not None or source["observation"] is not None or payload:
                _fail("Live metadata description source fields are invalid")
            return profile, None
        if operation == "conditional_write":
            _exact(
                source["request"],
                {
                    "request_id",
                    "bucket",
                    "object_name",
                    "if_generation_match",
                    "if_metageneration_match",
                    "ledger_object",
                },
            )
            request = dict(source["request"])
            if request["ledger_object"] is not None:
                request["ledger_object"] = _descriptor(request["ledger_object"])
            captured = _rebuild(GCSWriteRequest(**request, payload=payload), GCSWriteRequest)
            if (
                source["observation"] is not None
                or captured.bucket != profile.bucket
                or captured.object_name != name
            ):
                _fail("Write request substitutes the captured source")
            if name.startswith("ledger/"):
                descriptor = captured.ledger_object
                if (
                    descriptor is None
                    or descriptor.namespace_id != profile.namespace_id
                    or descriptor.failure_domain_id != profile.failure_domain_id
                ):
                    _fail("Write requires the exact declared local ledger descriptor")
            elif len(payload) > MAXIMUM_HEAD_BYTES or captured.ledger_object is not None:
                _fail("Head write exceeds its bound or uses a ledger descriptor")
            return profile, captured
        _exact(source["request"], {"bucket", "object_name", "generation", "metageneration"})
        request = _rebuild(GCSReadRequest(**source["request"]), GCSReadRequest)
        _exact(source["observation"], {"metadata", "crc32c"})
        meta_raw = dict(source["observation"]["metadata"])
        _exact(
            meta_raw,
            {
                "bucket",
                "object_name",
                "generation",
                "metageneration",
                "size_bytes",
                "retention_until",
                "ledger_object",
                "is_live",
            },
        )
        if meta_raw["ledger_object"] is not None:
            meta_raw["ledger_object"] = _descriptor(meta_raw["ledger_object"])
        observation = GCSWireObjectObservation(
            _rebuild(GCSObjectMetadata(**meta_raw), GCSObjectMetadata),
            source["observation"]["crc32c"],
        )
        metadata = observation.metadata
        if (
            payload
            or request.bucket != profile.bucket
            or request.object_name != name
            or (request.bucket, request.object_name, request.generation, request.metageneration)
            != (metadata.bucket, metadata.object_name, metadata.generation, metadata.metageneration)
        ):
            _fail("Pinned live read substitutes its metadata snapshot")
        if name.startswith("ledger/"):
            descriptor = metadata.ledger_object
            if (
                descriptor is None
                or name != "ledger/" + descriptor.object_id
                or metadata.size_bytes != descriptor.size_bytes
                or descriptor.namespace_id != profile.namespace_id
                or descriptor.failure_domain_id != profile.failure_domain_id
                or metadata.retention_until is None
                or _instant(metadata.retention_until) < _instant(descriptor.retention_until)
            ):
                _fail("Pinned ledger observation does not reproduce its declared local mapping")
        elif (
            metadata.ledger_object is not None
            or metadata.retention_until is not None
            or metadata.size_bytes > MAXIMUM_HEAD_BYTES
        ):
            _fail("Pinned head observation substitutes ledger retention or exceeds its bound")
        return profile, (request, observation)
    except (TypeError, ValueError, KeyError) as exc:
        raise GCSWireError("Captured wire source does not reconstruct") from exc


def _parts(operation: str, source_json: str, payload: bytes) -> tuple:
    if type(operation) is not str or len(operation) > 32 or operation not in _OPERATIONS:
        _fail("Unsupported wire operation")
    if (
        type(source_json) is not str
        or len(source_json) > MAXIMUM_JSON_BYTES
        or not source_json.isascii()
    ):
        _fail("Captured source must be native bounded ASCII JSON")
    if type(payload) is not bytes or len(payload) > MAXIMUM_OBJECT_BYTES:
        _fail("Captured payload exceeds its native byte bound")
    source = _decode(source_json.encode("ascii"))
    if _bounded_json(source).decode("ascii") != source_json:
        _fail("Captured source must be canonical")
    profile, request = _captured_source(operation, source, payload)
    path = "/storage/v1/b/" + quote(profile.bucket, safe="")
    query = {"projection": "noAcl"}
    body = b""
    headers = (("Accept-Encoding", "identity"),)
    method = "GET"
    if operation == "bucket_lookup":
        query["fields"] = BUCKET_FIELDS
    elif operation == "live_metadata":
        path += "/o/" + quote(source["object_name"], safe="")
        query["fields"] = OBJECT_FIELDS
    elif operation == "pinned_live_media":
        media_request, _ = request
        path += "/o/" + quote(media_request.object_name, safe="")
        query = {
            "alt": "media",
            "ifGenerationMatch": media_request.generation,
            "ifMetagenerationMatch": media_request.metageneration,
        }
    else:
        method = "POST"
        path = "/upload/storage/v1/b/" + quote(profile.bucket, safe="") + "/o"
        query.update(
            {
                "uploadType": "multipart",
                "fields": OBJECT_FIELDS,
                "ifGenerationMatch": request.if_generation_match,
            }
        )
        if request.if_metageneration_match is not None:
            query["ifMetagenerationMatch"] = request.if_metageneration_match
        metadata = {
            "name": request.object_name,
            "contentType": "application/octet-stream",
            "crc32c": crc32c_base64(payload),
        }
        if request.ledger_object is not None:
            metadata["metadata"] = {
                DESCRIPTOR_METADATA_KEY: _bounded_json(asdict(request.ledger_object)).decode(
                    "ascii"
                )
            }
        metadata_bytes = _bounded_json(metadata)
        token = hashlib.sha256(
            source_json.encode("ascii") + hashlib.sha256(payload).digest()
        ).hexdigest()
        boundary = "sunderkey_gcs_" + token
        delimiter = b"--" + boundary.encode("ascii")
        if delimiter in payload or delimiter in metadata_bytes:
            _fail("Payload collides with the deterministic multipart boundary")
        body = (
            delimiter
            + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            + metadata_bytes
            + b"\r\n"
            + delimiter
            + b"\r\nContent-Type: application/octet-stream\r\n\r\n"
            + payload
            + b"\r\n"
            + delimiter
            + b"--\r\n"
        )
        if len(body) > MAXIMUM_MULTIPART_BYTES:
            _fail("Multipart description exceeds its byte bound")
        headers += (
            ("Content-Type", "multipart/related; boundary=" + boundary),
            ("Content-Length", str(len(body))),
        )
    url = ORIGIN + path + "?" + urlencode(sorted(query.items()), quote_via=quote, safe="")
    return method, url, headers, body, source, request


@dataclass(frozen=True)
class GCSWireRequest:
    """Immutable bytes and URL description; has no dispatch or authentication operation."""

    operation: str
    source_json: str
    payload: bytes
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    environment_class = ENVIRONMENT_CLASS

    def __post_init__(self) -> None:
        _checked(self)


def _checked(value: GCSWireRequest) -> tuple:
    if type(value) is not GCSWireRequest:
        _fail("An exact inert wire description is required")
    operation, source_json, payload = value.operation, value.source_json, value.payload
    method, url, headers, body = value.method, value.url, value.headers, value.body
    if (
        type(method) is not str
        or len(method) > 4
        or type(url) is not str
        or len(url) > 4096
        or type(headers) is not tuple
        or len(headers) > 3
        or any(
            type(row) is not tuple
            or len(row) != 2
            or any(type(item) is not str or len(item) > 256 for item in row)
            for row in headers
        )
        or type(body) is not bytes
        or len(body) > MAXIMUM_MULTIPART_BYTES
    ):
        _fail("Wire description fields must be native and bounded")
    expected = _parts(operation, source_json, payload)
    if (method, url, headers, body) != expected[:4]:
        _fail("Wire description does not reproduce its captured request")
    return operation, expected[4], expected[5]


def _description(
    operation: str,
    profile: GCSBucketProfile,
    name=None,
    request=None,
    observation=None,
    payload=b"",
) -> GCSWireRequest:
    profile = _profile(profile)
    source = {
        "profile": asdict(profile),
        "object_name": name,
        "request": request,
        "observation": observation,
    }
    source_json = _bounded_json(source).decode("ascii")
    method, url, headers, body, _, _ = _parts(operation, source_json, payload)
    return GCSWireRequest(operation, source_json, payload, method, url, headers, body)


def describe_bucket_lookup(profile: GCSBucketProfile) -> GCSWireRequest:
    return _description("bucket_lookup", profile)


def describe_live_object_metadata(profile: GCSBucketProfile, object_name: str) -> GCSWireRequest:
    _object_name(object_name)
    return _description("live_metadata", profile, object_name)


def describe_pinned_media_read(
    profile: GCSBucketProfile, request: GCSReadRequest, *, observation: GCSWireObjectObservation
) -> GCSWireRequest:
    request = _rebuild(request, GCSReadRequest)
    if type(observation) is not GCSWireObjectObservation:
        _fail("An exact unsigned object observation is required")
    metadata = _rebuild(observation.metadata, GCSObjectMetadata)
    crc = _crc(observation.crc32c)
    return _description(
        "pinned_live_media",
        profile,
        request.object_name,
        asdict(request),
        {"metadata": asdict(metadata), "crc32c": crc},
    )


def describe_conditional_object_write(
    profile: GCSBucketProfile, request: GCSWriteRequest
) -> GCSWireRequest:
    request = _rebuild(request, GCSWriteRequest)
    raw = asdict(request)
    payload = raw.pop("payload")
    return _description("conditional_write", profile, request.object_name, raw, payload=payload)


def _status(operation: str, status: int, response: bytes) -> None:
    if type(status) is not int or not 100 <= status <= 599 or type(response) is not bytes:
        _fail("Response status and bytes must be exact native values")
    maximum = MAXIMUM_OBJECT_BYTES if operation == "pinned_live_media" else MAXIMUM_JSON_BYTES
    if len(response) > maximum:
        _fail("Response exceeds its pre-decode byte bound")
    if status == 412 and operation in {"pinned_live_media", "conditional_write"}:
        raise GCSPreconditionFailed("The conditional wire response reports status 412")
    if status != 200:
        if operation == "conditional_write":
            raise GCSAmbiguousWrite("Write outcome is unconfirmed; the codec does not retry")
        _fail("Response status is unsupported or unconfirmed; no redirect or range handling")


def parse_bucket_response(
    description: GCSWireRequest, status: int, response: bytes
) -> GCSBucketObservation:
    operation, source, _ = _checked(description)
    if operation != "bucket_lookup":
        _fail("Bucket response requires a bucket description")
    _status(operation, status, response)
    raw = _decode(response)
    _exact(
        raw,
        {"name", "metageneration", "versioning"},
        {
            "retentionPolicy",
            "objectRetention",
            "defaultEventBasedHold",
            "softDeleteTime",
            "hardDeleteTime",
        },
    )
    profile = _profile(GCSBucketProfile(**source["profile"]))
    if raw["name"] != profile.bucket or any(
        key in raw for key in ("objectRetention", "softDeleteTime", "hardDeleteTime")
    ):
        _fail("Bucket substitutes its name or uses unsupported retention/deleted modes")
    _generation(raw["metageneration"])
    _exact(raw["versioning"], {"enabled"})
    if (
        type(raw["versioning"]["enabled"]) is not bool
        or raw["versioning"]["enabled"] != profile.versioning_enabled
    ):
        _fail("Bucket versioning does not reproduce the explicit declaration")
    if "defaultEventBasedHold" in raw and (
        type(raw["defaultEventBasedHold"]) is not bool or raw["defaultEventBasedHold"]
    ):
        _fail("Default event holds are unsupported")
    locked, period = False, 0
    if "retentionPolicy" in raw:
        _exact(raw["retentionPolicy"], {"retentionPeriod", "isLocked"})
        locked = raw["retentionPolicy"]["isLocked"]
        if type(locked) is not bool:
            _fail("Retention lock must be a native boolean")
        period = _decimal(raw["retentionPolicy"]["retentionPeriod"], maximum=3_155_759_999)
    if (locked, period) != (profile.retention_policy_locked, profile.retention_period_seconds):
        _fail("Bucket retention does not reproduce the explicit declaration")
    return GCSBucketObservation(
        profile.bucket, raw["metageneration"], profile.versioning_enabled, locked, period
    )


def parse_object_metadata_response(
    description: GCSWireRequest, status: int, response: bytes
) -> GCSWireObjectObservation:
    operation, source, request = _checked(description)
    if operation not in {"live_metadata", "conditional_write"}:
        _fail("Object metadata response requires its exact operation description")
    _status(operation, status, response)
    profile = _profile(GCSBucketProfile(**source["profile"]))
    observation = _metadata(profile, source["object_name"], _decode(response))
    if operation == "conditional_write":
        metadata = observation.metadata
        if (
            metadata.size_bytes != len(request.payload)
            or metadata.ledger_object != request.ledger_object
            or (
                request.if_generation_match != "0"
                and metadata.generation == request.if_generation_match
            )
            or (
                observation.crc32c is not None
                and observation.crc32c != crc32c_base64(request.payload)
            )
        ):
            _fail(
                "Write acknowledgement does not reproduce the requested content or new generation"
            )
    return observation


def parse_media_response(
    description: GCSWireRequest,
    status: int,
    response: bytes,
    *,
    content_encoding: str | None = None,
) -> GCSObjectRead:
    operation, _, captured = _checked(description)
    if operation != "pinned_live_media":
        _fail("Media response requires its pinned live operation")
    _status(operation, status, response)
    if type(content_encoding) not in (str, type(None)) or content_encoding not in (
        None,
        "identity",
    ):
        _fail("Encoded media requires unsupported decompression")
    _, observation = captured
    metadata = observation.metadata
    if len(response) != metadata.size_bytes:
        _fail("Media bytes do not match the captured live metadata size")
    if observation.crc32c is not None and observation.crc32c != crc32c_base64(response):
        _fail("Media bytes do not match the captured CRC32C")
    if (
        metadata.ledger_object is not None
        and metadata.ledger_object.sha256 != "sha256:" + hashlib.sha256(response).hexdigest()
    ):
        _fail("Media bytes do not match the local ledger descriptor digest")
    return GCSObjectRead(_rebuild(metadata, GCSObjectMetadata), response)
