"""Inert finite-horizon GCS catalog wire descriptions and unsigned decoding."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

from . import gcp_gcs_catalog as catalog
from . import gcp_gcs_wire as common
from .candidate_enrollment_production_custody_contract import CatalogObjectDescriptor
from .gcp_gcs_catalog import (
    ENVIRONMENT_CLASS,
    MAXIMUM_OBJECT_BYTES,
    GCSCatalogDomain,
    GCSCatalogError,
    GCSCatalogObjectObservation,
    GCSCatalogObjectRead,
    GCSCatalogReadRequest,
    GCSCatalogSimulationProfile,
    GCSCatalogWriteRequest,
)
from .gcp_gcs_custody import GCSAmbiguousWrite, GCSPreconditionFailed

ORIGIN = common.ORIGIN
DESCRIPTOR_METADATA_KEY = "sunderkey-catalog-object-descriptor-v1"
MAXIMUM_JSON_BYTES = common.MAXIMUM_JSON_BYTES
MAXIMUM_DESCRIPTOR_BYTES = common.MAXIMUM_DESCRIPTOR_BYTES
MAXIMUM_MULTIPART_BYTES = common.MAXIMUM_MULTIPART_BYTES
MAXIMUM_PROVIDER_RETENTION_SECONDS = 3_155_759_999
BUCKET_FIELDS = common.BUCKET_FIELDS
OBJECT_FIELDS = common.OBJECT_FIELDS
_OPERATIONS = frozenset(
    {"bucket_lookup", "live_metadata", "pinned_live_media", "create_only_write"}
)
_TIME_FIELDS = ("year", "month", "day", "hour", "minute", "second", "microsecond", "fold")
_TIME_BOUNDS = ((1, 9999), (1, 12), (1, 31), (0, 23), (0, 59), (0, 59), (0, 999999), (0, 1))


class GCSCatalogWireError(GCSCatalogError):
    """Unsupported local wire material, never provider authority or policy evidence."""


def _fail(message: str) -> None:
    raise GCSCatalogWireError(message)


def _json(value: object) -> bytes:
    try:
        return common._bounded_json(value)
    except common.GCSWireError as exc:
        raise GCSCatalogWireError(
            "Catalog JSON exceeds its native structural or byte bounds"
        ) from exc


def _decode(raw: bytes, maximum: int = MAXIMUM_JSON_BYTES) -> dict:
    try:
        return common._decode(raw, maximum)
    except common.GCSWireError as exc:
        raise GCSCatalogWireError("Catalog response is not bounded strict JSON") from exc


def _exact(raw: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    try:
        common._exact(raw, required, optional)
    except common.GCSWireError as exc:
        raise GCSCatalogWireError("Catalog fields are missing, non-native or unsupported") from exc


def _crc(value: str | None) -> str | None:
    try:
        return common._crc(value)
    except common.GCSWireError as exc:
        raise GCSCatalogWireError("Catalog CRC32C is not canonical four-byte base64") from exc


def _profile(value: GCSCatalogSimulationProfile) -> GCSCatalogSimulationProfile:
    try:
        captured = catalog._owned(value, GCSCatalogSimulationProfile)
    except GCSCatalogError as exc:
        raise GCSCatalogWireError(
            "An exact source-bound catalog simulation profile is required"
        ) from exc
    if captured.retention_period_seconds > MAXIMUM_PROVIDER_RETENTION_SECONDS:
        _fail("Catalog period is outside the supported provider wire subset")
    return captured


def _profile_document(profile: GCSCatalogSimulationProfile) -> dict:
    return {item.name: getattr(profile, item.name) for item in fields(profile)} | {
        "catalog": asdict(profile.catalog),
        "ledger": asdict(profile.ledger),
    }


def _profile_from_document(raw: dict) -> GCSCatalogSimulationProfile:
    _exact(raw, {item.name for item in fields(GCSCatalogSimulationProfile)})
    for key in ("catalog", "ledger"):
        _exact(raw[key], {item.name for item in fields(GCSCatalogDomain)})
    value = GCSCatalogSimulationProfile(
        GCSCatalogDomain(**raw["catalog"]),
        GCSCatalogDomain(**raw["ledger"]),
        raw["simulation_started_at"],
        raw["simulation_use_until"],
        raw["retention_period_seconds"],
    )
    if type(raw["profile_sha256"]) is not str or raw["profile_sha256"] != value.profile_sha256:
        _fail("Captured catalog profile no longer matches its original content binding")
    return _profile(value)


def _time_document(value: datetime) -> dict[str, int]:
    catalog._utc(value)
    return {name: getattr(value, name) for name in _TIME_FIELDS}


def _time_from_document(raw: dict) -> datetime:
    _exact(raw, set(_TIME_FIELDS))
    if any(type(raw[name]) is not int for name in _TIME_FIELDS):
        _fail("Observation time requires exact native integer components")
    if any(
        not lower <= raw[name] <= upper
        for name, (lower, upper) in zip(_TIME_FIELDS, _TIME_BOUNDS, strict=True)
    ):
        _fail("Observation time components exceed their native UTC datetime bounds")
    return datetime(**raw, tzinfo=UTC)


def _active(profile: GCSCatalogSimulationProfile, observed_at: datetime) -> None:
    catalog._utc(observed_at)
    if not (
        catalog._instant(profile.simulation_started_at)
        <= observed_at
        < catalog._instant(profile.simulation_use_until)
    ):
        _fail("Caller-labeled observation time is outside the original finite source horizon")


def _descriptor(raw: dict) -> CatalogObjectDescriptor:
    _exact(raw, {item.name for item in fields(CatalogObjectDescriptor)})
    return catalog._owned(CatalogObjectDescriptor(**raw), CatalogObjectDescriptor)


@dataclass(frozen=True)
class GCSCatalogWireBucketObservation:
    """Unsigned selected provider fields with no caller domain or time labels."""

    bucket: str
    metageneration: str
    versioning_enabled: bool
    retention_policy_locked: bool
    retention_period_seconds: int
    default_event_based_hold: bool
    object_retention_configuration_present: bool

    def __post_init__(self) -> None:
        catalog._text(self.bucket, "bucket", catalog._BUCKET)
        catalog._token(self.metageneration)
        for name, expected in (
            ("versioning_enabled", False),
            ("retention_policy_locked", True),
            ("default_event_based_hold", False),
            ("object_retention_configuration_present", False),
        ):
            value = getattr(self, name)
            if type(value) is not bool or value is not expected:
                _fail("Bucket fact is outside the explicit supported boolean subset")
        if (
            type(self.retention_period_seconds) is not int
            or not 1 <= self.retention_period_seconds <= MAXIMUM_PROVIDER_RETENTION_SECONDS
        ):
            _fail("Bucket fact retention period is outside its native provider bound")


@dataclass(frozen=True)
class GCSCatalogWireObjectObservation:
    """Unsigned object fields with a separately caller-labeled observation time."""

    observation: GCSCatalogObjectObservation
    crc32c: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observation", catalog._owned(self.observation, GCSCatalogObjectObservation)
        )
        _crc(self.crc32c)


def _capture_observation(value: GCSCatalogWireObjectObservation) -> GCSCatalogWireObjectObservation:
    if type(value) is not GCSCatalogWireObjectObservation:
        _fail("An exact unsigned catalog wire observation is required")
    try:
        return GCSCatalogWireObjectObservation(value.observation, value.crc32c)
    except (AttributeError, TypeError, ValueError) as exc:
        raise GCSCatalogWireError("Catalog wire observation no longer reconstructs") from exc


def _observation_document(value: GCSCatalogWireObjectObservation) -> dict:
    observed = value.observation
    return {
        "observation": {
            item.name: (
                asdict(observed.descriptor)
                if item.name == "descriptor"
                else _time_document(observed.observed_at)
                if item.name == "observed_at"
                else getattr(observed, item.name)
            )
            for item in fields(GCSCatalogObjectObservation)
        },
        "crc32c": value.crc32c,
    }


def _observation_from_document(raw: dict) -> GCSCatalogWireObjectObservation:
    _exact(raw, {"observation", "crc32c"})
    _exact(raw["observation"], {item.name for item in fields(GCSCatalogObjectObservation)})
    body = dict(raw["observation"])
    body["descriptor"] = _descriptor(body["descriptor"])
    body["observed_at"] = _time_from_document(body["observed_at"])
    return GCSCatalogWireObjectObservation(GCSCatalogObjectObservation(**body), raw["crc32c"])


def _object_context(profile, name, observed, observed_at) -> None:
    descriptor = observed.descriptor
    if (
        observed.bucket != profile.catalog.bucket
        or observed.object_name != name
        or name != "catalog/" + descriptor.object_id
        or descriptor.namespace_id != profile.catalog.namespace_id
        or descriptor.failure_domain_id != profile.catalog.failure_domain_id
        or _time_document(observed.observed_at) != _time_document(observed_at)
        or not observed.is_current
        or observed.temporary_hold
        or observed.event_based_hold
        or observed.retention_mode != "bucket_policy"
        or catalog._instant(observed.retention_until)
        < catalog._instant(profile.simulation_use_until)
    ):
        _fail("Catalog object does not reproduce its coordinates, time or fixed protection horizon")


def _captured_source(operation, source, payload):
    _exact(source, {"profile", "observed_at", "object_name", "request", "observation"})
    profile = _profile_from_document(source["profile"])
    at = _time_from_document(source["observed_at"])
    _active(profile, at)
    name = source["object_name"]
    if operation == "bucket_lookup":
        if (
            name is not None
            or source["request"] is not None
            or source["observation"] is not None
            or payload
        ):
            _fail("Bucket lookup cannot carry object, request, observation or payload material")
        return profile, at, None
    catalog._name(name)
    if operation == "live_metadata":
        if source["request"] is not None or source["observation"] is not None or payload:
            _fail("Live metadata lookup cannot carry pinned or upload material")
        return profile, at, None
    raw = source["request"]
    expected = {
        item.name
        for item in fields(
            GCSCatalogWriteRequest if operation == "create_only_write" else GCSCatalogReadRequest
        )
    }
    expected.discard("payload")
    _exact(raw, expected)
    body = dict(raw)
    body["descriptor"] = _descriptor(body["descriptor"])
    body["observed_at"] = _time_from_document(body["observed_at"])
    if operation == "create_only_write":
        request = catalog._owned(
            GCSCatalogWriteRequest(**body, payload=payload), GCSCatalogWriteRequest
        )
        if source["observation"] is not None:
            _fail("A create-only request cannot contain a prior object observation")
    else:
        request = catalog._owned(GCSCatalogReadRequest(**body), GCSCatalogReadRequest)
        if payload:
            _fail("A pinned media request cannot contain upload bytes")
    if (
        request.bucket != profile.catalog.bucket
        or request.object_name != name
        or request.descriptor.namespace_id != profile.catalog.namespace_id
        or request.descriptor.failure_domain_id != profile.catalog.failure_domain_id
        or _time_document(request.observed_at) != _time_document(at)
    ):
        _fail("Catalog request substitutes its captured source coordinates or observation time")
    if operation == "create_only_write":
        return profile, at, request
    observation = _observation_from_document(source["observation"])
    observed = observation.observation
    _object_context(profile, name, observed, at)
    if (
        request.generation != observed.generation
        or request.metageneration != observed.metageneration
        or request.descriptor != observed.descriptor
    ):
        _fail("Pinned read does not reproduce its exact generation, metadata and descriptor")
    return profile, at, (request, observation)


def _parts(operation: str, source_json: str, payload: bytes) -> tuple:
    if type(operation) is not str or len(operation) > 32 or operation not in _OPERATIONS:
        _fail("Unsupported catalog wire operation")
    if (
        type(source_json) is not str
        or len(source_json) > MAXIMUM_JSON_BYTES
        or not source_json.isascii()
    ):
        _fail("Catalog source must be native bounded ASCII JSON")
    if type(payload) is not bytes or len(payload) > MAXIMUM_OBJECT_BYTES:
        _fail("Catalog payload exceeds its native byte bound")
    source = _decode(source_json.encode("ascii"))
    if _json(source).decode("ascii") != source_json:
        _fail("Catalog source bytes are not canonical")
    profile, at, request = _captured_source(operation, source, payload)
    path = "/storage/v1/b/" + quote(profile.catalog.bucket, safe="")
    query = {"projection": "noAcl"}
    headers = (("Accept-Encoding", "identity"),)
    method, body = "GET", b""
    if operation == "bucket_lookup":
        query["fields"] = BUCKET_FIELDS
    elif operation == "live_metadata":
        path += "/o/" + quote(source["object_name"], safe="")
        query["fields"] = OBJECT_FIELDS
    elif operation == "pinned_live_media":
        pinned, _ = request
        path += "/o/" + quote(pinned.object_name, safe="")
        query = {
            "alt": "media",
            "ifGenerationMatch": pinned.generation,
            "ifMetagenerationMatch": pinned.metageneration,
        }
    else:
        method = "POST"
        path = "/upload/storage/v1/b/" + quote(profile.catalog.bucket, safe="") + "/o"
        query.update({"uploadType": "multipart", "fields": OBJECT_FIELDS, "ifGenerationMatch": "0"})
        metadata = _json(
            {
                "name": request.object_name,
                "contentType": "application/octet-stream",
                "crc32c": common.crc32c_base64(payload),
                "metadata": {
                    DESCRIPTOR_METADATA_KEY: _json(asdict(request.descriptor)).decode("ascii")
                },
            }
        )
        token = hashlib.sha256(
            source_json.encode("ascii") + hashlib.sha256(payload).digest()
        ).hexdigest()
        boundary = "sunderkey_gcs_catalog_" + token
        delimiter = b"--" + boundary.encode("ascii")
        if delimiter in payload or delimiter in metadata:
            _fail("Catalog bytes collide with the deterministic multipart boundary")
        body = (
            delimiter
            + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            + metadata
            + b"\r\n"
            + delimiter
            + b"\r\nContent-Type: application/octet-stream\r\n\r\n"
            + payload
            + b"\r\n"
            + delimiter
            + b"--\r\n"
        )
        if len(body) > MAXIMUM_MULTIPART_BYTES:
            _fail("Catalog multipart body exceeds its independent bound")
        headers += (
            ("Content-Type", "multipart/related; boundary=" + boundary),
            ("Content-Length", str(len(body))),
        )
    url = ORIGIN + path + "?" + urlencode(sorted(query.items()), quote_via=quote, safe="")
    return method, url, headers, body, source, profile, at, request


@dataclass(frozen=True)
class GCSCatalogWireRequest:
    """Owned inert description with no send, transport or credential operation."""

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


def _checked(value: GCSCatalogWireRequest) -> tuple:
    if type(value) is not GCSCatalogWireRequest:
        _fail("An exact inert catalog wire description is required")
    try:
        if (
            type(value.method) is not str
            or len(value.method) > 4
            or type(value.url) is not str
            or len(value.url) > 4096
            or type(value.headers) is not tuple
            or len(value.headers) > 3
            or any(
                type(row) is not tuple
                or len(row) != 2
                or any(type(item) is not str or len(item) > 256 for item in row)
                for row in value.headers
            )
            or type(value.body) is not bytes
            or len(value.body) > MAXIMUM_MULTIPART_BYTES
        ):
            _fail("Catalog wire fields must be exact native bounded values")
        expected = _parts(value.operation, value.source_json, value.payload)
        if (value.method, value.url, value.headers, value.body) != expected[:4]:
            _fail("Catalog description does not reconstruct its original sources")
        return expected[4:]
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, GCSCatalogWireError):
            raise
        raise GCSCatalogWireError("Catalog wire source does not reconstruct") from exc


def _description(
    operation, profile, observed_at, name=None, request=None, observation=None, payload=b""
):
    try:
        profile = _profile(profile)
        _active(profile, observed_at)
        source = {
            "profile": _profile_document(profile),
            "observed_at": _time_document(observed_at),
            "object_name": name,
            "request": request,
            "observation": observation,
        }
        source_json = _json(source).decode("ascii")
        method, url, headers, body, *_ = _parts(operation, source_json, payload)
        return GCSCatalogWireRequest(operation, source_json, payload, method, url, headers, body)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, GCSCatalogWireError):
            raise
        raise GCSCatalogWireError("Catalog description source is invalid") from exc


def describe_catalog_bucket_lookup(
    profile: GCSCatalogSimulationProfile, *, observed_at: datetime
) -> GCSCatalogWireRequest:
    return _description("bucket_lookup", profile, observed_at)


def describe_catalog_live_metadata(
    profile: GCSCatalogSimulationProfile, object_name: str, *, observed_at: datetime
) -> GCSCatalogWireRequest:
    return _description("live_metadata", profile, observed_at, object_name)


def _request_document(request) -> dict:
    return {
        item.name: asdict(request.descriptor)
        if item.name == "descriptor"
        else _time_document(request.observed_at)
        if item.name == "observed_at"
        else getattr(request, item.name)
        for item in fields(type(request))
        if item.name != "payload"
    }


def describe_catalog_create_only_write(
    profile: GCSCatalogSimulationProfile, request: GCSCatalogWriteRequest
) -> GCSCatalogWireRequest:
    request = catalog._owned(request, GCSCatalogWriteRequest)
    return _description(
        "create_only_write",
        profile,
        request.observed_at,
        request.object_name,
        _request_document(request),
        payload=request.payload,
    )


def describe_catalog_pinned_media_read(
    profile: GCSCatalogSimulationProfile,
    request: GCSCatalogReadRequest,
    *,
    observation: GCSCatalogWireObjectObservation,
) -> GCSCatalogWireRequest:
    request = catalog._owned(request, GCSCatalogReadRequest)
    observation = _capture_observation(observation)
    return _description(
        "pinned_live_media",
        profile,
        request.observed_at,
        request.object_name,
        _request_document(request),
        _observation_document(observation),
    )


def _status(operation: str, status: int, response: bytes) -> None:
    if type(status) is not int or not 100 <= status <= 599 or type(response) is not bytes:
        _fail("Status and response must be exact native values")
    maximum = MAXIMUM_OBJECT_BYTES if operation == "pinned_live_media" else MAXIMUM_JSON_BYTES
    if len(response) > maximum:
        _fail("Catalog response exceeds its pre-decode byte bound")
    if status == 412 and operation in {"pinned_live_media", "create_only_write"}:
        raise GCSPreconditionFailed("Conditional catalog response reports status 412")
    if status != 200:
        if operation == "create_only_write":
            raise GCSAmbiguousWrite("Catalog write outcome is unconfirmed; no automatic retry")
        _fail("Catalog read status is unsupported or unconfirmed; no absence or redirect inference")


def parse_catalog_bucket_response(
    description: GCSCatalogWireRequest, status: int, response: bytes
) -> GCSCatalogWireBucketObservation:
    _, profile, _, _ = _checked(description)
    if description.operation != "bucket_lookup":
        _fail("Bucket response requires its exact catalog bucket description")
    _status(description.operation, status, response)
    raw = _decode(response)
    _exact(
        raw,
        {"name", "metageneration", "versioning", "retentionPolicy", "defaultEventBasedHold"},
        {"objectRetention", "softDeleteTime", "hardDeleteTime"},
    )
    if raw["name"] != profile.catalog.bucket or any(
        key in raw for key in ("objectRetention", "softDeleteTime", "hardDeleteTime")
    ):
        _fail("Bucket coordinates, object-retention or deletion configuration are unsupported")
    _exact(raw["versioning"], {"enabled"})
    _exact(raw["retentionPolicy"], {"retentionPeriod", "isLocked"})
    try:
        period = common._decimal(
            raw["retentionPolicy"]["retentionPeriod"], maximum=MAXIMUM_PROVIDER_RETENTION_SECONDS
        )
        result = GCSCatalogWireBucketObservation(
            raw["name"],
            raw["metageneration"],
            raw["versioning"]["enabled"],
            raw["retentionPolicy"]["isLocked"],
            period,
            raw["defaultEventBasedHold"],
            False,
        )
    except ValueError as exc:
        raise GCSCatalogWireError(
            "Returned bucket facts fail the supported native policy subset"
        ) from exc
    if period != profile.retention_period_seconds:
        _fail("Returned bucket period differs from the explicit finite profile")
    return result


def _metadata(profile, name, observed_at, raw) -> GCSCatalogWireObjectObservation:
    _exact(
        raw,
        {
            "bucket",
            "name",
            "generation",
            "metageneration",
            "size",
            "contentType",
            "temporaryHold",
            "eventBasedHold",
            "retentionExpirationTime",
            "metadata",
        },
        {
            "contentEncoding",
            "crc32c",
            "retention",
            "timeDeleted",
            "softDeleteTime",
            "hardDeleteTime",
        },
    )
    if "contentEncoding" in raw and (
        type(raw["contentEncoding"]) is not str or raw["contentEncoding"] != "identity"
    ):
        _fail("Present catalog encoding must be a native identity string")
    if "crc32c" in raw and type(raw["crc32c"]) is not str:
        _fail("Present catalog CRC32C must be a native canonical string")
    crc = _crc(raw["crc32c"]) if "crc32c" in raw else None
    if (
        raw["bucket"] != profile.catalog.bucket
        or raw["name"] != name
        or raw["contentType"] != "application/octet-stream"
        or any(
            key in raw for key in ("retention", "timeDeleted", "softDeleteTime", "hardDeleteTime")
        )
    ):
        _fail("Catalog coordinates, encoding, retention mode or deleted version are unsupported")
    for key in ("temporaryHold", "eventBasedHold"):
        if type(raw[key]) is not bool or raw[key] is not False:
            _fail("Catalog holds must be explicitly native false")
    _exact(raw["metadata"], {DESCRIPTOR_METADATA_KEY})
    text = raw["metadata"][DESCRIPTOR_METADATA_KEY]
    if type(text) is not str or len(text) > MAXIMUM_DESCRIPTOR_BYTES or not text.isascii():
        _fail("Catalog descriptor must be bounded native ASCII JSON text")
    try:
        descriptor = _descriptor(_decode(text.encode("ascii"), MAXIMUM_DESCRIPTOR_BYTES))
        if text.encode("ascii") != _json(asdict(descriptor)):
            _fail("Catalog descriptor must contain exact local canonical bytes")
        size = common._decimal(raw["size"], maximum=MAXIMUM_OBJECT_BYTES)
        if size != descriptor.size_bytes:
            _fail("Catalog size differs from the local descriptor")
        observed = GCSCatalogObjectObservation(
            raw["bucket"],
            raw["name"],
            raw["generation"],
            raw["metageneration"],
            descriptor,
            raw["retentionExpirationTime"],
            observed_at,
            True,
            False,
            False,
            "bucket_policy",
        )
        _object_context(profile, name, observed, observed_at)
        return GCSCatalogWireObjectObservation(observed, crc)
    except ValueError as exc:
        if isinstance(exc, GCSCatalogWireError):
            raise
        raise GCSCatalogWireError(
            "Catalog object response does not reconstruct its supported mapping"
        ) from exc


def parse_catalog_object_response(
    description: GCSCatalogWireRequest, status: int, response: bytes
) -> GCSCatalogWireObjectObservation:
    source, profile, at, request = _checked(description)
    if description.operation not in {"live_metadata", "create_only_write"}:
        _fail("Object response requires an exact live metadata or create-only description")
    _status(description.operation, status, response)
    observation = _metadata(profile, source["object_name"], at, _decode(response))
    if description.operation == "create_only_write" and (
        observation.observation.descriptor != request.descriptor
        or (
            observation.crc32c is not None
            and observation.crc32c != common.crc32c_base64(request.payload)
        )
    ):
        _fail("Catalog acknowledgement substitutes the uploaded descriptor or reported checksum")
    return observation


def parse_catalog_media_response(
    description: GCSCatalogWireRequest,
    status: int,
    response: bytes,
    *,
    content_encoding: str | None = None,
) -> GCSCatalogObjectRead:
    _, _, _, captured = _checked(description)
    if description.operation != "pinned_live_media":
        _fail("Catalog media response requires its exact live pinned description")
    _status(description.operation, status, response)
    if type(content_encoding) not in (str, type(None)) or content_encoding not in (
        None,
        "identity",
    ):
        _fail("Catalog media encoding would require unsupported decompression")
    _, observation = captured
    observed = observation.observation
    if (
        len(response) != observed.descriptor.size_bytes
        or observed.descriptor.sha256 != "sha256:" + hashlib.sha256(response).hexdigest()
        or (observation.crc32c is not None and observation.crc32c != common.crc32c_base64(response))
    ):
        _fail("Catalog media does not reproduce pinned size, SHA-256 and supplied CRC32C")
    return catalog._owned(GCSCatalogObjectRead(observed, response), GCSCatalogObjectRead)


__all__ = [
    "GCSCatalogWireError",
    "GCSCatalogWireRequest",
    "GCSCatalogWireBucketObservation",
    "GCSCatalogWireObjectObservation",
    "describe_catalog_bucket_lookup",
    "describe_catalog_live_metadata",
    "describe_catalog_create_only_write",
    "describe_catalog_pinned_media_read",
    "parse_catalog_bucket_response",
    "parse_catalog_object_response",
    "parse_catalog_media_response",
]
