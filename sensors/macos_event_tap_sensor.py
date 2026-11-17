"""Read-only macOS Quartz event-tap inventory.

CGGetEventTapList reports tap metadata (PID, ID, event bitmask) and does not
intercept, capture, replay, store or transmit any keyboard events or typed text.
This is one indicator of keyboard-event observation, NOT a malware verdict.
No native API is invoked unless running on macOS.
"""
import ctypes
import sys
from dataclasses import dataclass
from typing import Dict, List

# macOS Core Graphics event types; only key down/up are treated as keyboard taps.
KEY_DOWN = 10
KEY_UP = 11
KEYBOARD_MASK = (1 << KEY_DOWN) | (1 << KEY_UP)
COREGRAPHICS_PATH = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"


class _CGEventTapInformation(ctypes.Structure):
    """Field types/order from the public Core Graphics CGEventTypes.h header."""
    _fields_ = [
        ("eventTapID", ctypes.c_uint32),
        ("tapPoint", ctypes.c_uint32),
        ("options", ctypes.c_uint32),
        ("eventsOfInterest", ctypes.c_uint64),
        ("tappingProcess", ctypes.c_int32),
        ("processBeingTapped", ctypes.c_int32),
        ("enabled", ctypes.c_bool),
        ("minUsecLatency", ctypes.c_float),
        ("avgUsecLatency", ctypes.c_float),
        ("maxUsecLatency", ctypes.c_float),
    ]


@dataclass(frozen=True)
class TapAudit:
    state: str              # ok | unsupported | error
    message: str
    total_taps: int = 0
    keyboard_taps: int = 0
    by_pid: Dict[int, List[int]] = None

    def __post_init__(self):
        if self.by_pid is None:
            object.__setattr__(self, "by_pid", {})


def classify_taps(taps):
    """Return {pid: [tap IDs]} for enabled key down/up listeners, no key data."""
    mapped = {}
    for t in taps:
        # Event taps watching only mouse/scroll/modifier events are not counted.
        if t.enabled and int(t.tappingProcess) > 0 and (int(t.eventsOfInterest) & KEYBOARD_MASK):
            mapped.setdefault(int(t.tappingProcess), []).append(int(t.eventTapID))
    return mapped


def audit_keyboard_taps():
    """Enumerate existing taps. Never creates a tap or requests new OS privileges."""
    if sys.platform != "darwin":
        return TapAudit("unsupported", "macOS Quartz event-tap inventory is only available on macOS")

    try:
        cg = ctypes.CDLL(COREGRAPHICS_PATH)
        method = cg.CGGetEventTapList
        method.argtypes = [ctypes.c_uint32, ctypes.POINTER(_CGEventTapInformation),
                           ctypes.POINTER(ctypes.c_uint32)]
        method.restype = ctypes.c_int32

        count = ctypes.c_uint32(0)
        err = method(0, None, ctypes.byref(count))
        if err != 0:
            return TapAudit("error", f"CoreGraphics could not enumerate taps (CGError {err})")
        if count.value > 4096:
            return TapAudit("error", "Unusually large event-tap count; enumeration refused")
        if not count.value:
            return TapAudit("ok", "No event taps were returned by macOS")

        # A few taps can appear between the two calls; allocate a small buffer margin.
        capacity = min(4096, count.value + 32)
        array = (_CGEventTapInformation * capacity)()
        actual = ctypes.c_uint32(0)
        err = method(capacity, array, ctypes.byref(actual))
        if err != 0:
            return TapAudit("error", f"CoreGraphics could not read tap metadata (CGError {err})")
        taps = array[:min(capacity, actual.value)]
        by_pid = classify_taps(taps)
        return TapAudit("ok", "Event-tap metadata enumerated (not a complete keylogger scan)",
                        total_taps=len(taps),
                        keyboard_taps=sum(len(v) for v in by_pid.values()),
                        by_pid=by_pid)
    except (OSError, ValueError, AttributeError) as exc:
        return TapAudit("error", f"Event-tap audit unavailable: {type(exc).__name__}: {exc}")
