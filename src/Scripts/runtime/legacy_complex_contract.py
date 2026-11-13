"""Independent raw text/raster/layout acceptance for the new immutable helper.

These checks read actual widget state captured before each PNG. They do not
infer success from a host assertion count or accept an arbitrary false result.
"""
from collections import Counter
import math
import re


def number(value, minimum=0, maximum=4096):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def verify_style(selected, names, contract):
    plans, frames = {}, {}
    last = None
    for row in selected:
        kind = row.get("type")
        if kind == "inlineFixtureReady":
            plans[row["case"]] = row
        elif kind == "inlineStyleProbe":
            last = row
        elif kind == "saveCommitted" and row.get("requestID") in ("quick-save-active", "ordinary-save-active"):
            if (last is None or last.get("case") != "lifecycle" or last.get("index") != 15 or
                    last.get("applied") is not True or last.get("measured", {}).get("renderer") != "coretext-v1" or
                    last.get("actualTTS") != "مرحبا 中文 123 (ABC) بالعالم"):
                raise ValueError("A claimed active complex save actually saved a different case/renderer")
        elif kind == "inlineImageSaved":
            label = row.get("label")
            if label == "game-menu-clean":
                continue
            if last is None or last.get("case") not in plans:
                raise ValueError("A captured complex frame lacks its actual widget observation")
            frames[label] = last
            plan = plans[last["case"]]
            if type(last.get("globalRTL")) is not bool or last["globalRTL"] is not last.get("originalRTL"):
                raise ValueError("Complex inline changed the author's global bidi flag")
            if last.get("applied") is True:
                measured = last.get("measured", {})
                budget = measured.get("budget")
                if (last.get("activeWidget") is not True or last.get("ownedStyle") is not True or
                        last.get("translationUntruncated") is not True or type(last.get("actualStyleSize")) is not int or
                        not 21 <= last["actualStyleSize"] <= 58 or last["actualStyleSize"] != measured.get("size") or
                        not isinstance(budget, list) or len(budget) != 2 or
                        any(not number(value, .01) for value in budget) or
                        not number(measured.get("width"), .01, budget[0]) or not number(measured.get("height"), .01, budget[1])):
                    raise ValueError("A complex frame lacks complete actual measured layout")
                compared = label in ("comparison", "spanComparison")
                expected_tts = (plan["sourcePlain"] + "\n" if compared else "") + plan["translation"]
                if last.get("case") == "lifecycle" and not number(plan.get("sourceRevealTime"), .001, 1e6):
                    raise ValueError("The complex lifecycle never exercised a real nonzero source reveal duration")
                if last.get("actualTTS") != expected_tts:
                    raise ValueError("The actual spoken/full translation differs from the requested complete text")
                if (type(last.get("actualAFMLength")) is not int or last["actualAFMLength"] < max(plan["sourceAFMLength"], len(expected_tts) + 1) or
                        not number(last.get("actualGetTime"), plan["sourceRevealTime"], 1e6)):
                    raise ValueError("Complex inline shortened the actual reading/reveal duration")
                renderer = measured.get("renderer")
                if renderer == "coretext-v1":
                    prefix = plan["source"] + "\n" if compared else ""
                    if last.get("actualText") != [prefix + "{alt}" + plan["translation"] + "{/alt}", {"displayable": "OwnedInlineRaster"}]:
                        raise ValueError("The actual native Text does not own the expected single raster and accessible alternate text")
                    expected_bounds = dict(plan["bounds"], start=None, end=None)
                    if last.get("bounds") != expected_bounds:
                        raise ValueError("The raster retained old source substring bounds")
                    images = last.get("imageData")
                    if not isinstance(images, list) or len(images) != 1:
                        raise ValueError("Missing/duplicate actual raster data")
                    image = images[0]
                    if (image.get("cached") is not True or type(image.get("bytes")) is not int or not 0 < image["bytes"] <= 32 * 1024 ** 2 or
                            type(image.get("oversample")) not in (int, float) or image["oversample"] not in (1, 2) or
                            not isinstance(image.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", image["sha256"]) is None):
                        raise ValueError("The actual owned PNG/cache/scale evidence differs")
                    raster = measured.get("raster", {})
                    if (type(raster.get("schemaVersion")) is not int or raster["schemaVersion"] != 1 or
                            raster.get("renderer") != "coretext-v1" or type(raster.get("pixelScale")) is not int or raster["pixelScale"] != image["oversample"] or
                            type(raster.get("missingGlyphs")) is not int or raster["missingGlyphs"] != 0 or
                            type(raster.get("glyphCount")) is not int or raster["glyphCount"] <= 0 or
                            type(raster.get("iterations")) is not int or not 1 <= raster["iterations"] <= 8 or
                            raster.get("fontManifestSHA256") != "d0c613d211ebe54d6d596c643c6cf1bde8eb55fed8eac0732bba7d1ca4ee301d" or
                            not number(raster.get("width"), .01, budget[0]) or not number(raster.get("height"), .01, budget[1]) or
                            raster.get("pixelWidth") != raster["width"] * raster["pixelScale"] or raster.get("pixelHeight") != raster["height"] * raster["pixelScale"] or
                            raster["pixelWidth"] * raster["pixelHeight"] > 4 * 1024 ** 2 or
                            last["actualAFMLength"] != measured.get("afmLength") or last["actualGetTime"] < measured.get("revealTimeFloor", 0)):
                        raise ValueError("CoreText produced unbounded, missing-glyph or stale reading metadata")
                elif renderer in ("native", "native-harfbuzz"):
                    text = plan["translation"]
                    if last["case"] == "uniformBold":
                        text = "{b}" + text + "{/b}"
                    if compared:
                        text = plan["source"] + "\n" + text
                    if last.get("actualText") != [text] or last.get("bounds") != dict(plan["bounds"], start=0, end=len(text)) or last.get("imageData") != []:
                        raise ValueError("The actual native Text was truncated or its source markup changed")
                else:
                    raise ValueError("An unknown renderer claimed an applied translation")
            elif (last.get("applied") is not False or last.get("actualText") != [plan["source"]] or
                    any(last.get(key) is not True for key in ("sourceRestored", "exactOriginalStyle", "sourceBoundsRestored")) or
                    last.get("actualStyleSize") != plan["baselineSize"]):
                raise ValueError("A complex fallback/restore did not return the exact authored widget")
    required = {"zhHans", "ja", "ko", "ar", "he", "latin", "greek", "cyrillic", "devanagari", "thai", "mixedArabic", "mixedHebrew", "uniformBold", "spanComparison", "lifecycle", "comparison", "widget-rebuilt", "quickload-reapply", "ordinary-load-reapply", "game-menu-return-reapply"}
    if any(frames.get(label, {}).get("applied") is not True for label in required):
        raise ValueError("A required complex script/lifecycle was not actually applied/drawn")
    for label in ("devanagari", "thai"):
        expected = "native-harfbuzz" if plans[label].get("hbReachable") is True else "coretext-v1"
        if frames[label].get("measured", {}).get("renderer") != expected:
            raise ValueError("The actual HarfBuzz/CoreText route differs from the selected engine capability")
    for label in ("mixedArabic", "mixedHebrew", "spanComparison", "lifecycle", "comparison"):
        if frames.get(label, {}).get("measured", {}).get("renderer") != "coretext-v1":
            raise ValueError("A required complex case did not exercise the actual new native raster ABI")
    for label in ("lifecycle", "comparison", "before-widget-rebuild", "widget-rebuilt", "background-prepared", "quickload-reapply", "ordinary-load-reapply", "game-menu-return-reapply"):
        frame = frames.get(label, {})
        plan = plans.get("lifecycle", {})
        expected_tts = ("SOURCE LIFECYCLE\n" if label == "comparison" else "") + "مرحبا 中文 123 (ABC) بالعالم"
        if (frame.get("case") != "lifecycle" or frame.get("index") != 15 or frame.get("measured", {}).get("renderer") != "coretext-v1" or
                frame.get("actualTTS") != expected_tts or plan.get("source") != "SOURCE LIFECYCLE" or
                plan.get("translation") != "مرحبا 中文 123 (ABC) بالعالم" or not number(plan.get("sourceRevealTime"), .001, 1e6)):
            raise ValueError("A complex lifecycle/save/load label borrowed a CJK case or shortened its reveal time")
    for label, reason in (("missingGlyphs", "missingGlyph"), ("parent-changed", "geometryChanged")):
        if frames.get(label, {}).get("applied") is not False or frames[label].get("reason") != reason:
            raise ValueError("The explicit missing-glyph/geometry fallback differs")
    if frames.get("explicit-restore", {}).get("applied") is not False:
        raise ValueError("The actual explicit restore did not occur")
    for label in ("parent-restored", "background-resume-unmeasured"):
        if frames.get(label, {}).get("applied") is False and frames[label].get("reason") != "missingMeasuredBudget":
            raise ValueError("An unmeasured layout used an arbitrary fallback reason")
    for reason in ("authorChanged", "geometryChanged"):
        if not any(row.get("type") == "ack" and row.get("inlineTextStyle", {}).get("applied") is False and row["inlineTextStyle"].get("reason") == reason for row in selected):
            raise ValueError("A real fallback did not acknowledge its original request")
    for kind in ("auxiliaryBackgroundRequested", "auxiliaryBackgroundObserved", "suspended", "resumed", "inlineFixtureMenuClosed"):
        if not any(row.get("type") == kind for row in selected):
            raise ValueError("The background/menu path did not actually execute")
    if not any(row.get("type") == "inlineFixtureMenu" and row.get("sourceRestored") is True and row.get("globalRTL") is row.get("originalRTL") for row in selected):
        raise ValueError("The authored menu retained the translated widget")
    for request, slot in (("quick-save-active", "quick-1"), ("ordinary-save-active", "qa-manual-1")):
        if sum(row.get("type") == "saveCommitted" and row.get("requestID") == request and row.get("slot") == slot for row in selected) != 1:
            raise ValueError("A real active-raster save is missing")
    for request in ("quick-load-real", "ordinary-load-real"):
        if sum(row.get("type") == "ack" and row.get("status") == "accepted" and row.get("requestID") == request for row in selected) != 1:
            raise ValueError("A real active-raster load is missing")


# Runtime/owner/F/haptic criteria copied from exact ce906 parent; only the
# new renderer verifier and the explicitly expanded PNG count are successors.
def verify_runtime_events(parent, rows, plans, launch_plans, versions, contract):
    parent.previous.exact_plans(plans, versions)
    if launch_plans != [dict(plan, **({"startupSaveSlot": "qa-manual-1"} if plan["launchMode"] == "nativeCompatibility" else {})) for plan in plans]:
        raise ValueError("The actual startup/save plan changed")
    if any(row.get("type") in {"auxiliaryProbeFailed", "gameError", "error", "saveFailed", "quarantined"} for row in rows):
        raise ValueError("The actual joint runtime reported a failure")
    run_ids = {row.get("runID") for row in rows}
    if len(run_ids) != 1 or any(not isinstance(value, str) or not value for value in run_ids):
        raise ValueError("Mixed actual run IDs")
    processes = {row.get("processID") for row in rows}
    if len(processes) != 1 or any(type(pid) is not int or pid <= 0 for pid in processes):
        raise ValueError("One actual matrix phase must retain one process")
    for index, plan in enumerate(plans):
        selected = [row for row in rows if row.get("sessionIndex") == index]
        of = lambda name: [row for row in selected if row.get("type") == name]
        native = plan["launchMode"] == "nativeCompatibility"
        checks = [row for row in selected if row.get("type") == "auxiliaryCheck"]
        if not checks or any(row.get("passed") is not True for row in checks):
            raise ValueError("A real native/Bridge/style assertion failed")
        for kind in ("ready", "firstFrameDrawn", "willStop", "didStop", "didReset", "threadAudit"):
            matches = [row for row in selected if row.get("type") == kind]
            if len(matches) != 1 or (kind == "threadAudit" and matches[0].get("remaining") != []):
                raise ValueError("Incomplete runtime lifecycle or residual threads")
        observed = of("functionKeyObserved")
        names = Counter(row.get("name") for row in checks if row.get("name") != "CleanCandidateHasNoTestProbe")
        check_contract = contract["nativeCompatibility" if native else "enhancedAndMinimal"]
        if any(names[name] != count for name, count in check_contract["checksExact"].items()):
            raise ValueError("A required exact fixture assertion count changed")
        if set(names) - set(check_contract["checksExact"]) - set(check_contract.get("checksRanges", {})):
            raise ValueError("Unexpected fixture assertion names")
        for name, bounds in check_contract.get("checksRanges", {}).items():
            if not bounds[0] <= names[name] <= bounds[1]:
                raise ValueError("A fixture assertion range changed: " + name)
        start = of("auxiliarySessionStarted")
        if len(start) != 1 or start[0].get("runtimeID") != plan["runtimeID"] or start[0].get("launchMode") != plan["launchMode"] or type(start[0].get("epoch")) is not int or start[0].get("epoch") != index+1:
            raise ValueError("The actual session owner/runtime differs from the exact plan")
        for row in selected:
            if row.get("type") not in {"auxiliaryCheck"} and row.get("sessionID") != start[0]["sessionID"]:
                raise ValueError("A stale session contributed to the raw phase")
            if "epoch" in row and (type(row["epoch"]) is not int or row["epoch"] != index+1):
                raise ValueError("A stale generation contributed to the raw phase")
        for name, count in contract["allModes"]["eventsExact"].items():
            if len(of(name)) != count:
                raise ValueError("A required exact lifecycle event is missing: " + name)
        summary = of("eventQueueCleanupSummary")[0]
        if summary.get("succeeded") is not True or summary.get("publicRegistriesRestored") is not True or summary.get("errors") != []:
            raise ValueError("The actual public event registry/queue cleanup failed")
        if {row.get("stage") for row in of("eventQueueAudit")} != {"beforeQuit", "afterQuit", "afterModulePrune"}:
            raise ValueError("The event queue did not complete all teardown boundaries")
        for name in ("JointFunctionEdgeCount", "DurableHapticAliasesUseCurrentSessionOrInactiveNative"):
            if names[name] != 1:
                raise ValueError("The joint fixture did not complete its F/haptic state machine")
        ready = of("ready")[0]
        caps = ready.get("capabilities", {})
        if caps.get("inlineTextStyleV1") is not (not native) or caps.get("gameHaptics") is not (not native):
            raise ValueError("The real host negotiated the wrong feature capability")
        haptics = of("inlineHapticProbe")
        effects = of("deviceVibration")
        images = of("inlineImageSaved")
        closed = of("inlineTextStyleClosed")
        if names["SavedHapticCallableRebindsAfterActualLoad"] != (1 if native else 3):
            raise ValueError("The durable haptic callable was not tested after actual loads")
        if any(row.get("aliasCallable") is not True or row.get("error") is not None or row.get("aliasModule") != "rr_game_haptics" for row in haptics):
            raise ValueError("The actual saved alias does not use the trusted callable")
        if native:
            if observed or effects or images or closed or len(haptics) != 1:
                raise ValueError("Native mode admitted software function keys, inline styling or haptic effects")
            alias = haptics[0]
            if (alias.get("accepted") is not False or alias.get("ownsCurrentLease") is not False or
                    type(alias.get("generation")) is not int or alias["generation"] < 1 or
                    (alias.get("registeredAPI") is True and (alias.get("registeredCallable") is not True or alias.get("registeredCallIsFalse") is not True))):
                raise ValueError("Native did not safely load an inactive saved haptic alias")
            rejected = of("commandRejected")
            if len(rejected) != 1 or rejected[0].get("requestID") != "native-inline-denied":
                raise ValueError("Native mode did not reject a real valid style command")
            if len(of("functionKeysDisabled")) != 1 or of("functionKeysDisabled")[0].get("keys") != 10 or names["NativeRejectsEachFunctionKey"] != 10:
                raise ValueError("Native did not reject every F key")
        else:
            required_images = {"zhHans", "ja", "ko", "ar", "he", "latin", "greek", "cyrillic", "devanagari", "thai", "missingGlyphs", "lifecycle", "comparison", "explicit-restore", "before-widget-rebuild", "widget-rebuilt", "parent-changed", "parent-restored", "background-prepared", "quickload-reapply", "ordinary-load-reapply", "game-menu-clean", "game-menu-return-reapply"}
            labels = [row.get("label") for row in images]
            resumed = "background-resume-reapply" in labels or {"background-resume-unmeasured", "background-next-dialogue-reapply"} <= set(labels)
            if not required_images <= set(labels) or not resumed or not 28 <= len(labels) <= 29 or len(set(labels)) != len(labels):
                raise ValueError("The complete actual style/render/restore/menu/background PNG sequence is missing")
            for name in ("ActualInlineApplicationOrCleanFallback", "ActualRenPyMeasurementFitsOriginalBox", "PerWidgetBidiRestoresGlobalFlag", "AuthoredReplacementReleasesDetachedWidget", "ActualParentResizeRestoresAndAcknowledgesFallback", "RealBackgroundRestoresBeforeResumeReapply", "RealGameMenuReleasesOriginalStyleBeforeReturning"):
                if names[name] < 1:
                    raise ValueError("An actual style behavior was not checked: " + name)
            if len(closed) != 1 or any(type(closed[0].get(key)) is not int or closed[0][key] != 0 for key in ("ownedFacesRemaining", "ownedFontSizesRemaining", "ownedCallbacksRemaining")):
                raise ValueError("Owned font resources survived teardown")
            if len(haptics) != 3 or len(effects) != 3 or any(type(row.get("generation")) is not int for row in haptics) or [row.get("generation") for row in haptics] != [0, 1, 2]:
                raise ValueError("Initial/quick/manual saved haptic callable rebind sequence is missing")
            if any(row.get(key) is not True for row in haptics for key in ("accepted", "registeredAPI", "ownsCurrentAPI", "ownsCurrentLease")):
                raise ValueError("A saved haptic alias was not rebound to the active lease")
            if names["ActualGameHapticRequestBelongsToCurrentSession"] != 3:
                raise ValueError("Haptic request payload/ownership was not checked")
            for row in effects:
                request = row.get("hapticRequest", {})
                if type(request.get("schemaVersion")) is not int or type(request.get("epoch")) is not int or request != {"schemaVersion": 1, "sessionID": row.get("sessionID"), "epoch": row.get("epoch"), "duration": .01, "intensity": .1, "sharpness": .2}:
                    raise ValueError("The actual haptic request payload differs")
            verify_style(selected, names, check_contract)
            expected = [(i, edge) for i in range(1, 11) for edge in ("down", "up")]
            if [(row.get("function"), row.get("edge")) for row in observed] != expected:
                raise ValueError("The new platform lost actual F1-F10 down/up observations")
            for row in observed:
                if any(type(row.get(key)) is not int for key in ("function", "key", "scancode")) or row.get("key") != ((1 << 30) | (57 + row["function"])) or row.get("scancode") not in (-1, 57 + row["function"]):
                    raise ValueError("The actual engine key/scancode differs")
    finals = [row for row in rows if row.get("type") == "auxiliaryProbePassed"]
    if len(finals) != 1 or finals[0].get("sessions") != len(plans) or finals[0].get("checks") != sum(row.get("type") == "auxiliaryCheck" for row in rows):
        raise ValueError("The actual joint matrix did not reach its final completion marker")
    return next(iter(processes))
