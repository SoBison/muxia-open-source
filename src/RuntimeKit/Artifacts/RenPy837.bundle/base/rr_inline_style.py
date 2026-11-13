# -*- coding: utf-8 -*-
"""Isolated candidate: reversible styling of one owned plain stock Text widget.

Not imported by shipped hosts. Compatible with the Python 2/3 runtime families.
"""
from __future__ import unicode_literals
import hashlib
import io
import json
import math
import re
import ctypes
import os
import sys
import types
import unicodedata
import uuid

try:
    _texts = (basestring,)
    _ints = (int, long)
except NameError:
    _texts = (str,)
    _ints = (int,)

_MISSING = object()


def _frozen(value, depth=0):
    if depth >= 16:
        return (type(value), id(value))
    if type(value) is dict:
        return tuple(sorted((key, _frozen(item, depth + 1)) for key, item in value.items()))
    if type(value) in (list, tuple):
        return tuple(_frozen(item, depth + 1) for item in value)
    if isinstance(value, _texts) or type(value) in (bytes, bool, int, float, type(None)):
        return value
    return (type(value), id(value))


def _style_state(style):
    state = style.__getstate__() if hasattr(style, "__getstate__") else None
    if type(state) is dict and "properties" in state:
        return state
    return dict(properties=[{key: value for key, value in style.__dict__.items() if key != "parent"}])


def _style_properties(state):
    return {key: value for row in state["properties"] for key, value in row.items()}


def validate_style_options(style):
    fields = set(("fontFamily", "showOriginal", "autoFit", "rightToLeft", "textScale", "lineSpacing"))
    if (type(style) is not dict or set(style) != fields or style["fontFamily"] != "noto-sans-v1"
            or any(type(style[key]) is not bool for key in ("showOriginal", "autoFit", "rightToLeft"))
            or type(style["textScale"]) not in _ints + (float,) or not 0.8 <= style["textScale"] <= 1.8
            or type(style["lineSpacing"]) not in _ints + (float,) or not 0 <= style["lineSpacing"] <= 16):
        raise ValueError("Invalid inline style options")


class Fonts(object):
    def __init__(self, root, manifest_sha256):
        root = os.path.abspath(root)
        if root != os.path.realpath(root) or not os.path.isdir(root) or os.path.islink(root):
            raise ValueError("Fonts root is not canonical")
        manifest_path = os.path.join(root, "manifest.json")
        if os.path.islink(manifest_path):
            raise ValueError("Linked font manifest")
        with open(manifest_path, "rb") as source:
            data = source.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != manifest_sha256:
            raise ValueError("Font manifest identity changed")
        manifest = json.loads(data.decode("utf-8"))
        if manifest.get("schemaVersion") != 1 or not 1 <= len(manifest.get("assets", [])) <= 16:
            raise ValueError("Invalid font manifest")
        self.root = root
        self.entries = []
        self.points = set()
        self.coverages = {}
        self.group = None
        self.callback = None
        self.renpy = None
        self.data = {}
        namespace = "rr-inline-font-" + manifest_sha256[:16] + "-" + uuid.uuid4().hex + "/"
        for entry in manifest["assets"]:
            filename = entry["filename"]
            path = os.path.join(root, filename)
            if (not isinstance(filename, _texts) or os.path.basename(filename) != filename
                    or os.path.islink(path) or os.path.realpath(path) != path
                    or type(entry["byteCount"]) not in _ints or not 1 <= entry["byteCount"] <= 32 * 1024 * 1024):
                raise ValueError("Invalid font asset path")
            with open(path, "rb") as source:
                data = source.read(32 * 1024 * 1024 + 1)
            if len(data) != entry["byteCount"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("Font asset identity changed")
            if "ranges" not in entry:
                continue
            if not filename.endswith((".ttf", ".otf")):
                raise ValueError("Unsupported font format")
            ranges = entry["ranges"]
            if type(ranges) is not list or len(ranges) > 8192:
                raise ValueError("Invalid font coverage")
            covered = set()
            for first, last in ranges:
                if type(first) not in _ints or type(last) not in _ints or not 0 <= first <= last <= 0x10FFFF:
                    raise ValueError("Invalid glyph range")
                self.points.update(range(first, last + 1))
                covered.update(range(first, last + 1))
            alias = namespace + filename.lower()
            self.entries.append((alias, ranges))
            self.coverages[alias] = covered
            self.data[alias] = data
            self.data["fonts/" + alias] = data
        if not self.entries:
            raise ValueError("No supported fonts")

    def covers(self, text):
        return all(char in "\n\t" or unicodedata.category(char) == "Cf" or ord(char) in self.points for char in text)

    def single_font(self, text):
        for alias, _ in self.entries:
            if all(char in "\n\t" or unicodedata.category(char) == "Cf" or ord(char) in self.coverages[alias] for char in text):
                return alias
        return None

    def font(self, renpy, text=None):
        if self.callback is None:
            # Ren'Py's loader deliberately strips absolute paths. Expose only
            # session-unique aliases backed by the already verified bytes.
            self.renpy = renpy
            def read_host_font(name):
                data = self.data.get(name)
                return io.BytesIO(data) if data is not None else None
            self.callback = read_host_font
            renpy.loader.file_open_callbacks.insert(0, read_host_font)
        if text is not None:
            single = self.single_font(text)
            if single is not None:
                return single
        if self.group is None:
            group = renpy.text.font.FontGroup()
            for path, ranges in self.entries:
                for first, last in ranges:
                    group.add(path, first, last)
            self.group = group
        return self.group

    def close(self):
        if self.callback is not None:
            callbacks = self.renpy.loader.file_open_callbacks
            callbacks[:] = [callback for callback in callbacks if callback is not self.callback]
            aliases = set(alias for alias, _ in self.entries)
            for cache_name in ("font_cache", "face_cache"):
                cache = getattr(self.renpy.text.font, cache_name)
                for key in list(cache):
                    name = key[0] if type(key) is tuple else key
                    if name in aliases:
                        cache.pop(key, None)
        self.callback, self.group = None, None


class InlineStyle(object):
    def __init__(self, renpy, fonts, on_fallback=None, raster_backend=_MISSING):
        self.renpy, self.fonts = renpy, fonts
        self.on_fallback = on_fallback
        self.widget = None
        self._raster_backend = raster_backend
        self._owned_content = None
        self._owned_images = []
        self._afm_lease = None
        self.result = {}
        self.revision = -1
        self.interaction = None

    @staticmethod
    def _layout_signature(screen, widget):
        # Ren'Py may reuse a child's cached Render without calling Text.render.
        # Lease its actual ancestor layout too; any changed parent geometry or
        # reconstructed path must release this translation before another one.
        pending = [(screen, ())]
        seen = set()
        for _ in range(512):
            if not pending:
                return None
            current, path = pending.pop()
            if current is None:
                continue
            if current is widget:
                return path
            if id(current) in seen or len(path) >= 32:
                continue
            seen.add(id(current))
            try:
                style = getattr(current, "style", None)
                values = tuple(getattr(style, key, None) for key in
                               ("xminimum", "yminimum", "xmaximum", "ymaximum", "xfill", "yfill", "xfit", "yfit"))
                children = current.visit()
                if type(children) not in (list, tuple) or len(children) > 512:
                    return None
            except Exception:
                return None
            pending.extend((child, path + ((id(current), values),)) for child in children)
        return None

    def _invalidate(self, widget):
        widget.kill_layout()
        self.renpy.display.render.redraw(widget, 0)

    @staticmethod
    def _script_is_qualified(text):
        # Glyph availability is separate from shaping qualification. The current
        # candidate covers these scripts; Indic/Thai and other shaping systems
        # keep the native App translation layer even if a font has their glyphs.
        ranges = ((0x0000, 0x052F), (0x0590, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
                  (0x1100, 0x11FF), (0x1E00, 0x1FFF), (0x2000, 0x2BFF), (0x3000, 0x30FF),
                  (0x3130, 0x318F), (0x31F0, 0x31FF), (0x3400, 0x9FFF), (0xA960, 0xA97F),
                  (0xAC00, 0xD7FF), (0xF900, 0xFAFF), (0xFB1D, 0xFDFF), (0xFE10, 0xFEFF),
                  (0xFF00, 0xFFEF), (0x20000, 0x2FA1F))
        return all(unicodedata.category(char) == "Cf" or any(first <= ord(char) <= last for first, last in ranges) for char in text)

    def apply(self, interaction, revision, screen, widget, original, translation, style, budget=None):
        validate_style_options(style)
        return self.update(interaction, revision, screen, widget, original, translation,
                           auto_fit=style["autoFit"], rtl=style["rightToLeft"], scale=style["textScale"],
                           line_spacing=style["lineSpacing"], budget=budget, comparison=style["showOriginal"])

    def _owned_values(self):
        return self._owned_content if self._owned_content is not None else [self.translation]

    def _remember_style(self, style):
        state = _style_state(style)
        self._style_stamp = _frozen(state)
        self._owned_metadata = {key: _frozen(value) for key, value in state.items() if key != "properties"}
        self._owned_properties = {key: _frozen(value) for key, value in _style_properties(state).items()}
        return style

    def _style_unchanged(self):
        return _frozen(_style_state(self.applied_style)) == self._style_stamp

    def _restore_style(self):
        if self._style_unchanged():
            return self.original_style
        # The anonymous style is mutable. Preserve later author property writes
        # while removing our font/size/RTL overrides, including in-place lists.
        current = _style_state(self.applied_style)
        values = _style_properties(current)
        changes = {key: value for key, value in values.items()
                   if key not in self._owned_properties or _frozen(value) != self._owned_properties[key]}
        removed = set(self._owned_properties) - set(values)
        restored = self.original_style.copy()
        if hasattr(restored, "add_properties"):
            state = _style_state(restored)
            state["properties"] = [{key: value for key, value in row.items() if key not in removed}
                                   for row in state["properties"]]
            for key, value in current.items():
                if key != "properties" and _frozen(value) != self._owned_metadata.get(key):
                    state[key] = value
            restored.__setstate__(state)
            restored.add_properties(changes)
        else:
            for key, value in changes.items():
                setattr(restored, key, value)
        return restored

    def restore(self):
        widget = self.widget
        if widget is None:
            return False
        self.widget = None
        changed = False
        # Some legacy bootstraps clear all contexts before session_did_reset.
        # The detached stock Text still needs its owned fields released, but
        # set_text/redraw require a live engine context in those versions.
        contexts = getattr(getattr(self.renpy, "game", None), "contexts", None)
        live_context = contexts is None or bool(contexts)
        # Compare-and-restore only our own values; an author's later changes win.
        if getattr(widget, "style", None) is self.applied_style:
            widget.style = self._restore_style()
            changed = True
        if getattr(widget, "text", None) == self._owned_values():
            if live_context:
                changed = bool(widget.set_text(self.original, substitute=False)) or changed
            else:
                widget.text = [self.original]
                changed = True
        for name, value in self.original_bounds.items():
            if getattr(widget, name) == self.applied_bounds[name]:
                setattr(widget, name, value)
                changed = True
        for name, wrapper in self.wrappers.items():
            if getattr(widget, name, None) is wrapper:
                delattr(widget, name)
                changed = True
        if changed and live_context:
            self._invalidate(widget)
        self._release_raster()
        return changed

    def _wrap_layout(self, widget, rtl):
        # Legacy Text gates bidi in its layout through config.rtl. Scope that
        # flag to this stock, childless widget's synchronous layout calls only.
        for name in ("render", "size", "get_placement"):
            original = getattr(widget, name)
            if name in widget.__dict__:
                raise ValueError("Author-overridden text layout is unsupported")
            def make_wrapper(method, method_name):
                def scoped(unused, *args, **kwargs):
                    if self.widget is not widget:
                        return method(*args, **kwargs)
                    if widget.style is not self.applied_style or not self._style_unchanged() or widget.text != self._owned_values():
                        self.restore()
                        self.result = {"applied": False, "reason": "authorChanged"}
                        if self.on_fallback is not None:
                            try:
                                self.on_fallback(dict(self.result))
                            except Exception:
                                pass
                        return method(*args, **kwargs)
                    if method_name == "render" and len(args) >= 2 and tuple(args[:2]) != tuple(self.budget):
                        self.restore()
                        self.result = {"applied": False, "reason": "geometryChanged"}
                        if self.on_fallback is not None:
                            try:
                                self.on_fallback(dict(self.result))
                            except Exception:
                                pass
                        return method(*args, **kwargs)
                    if not rtl:
                        return method(*args, **kwargs)
                    previous = self.renpy.config.rtl
                    self.renpy.config.rtl = True
                    try:
                        return method(*args, **kwargs)
                    finally:
                        self.renpy.config.rtl = previous
                return scoped
            function = make_wrapper(original, name)
            wrapper = types.MethodType(function, widget, type(widget)) if sys.version_info[0] == 2 else types.MethodType(function, widget)
            self.wrappers[name] = wrapper
            setattr(widget, name, wrapper)

    def observe(self, screen, widget):
        if self.widget is None:
            return
        same_widget = widget is self.widget and screen is self.screen
        same_geometry = same_widget and self._layout_signature(screen, widget) == self.layout_signature
        if (same_geometry and widget.style is self.applied_style and self._style_unchanged() and widget.text == self._owned_values()):
            return
        self.restore()
        self.result = {"applied": False, "reason": "geometryChanged" if same_widget and not same_geometry else "authorChanged"}
        if self.on_fallback is not None:
            try:
                self.on_fallback(dict(self.result))
            except Exception:
                pass

    def update(self, interaction, revision, screen, widget, original, translation,
               auto_fit=False, rtl=False, scale=1.0, line_spacing=None, budget=None, comparison=False):
        self.result = {"applied": False, "reason": "unsupported"}
        if (not isinstance(interaction, _texts) or not interaction or type(revision) not in _ints
                or revision < 0 or (interaction == self.interaction and revision <= self.revision)):
            return False
        previous_budget = self.budget if self.widget is not None and self.widget is widget else None
        previous_time = getattr(self, "_original_reveal_time", 0) if (self.widget is widget and self.interaction == interaction
            and getattr(self, "original", None) == original and widget.style is self.applied_style) else 0
        self.restore()
        self.interaction, self.revision = interaction, revision
        if translation is None:
            self.result = {"applied": False, "restored": True}
            return True
        text_class = self.renpy.text.text.Text
        if (screen is None or type(widget) is not text_class or not isinstance(original, _texts)
                or not original or "[" in original or widget.text != [original]
                or not isinstance(translation, _texts) or not translation.strip()
                or len(original) > 32000 or len(translation) > 32000
                or len(original.encode("utf-8")) > 32000 or len(translation.encode("utf-8")) > 32000 or "{" in translation or "[" in translation
                or any(ord(char) < 32 and char not in "\n\t" for char in translation)
                or type(auto_fit) is not bool or type(rtl) is not bool or type(comparison) is not bool
                or type(scale) not in _ints + (float,) or not 0.8 <= scale <= 1.8
                or (line_spacing is not None and (type(line_spacing) not in _ints + (float,) or not 0 <= line_spacing <= 16))):
            return False
        try:
            source = source_markup(original)
        except ValueError:
            self.result["reason"] = "unsupportedMarkup"
            return False
        if source["tagged"] and not comparison and not source["uniform"]:
            self.result["reason"] = "markupAlignmentUnavailable"
            return False
        visible = source["plain"] + "\n" + translation if comparison else translation
        rendered = original + "\n" + translation if comparison else source["prefix"] + translation + source["suffix"]
        if len(rendered) > 32000 or len(rendered.encode("utf-8")) > 32000:
            self.result["reason"] = "textLimit"
            return False
        if not self.fonts.covers(visible):
            self.result["reason"] = "missingGlyph"
            return False
        complex_script = any(0x0900 <= ord(char) <= 0x097F or 0x0E00 <= ord(char) <= 0x0E7F for char in visible)
        hb = self._has_harfbuzz()
        modern_bidi = hasattr(self.renpy.text.text, "READING_ORDER")
        legacy_mixed = rtl and self.fonts.single_font(visible) is None
        raster = (complex_script and (not hb or (self.renpy.config.rtl and not modern_bidi))) or legacy_mixed or (source["tagged"] and comparison)
        if not self._script_is_qualified("".join(char for char in visible if not (0x0900 <= ord(char) <= 0x097F or 0x0E00 <= ord(char) <= 0x0E7F))):
            self.result["reason"] = "unsupportedScript"
            return False
        if raster and self._backend() is None:
            self.result["reason"] = "mixedBidiUnqualified" if legacy_mixed else "unsupportedScript"
            return False
        # A custom embedded displayable can recursively lay out unrelated text;
        # it cannot share the legacy scoped bidi context.
        if budget is None:
            layout = widget.get_virtual_layout() if hasattr(widget, "get_virtual_layout") else widget.get_layout()
            budget = (layout.width, layout.height) if layout is not None else previous_budget
        if getattr(widget, "dirty", False) or widget.displayables is None:
            widget.update()
        if widget.displayables:
            self.result["reason"] = "embeddedDisplayable"
            return False
        if (getattr(widget, "start", None) not in (None, 0)
                or getattr(widget, "end", None) not in (None, len(original))):
            self.result["reason"] = "partialSource"
            return False
        if (type(budget) not in (tuple, list) or len(budget) != 2
                or any(type(value) not in (int, float) or not 1 <= value <= 32767 for value in budget)):
            self.result["reason"] = "missingMeasuredBudget"
            return False
        layout_signature = self._layout_signature(screen, widget)
        if layout_signature is None:
            self.result["reason"] = "unsupportedLayout"
            return False
        reading = self._reading_behavior(widget, screen)
        if reading is None or type(getattr(reading, "afm_length", None)) not in _ints or "get_time" in widget.__dict__:
            self.result["reason"] = "unsupportedReadingOwner"
            return False
        source_time = max(previous_time, widget.get_time())
        self._original_reveal_time = source_time
        if raster:
            return self._update_raster(screen, widget, original, translation, source, comparison,
                                       auto_fit, rtl, scale, line_spacing, budget, layout_signature, reading, source_time)
        self._owned_content = None
        translation = rendered
        self.widget, self.screen = widget, screen
        self.layout_signature = layout_signature
        self.original, self.translation = original, translation
        self.budget = budget
        self.original_style = widget.style
        self.wrappers = {}
        self.original_bounds = {name: getattr(widget, name) for name in ("start", "end", "afm_start") if hasattr(widget, name)}
        self.applied_bounds = {name: len(translation) if name == "end" else 0 for name in self.original_bounds}
        self.applied_style = self._remember_style(self.original_style)
        try:
            base = min(256, max(8, int(self.original_style.size * scale)))
            font = self.fonts.font(self.renpy, visible)
            def style_for(size):
                style = self.original_style.copy()
                style.font = font
                if complex_script:
                    style.shaper = "harfbuzz"
                style.size = size
                if line_spacing is not None:
                    style.line_spacing = line_spacing
                if rtl:
                    style.text_align = 1.0
                    style.min_width = int(budget[0])
                if hasattr(self.renpy.text.text, "READING_ORDER"):
                    style.reading_order = "rtl" if rtl else None
                style.set_prefix(self.original_style.prefix)
                return self._remember_style(style)
            self.applied_style = style_for(base)
            widget.style = self.applied_style
            self._wrap_layout(widget, rtl and not self.renpy.config.rtl)
            if reading is not None:
                self._wrap_reveal_time(widget, source_time)
            for name, value in self.applied_bounds.items():
                setattr(widget, name, value)
            widget.set_text(translation, substitute=False)
            self._invalidate(widget)
            minimum = max(8, int(math.ceil(base * 0.65))) if auto_fit else base
            chosen = base
            measured = None
            # At most 8 true engine measurements through bounded binary search.
            low, high = minimum, base
            while low <= high:
                candidate = (low + high) // 2
                self.applied_style = style_for(candidate)
                widget.style = self.applied_style
                self._invalidate(widget)
                width, height = widget.size(width=budget[0], height=budget[1])
                if width <= budget[0] and height <= budget[1]:
                    chosen, measured = candidate, (width, height)
                    low = candidate + 1
                else:
                    high = candidate - 1
            if measured is None:
                self.result["reason"] = "doesNotFit"
                self.restore()
                return False
            self.applied_style = style_for(chosen)
            widget.style = self.applied_style
            self._invalidate(widget)
            if reading is not None:
                self._lease_reading_length(reading, visible)
            self.result = {"applied": True, "size": chosen, "baseSize": base,
                           "width": measured[0], "height": measured[1], "budget": budget,
                           "rtl": rtl, "autoFit": auto_fit, "renderer": "native-harfbuzz" if complex_script else "native",
                           "sourceMarkup": bool(source["tagged"])}
            return True
        except Exception:
            self.restore()
            raise

    def _has_harfbuzz(self):
        module = getattr(self.renpy.text.font, "hbfont", None)
        return module is not None and hasattr(module, "HBFont")

    def _backend(self):
        if self._raster_backend is _MISSING:
            self._raster_backend = fixed_raster_backend(self.fonts.root)
        return self._raster_backend

    def _drop_image(self, image):
        cache = self.renpy.display.im.cache
        contexts = getattr(getattr(self.renpy, "game", None), "contexts", None)
        live = contexts is None or bool(contexts)
        with cache.lock:
            entry = cache.cache.get(image)
            if entry is not None:
                if live:
                    cache.kill(entry)
                else:
                    del cache.cache[image]
        if live:
            self.renpy.display.render.invalidate(image)

    def _release_raster(self):
        if self._afm_lease is not None:
            behavior, field, owner, original, owned = self._afm_lease
            if getattr(behavior, field, None) is owner and getattr(behavior, "afm_length", None) == owned:
                behavior.afm_length = original
            self._afm_lease = None
        for image in self._owned_images:
            self._drop_image(image)
        self._owned_images = []
        self._owned_content = None

    def _reading_behavior(self, widget, screen=None):
        try:
            pending = list(self.renpy.game.context().scene_lists.get_all_displayables(current=True))
        except Exception:
            return None
        seen, matches = set(), []
        behavior_class = self.renpy.display.behavior.SayBehavior
        # 7.4.11 has exactly one stock SayBehavior.text, before the global queue
        # and text_tuple API introduced in 7.5. Never infer this legacy route
        # from an empty modern queue or a custom/subclassed behavior.
        legacy = not hasattr(behavior_class, "text_tuple") and not hasattr(self.renpy.character, "afm_text_queue")
        queue = tuple(getattr(self.renpy.character, "afm_text_queue", ()))
        if not legacy and (len(queue) != 1 or type(queue[0]) is not self.renpy.text.text.Text):
            return None
        def related(queued):
            if type(queued) is not self.renpy.text.text.Text:
                return False
            if queued is widget:
                return True
            location = getattr(widget, "_location", None)
            try:
                actual_screen = self.renpy.exports.get_screen("say")
                actual_widget = self.renpy.exports.get_widget("say", "what")
            except Exception:
                return False
            if (actual_widget is not widget or actual_screen is None or (screen is not None and actual_screen is not screen)
                    or type(location) not in (list, tuple) or len(location) != 2
                    or not isinstance(location[0], _texts) or type(location[1]) not in _ints
                    or getattr(queued, "_location", None) != location
                    or queued.text != widget.text or type(widget.text) is not list or len(widget.text) != 1):
                return False
            return True
        if not legacy and not related(queue[0]):
            return None
        for unused in range(512):
            if not pending:
                break
            current = pending.pop()
            if current is None:
                continue
            if id(current) in seen:
                continue
            seen.add(id(current))
            if type(current) is behavior_class and (related(getattr(current, "text", None)) if legacy
                    else getattr(current, "text_tuple", None) == queue):
                matches.append(current)
            try:
                children = current.visit()
            except Exception:
                return None
            if type(children) not in (list, tuple) or len(children) > 512:
                return None
            pending.extend(children)
        return matches[0] if not pending and len(matches) == 1 else None

    def _raster_style(self, widget):
        style, config = widget.style, self.renpy.config
        if (bool(getattr(widget, "slow", False)) or "get_time" in widget.__dict__
                or getattr(config, "custom_text_tags", {}) or getattr(config, "self_closing_custom_text_tags", {})
                or getattr(config, "replace_text", None) is not None):
            return False
        # This first renderer explicitly declines effects not represented by its
        # fixed request. The existing native route retains those author styles.
        for name in ("bold", "italic", "underline", "strikethrough", "vertical", "kerning", "first_indent", "rest_indent"):
            if getattr(style, name, None):
                return False
        for name in ("outlines", "drop_shadow"):
            if getattr(style, name, None):
                return False
        if (getattr(style, "text_align", 0.0) != 0.0 or getattr(style, "antialias", True) is False
                or getattr(style, "line_leading", 0) or getattr(style, "justify", False)
                or getattr(style, "layout", "subtitle") not in ("tex", "subtitle", "greedy")
                or getattr(style, "language", "unicode") not in (None, "unicode")):
            return False
        return True

    def _wrap_reveal_time(self, widget, original_time):
        if "get_time" in widget.__dict__:
            return
        method = widget.get_time
        def reveal_floor(unused):
            if self.widget is widget and widget.style is self.applied_style and widget.text == self._owned_values():
                return max(original_time, method())
            return method()
        wrapper = types.MethodType(reveal_floor, widget, type(widget)) if sys.version_info[0] == 2 else types.MethodType(reveal_floor, widget)
        self.wrappers["get_time"] = wrapper
        widget.get_time = wrapper

    def _lease_reading_length(self, behavior, visible):
        field = "text_tuple" if hasattr(behavior, "text_tuple") else "text"
        old, owner = behavior.afm_length, getattr(behavior, field)
        if type(old) not in _ints:
            return
        owned = max(old, 1 + len(visible))
        behavior.afm_length = owned
        self._afm_lease = (behavior, field, owner, old, owned)

    def _update_raster(self, screen, widget, original, translation, source, comparison,
                       auto_fit, rtl, scale, line_spacing, budget, signature, behavior, original_time):
        if not self._raster_style(widget) or (source["tagged"] and not comparison):
            self.result["reason"] = "unsupportedRasterStyle"
            return False
        if behavior is None or type(getattr(behavior, "afm_length", None)) not in _ints:
            self.result["reason"] = "unsupportedReadingOwner"
            return False
        original_afm = behavior.afm_length
        self.widget, self.screen, self.layout_signature = widget, screen, signature
        self.original, self.translation, self.budget = original, translation, budget
        self.original_style = widget.style
        self.applied_style = self._remember_style(self.original_style)
        self.wrappers = {}
        self.original_bounds = {name: getattr(widget, name) for name in ("start", "end", "afm_start") if hasattr(widget, name)}
        self.applied_bounds = {name: None if name in ("start", "end") else 0 for name in self.original_bounds}
        try:
            base = min(256, max(8, int(self.original_style.size * scale)))
            minimum = max(8, int(math.ceil(base * .65))) if auto_fit else base
            rgba = self.renpy.color.Color(self.original_style.color).rgba
            color = [max(0, min(255, int(round(value * 255)))) for value in rgba]
            layout = widget.get_layout()
            pixel_scale = min(4, max(1, int(math.ceil(getattr(layout, "oversample", 1)))))
            while pixel_scale > 1 and (max(budget) * pixel_scale > 4096 or budget[0] * budget[1] * pixel_scale * pixel_scale > 4194304):
                pixel_scale -= 1
            self._owned_content = [original]
            def style_for(size):
                style = self.original_style.copy()
                style.size = size
                if line_spacing is not None:
                    style.line_spacing = line_spacing
                style.set_prefix(self.original_style.prefix)
                return self._remember_style(style)
            self.applied_style = style_for(base)
            widget.style = self.applied_style
            self._wrap_layout(widget, False)
            self._wrap_reveal_time(widget, original_time)
            for name, value in self.applied_bounds.items():
                setattr(widget, name, value)
            best = None
            low, high = minimum, base
            while low <= high:
                size = (low + high) // 2
                request = dict(schemaVersion=1, text=translation, fontFamily="noto-sans-v1", budget=list(budget),
                               baseSize=size, minimumSize=size, lineSpacing=line_spacing or 0,
                               rtl=rtl, color=color, pixelScale=pixel_scale)
                rendered = self._backend().render(request)
                if rendered is None:
                    high = size - 1
                    continue
                data, metadata = rendered
                image = raster_image(self.renpy, data, "rr-inline-raster-" + uuid.uuid4().hex + ".png", pixel_scale)
                self._owned_images.append(image)
                alt = "{alt}" + translation + "{/alt}"
                content = [original + "\n" + alt, image] if comparison else [alt, image]
                self._owned_content = content
                self.applied_style = style_for(size)
                widget.style = self.applied_style
                widget.set_text(content, substitute=False)
                self._invalidate(widget)
                measured = widget.size(width=budget[0], height=budget[1])
                if measured[0] <= budget[0] and measured[1] <= budget[1]:
                    if best is not None:
                        self._drop_image(best[0])
                        self._owned_images.remove(best[0])
                    best = (image, content, size, measured, metadata)
                    low = size + 1
                else:
                    self._drop_image(image)
                    self._owned_images.remove(image)
                    high = size - 1
            if best is None:
                self.result["reason"] = "doesNotFit"
                self.restore()
                return False
            image, content, size, measured, metadata = best
            self._owned_content = content
            self.applied_style = style_for(size)
            widget.style = self.applied_style
            widget.set_text(content, substitute=False)
            self._invalidate(widget)
            # Screen-language can replace the visible Text while SayBehavior
            # legitimately retains its original queue instance. Do not rewire
            # that author queue: only lease its scalar reading-length budget.
            afm_text = source["plain"] + "\n" + translation if comparison else translation
            self._lease_reading_length(behavior, afm_text)
            owned_afm = behavior.afm_length
            self.result = dict(applied=True, size=size, baseSize=base, width=measured[0], height=measured[1], budget=budget,
                               rtl=rtl, autoFit=auto_fit, renderer="coretext-v1", raster=metadata, sourceMarkup=source["tagged"],
                               afmLength=owned_afm, originalAFMLength=original_afm, revealTimeFloor=original_time)
            return True
        except Exception as error:
            self.restore()
            if isinstance(error, getattr(self.renpy.game, "CONTROL_EXCEPTIONS", ())):
                raise
            self.result = {"applied": False, "reason": "rasterUnavailable"}
            return False


def source_markup(original):
    """Only pure standard styles; unknown tags never get interpreted again."""
    if "[" in original:
        raise ValueError("Substitution is unsupported")
    stack, chunks, plain, count, offset = [], [], [], 0, 0
    for match in re.finditer(r"\{([^{}]*)\}", original):
        text = original[offset:match.start()]
        if "{" in text or "}" in text:
            raise ValueError("Malformed source tag")
        if text:
            plain.append(text); chunks.append(tuple(stack))
        tag = match.group(1); count += 1
        if count > 64:
            raise ValueError("Too many source tags")
        if tag.startswith("/"):
            if not stack or stack[-1][0] != tag[1:]:
                raise ValueError("Unbalanced source tag")
            stack.pop()
        else:
            name = tag.split("=", 1)[0]
            if not (tag in ("b", "i", "u", "s") or re.match(r"^color=#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?$", tag)):
                raise ValueError("Non-style source tag")
            stack.append((name, "{" + tag + "}"))
            if len(stack) > 8:
                raise ValueError("Source tag nesting limit")
        offset = match.end()
    text = original[offset:]
    if "{" in text or "}" in text or stack:
        raise ValueError("Unbalanced source markup")
    if text:
        plain.append(text); chunks.append(tuple(stack))
    if not plain:
        raise ValueError("No visible source text")
    uniform = all(chunk == chunks[0] for chunk in chunks)
    active = chunks[0] if uniform else ()
    return dict(plain="".join(plain), tagged=bool(count), uniform=uniform,
                prefix="".join(value for name, value in active),
                suffix="".join("{/" + name + "}" for name, value in reversed(active)))


class NativeRaster(object):
    def __init__(self, library):
        self.library = library
        library.RRInlineRasterVersion.restype = ctypes.c_uint32
        if library.RRInlineRasterVersion() != 1:
            raise ValueError("Unknown raster ABI")
        library.RRInlineRasterCreate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)]
        library.RRInlineRasterCreate.restype = ctypes.c_int
        library.RRInlineRasterFree.argtypes = [ctypes.c_void_p]
        library.RRInlineRasterFree.restype = None

    def render(self, request):
        blob = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8")
        png, info = ctypes.c_void_p(), ctypes.c_void_p()
        png_length, info_length = ctypes.c_size_t(), ctypes.c_size_t()
        code = self.library.RRInlineRasterCreate(blob, len(blob), ctypes.byref(png), ctypes.byref(png_length), ctypes.byref(info), ctypes.byref(info_length))
        try:
            if code == -3:
                return None
            if code != 1 or not png.value or not info.value or not 1 <= png_length.value <= 32 * 1024 * 1024 or not 1 <= info_length.value <= 65536:
                raise ValueError("Native raster refused the request")
            data = ctypes.string_at(png, png_length.value)
            result = json.loads(ctypes.string_at(info, info_length.value).decode("utf-8"))
            if (result.get("renderer") != "coretext-v1" or result.get("fontManifestSHA256") != "d0c613d211ebe54d6d596c643c6cf1bde8eb55fed8eac0732bba7d1ca4ee301d"
                    or result.get("missingGlyphs") != 0 or result.get("size") != request["baseSize"] or result.get("pixelScale") != request["pixelScale"]
                    or result.get("width") != request["budget"][0] or not 1 <= result.get("height", 0) <= request["budget"][1]
                    or data[:8] != b"\x89PNG\r\n\x1a\n"):
                raise ValueError("Unexpected native raster identity/geometry")
            return data, result
        finally:
            self.library.RRInlineRasterFree(png)
            self.library.RRInlineRasterFree(info)


def fixed_raster_backend(font_root):
    parent = os.path.dirname(font_root)
    path = os.path.join(parent, "Frameworks", "RRPlatform.framework", "RRPlatform")
    if not parent.endswith(".app") or os.path.realpath(path) != path or not os.path.isfile(path):
        return None
    try:
        mode = getattr(os, "RTLD_NOLOAD", 0x10) | getattr(os, "RTLD_NOW", 2)
        return NativeRaster(ctypes.CDLL(path, mode=mode))
    except Exception:
        return None


_image_type = None

def restore_raster_image(data, filename, scale):
    import renpy
    return raster_image(renpy, data, filename, scale)


def raster_image(renpy, data, filename, scale):
    global _image_type
    if _image_type is None or _image_type.__bases__[0] is not renpy.display.im.Data:
        native_oversample = hasattr(renpy.display.im.ImageBase, "get_oversample")
        class OwnedInlineRaster(renpy.display.im.Data):
            def __init__(self, data, filename, oversample):
                properties = {"oversample": oversample} if native_oversample else {}
                super(OwnedInlineRaster, self).__init__(data, filename, **properties)
                if not native_oversample:
                    self.oversample = oversample
            def render(self, width, height, st, at):
                child = renpy.display.im.cache.get(self, render=True)
                if native_oversample:
                    return child
                # 7.4/7.5 im.Data predates image oversampling. Its standard
                # Render.zoom scales the full-resolution texture children,
                # without downsampling PNG pixels or touching another image.
                w, h = child.get_size()
                result = renpy.display.render.Render(w / float(self.oversample), h / float(self.oversample))
                result.zoom(1.0 / self.oversample, 1.0 / self.oversample)
                result.blit(child, (0, 0))
                return result
            def predict_one(self):
                return None
            def __reduce__(self):
                return (restore_raster_image, (self.data, self.filename, self.oversample))
        _image_type = OwnedInlineRaster
    return _image_type(data, filename, oversample=scale)
