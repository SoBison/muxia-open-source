"""Bounded static text collection; never evaluates expressions or story code.

The host calls this only after a native request carrying separate script-send
consent. This includes unseen branches. Dynamic/interpolated strings are skipped.
"""
from __future__ import unicode_literals
import time
import base64
import struct
import hashlib

try:
    _texts = (str, unicode)
except NameError:
    _texts = (str,)

try:
    _integers = (int, long)
except NameError:
    _integers = (int,)


def _owner_token(statements, session_id, epoch):
    if (type(session_id) not in _texts or not 1 <= len(session_id) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in session_id)
            or type(epoch) not in _integers or not 1 <= epoch <= 18446744073709551615):
        raise ValueError("Invalid script collection owner")
    identity = "%d:%d:%s:%d" % (id(statements), len(session_id), session_id, epoch)
    return hashlib.sha256(identity.encode("ascii")).hexdigest()[:32]


def _rows(node):
    try:
        rows = object.__getattribute__(node, "items")
    except AttributeError:
        return None
    return rows if type(rows) in (list, tuple) and len(rows) <= 1000 else None


def collect_page(renpy, maximum_lines=1000, maximum_characters=100000, cursor=None,
                 session_id=None, epoch=None, clock=None):
    if type(maximum_lines) is not int or not 1 <= maximum_lines <= 1000:
        raise ValueError("Invalid script line budget")
    if type(maximum_characters) is not int or not 1 <= maximum_characters <= 100000:
        raise ValueError("Invalid script character budget")
    statements = renpy.game.script.all_stmts
    if type(statements) is not list or len(statements) > 2147483647:
        raise ValueError("Script statement table unavailable")
    token = _owner_token(statements, session_id, epoch)
    count = len(statements)
    say_type, menu_type = renpy.ast.Say, renpy.ast.Menu
    translate_say = getattr(renpy.ast, "TranslateSay", None)
    say_types = (say_type,) if translate_say is None else (say_type, translate_say)
    index, choice = 0, 0
    if cursor is not None:
        if type(cursor) is not dict or set(cursor) != set(("nodeIndex", "choiceIndex", "statementCount", "scriptToken")):
            raise ValueError("Invalid script cursor fields")
        index, choice = cursor["nodeIndex"], cursor["choiceIndex"]
        value = cursor["scriptToken"]
        if (type(index) is not int or not 0 <= index < count
                or type(choice) is not int or not 0 <= choice <= 1000
                or type(cursor["statementCount"]) is not int or cursor["statementCount"] != count
                or type(value) not in _texts or len(value) != 32
                or any(char not in "0123456789abcdef" for char in value) or value != token):
            raise ValueError("Invalid or stale script cursor")
        if choice:
            rows = _rows(statements[index]) if type(statements[index]) is menu_type else None
            if rows is None or choice >= len(rows):
                raise ValueError("Invalid menu cursor position")
    clock = clock or getattr(time, "monotonic", time.time)
    deadline = clock() + 0.15
    seen, items = set(), []
    characters, visited, last_node = 0, 0, None
    skipped = False
    while index < count:
        if index != last_node:
            if visited >= 20000:
                break
            visited += 1
            last_node = index
        node = statements[index]
        node_type = type(node)
        text = None
        next_index, next_choice = index + 1, 0
        # Official iOS AST classes can be transformed to C slots and have no
        # __dict__. Read their exact public fields without calling eval/execute.
        if node_type in say_types or node_type is menu_type:
            try:
                filename = object.__getattribute__(node, "filename")
            except AttributeError:
                filename = None
            if type(filename) in _texts and len(filename) <= 4096:
                filename = filename.replace("\\", "/")
                if not filename.startswith("renpy/") and "/renpy/common/" not in filename:
                    if node_type in say_types:
                        try:
                            text = object.__getattribute__(node, "what")
                        except AttributeError:
                            pass
                    else:
                        rows = _rows(node)
                        if rows is None:
                            try:
                                raw_rows = object.__getattribute__(node, "items")
                            except AttributeError:
                                raw_rows = None
                            if type(raw_rows) in (list, tuple) and len(raw_rows) > 1000:
                                skipped = True
                        if rows and choice < len(rows):
                            row = rows[choice]
                            if type(row) in (list, tuple) and len(row) == 3:
                                text = row[0]
                            if choice + 1 < len(rows):
                                next_index, next_choice = index, choice + 1
        if type(text) in _texts:
            oversized = len(text) > 4000 or len(text) > maximum_characters
            if not oversized:
                try:
                    oversized = len(text.encode("utf-8")) > 4000
                except UnicodeError:
                    text = None
            if oversized:
                skipped = True
                text = None
        if type(text) in _texts and text.strip() and "[" not in text and text not in seen:
            # A string that can fit on an empty page is deferred intact. A
            # single string above the whole-page budget was skipped above.
            if characters + len(text) > maximum_characters:
                break
            seen.add(text)
            characters += len(text)
            items.append({"id": "%d:%d" % (index, choice), "text": text})
        index, choice = next_index, next_choice
        # Even an already-expired deadline must advance one node or menu
        # choice, so a large script can finish through bounded empty pages.
        if len(items) >= maximum_lines or characters >= maximum_characters or clock() > deadline:
            break
    next_cursor = None if index == count else {"nodeIndex": index, "choiceIndex": choice,
        "statementCount": count, "scriptToken": token}
    return {"items": items, "truncated": next_cursor is not None or skipped,
            "nextCursor": next_cursor, "scannedStatements": index,
            "totalStatements": count, "skippedOversized": skipped}


def collect(renpy, maximum_lines=1000, maximum_characters=100000, clock=None):
    """Keep the original direct first-page API; host requests supply real owners."""
    return collect_page(renpy, maximum_lines, maximum_characters,
                        session_id="legacy-collect", epoch=1, clock=clock)


def handle(request, renpy, emit):
    """Handle only the two additive commands, after host session/mode checks."""
    if type(request) is not dict:
        raise ValueError("Invalid translation request")
    kind = request.get("type")
    if kind not in ("captureTranslationFrame", "collectTranslationScript"):
        return False
    request_id = request.get("requestID")
    if (type(request_id) not in _texts or not 1 <= len(request_id) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in request_id)):
        raise ValueError("Invalid translation request identity")
    payload = request.get("payload")
    if type(payload) is not dict:
        raise ValueError("Invalid translation payload")
    if kind == "collectTranslationScript":
        if set(payload) not in (set(("maximumLines", "maximumCharacters")),
                                set(("maximumLines", "maximumCharacters", "cursor"))):
            raise ValueError("Invalid script budget fields")
        result = collect_page(renpy, payload["maximumLines"], payload["maximumCharacters"],
                              cursor=payload.get("cursor"), session_id=request.get("sessionID"), epoch=request.get("epoch"))
        emit("translationScript", request_id, **result)
        return True
    if set(payload) != set(("maxWidth", "maxHeight")):
        raise ValueError("Invalid screenshot budget fields")
    limits = (payload["maxWidth"], payload["maxHeight"])
    if any(type(value) not in _integers or not 1 <= value <= 1280 for value in limits):
        raise ValueError("Invalid screenshot dimensions")
    width, height = renpy.config.screen_width, renpy.config.screen_height
    if any(type(value) not in _integers or not 1 <= value <= 100000 for value in (width, height)):
        raise ValueError("Invalid game dimensions")
    scale = min(1.0, float(limits[0]) / width, float(limits[1]) / height)
    size = (max(1, int(width * scale)), max(1, int(height * scale)))
    data = renpy.exports.screenshot_to_bytes(size)
    if type(data) is not bytes or not 24 <= len(data) <= 6 * 1024 * 1024:
        raise ValueError("Screenshot unavailable or exceeds byte budget")
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR" or struct.unpack(">II", data[16:24]) != size:
        raise ValueError("Screenshot PNG dimensions do not match request")
    encoded = base64.b64encode(data).decode("ascii")
    emit("translationFrame", request_id, imageBase64=encoded)
    return True
