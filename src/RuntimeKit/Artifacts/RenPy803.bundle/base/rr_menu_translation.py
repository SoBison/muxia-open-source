"""Read only selectable text from the completed render's clipped focus list.

No item actions are called. Image/custom nontext buttons and unsupported text
markup are intentionally omitted rather than sending an unshown source label.
"""
import math

MAX_RENDER_NODES = 4096
MAX_RENDER_EDGES = 8192
MAX_RENDER_DEPTH = 64

try:
    _texts = (str, unicode)
    _numbers = (int, long, float)
except NameError:
    _texts = (str,)
    _numbers = (int, float)

_installed = False
_enabled = None
_emit = None
_focus = _ui = None
_take_focuses_wrapper = _interact_wrapper = None
_button_type = _text_type = _choice_type = _focus_type = None
_text_token = _paragraph_token = _tag_token = None
_render_module = _render_type = _color_type = _style_type = _config = None
_shader_module = _shader_part_type = _shader_variable_type = None
_interactions = []
_interaction_counter = 0
_menu_counter = 0
_last_signature = None
_last_id = None


def _plain_caption(text):
    tokens = text.tokens
    if type(tokens) not in (list, tuple) or len(tokens) > 512:
        return None
    parts = []
    length = 0
    for token in tokens:
        if type(token) not in (list, tuple) or len(token) != 2:
            return None
        kind, value = token
        if kind == _text_token:
            if type(value) not in _texts:
                return None
            length += len(value)
            if length > 2048 or any(ord(char) < 32 and char not in "\n\t" for char in value):
                return None
            parts.append(value)
        elif kind == _paragraph_token:
            parts.append("\n")
        elif kind == _tag_token:
            # Alt/custom tags can contain text that was not visually displayed.
            # Only simple emphasis is known not to hide or replace text.
            if value not in ("b", "/b", "i", "/i", "u", "/u", "s", "/s"):
                return None
        else:
            return None
    caption = "".join(parts).strip()
    return caption if caption and len(caption.encode("utf-8")) <= 2048 else None


def _close_current():
    global _last_signature, _last_id
    previous = _last_id
    _last_signature = _last_id = None
    if previous is not None and _enabled():
        _emit("menuClosed", menuID=previous)


def _finite_number(value):
    if type(value) not in _numbers:
        return False
    try:
        return not math.isnan(value) and not math.isinf(value)
    except OverflowError:
        return False


def _plain_text_visible(text):
    style = text.style
    if type(style) is not _style_type:
        return False
    color = style.color
    if type(color) is not _color_type or tuple.__len__(color) != 4:
        return False
    alpha = tuple.__getitem__(color, 3)
    if not _finite_number(alpha) or alpha <= 0:
        return False
    # Newer official Text shaders can replace/fade glyphs independently of
    # parent opacity. No arbitrary shader is interpreted as visible text.
    if "default_textshader" in _config.__dict__:
        if _config.__dict__["default_textshader"] is not None or style.textshader is not None:
            return False
    return True


# Exact built-in programs in all eleven pinned common/_shaders.rpym files.
# A reserved name alone is insufficient: register_shader permits replacement.
_SHADER_DEFINITIONS = {
    "renpy.alpha": ({"u_renpy_alpha": "float", "u_renpy_over": "float"}, [],
        [(500, "gl_FragColor=gl_FragColor*vec4(u_renpy_alpha,u_renpy_alpha,u_renpy_alpha,u_renpy_alpha*u_renpy_over);")]),
    "renpy.texture": ({"u_lod_bias": "float", "tex0": "sampler2D", "a_tex_coord": "vec2", "v_tex_coord": "vec2"},
        [(200, "v_tex_coord=a_tex_coord;")], [(200, "gl_FragColor=texture2D(tex0,v_tex_coord.xy,u_lod_bias);")])
}

_SHADER_VARIABLES = {
    "renpy.alpha": (set(), set((("uniform", "float", "u_renpy_alpha"), ("uniform", "float", "u_renpy_over")))),
    "renpy.texture": (set((("attribute", "vec2", "a_tex_coord"), ("varying", "vec2", "v_tex_coord"))),
        set((("uniform", "float", "u_lod_bias"), ("uniform", "sampler2D", "tex0"), ("varying", "vec2", "v_tex_coord"))))
}


def _default_shader(name):
    if _shader_module is None:
        return False
    registry = _shader_module.__dict__.get("shader_part")
    if type(registry) is not dict:
        return False
    part = registry.get(name)
    if type(part) is not _shader_part_type:
        return False
    data = part.__dict__
    variables, vertex, fragment = _SHADER_DEFINITIONS[name]
    actual = data.get("variable_types")
    if actual is not None and (type(actual) is not dict or len(actual) != len(variables) or any(type(k) not in _texts or type(v) not in _texts for k, v in actual.items()) or actual != variables):
        return False
    for key, expected in zip(("vertex_variables", "fragment_variables"), _SHADER_VARIABLES[name]):
        value = data.get(key)
        if type(value) is not set or len(value) != len(expected):
            return False
        actual_variables = set()
        for row in value:
            if type(row) is tuple and len(row) == 3:
                fields = row
            elif _shader_variable_type is not None and type(row) is _shader_variable_type:
                array = row.array
                if array is not None and (type(array) is not int or array != 0):
                    return False
                fields = (row.storage, row.type, row.name)
            else:
                return False
            if any(type(item) not in _texts or len(item) > 128 for item in fields):
                return False
            actual_variables.add(fields)
        if actual_variables != expected:
            return False
    for key in ("vertex_functions", "fragment_functions"):
        value = data.get(key)
        if type(value) not in _texts or value != "":
            return False
    for key, expected in (("vertex_parts", vertex), ("fragment_parts", fragment)):
        parts = data.get(key)
        if type(parts) is not list or len(parts) != len(expected):
            return False
        for row, (priority, code) in zip(parts, expected):
            if type(row) is not tuple or len(row) not in (2, 3) or type(row[0]) is not int or row[0] != priority:
                return False
            if len(row) == 3 and (type(row[1]) not in _texts or row[1] != name):
                return False
            value = row[-1]
            if type(value) not in _texts or len(value) > 2048 or "".join(value.split()) != code:
                return False
    return True


def _standard_render(node):
    if not _finite_number(node.alpha) or node.alpha <= 0 or node.over != 1.0:
        return False
    if node.operation != 0 or node.mesh is not None:
        return False
    shaders = node.shaders
    if shaders is not None:
        if type(shaders) is not tuple or len(shaders) > 2 or any(type(s) not in _texts or len(s) > 128 or s not in _SHADER_DEFINITIONS or not _default_shader(s) for s in shaders):
            return False
    uniforms = node.uniforms
    if uniforms is not None:
        if type(uniforms) is not dict or len(uniforms) > 2 or any(type(k) not in _texts or k not in ("u_renpy_alpha", "u_renpy_over") for k in uniforms):
            return False
        for key, value in uniforms.items():
            if not _finite_number(value) or (value <= 0 if key == "u_renpy_alpha" else value != 1):
                return False
    properties = node.properties
    if properties is not None:
        if type(properties) is not dict or len(properties) > 1 or any(type(k) not in _texts or type(v) not in _texts or k != "texture_scaling" or v not in ("nearest", "linear_mipmap_nearest") for k, v in properties.items()):
            return False
    return True


def _visible_widgets(wanted):
    root = _render_module.__dict__.get("screen_render")
    if type(root) is not _render_type:
        return None
    stack = [(root, 0, False)]
    active, completed, visible = set(), set(), set()
    edges = 0
    while stack:
        node, depth, exiting = stack.pop()
        key = id(node)
        if exiting:
            active.remove(key)
            completed.add(key)
            continue
        if type(node) is not _render_type or not _standard_render(node):
            continue
        if key in active:
            return None
        if key in completed:
            continue
        if depth > MAX_RENDER_DEPTH or len(active) + len(completed) >= MAX_RENDER_NODES:
            return None
        active.add(key)
        stack.append((node, depth, True))
        focuses = node.focuses
        if focuses is not None:
            if type(focuses) is not list:
                return None
            edges += len(focuses)
            if edges > MAX_RENDER_EDGES:
                return None
            for row in focuses:
                if type(row) is not tuple or len(row) != 9:
                    return None
                widget = row[0]
                # A focus mask can make an otherwise positive rectangle blank.
                if id(widget) in wanted and row[8] is None:
                    visible.add(id(widget))
        children, passed = node.children, node.pass_focuses
        if type(children) is not list or (passed is not None and type(passed) is not list):
            return None
        if edges + len(children) + len(passed or []) > MAX_RENDER_EDGES:
            return None
        for row in children:
            edges += 1
            if type(row) is not tuple or len(row) != 5:
                return None
            child, x, y, focus, main = row
            if type(focus) not in (bool, int) or focus not in (False, True):
                return None
            if focus and type(child) is _render_type:
                stack.append((child, depth + 1, False))
        for child in passed or []:
            edges += 1
            if type(child) is not _render_type:
                return None
            stack.append((child, depth + 1, False))
        if edges > MAX_RENDER_EDGES:
            return None
    return visible


def _capture_visible():
    global _last_signature, _last_id, _menu_counter
    if not _enabled() or not _interactions:
        _close_current()
        return
    focuses = _focus.__dict__.get("focus_list")
    if type(focuses) not in (list, tuple) or len(focuses) > 4096:
        _close_current()
        return
    candidates = []
    seen = set()
    for focus in focuses:
        if type(focus) is not _focus_type:
            continue
        if any(not _finite_number(v) for v in (focus.x, focus.y, focus.w, focus.h)) or focus.w <= 0 or focus.h <= 0:
            continue
        button = focus.widget
        if type(button) is not _button_type or id(button) in seen or not button.focusable:
            continue
        if type(button.clicked) is not _choice_type or type(button.child) is not _text_type:
            continue
        try:
            if not _plain_text_visible(button.child):
                continue
        except (AttributeError, TypeError, ValueError, IndexError):
            continue
        seen.add(id(button))
        candidates.append(button)
    if not candidates:
        _close_current()
        return
    try:
        visible = _visible_widgets(seen)
    except (AttributeError, TypeError, ValueError, IndexError, OverflowError):
        visible = None
    if visible is None:
        _close_current()
        return
    captions = []
    total = 0
    for button in candidates:
        if id(button) not in visible:
            continue
        caption = _plain_caption(button.child)
        if caption is None:
            continue
        total += len(caption.encode("utf-8"))
        captions.append(caption)
        if len(captions) > 20 or total > 16000:
            _close_current()
            return
    if not captions:
        _close_current()
        return
    signature = (_interactions[-1], tuple(captions))
    if signature == _last_signature:
        return
    _close_current()
    _menu_counter += 1
    _last_id = "menu-" + str(_menu_counter)
    _last_signature = signature
    options = [{"id": str(index), "text": text} for index, text in enumerate(captions)]
    _emit("menuShown", menuID=_last_id, options=options)


def install(renpy, enabled, emit):
    global _installed, _enabled, _emit, _focus, _ui
    global _take_focuses_wrapper, _interact_wrapper
    global _button_type, _text_type, _choice_type, _focus_type
    global _text_token, _paragraph_token, _tag_token
    global _render_module, _render_type, _color_type, _style_type, _config
    global _shader_module, _shader_part_type, _shader_variable_type
    if _installed:
        return
    _enabled, _emit = enabled, emit
    _focus, _ui = renpy.display.focus, renpy.ui
    _render_module, _render_type = renpy.display.render, renpy.display.render.Render
    _color_type, _style_type, _config = renpy.color.Color, renpy.style.Style, renpy.config
    _shader_module = getattr(getattr(renpy, "gl2", None), "gl2shadercache", None)
    _shader_part_type = getattr(_shader_module, "ShaderPart", None)
    _shader_variable_type = getattr(getattr(getattr(renpy, "gl2", None), "gl2shader", None), "Variable", None)
    _button_type = renpy.display.behavior.Button
    _text_type = renpy.text.text.Text
    _choice_type = renpy.ui.ChoiceReturn
    _focus_type = _focus.Focus
    _text_token, _paragraph_token, _tag_token = renpy.text.text.TEXT, renpy.text.text.PARAGRAPH, renpy.text.text.TAG
    original_focuses = _focus.take_focuses
    def take_focuses():
        result = original_focuses()
        _capture_visible()
        return result
    _take_focuses_wrapper = _focus.take_focuses = take_focuses
    original_interact = _ui.interact
    def interact(*args, **kwargs):
        global _interaction_counter
        _interaction_counter += 1
        _interactions.append(_interaction_counter)
        _close_current()
        try:
            return original_interact(*args, **kwargs)
        finally:
            _close_current()
            _interactions.pop()
    _interact_wrapper = _ui.interact = interact
    _installed = True


def reset_session():
    """Clean up only after official engine reset, with no active interaction."""
    global _menu_counter
    if _interactions:
        raise RuntimeError("Menu cleanup requires the quiescent interaction boundary")
    try:
        _close_current()
    finally:
        _menu_counter = 0
        if _installed:
            # Backup.restore resolves function globals by their current names.
            # Reclaim only our two wrappers; author hooks remain in charge
            # throughout the title's active interactions.
            _focus.take_focuses = _take_focuses_wrapper
            _ui.interact = _interact_wrapper
