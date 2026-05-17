import base64
import re
from email import policy
from email.header import decode_header
from email.parser import Parser
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

GMAIL_MESSAGE_LIST_FIELDS = "messages(id)"
GMAIL_MESSAGE_PART_FIELDS_MAX_DEPTH = 12
_GMAIL_MESSAGE_PART_BASE_FIELDS = "mimeType,filename,headers(name,value),body(data)"


def _gmail_message_part_fields(depth: int = GMAIL_MESSAGE_PART_FIELDS_MAX_DEPTH) -> str:
    if depth <= 0:
        return _GMAIL_MESSAGE_PART_BASE_FIELDS

    return (
        f"{_GMAIL_MESSAGE_PART_BASE_FIELDS},"
        f"parts({_gmail_message_part_fields(depth - 1)})"
    )


GMAIL_MESSAGE_GET_FIELDS = (
    "id,threadId,labelIds,snippet,"
    f"payload({_gmail_message_part_fields()})"
)
_AUTHENTICATION_RESULT_HEADER_LABELS = {
    "authentication-results": "Authentication-Results",
    "arc-authentication-results": "ARC-Authentication-Results",
}
_AUTHENTICATION_WARNING_RESULTS = {"fail", "softfail", "temperror", "permerror"}
_AUTHENTICATION_MECHANISM_LABELS = {
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
}
_AUTHENTICATION_RESULT_RE = re.compile(
    r"^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b",
    re.IGNORECASE,
)


def _decode_base64_urlsafe(data: Optional[str]) -> str:
    if not data:
        return ""

    try:
        encoded = data.encode("ascii").translate(None, b" \t\n\r\f\v")
        padding = b"=" * (-len(encoded) % 4)
        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


_HTML_CONTENT_TAGS_TO_DROP = {"script", "style", "template", "noscript", "title"}
# SVG/MathML annotation subtrees are not trusted visible email body content;
# keep suppressing them across SVG/foreignObject-like namespace edges.
_SVG_NON_RENDERED_CONTENT_TAGS_TO_DROP = {"defs", "desc", "metadata"}
# MathML annotations can contain alternate representations rather than visible
# rendered text. Drop them conservatively before exposing email content to LLMs.
_MATHML_NON_RENDERED_CONTENT_TAGS_TO_DROP = {
    "annotation",
    "annotation-xml",
    "desc",
    "metadata",
}
_HTML_VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
_HTML_BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "caption",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
}
_DANGEROUS_LINK_SCHEMES = {"javascript", "data", "file", "tel", "sms", "mailto"}
_REMOTE_IMAGE_WARNING = (
    "HTML message contains remote images that may load tracking or remote content."
)
_EMBEDDED_FORM_WARNING = (
    "HTML email contains an embedded form that may collect or submit sensitive data."
)
_HIDDEN_HTML_CONTENT_WARNING = (
    "HTML message contains hidden or visually suppressed content; hidden text was "
    "excluded from extracted text."
)
_META_REFRESH_REDIRECT_WARNING = "HTML email contains a meta refresh redirect."
_META_REFRESH_URL_RE = re.compile(
    r"(?:^|;)\s*url\s*=\s*(?P<url>.*)",
    re.IGNORECASE | re.DOTALL,
)
_DANGEROUS_META_REFRESH_SCHEMES = _DANGEROUS_LINK_SCHEMES | {"vbscript"}
_EXECUTABLE_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".dmg",
    ".pkg",
    ".sh",
}
_MACRO_ENABLED_ATTACHMENT_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
_ACTIVE_WEB_CONTENT_ATTACHMENT_EXTENSIONS = {
    ".html",
    ".htm",
    ".xhtml",
    ".hta",
    ".svg",
    ".mhtml",
    ".mht",
    ".shtml",
}
_ARCHIVE_ATTACHMENT_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".iso",
}
_BENIGN_DOCUMENT_MEDIA_ATTACHMENT_EXTENSIONS = {
    ".csv",
    ".doc",
    ".docx",
    ".gif",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".odp",
    ".ods",
    ".odt",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rtf",
    ".txt",
    ".wav",
    ".xls",
    ".xlsx",
}
_DISPLAY_URL_STRIP_CHARS = " \t\r\n\f\v<>()[]{}\"'`"
_DISPLAY_URL_TRAILING_PUNCTUATION = ".,;:!?"
# Replace these controls with spaces so hidden active extensions stay
# separated and detectable, e.g. invoice.exe\u202egnp -> invoice.exe gnp.
_ATTACHMENT_FILENAME_DISPLAY_CONTROL_RE = re.compile(
    "[\x00-\x1f\x7f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060\u2066-\u2069\ufeff]"
)
_CSS_ZERO_VALUE_RE = re.compile(
    r"^[+-]?(?:0+(?:\.0*)?|\.0+)(?:[a-z%]+)?$",
    re.IGNORECASE,
)
_CSS_ZERO_ALPHA_RE = re.compile(
    r"^[+-]?(?:0+(?:\.0*)?|\.0+)%?$",
    re.IGNORECASE,
)
_CSS_NUMERIC_LENGTH_RE = re.compile(
    r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+))"
    r"(?:px|em|rem|vh|vw|vmin|vmax|pt|pc|cm|mm|in|%)?$",
    re.IGNORECASE,
)
_CSS_OPAQUE_ALPHA_RE = re.compile(
    r"^\+?(?:1(?:\.0*)?|100(?:\.0*)?%)$",
    re.IGNORECASE,
)
_CSS_COLOR_FUNCTION_RE = re.compile(
    r"^(rgba?|hsla?)\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_CSS_RECT_FUNCTION_RE = re.compile(
    r"^rect\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_CSS_INSET_FUNCTION_RE = re.compile(
    r"^inset\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_CSS_CIRCLE_FUNCTION_RE = re.compile(
    r"^circle\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_CSS_ELLIPSE_FUNCTION_RE = re.compile(
    r"^ellipse\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_CSS_COLOR_KEYWORDS_TO_IGNORE = {
    "currentcolor",
    "inherit",
    "initial",
    "revert",
    "revert-layer",
    "unset",
}
_CSS_NAMED_COLOR_ALIASES = {"black": "#000000", "white": "#ffffff"}
_CSS_FONT_OPTIONAL_KEYWORDS = {
    "normal",
    "italic",
    "oblique",
    "small-caps",
    "bold",
    "bolder",
    "lighter",
    "ultra-condensed",
    "extra-condensed",
    "condensed",
    "semi-condensed",
    "semi-expanded",
    "expanded",
    "extra-expanded",
    "ultra-expanded",
}
_CSS_FONT_WEIGHT_RE = re.compile(r"^(?:[1-9]\d{0,2}|1000)$")
_CSS_NONZERO_PERCENT_RE = re.compile(
    r"^(?:[1-9]\d*(?:\.\d+)?|0*\.\d*[1-9]\d*)%$"
)
_CSS_CLIPPING_OVERFLOW_VALUES = {"hidden", "clip"}
_CSS_OFFSCREEN_POSITION_THRESHOLD = 1000
_CSS_OFFSCREEN_TEXT_INDENT_THRESHOLD = 100
_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_CSS_RULE_RE = re.compile(
    r"(?P<selectors>[^{}]+)\{(?P<declarations>[^{}]*)\}",
    re.DOTALL,
)
_CSS_ESCAPE_RE = re.compile(
    r"\\(?:([0-9A-Fa-f]{1,6})(?:\r\n|[ \t\r\n\f])?|([^\r\n\f]))"
)
_CSS_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_HiddenStylesheetSelector = Tuple[Optional[str], Optional[str], Tuple[str, ...]]


def _html_tag_drops_content(
    tag: str,
    *,
    in_svg: bool = False,
    in_math: bool = False,
) -> bool:
    return tag in _HTML_CONTENT_TAGS_TO_DROP or (
        in_svg and tag in _SVG_NON_RENDERED_CONTENT_TAGS_TO_DROP
    ) or (
        in_math and tag in _MATHML_NON_RENDERED_CONTENT_TAGS_TO_DROP
    )


def _html_attrs_by_name(attrs) -> Dict[str, str]:
    return {
        str(name).lower(): str(value or "")
        for name, value in attrs
        if name is not None
    }


def _strip_css_important(value: str) -> str:
    return re.sub(r"\s*!important\s*$", "", value, flags=re.IGNORECASE).strip()


def _css_declarations(style: str) -> Dict[str, str]:
    declarations: Dict[str, str] = {}
    # CSS comments are parsed as whitespace by browsers. Normalize them before
    # checking inline styles so comment-obfuscated hidden declarations do not
    # leak visually suppressed prompt text into extracted email content.
    normalized_style = _CSS_COMMENT_RE.sub(" ", str(style or ""))
    for declaration in normalized_style.split(";"):
        property_name, separator, value = declaration.partition(":")
        if not separator:
            continue

        property_name = property_name.strip().lower()
        if property_name:
            declarations[property_name] = value.strip()

    return declarations


class _HTMLStyleBlockParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._chunks: List[str] = []
        self._style_depth = 0
        self._ignored_depth = 0
        self._svg_depth = 0
        self._math_depth = 0
        self._tag_stack: List[Tuple[str, bool, bool]] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        in_svg = self._svg_depth > 0
        in_math = self._math_depth > 0
        hides_nested_styles = tag != "style" and _html_tag_drops_content(
            tag,
            in_svg=in_svg,
            in_math=in_math,
        )
        collects_style = tag == "style" and not self._ignored_depth

        if tag not in _HTML_VOID_TAGS:
            self._tag_stack.append((tag, hides_nested_styles, collects_style))

        if tag == "svg":
            self._svg_depth += 1
        elif tag == "math":
            self._math_depth += 1

        if hides_nested_styles:
            self._ignored_depth += 1

        if collects_style:
            self._style_depth += 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        for open_tag, hides_nested_styles, collects_style in _pop_html_tag_stack(
            self._tag_stack,
            tag,
        ):
            if open_tag == "svg" and self._svg_depth:
                self._svg_depth -= 1
            elif open_tag == "math" and self._math_depth:
                self._math_depth -= 1
            if hides_nested_styles and self._ignored_depth:
                self._ignored_depth -= 1
            if collects_style and self._style_depth:
                self._style_depth -= 1

    def handle_data(self, data):
        if self._style_depth and not self._ignored_depth:
            self._chunks.append(data)

    def get_text(self) -> str:
        return "\n".join(self._chunks)


def _html_stylesheet_text(content: str) -> str:
    parser = _HTMLStyleBlockParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return ""

    return parser.get_text()


def _css_keyword(value: str) -> str:
    return re.sub(r"\s+", " ", _strip_css_important(value).lower())


def _css_axis_overflow_value(
    declarations: Dict[str, str],
    axis: str,
) -> str:
    axis_value = _css_keyword(declarations.get(f"overflow-{axis}", ""))
    if axis_value:
        return axis_value

    shorthand_value = _css_keyword(declarations.get("overflow", ""))
    shorthand_parts = shorthand_value.split()
    if not shorthand_parts:
        return ""
    if len(shorthand_parts) == 1:
        return shorthand_parts[0]
    if axis == "x":
        return shorthand_parts[0]
    return shorthand_parts[1]


def _css_overflow_clips_axis(declarations: Dict[str, str], axis: str) -> bool:
    return (
        _css_axis_overflow_value(declarations, axis)
        in _CSS_CLIPPING_OVERFLOW_VALUES
    )


def _css_zero_value(value: str) -> bool:
    return bool(_CSS_ZERO_VALUE_RE.fullmatch(_strip_css_important(value).lower()))


def _css_numeric_length(value: str) -> Optional[float]:
    match = _CSS_NUMERIC_LENGTH_RE.fullmatch(
        _strip_css_important(value).strip().lower()
    )
    if not match:
        return None

    try:
        return float(match.group(1))
    except ValueError:
        return None


def _css_large_offscreen_position(property_name: str, value: str) -> bool:
    length = _css_numeric_length(value)
    if length is None:
        return False

    if property_name in {"left", "right", "top", "bottom"}:
        return abs(length) >= _CSS_OFFSCREEN_POSITION_THRESHOLD

    return False


def _css_large_negative_text_indent(value: str) -> bool:
    length = _css_numeric_length(value)
    return (
        length is not None
        and length <= -_CSS_OFFSCREEN_TEXT_INDENT_THRESHOLD
    )


def _css_font_shorthand_has_zero_size(value: str) -> bool:
    candidate = _css_keyword(value)
    if not candidate:
        return False

    # Normalize "font: 0 / 0 Arial" to the same size token as "font: 0/0 Arial".
    candidate = re.sub(r"\s*/\s*", "/", candidate)
    for raw_token in candidate.split():
        token = raw_token.strip(",")
        if not token:
            continue

        size_token = token.split("/", 1)[0]
        if not size_token:
            continue

        if (
            size_token in _CSS_FONT_OPTIONAL_KEYWORDS
            or _CSS_FONT_WEIGHT_RE.fullmatch(size_token)
            or _CSS_NONZERO_PERCENT_RE.fullmatch(size_token)
        ):
            continue

        if _css_zero_value(size_token):
            return True

        if _css_numeric_length(size_token) is not None:
            return False

        return False

    return False


def _normalize_css_alpha(value: str) -> Optional[str]:
    alpha = re.sub(r"\s+", "", value.strip().lower())
    if not alpha:
        return None
    if _CSS_ZERO_ALPHA_RE.fullmatch(alpha):
        return "transparent"
    if _CSS_OPAQUE_ALPHA_RE.fullmatch(alpha):
        return ""
    return alpha


def _normalize_css_color_function(function_name: str, args: str) -> Optional[str]:
    alpha = None
    if "/" in args:
        args, separator, alpha = args.partition("/")
        if separator and "/" in alpha:
            return None

    if "," in args:
        parts = [part.strip() for part in args.split(",")]
        if alpha is None and len(parts) == 4:
            alpha = parts.pop()
    else:
        parts = args.split()
        if alpha is None and len(parts) == 4:
            alpha = parts.pop()

    if len(parts) != 3 or any(not part for part in parts):
        return None

    normalized_alpha = None
    if alpha is not None:
        normalized_alpha = _normalize_css_alpha(alpha)
        if normalized_alpha is None:
            return None
        if normalized_alpha == "transparent":
            return "transparent"

    color_type = "rgb" if function_name.startswith("rgb") else "hsl"
    normalized_parts = [
        re.sub(r"\s+", "", part.lower())
        for part in parts
    ]
    normalized_color = f"{color_type}({','.join(normalized_parts)})"
    if normalized_alpha:
        return f"{normalized_color}/{normalized_alpha}"
    return normalized_color


def _normalize_css_color(value: str) -> Optional[str]:
    candidate = _strip_css_important(value).lower()
    if not candidate or candidate in _CSS_COLOR_KEYWORDS_TO_IGNORE:
        return None
    if candidate in _CSS_NAMED_COLOR_ALIASES:
        return _CSS_NAMED_COLOR_ALIASES[candidate]
    if candidate == "transparent":
        return candidate

    function_match = _CSS_COLOR_FUNCTION_RE.fullmatch(candidate)
    if function_match:
        return _normalize_css_color_function(
            function_match.group(1),
            function_match.group(2),
        )

    candidate = re.sub(r"\s+", "", candidate)

    if candidate.startswith("#"):
        hex_value = candidate[1:]
        if len(hex_value) in {3, 4}:
            hex_value = "".join(char * 2 for char in hex_value)
        if len(hex_value) in {6, 8} and not re.fullmatch(
            r"[0-9a-f]+",
            hex_value,
        ):
            return None
        if len(hex_value) == 8:
            alpha = hex_value[6:]
            if alpha == "00":
                return "transparent"
            if alpha == "ff":
                hex_value = hex_value[:6]
            else:
                return f"#{hex_value}"
        if len(hex_value) == 6:
            return f"#{hex_value}"
        return None

    if re.fullmatch(r"[a-z-]+", candidate):
        return candidate

    return None


def _css_rect_clips_all_text(value: str) -> bool:
    candidate = _css_keyword(value)
    match = _CSS_RECT_FUNCTION_RE.fullmatch(candidate)
    if not match:
        return False

    args = match.group(1).strip()
    if "," in args:
        parts = [part.strip() for part in args.split(",")]
    else:
        parts = args.split()
    if len(parts) != 4:
        return False

    lengths: List[Optional[float]] = []
    for part in parts:
        if part.strip().lower() == "auto":
            lengths.append(None)
            continue

        length = _css_numeric_length(part)
        if length is None:
            return False
        lengths.append(length)

    top, right, bottom, left = lengths
    height_clipped = top is not None and bottom is not None and bottom <= top
    width_clipped = left is not None and right is not None and right <= left
    return height_clipped or width_clipped


def _css_percentage(value: str) -> Optional[float]:
    candidate = _strip_css_important(value).strip().lower()
    if not candidate.endswith("%"):
        return None

    try:
        return float(candidate[:-1])
    except ValueError:
        return None


def _css_inset_clips_all_text(value: str) -> bool:
    candidate = _css_keyword(value)
    match = _CSS_INSET_FUNCTION_RE.fullmatch(candidate)
    if not match:
        return False

    args = re.split(r"\s+round\s+", match.group(1).strip(), maxsplit=1)[0]
    if not args or "," in args:
        return False

    parts = args.split()
    if len(parts) == 1:
        top = right = bottom = left = parts[0]
    elif len(parts) == 2:
        top = bottom = parts[0]
        right = left = parts[1]
    elif len(parts) == 3:
        top = parts[0]
        right = left = parts[1]
        bottom = parts[2]
    elif len(parts) == 4:
        top, right, bottom, left = parts
    else:
        return False

    top_percent = _css_percentage(top)
    right_percent = _css_percentage(right)
    bottom_percent = _css_percentage(bottom)
    left_percent = _css_percentage(left)
    return (
        top_percent is not None
        and bottom_percent is not None
        and top_percent + bottom_percent >= 100
    ) or (
        right_percent is not None
        and left_percent is not None
        and right_percent + left_percent >= 100
    )


def _css_circle_clips_all_text(value: str) -> bool:
    candidate = _css_keyword(value)
    match = _CSS_CIRCLE_FUNCTION_RE.fullmatch(candidate)
    if not match:
        return False

    radius = re.split(r"\s+at\s+", match.group(1).strip(), maxsplit=1)[0]
    radius_parts = radius.split()
    if len(radius_parts) != 1:
        return False

    length = _css_numeric_length(radius_parts[0])
    return length is not None and length == 0


def _css_ellipse_clips_all_text(value: str) -> bool:
    candidate = _css_keyword(value)
    match = _CSS_ELLIPSE_FUNCTION_RE.fullmatch(candidate)
    if not match:
        return False

    radii = re.split(r"\s+at\s+", match.group(1).strip(), maxsplit=1)[0]
    radius_parts = radii.split()
    if len(radius_parts) != 2:
        return False

    for part in radius_parts:
        length = _css_numeric_length(part)
        if length is not None and length == 0:
            return True

    return False


def _css_clip_path_clips_all_text(value: str) -> bool:
    return (
        _css_inset_clips_all_text(value)
        or _css_circle_clips_all_text(value)
        or _css_ellipse_clips_all_text(value)
    )


def _html_attrs_hidden_or_suppressed(attrs_by_name: Dict[str, str]) -> bool:
    if "hidden" in attrs_by_name:
        return True

    if attrs_by_name.get("aria-hidden", "").strip().lower() == "true":
        return True

    declarations = _css_declarations(attrs_by_name.get("style", ""))
    if not declarations:
        return False

    if _css_keyword(declarations.get("mso-hide", "")) == "all":
        return True

    if _css_keyword(declarations.get("display", "")) == "none":
        return True

    if _css_keyword(declarations.get("visibility", "")) in {"hidden", "collapse"}:
        return True

    if _css_zero_value(declarations.get("opacity", "")):
        return True

    if _css_zero_value(declarations.get("font-size", "")):
        return True

    if _css_font_shorthand_has_zero_size(declarations.get("font", "")):
        return True

    if _css_keyword(declarations.get("position", "")) in {"absolute", "fixed"}:
        if any(
            _css_large_offscreen_position(
                property_name,
                declarations.get(property_name, ""),
            )
            for property_name in ("left", "right", "top", "bottom")
        ):
            return True

    if _css_large_negative_text_indent(declarations.get("text-indent", "")):
        return True

    if _css_rect_clips_all_text(declarations.get("clip", "")):
        return True

    if any(
        _css_clip_path_clips_all_text(declarations.get(property_name, ""))
        for property_name in ("clip-path", "-webkit-clip-path")
    ):
        return True

    if (
        _css_zero_value(declarations.get("height", ""))
        or _css_zero_value(declarations.get("max-height", ""))
    ) and _css_overflow_clips_axis(declarations, "y"):
        return True

    if (
        _css_zero_value(declarations.get("width", ""))
        or _css_zero_value(declarations.get("max-width", ""))
    ) and _css_overflow_clips_axis(declarations, "x"):
        return True

    text_color = _normalize_css_color(declarations.get("color", ""))
    if text_color == "transparent":
        return True

    background_color = _normalize_css_color(
        declarations.get("background-color", "")
    ) or _normalize_css_color(declarations.get("background", ""))
    if text_color and background_color and text_color == background_color:
        return True

    return False


def _decode_css_escape(match: re.Match) -> str:
    hex_digits = match.group(1)
    if hex_digits is None:
        return match.group(2)

    codepoint = int(hex_digits, 16)
    if (
        codepoint <= 0
        or 0xD800 <= codepoint <= 0xDFFF
        or codepoint > 0x10FFFF
    ):
        return chr(0xFFFD)

    return chr(codepoint)


def _decode_css_selector_escapes(selector: str) -> str:
    return _CSS_ESCAPE_RE.sub(_decode_css_escape, selector)


def _parse_simple_css_selector(selector: str):
    # Intentionally narrow: simple class/id selectors, optionally tag-qualified
    # (e.g. .foo, #bar, span.foo.bar). Combinators, pseudo selectors,
    # attribute selectors, and bare tag selectors are ignored to avoid
    # over-hiding broad email content.
    selector = _decode_css_selector_escapes(selector.strip())
    if (
        not selector
        or selector.startswith("@")
        or any(char in selector for char in " >+~[:*")
    ):
        return None

    tag = None
    index = 0
    tag_match = _CSS_IDENTIFIER_RE.match(selector)
    if tag_match:
        tag = tag_match.group(0).lower()
        index = tag_match.end()

    selector_id = None
    classes = []
    while index < len(selector):
        marker = selector[index]
        if marker not in ".#":
            return None

        token_match = _CSS_IDENTIFIER_RE.match(selector, index + 1)
        if token_match is None:
            return None

        token = token_match.group(0)
        if marker == "#":
            if selector_id is not None:
                return None
            selector_id = token
        else:
            classes.append(token)
        index = token_match.end()

    if selector_id is None and not classes:
        return None

    return tag, selector_id, tuple(classes)


def _hidden_stylesheet_selectors(content: str) -> List[_HiddenStylesheetSelector]:
    stylesheet = _html_stylesheet_text(content)
    if not stylesheet:
        return []

    # This is not a full CSS/media-query evaluator. Regex scanning may
    # conservatively apply inner simple hidden selectors from nested at-rules.
    css = _CSS_COMMENT_RE.sub("", stylesheet)
    selectors = []
    seen = set()

    for rule_match in _CSS_RULE_RE.finditer(css):
        declarations = rule_match.group("declarations")
        if not _html_attrs_hidden_or_suppressed({"style": declarations}):
            continue

        for selector_text in rule_match.group("selectors").split(","):
            selector = _parse_simple_css_selector(selector_text)
            if selector is None or selector in seen:
                continue

            seen.add(selector)
            selectors.append(selector)

    return selectors


def _html_attrs_match_hidden_stylesheet_selector(
    tag: str,
    attrs_by_name: Dict[str, str],
    hidden_stylesheet_selectors: List[_HiddenStylesheetSelector],
) -> bool:
    if not hidden_stylesheet_selectors:
        return False

    element_id = attrs_by_name.get("id", "")
    class_names = set(attrs_by_name.get("class", "").split())

    for selector_tag, selector_id, selector_classes in hidden_stylesheet_selectors:
        if selector_tag and selector_tag != tag:
            continue
        if selector_id and selector_id != element_id:
            continue
        if selector_classes and not set(selector_classes).issubset(class_names):
            continue

        return True

    return False


def _html_tag_suppresses_text(
    tag: str,
    attrs_by_name: Dict[str, str],
    hidden_stylesheet_selectors: List[_HiddenStylesheetSelector],
    *,
    in_svg: bool = False,
    in_math: bool = False,
) -> bool:
    return (
        _html_tag_drops_content(tag, in_svg=in_svg, in_math=in_math)
        or _html_attrs_hidden_or_suppressed(attrs_by_name)
        or _html_attrs_match_hidden_stylesheet_selector(
            tag,
            attrs_by_name,
            hidden_stylesheet_selectors,
        )
    )


def _pop_html_tag_stack(tag_stack: List[Tuple], tag: str) -> List[Tuple]:
    for index in range(len(tag_stack) - 1, -1, -1):
        if tag_stack[index][0] == tag:
            popped_tags = tag_stack[index:]
            del tag_stack[index:]
            return popped_tags

    return []


def _html_downlevel_revealed_conditional_marker(data: str) -> str:
    normalized = str(data or "").strip().lower()
    if normalized == "endif":
        return "end"
    if normalized == "if" or (
        normalized.startswith("if") and normalized[2].isspace()
    ):
        return "start"
    return ""


class _HTMLToPlainTextParser(HTMLParser):
    def __init__(
        self,
        hidden_stylesheet_selectors: List[_HiddenStylesheetSelector],
    ):
        super().__init__(convert_charrefs=True)
        self._chunks: List[str] = []
        self._suppressed_depth = 0
        self._conditional_comment_depth = 0
        self._svg_depth = 0
        self._math_depth = 0
        self._tag_stack: List[Tuple[str, bool]] = []
        self._hidden_stylesheet_selectors = hidden_stylesheet_selectors

    def _pop_tag(self, tag: str) -> None:
        for open_tag, suppresses_text in _pop_html_tag_stack(
            self._tag_stack, tag
        ):
            if open_tag == "svg" and self._svg_depth:
                self._svg_depth -= 1
            elif open_tag == "math" and self._math_depth:
                self._math_depth -= 1
            if suppresses_text and self._suppressed_depth:
                self._suppressed_depth -= 1

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        attrs_by_name = _html_attrs_by_name(attrs)
        suppresses_text = _html_tag_suppresses_text(
            tag,
            attrs_by_name,
            self._hidden_stylesheet_selectors,
            in_svg=self._svg_depth > 0,
            in_math=self._math_depth > 0,
        )

        if tag not in _HTML_VOID_TAGS:
            self._tag_stack.append((tag, suppresses_text))

        if tag == "svg":
            self._svg_depth += 1
        elif tag == "math":
            self._math_depth += 1

        if suppresses_text:
            if tag not in _HTML_VOID_TAGS:
                self._suppressed_depth += 1
            return

        if self._suppressed_depth:
            return

        if tag in _HTML_BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        attrs_by_name = _html_attrs_by_name(attrs)
        suppresses_text = _html_tag_suppresses_text(
            tag,
            attrs_by_name,
            self._hidden_stylesheet_selectors,
            in_svg=self._svg_depth > 0,
            in_math=self._math_depth > 0,
        )

        if suppresses_text or self._suppressed_depth:
            return

        if tag in _HTML_BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        was_suppressed = bool(self._suppressed_depth)
        self._pop_tag(tag)

        if was_suppressed or self._suppressed_depth:
            return

        if tag in _HTML_BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data):
        if not self._suppressed_depth and not self._conditional_comment_depth:
            self._chunks.append(data)

    def handle_comment(self, data):
        return

    def unknown_decl(self, data):
        marker = _html_downlevel_revealed_conditional_marker(data)
        if marker == "start":
            self._conditional_comment_depth += 1
        elif marker == "end" and self._conditional_comment_depth:
            self._conditional_comment_depth -= 1

    def get_text(self) -> str:
        text = "".join(self._chunks)
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = text.replace("\xa0", " ")
        text = re.sub(r"[^\S\n]+", " ", text)
        text = re.sub(r" *\n *", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _html_to_plain_text(content: str) -> str:
    if not content:
        return ""

    parser = _HTMLToPlainTextParser(_hidden_stylesheet_selectors(content))
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return ""

    return parser.get_text()


def _normalized_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None

    normalized = hostname.strip().lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    return normalized or None


def _http_url_host(
    value: Optional[str],
    *,
    allow_www_shorthand: bool = False,
) -> Optional[str]:
    if not value:
        return None

    candidate = value.strip()
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"
    elif allow_www_shorthand and candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    return _normalized_hostname(parsed.hostname)


def _display_url_host(text: str) -> Optional[str]:
    candidate = " ".join((text or "").split())
    candidate = candidate.strip(_DISPLAY_URL_STRIP_CHARS).rstrip(
        _DISPLAY_URL_TRAILING_PUNCTUATION
    )
    if not candidate or any(char.isspace() for char in candidate):
        return None

    lower_candidate = candidate.lower()
    if not (
        lower_candidate.startswith("http://")
        or lower_candidate.startswith("https://")
        or lower_candidate.startswith("www.")
    ):
        return None

    return _http_url_host(candidate, allow_www_shorthand=True)


def _url_scheme(value: Optional[str]) -> str:
    if not value:
        return ""

    candidate = value.strip()
    colon_index = candidate.find(":")
    if colon_index <= 0:
        return ""

    scheme = candidate[:colon_index].lower()
    if not scheme:
        return ""

    for char in scheme:
        if not (char.isalnum() or char in {"+", "-", "."}):
            return ""

    return scheme


def _meta_refresh_target(content: Optional[str]) -> str:
    if not content:
        return ""

    match = _META_REFRESH_URL_RE.search(str(content))
    if match is None:
        return ""

    target = match.group("url").strip()
    if len(target) >= 2 and target[0] == target[-1] and target[0] in {"'", '"'}:
        target = target[1:-1].strip()

    return target


def _meta_refresh_warning(content: Optional[str]) -> str:
    target = _meta_refresh_target(content)
    scheme = _url_scheme(target)
    if scheme in _DANGEROUS_META_REFRESH_SCHEMES:
        return (
            "HTML email contains a meta refresh redirect using potentially unsafe "
            f"{scheme}: URL scheme."
        )

    target_host = _http_url_host(target)
    if target_host:
        return f"HTML email contains a meta refresh redirect to {target_host}."

    return _META_REFRESH_REDIRECT_WARNING


class _HTMLSafetyParser(HTMLParser):
    def __init__(
        self,
        hidden_stylesheet_selectors: List[_HiddenStylesheetSelector],
    ):
        super().__init__(convert_charrefs=True)
        self._warnings: List[str] = []
        self._seen_warnings = set()
        self._drop_depth = 0
        self._hidden_depth = 0
        self._conditional_comment_depth = 0
        self._svg_depth = 0
        self._math_depth = 0
        self._tag_stack: List[Tuple[str, bool, bool]] = []
        self._anchor_stack: List[Dict] = []
        self._hidden_stylesheet_selectors = hidden_stylesheet_selectors

    def _add_warning(self, warning: str) -> None:
        if warning in self._seen_warnings:
            return

        self._seen_warnings.add(warning)
        self._warnings.append(warning)

    def _pop_tag(self, tag: str) -> List[Tuple[str, bool, bool]]:
        popped_tags = _pop_html_tag_stack(self._tag_stack, tag)
        for _open_tag, drops_content, hides_text in popped_tags:
            if _open_tag == "svg" and self._svg_depth:
                self._svg_depth -= 1
            elif _open_tag == "math" and self._math_depth:
                self._math_depth -= 1
            if drops_content and self._drop_depth:
                self._drop_depth -= 1
            if hides_text and self._hidden_depth:
                self._hidden_depth -= 1

        return popped_tags

    def _check_anchor(self, anchor: Dict) -> None:
        display_host = _display_url_host("".join(anchor["chunks"]))
        href_host = _http_url_host(anchor.get("href"))
        if display_host and href_host and display_host != href_host:
            self._add_warning(
                f"Link text host {display_host} points to different host {href_host}."
            )

    def _check_form(self, action: str) -> None:
        scheme = _url_scheme(action)
        if scheme in _DANGEROUS_LINK_SCHEMES:
            self._add_warning(
                "HTML email contains an embedded form that uses potentially unsafe "
                f"{scheme}: URL scheme and may collect or submit sensitive data."
            )
            return

        action_host = _http_url_host(action, allow_www_shorthand=True)
        if action_host:
            self._add_warning(
                "HTML email contains an embedded form that submits to "
                f"{action_host} and may collect or submit sensitive data."
            )
            return

        self._add_warning(_EMBEDDED_FORM_WARNING)

    def _check_start_tag_security(
        self,
        tag: str,
        attrs_by_name: Dict[str, str],
        *,
        collect_anchor_text: bool,
    ) -> None:
        if tag == "a":
            href = attrs_by_name.get("href", "")
            scheme = _url_scheme(href)
            if scheme in _DANGEROUS_LINK_SCHEMES:
                self._add_warning(
                    f"Link uses potentially unsafe {scheme}: URL scheme."
                )
            if collect_anchor_text:
                self._anchor_stack.append({"href": href, "chunks": []})
        elif tag == "form":
            self._check_form(attrs_by_name.get("action", ""))
        elif tag == "img" and _http_url_host(attrs_by_name.get("src")):
            self._add_warning(_REMOTE_IMAGE_WARNING)
        elif (
            tag == "meta"
            and (attrs_by_name.get("http-equiv") or "").strip().lower() == "refresh"
        ):
            self._add_warning(_meta_refresh_warning(attrs_by_name.get("content")))

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        attrs_by_name = _html_attrs_by_name(attrs)
        drops_content = _html_tag_drops_content(
            tag,
            in_svg=self._svg_depth > 0,
            in_math=self._math_depth > 0,
        )
        hides_text = not drops_content and (
            _html_attrs_hidden_or_suppressed(attrs_by_name)
            or _html_attrs_match_hidden_stylesheet_selector(
                tag,
                attrs_by_name,
                self._hidden_stylesheet_selectors,
            )
        )

        if tag not in _HTML_VOID_TAGS:
            self._tag_stack.append((tag, drops_content, hides_text))

        if tag == "svg":
            self._svg_depth += 1
        elif tag == "math":
            self._math_depth += 1

        if drops_content:
            if tag not in _HTML_VOID_TAGS:
                self._drop_depth += 1
            return

        if self._drop_depth:
            return

        if hides_text:
            self._add_warning(_HIDDEN_HTML_CONTENT_WARNING)
            if tag not in _HTML_VOID_TAGS:
                self._hidden_depth += 1

        self._check_start_tag_security(
            tag,
            attrs_by_name,
            collect_anchor_text=True,
        )

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        attrs_by_name = _html_attrs_by_name(attrs)
        if (
            _html_tag_drops_content(
                tag,
                in_svg=self._svg_depth > 0,
                in_math=self._math_depth > 0,
            )
            or self._drop_depth
        ):
            return

        hides_text = _html_attrs_hidden_or_suppressed(
            attrs_by_name
        ) or _html_attrs_match_hidden_stylesheet_selector(
            tag,
            attrs_by_name,
            self._hidden_stylesheet_selectors,
        )
        if hides_text:
            self._add_warning(_HIDDEN_HTML_CONTENT_WARNING)

        self._check_start_tag_security(
            tag,
            attrs_by_name,
            collect_anchor_text=False,
        )

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._conditional_comment_depth:
            return

        was_dropped = bool(self._drop_depth)
        was_hidden = bool(self._hidden_depth)
        popped_tags = self._pop_tag(tag)

        if was_hidden:
            for open_tag, _drops_content, _hides_text in popped_tags:
                if open_tag == "a" and self._anchor_stack:
                    self._anchor_stack.pop()

        if was_dropped or self._drop_depth or was_hidden or self._hidden_depth:
            return

        if tag != "a" or not self._anchor_stack:
            return

        self._check_anchor(self._anchor_stack.pop())

    def handle_data(self, data):
        if (
            self._drop_depth
            or self._hidden_depth
            or self._conditional_comment_depth
        ):
            return

        for anchor in self._anchor_stack:
            anchor["chunks"].append(data)

    def handle_comment(self, data):
        if data.strip():
            self._add_warning(_HIDDEN_HTML_CONTENT_WARNING)

    def unknown_decl(self, data):
        marker = _html_downlevel_revealed_conditional_marker(data)
        if marker == "start":
            self._add_warning(_HIDDEN_HTML_CONTENT_WARNING)
            self._conditional_comment_depth += 1
        elif marker == "end" and self._conditional_comment_depth:
            self._conditional_comment_depth -= 1

    def get_warnings(self) -> List[str]:
        while self._anchor_stack:
            self._check_anchor(self._anchor_stack.pop())

        return self._warnings


def _html_content_security_warnings(content: str) -> List[str]:
    if not content:
        return []

    parser = _HTMLSafetyParser(_hidden_stylesheet_selectors(content))
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return []

    return parser.get_warnings()


def _base_mime_type(mime_type: str) -> str:
    return mime_type.split(";", 1)[0].strip().lower()


def _is_attachment_part(part: Dict) -> bool:
    if part.get("filename"):
        return True

    disposition = _header_value(part.get("headers", []) or [], "Content-Disposition", "")
    disposition_type = disposition.split(";", 1)[0].strip().lower()
    return disposition_type == "attachment"


def _dedupe_preserving_order(values: List[str]) -> List[str]:
    deduped: List[str] = []
    seen = set()

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        deduped.append(value)

    return deduped


def _header_parameter(headers: List[Dict], key: str, parameter: str) -> str:
    value = _header_value(headers, key, "")
    if not value:
        return ""

    unfolded_value = str(value).replace("\r", " ").replace("\n", " ")
    try:
        message = Parser(policy=policy.default).parsestr(
            f"{key}: {unfolded_value}\n\n"
        )
        parsed_header = message[key]
    except Exception:
        return ""

    if parsed_header is None:
        return ""

    params = getattr(parsed_header, "params", {}) or {}
    return str(params.get(parameter, "") or "")


def _decode_attachment_filename(filename: str) -> str:
    return _decode_mime_header_value(filename)


def _canonical_attachment_filename(filename: str) -> str:
    normalized = _ATTACHMENT_FILENAME_DISPLAY_CONTROL_RE.sub(
        " ",
        str(filename or ""),
    )
    basename = re.split(r"[\\/]+", normalized)[-1]
    return " ".join(basename.split())


def _attachment_filename(part: Dict) -> str:
    headers = part.get("headers", []) or []
    part_filename = str(part.get("filename") or "")
    if part_filename:
        return _canonical_attachment_filename(
            _decode_attachment_filename(part_filename)
        )

    filename = _header_parameter(
        headers, "Content-Disposition", "filename"
    ) or _header_parameter(headers, "Content-Type", "name")
    return _canonical_attachment_filename(_decode_attachment_filename(filename))


def _attachment_extension_candidates(filename: str) -> List[str]:
    basename = re.split(r"[\\/]+", filename.strip().lower().rstrip(" ."))[-1]
    candidates = [basename]
    # After control-character folding, line-forged text can trail a filename;
    # test each token so forged text cannot hide a dangerous extension.
    candidates.extend(part.rstrip(" .") for part in basename.split())
    return _dedupe_preserving_order(
        [candidate for candidate in candidates if candidate]
    )


def _attachment_extensions(filename: str) -> List[str]:
    normalized = filename.strip().lower().rstrip(" .")
    basename = re.split(r"[\\/]", normalized)[-1]
    if "." not in basename:
        return []

    return [f".{extension}" for extension in basename.split(".")[1:] if extension]


def _attachment_extension(filename: str) -> str:
    extensions = _attachment_extensions(filename)
    if not extensions:
        return ""

    return extensions[-1]


def _deceptive_double_attachment_extensions(
    filename: str,
) -> Optional[Tuple[str, str]]:
    extensions = _attachment_extensions(filename)
    if len(extensions) < 2:
        return None

    previous_extension, extension = extensions[-2], extensions[-1]
    if (
        extension not in _EXECUTABLE_ATTACHMENT_EXTENSIONS
        and extension not in _MACRO_ENABLED_ATTACHMENT_EXTENSIONS
        and extension not in _ACTIVE_WEB_CONTENT_ATTACHMENT_EXTENSIONS
    ):
        return None

    if (
        previous_extension not in _BENIGN_DOCUMENT_MEDIA_ATTACHMENT_EXTENSIONS
        and previous_extension not in _ARCHIVE_ATTACHMENT_EXTENSIONS
    ):
        return None

    return previous_extension, extension


def _attachment_security_warning(filename: str) -> Optional[str]:
    extension_candidates = _attachment_extension_candidates(filename)
    for extension_filename in extension_candidates:
        double_extensions = _deceptive_double_attachment_extensions(extension_filename)
        if double_extensions:
            previous_extension, extension = double_extensions
            return (
                f"Attachment {filename} uses a deceptive double extension "
                f"({previous_extension}{extension}) and may contain active content."
            )

    for extension_filename in extension_candidates:
        extension = _attachment_extension(extension_filename)
        if extension in _MACRO_ENABLED_ATTACHMENT_EXTENSIONS:
            return (
                f"Attachment {filename} is macro-enabled and may contain active content."
            )

        if extension in _EXECUTABLE_ATTACHMENT_EXTENSIONS:
            return (
                f"Attachment {filename} uses executable or script file extension "
                f"{extension} and may contain active content."
            )

        if extension in _ACTIVE_WEB_CONTENT_ATTACHMENT_EXTENSIONS:
            return (
                f"Attachment {filename} is active web content and may contain "
                "scripts or credential collection pages."
            )

        if extension in _ARCHIVE_ATTACHMENT_EXTENSIONS:
            return (
                f"Attachment {filename} is an archive file and may conceal other files."
            )

    return None


def _attachment_security_warnings(payload: Dict) -> List[str]:
    if not payload:
        return []

    warnings: List[str] = []
    if _is_attachment_part(payload):
        filename = _attachment_filename(payload)
        if filename:
            warning = _attachment_security_warning(filename)
            if warning:
                warnings.append(warning)

    for part in payload.get("parts", []) or []:
        warnings.extend(_attachment_security_warnings(part))

    return _dedupe_preserving_order(warnings)


def _find_decoded_mime_part(payload: Dict, mime_type: str) -> Optional[str]:
    if not payload or _is_attachment_part(payload):
        return None

    if _base_mime_type(payload.get("mimeType", "")) == mime_type:
        data = payload.get("body", {}).get("data")
        if data is None:
            return None
        decoded = _decode_base64_urlsafe(data)
        if decoded:
            return decoded
        return None

    for part in payload.get("parts", []) or []:
        decoded = _find_decoded_mime_part(part, mime_type)
        if decoded is not None:
            return decoded

    return None


def _find_decoded_mime_parts(payload: Dict, mime_type: str) -> List[str]:
    if not payload or _is_attachment_part(payload):
        return []

    decoded_parts: List[str] = []
    if _base_mime_type(payload.get("mimeType", "")) == mime_type:
        data = payload.get("body", {}).get("data")
        if data is not None:
            decoded = _decode_base64_urlsafe(data)
            if decoded:
                decoded_parts.append(decoded)

    for part in payload.get("parts", []) or []:
        decoded_parts.extend(_find_decoded_mime_parts(part, mime_type))

    return decoded_parts


def _extract_plain_text(payload: Dict) -> str:
    if not payload:
        return ""

    plain_text = _find_decoded_mime_part(payload, "text/plain")
    if plain_text is not None:
        return plain_text

    html_text = _find_decoded_mime_part(payload, "text/html")
    if html_text is not None:
        return _html_to_plain_text(html_text)

    return ""


def _html_security_warnings(payload: Dict) -> List[str]:
    warnings: List[str] = []
    seen = set()

    for html_text in _find_decoded_mime_parts(payload, "text/html"):
        for warning in _html_content_security_warnings(html_text):
            if warning in seen:
                continue

            seen.add(warning)
            warnings.append(warning)

    return warnings


def _header_value(headers: List[Dict], key: str, default: str = "") -> str:
    for item in headers:
        if item.get("name", "").lower() == key.lower():
            return item.get("value", default)
    return default


_ASCII_HEADER_DISPLAY_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _normalize_header_display_controls(value: str) -> str:
    return _ASCII_HEADER_DISPLAY_CONTROL_RE.sub(" ", value)


def _decode_mime_header_value(value: str) -> str:
    unfolded_value = str(value or "").replace("\r", " ").replace("\n", " ")
    try:
        decoded_parts = decode_header(unfolded_value)
    except Exception:
        return _normalize_header_display_controls(unfolded_value)

    chunks = []
    for chunk, charset in decoded_parts:
        if isinstance(chunk, bytes):
            encoding = charset or "utf-8"
            try:
                chunks.append(chunk.decode(encoding, errors="replace"))
            except LookupError:
                chunks.append(chunk.decode("utf-8", errors="replace"))
        else:
            chunks.append(str(chunk))

    return _normalize_header_display_controls("".join(chunks))


def _display_header_value(headers: List[Dict], key: str, default: str = "") -> str:
    return _decode_mime_header_value(_header_value(headers, key, default))


def _header_values(headers: List[Dict], key: str) -> List[str]:
    return [
        str(item.get("value", ""))
        for item in headers or []
        if str(item.get("name", "")).lower() == key.lower()
    ]


def _normalize_email_domain(domain: str) -> Optional[str]:
    normalized = domain.strip().lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    return _normalize_safe_domain(normalized)


def _email_header_value_domains(header_name: str, value: str) -> List[str]:
    unfolded_value = str(value).replace("\r", " ").replace("\n", " ")
    if not unfolded_value.strip():
        return []

    try:
        message = Parser(policy=policy.default).parsestr(
            f"{header_name}: {unfolded_value}\n\n"
        )
        parsed_header = message[header_name]
    except Exception:
        return []

    if parsed_header is None or getattr(parsed_header, "defects", ()):
        return []

    domains: List[str] = []
    for address in getattr(parsed_header, "addresses", ()):
        if not getattr(address, "username", "") or not getattr(address, "domain", ""):
            continue

        domain = _normalize_email_domain(str(address.domain))
        if domain:
            domains.append(domain)

    return domains


def _email_header_domains(headers: List[Dict], key: str) -> List[str]:
    values = _header_values(headers, key)
    if not values:
        return []

    domains: List[str] = []
    seen = set()
    for value in values:
        for domain in _email_header_value_domains(key, value):
            if domain in seen:
                continue

            seen.add(domain)
            domains.append(domain)

    return domains


def _reply_to_security_warnings(headers: List[Dict]) -> List[str]:
    from_domains = _email_header_domains(headers, "From")
    if not from_domains:
        return []

    sender_domain = from_domains[0]
    warnings: List[str] = []
    for reply_to_domain in _email_header_domains(headers, "Reply-To"):
        if reply_to_domain == sender_domain:
            continue

        warnings.append(
            f"Reply-To domain {reply_to_domain} differs from "
            f"sender domain {sender_domain}."
        )

    return warnings


def _authentication_result_clauses(value: str) -> List[str]:
    clauses: List[str] = []
    current: List[str] = []
    comment_depth = 0
    in_quote = False
    escaped = False

    for char in value:
        current.append(char)

        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
            continue

        if char == '"':
            in_quote = True
        elif char == "(":
            comment_depth += 1
        elif char == ")" and comment_depth:
            comment_depth -= 1
        elif char == ";" and not comment_depth:
            current.pop()
            clauses.append("".join(current))
            current = []

    clauses.append("".join(current))
    return clauses


def _authentication_security_warnings(headers: List[Dict]) -> List[str]:
    warnings: List[str] = []
    seen = set()

    for item in headers or []:
        header_name = str(item.get("name", ""))
        normalized_header_name = header_name.lower()
        header_label = _AUTHENTICATION_RESULT_HEADER_LABELS.get(normalized_header_name)
        if header_label is None:
            continue

        value = str(item.get("value", ""))
        unfolded_value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
        for clause in _authentication_result_clauses(unfolded_value):
            result_match = _AUTHENTICATION_RESULT_RE.match(clause)
            if not result_match:
                continue

            mechanism = result_match.group(1).lower()
            result = result_match.group(2).lower()
            if result not in _AUTHENTICATION_WARNING_RESULTS:
                continue

            warning_key = (normalized_header_name, mechanism, result)
            if warning_key in seen:
                continue
            seen.add(warning_key)

            warnings.append(
                f"{_AUTHENTICATION_MECHANISM_LABELS[mechanism]} authentication "
                f"result is {result} in {header_label}."
            )

    return warnings


def get_emails_by_query(service, query: str, max_results: int = 100) -> List[Dict]:
    results = (
        service.users()
        .messages()
        .list(
            userId="me",
            q=query,
            maxResults=max_results,
            fields=GMAIL_MESSAGE_LIST_FIELDS,
        )
        .execute()
    )
    messages = results.get("messages", [])

    emails: List[Dict] = []
    for message in messages:
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="full",
                fields=GMAIL_MESSAGE_GET_FIELDS,
            )
            .execute()
        )

        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        label_ids = msg.get("labelIds", [])

        emails.append(
            {
                "id": msg.get("id"),
                "thread_id": msg.get("threadId"),
                "subject": _display_header_value(headers, "Subject", "(No Subject)"),
                "sender": _display_header_value(headers, "From", "Unknown Sender"),
                "date": _display_header_value(headers, "Date", ""),
                "snippet": msg.get("snippet", ""),
                "label_ids": label_ids,
                "is_archived": "INBOX" not in label_ids,
                "security_warnings": _dedupe_preserving_order(
                    _authentication_security_warnings(headers)
                    + _reply_to_security_warnings(headers)
                    + _html_security_warnings(payload)
                    + _attachment_security_warnings(payload)
                ),
                "content": _extract_plain_text(payload),
            }
        )

    return emails


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FINAL_DOMAIN_LABEL_RE = re.compile(r"^[a-z]{2,}$")


def _normalize_safe_domain(domain: str) -> Optional[str]:
    normalized = domain.strip().lower()
    if normalized.startswith("@"):
        normalized = normalized[1:]

    if not normalized or len(normalized) > 253:
        return None

    labels = normalized.split(".")
    if len(labels) < 2 or not _FINAL_DOMAIN_LABEL_RE.fullmatch(labels[-1]):
        return None

    for label in labels:
        if not 1 <= len(label) <= 63 or not _DOMAIN_LABEL_RE.fullmatch(label):
            return None

    return normalized


def get_emails_from_domains(service, domains, max_results: int = 100):
    valid_domains = [
        normalized
        for domain in domains
        if domain and (normalized := _normalize_safe_domain(domain))
    ]
    if not valid_domains:
        return []

    query = " OR ".join([f"from:{domain}" for domain in valid_domains])
    return get_emails_by_query(service, query=query, max_results=max_results)
