"""HTML sanitizer for question prompts/options, mirroring CList's client-side
_rssSanitizeHtml (js/rss.js): same allowed-tag/attribute lists, same
strip-with-children set for dangerous tags, same unwrap-unknown-tags
behaviour, same javascript:/data:/vbscript: URL blocking on href/src, and the
same target="_blank" rel="noopener noreferrer" forced onto links. Kept in
sync with rss.js deliberately, since this is the same feature applied
server-side (survey prompts render into an anonymous public page, so
sanitizing must happen before storage, not just in the browser).
"""
import html
import re
from html.parser import HTMLParser

STRIP_WITH_CHILDREN = {
    "script", "noscript", "style", "iframe", "frame", "frameset",
    "object", "embed", "applet", "form", "input", "button", "select", "textarea",
}
ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "caption", "cite", "code", "col", "colgroup",
    "dd", "del", "details", "dfn", "div", "dl", "dt", "em", "figcaption", "figure",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd", "li", "mark",
    "ol", "p", "pre", "q", "s", "samp", "small", "span", "strong", "sub", "summary",
    "sup", "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr", "u", "ul", "var",
}
ALLOWED_ATTRS = {
    "a": {"href", "title", "target", "rel"},
    "img": {"src", "alt", "title", "width", "height", "loading"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
    "col": {"span"},
    "time": {"datetime"},
}
VOID_TAGS = {"br", "hr", "img", "col"}
BAD_URL_SCHEMES = ("javascript:", "data:", "vbscript:")


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._skip_depth = 0
        self._open_allowed = []

    def _open(self, tag, attrs, self_closing):
        if self._skip_depth:
            if tag in STRIP_WITH_CHILDREN:
                self._skip_depth += 1
            return
        if tag in STRIP_WITH_CHILDREN:
            self._skip_depth += 1
            return
        if tag not in ALLOWED_TAGS:
            return  # unwrap: drop the tag, keep processing its children/text

        allowed = ALLOWED_ATTRS.get(tag, set())
        kept = []
        for name, value in attrs:
            name = name.lower()
            if name.startswith("on") or name not in allowed:
                continue
            if name in ("href", "src") and value:
                v = re.sub(r"\s+", "", value).lower()
                if v.startswith(BAD_URL_SCHEMES):
                    continue
            kept.append((name, value))
        if tag == "a":
            kept = [kv for kv in kept if kv[0] not in ("target", "rel")]
            kept += [("target", "_blank"), ("rel", "noopener noreferrer")]

        attr_str = "".join(f' {n}="{html.escape(v or "", quote=True)}"' for n, v in kept)
        self.out.append(f"<{tag}{attr_str}>")
        if not (self_closing or tag in VOID_TAGS):
            self._open_allowed.append(tag)

    def handle_starttag(self, tag, attrs):
        self._open(tag, attrs, self_closing=False)

    def handle_startendtag(self, tag, attrs):
        self._open(tag, attrs, self_closing=True)

    def handle_endtag(self, tag):
        if self._skip_depth:
            if tag in STRIP_WITH_CHILDREN:
                self._skip_depth -= 1
            return
        if tag in VOID_TAGS:
            return
        if self._open_allowed and self._open_allowed[-1] == tag:
            self._open_allowed.pop()
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self._skip_depth:
            self.out.append(html.escape(data))

    def get_html(self):
        for tag in reversed(self._open_allowed):
            self.out.append(f"</{tag}>")
        return "".join(self.out)


def sanitize_html(raw):
    if not raw:
        return ""
    parser = _Sanitizer()
    parser.feed(raw)
    parser.close()
    return parser.get_html()


class _TextExtractor(HTMLParser):
    """Strips all tags, keeping only text content — for plain-text contexts
    (CSV export) where the sanitized HTML markup itself would just be noise."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in STRIP_WITH_CHILDREN:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if self._skip_depth and tag in STRIP_WITH_CHILDREN:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            self.out.append(data)

    def get_text(self):
        return "".join(self.out)


def strip_tags(raw):
    if not raw:
        return ""
    parser = _TextExtractor()
    parser.feed(raw)
    parser.close()
    return parser.get_text()
