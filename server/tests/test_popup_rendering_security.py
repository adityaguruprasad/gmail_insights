from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
POPUP_JS = REPO_ROOT / "popup.js"


def _display_insights_body():
    assert POPUP_JS.exists(), "popup.js was not found at the repository root"
    popup_source = POPUP_JS.read_text()
    match = re.search(
        r"function displayInsights\(insights\) \{(?P<body>.*?)\n  \}",
        popup_source,
        re.DOTALL,
    )
    assert match, "displayInsights function was not found in popup.js"
    return match.group("body")


def test_display_insights_does_not_interpolate_untrusted_fields_into_inner_html():
    body = _display_insights_body()

    assert "innerHTML" not in body
    assert not re.search(r"`[^`]*\$\{\s*insight\.(subject|sender|summary)", body)
    assert not re.search(r"innerHTML\s*=.*insight\.(subject|sender|summary)", body)


def test_display_insights_renders_fields_with_text_safe_apis_and_empty_fallbacks():
    body = _display_insights_body()

    assert re.search(r"\.textContent\s*=\s*insight\.subject\s*\?\?\s*(['\"])\1", body)
    assert re.search(r"\.textContent\s*=\s*insight\.summary\s*\?\?\s*(['\"])\1", body)
    assert re.search(r"\.append\([^)]*insight\.sender\s*\?\?\s*(['\"])\1", body)
    assert re.search(r"\.textContent\s*=\s*(['\"])From:\1", body)
