from dataclasses import dataclass, field
from typing import Dict, List, Union
import unicodedata


def unicode_data_factory() -> Dict[str, List[str]]:
    """Factory function for Unicode test data."""
    return {
        # Latin-based languages
        "latin": [
            "Café résumé naïve",
            "Zürich Köln München",
            "Åse Øystein Bjørn",
            "Ñoño español piñata",
            "Português açaí coração",
            "Français hôpital théâtre",
            "Polska żółć gęślą jaźń",
            "Čeština žluťoučký kůň"
        ],

        # Cyrillic scripts
        "cyrillic": [
            "Привет мир",  # Russian
            "Здравствуйте",  # Russian formal
            "Български език",  # Bulgarian
            "Српски језик",  # Serbian
            "Українська мова",  # Ukrainian
            "Монгол хэл",  # Mongolian
            "Македонски јазик"  # Macedonian
        ],

        # Arabic and related scripts
        "arabic": [
            "مرحبا بالعالم",  # Arabic - Hello World
            "السلام عليكم",  # Arabic - Peace be upon you
            "فارسی زبان",  # Persian
            "اردو زبان",  # Urdu
            "עברית שפה",  # Hebrew
            "ܠܫܢܐ ܐܪܡܝܐ"  # Aramaic
        ],

        # East Asian scripts
        "cjk": [
            "你好世界",  # Chinese Simplified
            "你好世界",  # Chinese Traditional
            "こんにちは世界",  # Japanese Hiragana
            "コンニチハ世界",  # Japanese Katakana
            "漢字ひらがなカタカナ",  # Japanese Mixed
            "안녕하세요 세계",  # Korean
            "한국어 조선말",  # Korean
            "中文繁體字",  # Traditional Chinese
        ],

        "japanese": [
            "こんにちは世界",  # Japanese Hiragana
        ],

        # South Asian scripts
        "indic": [
            "नमस्ते दुनिया",  # Hindi/Devanagari
            "হ্যালো বিশ্ব",  # Bengali
            "ਸਤ ਸ੍ਰੀ ਅਕਾਲ",  # Punjabi/Gurmukhi
            "નમસ્તે વિશ્વ",  # Gujarati
            "ನಮಸ್ಕಾರ ಜಗತ್ತು",  # Kannada
            "नमस्कार जग",  # Marathi
            "നമസ്കാരം ലോകം",  # Malayalam
            "வணக்கம் உலகம்",  # Tamil
            "నమస్కారం ప్రపంచం",  # Telugu
            "ଓଡ଼ିଆ ଭାଷା",  # Odia
            "සිංහල භාෂාව"  # Sinhala
        ],

        # Southeast Asian scripts
        "asian": [
            "สวัสดีชาวโลก",  # Thai
            "ສະບາຍດີ",  # Lao
            "ជំរាបសួរ",  # Khmer/Cambodian
            "မင်္ဂလာပါ",  # Myanmar/Burmese
            "ཐུབ་བསྟན་",  # Tibetan
            "ᐃᓄᒃᑎᑐᑦ"  # Inuktitut
        ],

        # Mathematical symbols
        "mathematical": [
            "∑∏∫∮∇∆∂",  # Calculus symbols
            "∞∅∈∉∋∌∧∨",  # Set theory
            "≤≥≠≈≡≢⊂⊃",  # Relations
            "±×÷√∛∜∝∴",  # Operators
            "αβγδεζηθικλμνξοπρστυφχψω",  # Greek lowercase
            "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ",  # Greek uppercase
            "ℵℶℷℸ",  # Hebrew aleph numbers
            "ℕℤℚℝℂ"  # Number sets
        ],

        # Currency symbols
        "currency": [
            "$€£¥₹₽₩₪₫₱₡₵₸₺₼₴₲₦₨₯₰₳₴₵₶₷₸₹₺₻₼₽₾₿",
            "¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿",
            "＄￠￡￢￣￤￥￦"  # Full-width variants
        ],

        # Punctuation and symbols
        "punctuation": [
            "‚„""''‛‟‹›«»",  # Quotes
            "–—―‖‗''‚‛""„‟",  # Dashes and quotes
            "†‡•‰′″‴‵‶‷‸‹›",  # Misc punctuation
            "¡¿؟՞؞՟؟",  # Inverted punctuation
            "。、？！：；",  # CJK punctuation
            "।॥॰",  # Devanagari punctuation
            "؛؟",  # Arabic punctuation
        ],

        # Emoji and pictographs
        "emoji": [
            "😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗😙😚",  # Faces
            "🏠🏡🏢🏣🏤🏥🏦🏧🏨🏩🏪🏫🏬🏭🏮🏯",  # Buildings
            "🚗🚕🚙🚌🚎🏎🚓🚑🚒🚐🚚🚛🚜🏍🛵🚲",  # Transport
            "🍎🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🍆",  # Food
            "🌍🌎🌏🌐🗺🗾🧭🏔⛰🌋🗻🏕🏖🏜🏝🏞",  # Geography
            "👨‍👩‍👧‍👦👩‍👩‍👦👨‍👨‍👧‍👦👨‍👩‍👧‍👧",  # Family emojis
        ],

        # Special cases and edge cases
        "special": [
            "\t\n\r",  # Whitespace characters
            "a\u0300",  # Combining grave accent
            "e\u0301",  # Combining acute accent
            "o\u0308",  # Combining diaeresis
            "n\u0303",  # Combining tilde
            "c\u0327",  # Combining cedilla
            "\u200B",  # Zero-width space
            "\u200C",  # Zero-width non-joiner
            "\u200D",  # Zero-width joiner
            "\uFEFF",  # Byte order mark
            "\u2028",  # Line separator
            "\u2029",  # Paragraph separator
            "\u00A0",  # Non-breaking space
            "\u1680",  # Ogham space mark
            "\u180E",  # Mongolian vowel separator
        ],

        # Mixed scripts (potential confusables)
        "mixed": [
            "Аpple",  # Cyrillic А + Latin pple
            "Micr߀soft",  # Latin + NKo digit
            "Gⲟⲟgle",  # Latin + Coptic
            "АӀibаbа",  # Cyrillic + Latin look-alikes
            "а‍рр‍lе",  # Cyrillic with zero-width joiners
            "раура1",  # Cyrillic + Latin + digit
        ],

        # Bidirectional text
        "bidi": [
            "Hello العالم",  # English + Arabic
            "שלום World",  # Hebrew + English
            "مرحبا by the العالم",  # Arabic + English + Arabic
            "123 العربية 456",  # Numbers + Arabic + Numbers
            "\u202Eright-to-left\u202C",  # RTL override
            "\u202Dleft-to-right\u202C",  # LTR override
        ],

        # Normalization test cases
        "normalization": [
            "é",  # Precomposed (NFC)
            "e\u0301",  # Decomposed (NFD)
            "ﬁ",  # Ligature
            "fi",  # Separate characters
            "㈠",  # Parenthesized Hangul
            "(가)",  # Parenthesized separate
            "Ⅰ",  # Roman numeral
            "I",  # Latin I
        ],

        # Very long strings
        "long": [
            "a" * 1000,  # 1000 ASCII characters
            "🚀" * 100,  # 100 emoji
            "测试" * 500,  # 1000 CJK characters
            "🏴󠁧󠁢󠁥󠁮󠁧󠁿" * 50,  # Flag sequences
        ],

        # Control characters
        "control": [
            "\x00\x01\x02\x03\x04\x05\x06\x07",  # C0 controls
            "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",  # More C0 controls
            "\x80\x81\x82\x83\x84\x85\x86\x87",  # C1 controls
            "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007",  # Unicode escapes
        ]
    }


@dataclass
class UnicodeFactory:
    """Factory for generating Unicode test data."""

    data: Dict[str, List[str]] = field(default_factory=unicode_data_factory)

    def get_data(self) -> Dict[str, List[str]]:
        """Return Unicode data dictionary."""
        return self.data



