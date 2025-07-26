"""
Shared constants across the file generators package.
"""

DEFAULT_PASSWORD = "123456"
DEFAULT_MARGIN = 72
DEFAULT_LINE_HEIGHT = 14
DEFAULT_FONT_SIZE = 12

SUPPORTED_FILE_TYPES = {
    'word': '.docx',
    'excel': '.xlsx',
    'pdf': '.pdf',
    'csv': '.csv',
    'json': '.json',
    'txt': '.txt',
    'xml': '.xml',
    'zip': '.zip',
    'rar': '.rar',
    'ace': '.ace'
}

FILE_TYPE_EXTENSIONS = {
    'word': 'docx',
    'excel': 'xlsx',
    'pdf': 'pdf',
    'txt': 'txt',
    'csv': 'csv',
    'json': 'json',
    'xml': 'xml'
}

TEXT_ALIGNMENTS = {
    "top-left": "LEFT",
    "top-right": "RIGHT",
    "center": "CENTER",
    "justified": "JUSTIFY"
}

EXCEL_LOCATION_MAPPING = {
    'center': 'D4',
    'top': 'A1',
    'bottom': 'A20',
    'left': 'A1',
    'right': 'J1',
    'beginning': 'A1',
    'middle': 'D4',
    'end': 'J20',
    'start': 'A1'
}

TXT_LOCATION_MAPPING = {
    'top': 1,
    'center': 10,
    'bottom': 20,
    'beginning': 1,
    'middle': 10,
    'end': 20,
    'start': 1,
    'left': 1,
    'right': 1
}

CSV_LOCATION_MAPPING = {
    'center': '5:2',
    'top': '1:1',
    'bottom': '10:1',
    'left': '3:1',
    'right': '3:5',
    'beginning': '1:1',
    'end': '10:5',
    'start': '1:1',
    'middle': '5:2'
}

XML_LOCATION_MAPPING = {
    'center': 'root:content',
    'top': 'root:header',
    'bottom': 'root:footer',
    'beginning': 'root:header',
    'end': 'root:footer',
    'middle': 'root:content',
    'start': 'root:header',
    'left': 'root:content',
    'right': 'root:content'
}

WORD_PDF_LOCATION_MAPPING = {
    'center': 'center',
    'top': 'top',
    'bottom': 'bottom',
    'left': 'left',
    'right': 'right',
    'beginning': 'top',
    'end': 'bottom',
    'start': 'top',
    'middle': 'center'
}

LOCATION_MAPPINGS = {
    'excel': EXCEL_LOCATION_MAPPING,
    'txt': TXT_LOCATION_MAPPING,
    'csv': CSV_LOCATION_MAPPING,
    'xml': XML_LOCATION_MAPPING,
    'word': WORD_PDF_LOCATION_MAPPING,
    'pdf': WORD_PDF_LOCATION_MAPPING
}

DEFAULT_LOCATIONS = {
    'excel': 'A1',
    'txt': 1,
    'csv': '1:1',
    'xml': 'root:content',
    'word': 'center',
    'pdf': 'top-left',
    'json': 'message'
}

ENCRYPTION_SUPPORT = {
    'word': True,
    'excel': True,
    'pdf': True,
    'txt': False,
    'csv': False,
    'json': False,
    'xml': False,
    'zip': True,
    'rar': True,
    'ace': True
}
