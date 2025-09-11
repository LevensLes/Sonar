// icons.h
#pragma once

// Use the actual filename of the font file. For Font Awesome 5 Free, it's "fa-solid-900.ttf".
// For Font Awesome 6 Free, it might be "Font Awesome 6 Free-Solid-900.otf". Double-check the filename.
#define FONT_ICON_FILE_NAME_FAS "fa-solid-900.ttf"

#define ICON_MIN_FA 0xe005
#define ICON_MAX_FA 0xf8ff

// Prepending u8 ensures the strings are treated as UTF-8 literals.
#define ICON_FA_SEARCH u8"\uf002"
#define ICON_FA_LIST u8"\uf03a"
#define ICON_FA_COG u8"\uf013"
#define ICON_FA_FLOPPY_DISK u8"\uf0c7"
#define ICON_FA_FOLDER_OPEN u8"\uf07c"
#define ICON_FA_CLIPBOARD u8"\uf328"
#define ICON_FA_EXCHANGE_ALT u8"\uf362"
#define ICON_FA_FILE_CODE u8"\uf1c9"
#define ICON_FA_MICROCHIP u8"\uf2db"
#define ICON_FA_DATABASE u8"\uf1c0"
#define ICON_FA_WRENCH u8"\uf0ad"
#define ICON_FA_FILTER u8"\uf0b0"
#define ICON_FA_INFO_CIRCLE u8"\uf05a"
#define ICON_FA_CHECK_CIRCLE u8"\uf058"
#define ICON_FA_TIMES_CIRCLE u8"\uf057"
#define ICON_FA_SYNC u8"\uf021"
#define ICON_FA_EXCLAMATION_TRIANGLE u8"\uf071"
#define ICON_FA_WARNING u8"\uf071" 
#define ICON_FA_COPY u8"\uf0c5"

// --- ADDED: Icon for elevation/admin rights ---
// The icon code \uf3ed corresponds to "shield-alt".
#define ICON_FA_SHIELD_ALT u8"\uf3ed"
#define ICON_FA_PAINT_BRUSH u8"\uf1fc"