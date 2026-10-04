# nepomuk brand

The mark is a vault door: an N on a navy door with a teal frame and hinges.

| File | Use |
| --- | --- |
| `icon.svg` | App icon and favicon source (also `gui/assets/icon.svg`) |
| `logo.svg` | Icon with the wordmark, for light backgrounds |
| `logo-dark.svg` | Icon with the wordmark, for dark backgrounds |

The wordmark is Manrope ExtraBold converted to outlines, so no font is needed to render it.

## Colours

| Token | Hex | Use |
| --- | --- | --- |
| Navy | `#16233F` | Icon background, GUI sidebar and text |
| Teal | `#5FB4AA` | Icon frame and diagonal, accents on navy and in dark mode |
| Teal, deep | `#2B7A71` | Accent on light backgrounds (teal itself is only 2.4:1 on white) |

The GUI maps these to CSS variables in [`gui/ui/styles.css`](../../gui/ui/styles.css); crimson stays reserved for errors, conflicts and destructive actions.

To regenerate the raster app icons: `cd gui/assets && python3 make-icon.py`, then `cargo tauri icon icon-source.png`. At 32 px and below use `gui/assets/icon-small.svg` (no frame or hinges) so the N stays legible.
