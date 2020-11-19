#ifndef __DRAW_H__
#define __DRAW_H__

#include <defines.h>

#define CREDENTIALS_IMAGE   IMG_DIR"/credentials.png"
#define SETTINGS_IMAGE      IMG_DIR"/settings.png"
#define LOCK_IMAGE          IMG_DIR"/lock.png"
#define SHUTDOWN_IMAGE      IMG_DIR"/shutdown.png"

#define GITHUB_IMAGE IMG_DIR"/github.png"

#define FREEPIXEL_FONT_PATH FONTS_DIR"/FreePixel.ttf"
#define PIXELMIX_FONT_PATH FONTS_DIR"/pixelmix.ttf"
#define FONTAWESOME_FONT_PATH FONTS_DIR"/fontawesome-webfont.ttf"


PIPASS_ERR draw_screen(uint8_t screen, int32_t option, int32_t nargs, ...);

#endif