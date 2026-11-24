from PIL import Image, ImageDraw
import math, os

# 资源目录以脚本自身位置计算，避免写死本机绝对路径。
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE_DIR, 'resources')
UI_OUT = os.path.join(BASE_DIR, 'ui')

BLUE1 = (79, 140, 255, 255)   # #4F8CFF
BLUE2 = (123, 92, 255, 255)   # #7B5CFF
WHITE = (255, 255, 255, 255)
DARK  = (10, 15, 30, 255)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(4))


def gradient(size, c1, c2):
    img = Image.new('RGBA', (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1))
            px[x, y] = lerp(c1, c2, t)
    return img


def ring_layer(size, outline=None):
    """Transparent blue-purple C ring with white dot."""
    s = size
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = int(s * 0.10)
    box = [pad, pad, s - pad, s - pad]
    width = max(2, int(s * 0.105))
    # outline for contrast
    if outline:
        d.arc(box, start=45, end=315, fill=outline, width=width + max(2, int(s * 0.05)))
    # gradient arc, drawn in small steps
    grad = gradient(s, BLUE1, BLUE2)
    mask = Image.new('L', (s, s), 0)
    md = ImageDraw.Draw(mask)
    md.arc(box, start=45, end=315, fill=255, width=width)
    # rounded caps
    for ang in (45, 315):
        rad = math.radians(ang)
        cx = s / 2 + (s / 2 - pad) * math.cos(rad)
        cy = s / 2 + (s / 2 - pad) * math.sin(rad)
        r = width / 2
        md.ellipse([cx - r, cy - r, cx + r, cy + r], fill=255)
    img.paste(grad, (0, 0), mask)
    # inner dot
    r = int(s * 0.16)
    c = s / 2
    if outline:
        d.ellipse([c-r-2, c-r-2, c+r+2, c+r+2], fill=outline)
    d.ellipse([c-r, c-r, c+r, c+r], fill=WHITE)
    # small blue core
    r2 = int(s * 0.07)
    d.ellipse([c-r2, c-r2, c+r2, c+r2], fill=BLUE1)
    return img


def app_icon(size=256):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # rounded dark background
    d.rounded_rectangle([0, 0, size-1, size-1], radius=int(size*0.22), fill=DARK)
    # subtle inner border
    d.rounded_rectangle([2, 2, size-3, size-3], radius=int(size*0.21),
                        outline=(80, 100, 140, 180), width=max(1, size//128))
    ring = ring_layer(int(size * 0.82), outline=(0, 0, 0, 120))
    img.alpha_composite(ring, (int(size*0.09), int(size*0.09)))
    # small white "go" tick at bottom-right
    d = ImageDraw.Draw(img)
    d.arc([int(size*0.56), int(size*0.56), int(size*0.86), int(size*0.86)],
          start=200, end=340, fill=WHITE, width=max(2, size//48))
    return img


os.makedirs(OUT, exist_ok=True)
os.makedirs(UI_OUT, exist_ok=True)

app = app_icon(256)
app.save(os.path.join(OUT, 'app-icon.png'))
sizes = [(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)]
app.save(os.path.join(OUT, 'app-icon.ico'), sizes=sizes)

tray = ring_layer(64, outline=(255,255,255,210))
tray.save(os.path.join(OUT, 'tray.png'))
tray_dark = ring_layer(64, outline=(255,255,255,230))
tray_dark.save(os.path.join(OUT, 'tray-dark.png'))
tray_light = ring_layer(64, outline=(15,20,35,220))
tray_light.save(os.path.join(OUT, 'tray-light.png'))
ring_layer(16, outline=(255,255,255,220)).save(os.path.join(OUT, 'tray-16.png'))

# In-app logo: same mark on transparent background, 128px
logo = ring_layer(128, outline=(255,255,255,40))
logo.save(os.path.join(UI_OUT, 'logo.png'))

print('icons written')
