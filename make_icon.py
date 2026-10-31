"""生成 FileSync 图标：蓝色渐变圆角底 + 白色双向箭头。

输出 DSM 套件需要的全部尺寸：
    pkg/ui/images/icon_{16,24,32,48,64,72,256}.png
    PACKAGE_ICON.PNG (72) / PACKAGE_ICON_256.PNG (256)
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
SIZES = [16, 24, 32, 48, 64, 72, 256]
BASE = 512  # 先在大画布上绘制再缩小，边缘更平滑


def build():
    img = Image.new("RGBA", (BASE, BASE), (0, 0, 0, 0))

    # 背景：自上而下的蓝色渐变
    grad = Image.new("RGB", (BASE, BASE))
    pen = ImageDraw.Draw(grad)
    top, bottom = (20, 66, 98), (44, 130, 190)
    for y in range(BASE):
        t = y / (BASE - 1)
        pen.line(
            [(0, y), (BASE, y)],
            fill=(
                int(top[0] + (bottom[0] - top[0]) * t),
                int(top[1] + (bottom[1] - top[1]) * t),
                int(top[2] + (bottom[2] - top[2]) * t),
            ),
        )

    mask = Image.new("L", (BASE, BASE), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, BASE - 1, BASE - 1], radius=112, fill=255)
    img.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    stroke = 34

    # 上箭头：从左到右
    draw.line([(120, 196), (352, 196)], fill=white, width=stroke)
    draw.polygon([(352, 150), (424, 196), (352, 242)], fill=white)

    # 下箭头：从右到左
    draw.line([(392, 316), (160, 316)], fill=white, width=stroke)
    draw.polygon([(160, 270), (88, 316), (160, 362)], fill=white)

    # 两个小圆点，暗示"两端站点"
    draw.ellipse([110, 158, 154, 202], fill=white)
    draw.ellipse([358, 310, 402, 354], fill=white)

    return img


def main():
    master = build()
    out_dir = ROOT / "pkg" / "ui" / "images"
    out_dir.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        resized = master.resize((size, size), Image.LANCZOS)
        path = out_dir / ("icon_%d.png" % size)
        resized.save(path, "PNG", optimize=True)
        print("  %-24s %d bytes" % (path.name, path.stat().st_size))

    master.resize((72, 72), Image.LANCZOS).save(ROOT / "PACKAGE_ICON.PNG", "PNG", optimize=True)
    master.resize((256, 256), Image.LANCZOS).save(ROOT / "PACKAGE_ICON_256.PNG", "PNG", optimize=True)
    print("  PACKAGE_ICON.PNG / PACKAGE_ICON_256.PNG")


if __name__ == "__main__":
    main()
