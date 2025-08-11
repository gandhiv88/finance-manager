#!/usr/bin/env python3
"""
Generate application icon with F and M letters for Personal Finance Manager
"""

from PIL import Image, ImageDraw, ImageFont
import os
from pathlib import Path


def create_app_icon():
    """Create a professional app icon with F and M letters"""

    # Create resources directory if it doesn't exist
    resources_dir = Path(__file__).parent
    resources_dir.mkdir(exist_ok=True)

    # Icon settings
    size = 512
    background_color = "#2E7D32"  # Professional green
    text_color = "#FFFFFF"  # White text

    # Create image
    image = Image.new("RGBA", (size, size), background_color)
    draw = ImageDraw.Draw(image)

    # Try to use a system font, fallback to default
    try:
        # For macOS
        font_size = size // 3
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
    except:
        try:
            # Alternative system font
            font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", font_size)
        except:
            # Fallback to default
            font = ImageFont.load_default()

    # Calculate text position for "FM"
    text = "FM"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x = (size - text_width) // 2
    y = (size - text_height) // 2 - 20  # Slight adjustment for better centering

    # Draw the text
    draw.text((x, y), text, fill=text_color, font=font)

    # Add a subtle border
    border_width = 8
    draw.rectangle([0, 0, size - 1, size - 1], outline="#1B5E20", width=border_width)

    # Save in multiple formats and sizes
    formats = [
        ("app_icon.png", 512),
        ("app_icon_256.png", 256),
        ("app_icon_128.png", 128),
        ("app_icon_64.png", 64),
        ("app_icon_32.png", 32),
        ("app_icon_16.png", 16),
    ]

    for filename, icon_size in formats:
        if icon_size != size:
            resized = image.resize((icon_size, icon_size), Image.Resampling.LANCZOS)
            resized.save(resources_dir / filename)
        else:
            image.save(resources_dir / filename)
        print(f"Created: {filename} ({icon_size}x{icon_size})")


if __name__ == "__main__":
    create_app_icon()
    print("App icons generated successfully!")
