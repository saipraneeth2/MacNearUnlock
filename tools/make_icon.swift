// Renders the MacNearUnlock app icon at every size the asset catalogs need.
//
//   swift tools/make_icon.swift
//
// Writes into MacNearUnlockMac/Assets.xcassets/AppIcon.appiconset,
// MacNearUnlockiOS/Assets.xcassets/AppIcon.appiconset and docs/logo.png.
// Pure CoreGraphics vector drawing, so every size is rendered crisply rather
// than downscaled. Original design: an open padlock whose body carries a
// scan frame with a check mark: "approved by a face scan, unlocked".

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let space = CGColorSpace(name: CGColorSpace.sRGB)!

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: space, components: [
        CGFloat((hex >> 16) & 0xFF) / 255, CGFloat((hex >> 8) & 0xFF) / 255, CGFloat(hex & 0xFF) / 255, alpha,
    ])!
}

let gradientTop = color(0x3D8BFF)
let gradientBottom = color(0x5A2DD8)
let glyphInk = color(0x4A48E6)

enum Style { case mac, ios }

/// Draws the foreground in a 1024-point design space (y up).
func drawGlyph(_ ctx: CGContext) {
    // Shackle: open (left leg lifted clear of the body) = unlocked.
    // Legs sit inside the body's straight top edge so they meet it cleanly.
    ctx.setStrokeColor(color(0xFFFFFF))
    ctx.setLineWidth(92)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    let shackle = CGMutablePath()
    shackle.move(to: CGPoint(x: 662, y: 540))
    shackle.addLine(to: CGPoint(x: 662, y: 680))
    shackle.addArc(center: CGPoint(x: 512, y: 680), radius: 150, startAngle: 0, endAngle: .pi, clockwise: false)
    shackle.addLine(to: CGPoint(x: 362, y: 670))
    ctx.addPath(shackle)
    ctx.strokePath()

    // Lock body.
    let body = CGRect(x: 252, y: 160, width: 520, height: 410)
    ctx.setFillColor(color(0xFFFFFF))
    ctx.addPath(CGPath(roundedRect: body, cornerWidth: 64, cornerHeight: 64, transform: nil))
    ctx.fillPath()

    // Scan frame: four corner brackets.
    ctx.setStrokeColor(glyphInk)
    ctx.setLineWidth(30)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    let frame = CGRect(x: 512 - 125, y: 365 - 125, width: 250, height: 250)
    let arm: CGFloat = 66
    let corners: [(CGPoint, CGFloat, CGFloat)] = [
        (CGPoint(x: frame.minX, y: frame.maxY), 1, -1),
        (CGPoint(x: frame.maxX, y: frame.maxY), -1, -1),
        (CGPoint(x: frame.minX, y: frame.minY), 1, 1),
        (CGPoint(x: frame.maxX, y: frame.minY), -1, 1),
    ]
    for (corner, dx, dy) in corners {
        ctx.move(to: CGPoint(x: corner.x + dx * arm, y: corner.y))
        ctx.addLine(to: corner)
        ctx.addLine(to: CGPoint(x: corner.x, y: corner.y + dy * arm))
    }
    ctx.strokePath()

    // Check mark: approved.
    ctx.setLineWidth(38)
    ctx.move(to: CGPoint(x: 452, y: 372))
    ctx.addLine(to: CGPoint(x: 498, y: 324))
    ctx.addLine(to: CGPoint(x: 580, y: 416))
    ctx.strokePath()
}

func render(size: Int, style: Style) -> CGImage {
    let alpha: CGImageAlphaInfo = style == .ios ? .noneSkipLast : .premultipliedLast
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: space, bitmapInfo: alpha.rawValue)!
    let scale = CGFloat(size) / 1024
    ctx.scaleBy(x: scale, y: scale)
    ctx.setShouldAntialias(true)
    ctx.interpolationQuality = .high

    // macOS: 824-point rounded square on the 1024 grid with a soft shadow.
    // iOS: full-bleed opaque square; the system applies the mask.
    let tile = style == .mac ? CGRect(x: 100, y: 100, width: 824, height: 824) : CGRect(x: 0, y: 0, width: 1024, height: 1024)
    let tilePath = style == .mac
        ? CGPath(roundedRect: tile, cornerWidth: 185, cornerHeight: 185, transform: nil)
        : CGPath(rect: tile, transform: nil)

    if style == .mac {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: color(0x000000, 0.32))
        ctx.addPath(tilePath)
        ctx.setFillColor(gradientBottom)
        ctx.fillPath()
        ctx.restoreGState()
    }

    ctx.saveGState()
    ctx.addPath(tilePath)
    ctx.clip()
    let gradient = CGGradient(colorsSpace: space, colors: [gradientTop, gradientBottom] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: tile.midX, y: tile.maxY), end: CGPoint(x: tile.midX, y: tile.minY), options: [])
    let shine = CGGradient(colorsSpace: space, colors: [color(0xFFFFFF, 0.20), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(shine, start: CGPoint(x: tile.midX, y: tile.maxY), end: CGPoint(x: tile.midX, y: tile.midY), options: [])
    ctx.restoreGState()

    ctx.saveGState()
    ctx.translateBy(x: tile.minX, y: tile.minY)
    ctx.scaleBy(x: tile.width / 1024, y: tile.height / 1024)
    ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 18, color: color(0x1A0A66, 0.35))
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    drawGlyph(ctx)
    ctx.endTransparencyLayer()
    ctx.restoreGState()

    return ctx.makeImage()!
}

func write(_ image: CGImage, to url: URL) {
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, image, nil)
    precondition(CGImageDestinationFinalize(destination), "Could not write \(url.path)")
}

func writeJSON(_ text: String, to url: URL) {
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! text.write(to: url, atomically: true, encoding: .utf8)
}

let catalogInfo = #"{"info":{"author":"xcode","version":1}}"# + "\n"

// macOS
let macSet = root.appendingPathComponent("MacNearUnlockMac/Assets.xcassets/AppIcon.appiconset")
for size in [16, 32, 64, 128, 256, 512, 1024] {
    write(render(size: size, style: .mac), to: macSet.appendingPathComponent("icon_\(size).png"))
}
let macEntries: [(Int, Int, Int)] = [(16, 1, 16), (16, 2, 32), (32, 1, 32), (32, 2, 64), (128, 1, 128), (128, 2, 256), (256, 1, 256), (256, 2, 512), (512, 1, 512), (512, 2, 1024)]
let macImages = macEntries.map { #"{"idiom":"mac","scale":"\#($0.1)x","size":"\#($0.0)x\#($0.0)","filename":"icon_\#($0.2).png"}"# }
writeJSON(#"{"images":["# + macImages.joined(separator: ",") + #"],"info":{"author":"xcode","version":1}}"# + "\n", to: macSet.appendingPathComponent("Contents.json"))
writeJSON(catalogInfo, to: root.appendingPathComponent("MacNearUnlockMac/Assets.xcassets/Contents.json"))

// iOS (single 1024 universal icon, opaque)
let iosSet = root.appendingPathComponent("MacNearUnlockiOS/Assets.xcassets/AppIcon.appiconset")
write(render(size: 1024, style: .ios), to: iosSet.appendingPathComponent("icon_1024.png"))
writeJSON(#"{"images":[{"idiom":"universal","platform":"ios","size":"1024x1024","filename":"icon_1024.png"}],"info":{"author":"xcode","version":1}}"# + "\n", to: iosSet.appendingPathComponent("Contents.json"))
writeJSON(catalogInfo, to: root.appendingPathComponent("MacNearUnlockiOS/Assets.xcassets/Contents.json"))

// README / docs logo
write(render(size: 512, style: .mac), to: root.appendingPathComponent("docs/logo.png"))
print("Icons written.")
