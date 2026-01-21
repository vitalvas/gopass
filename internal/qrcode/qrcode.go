package qrcode

import (
	"fmt"
	"io"
	"strings"

	"github.com/skip2/go-qrcode"
)

const (
	blockFull      = "\u2588\u2588"
	blockEmpty     = "  "
	blockUpperHalf = "\u2580\u2580"
	blockLowerHalf = "\u2584\u2584"
)

func Generate(content string) (string, error) {
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	return renderTerminal(qr), nil
}

func Print(w io.Writer, content string) error {
	output, err := Generate(content)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, output)

	return nil
}

func renderTerminal(qr *qrcode.QRCode) string {
	bitmap := qr.Bitmap()
	size := len(bitmap)

	var sb strings.Builder

	sb.WriteString("\n")

	for y := -1; y < size+1; y += 2 {
		sb.WriteString("  ")

		for x := -1; x < size+1; x++ {
			upper := getPixel(bitmap, x, y, size)
			lower := getPixel(bitmap, x, y+1, size)

			switch {
			case upper && lower:
				sb.WriteString(blockEmpty)
			case upper && !lower:
				sb.WriteString(blockLowerHalf)
			case !upper && lower:
				sb.WriteString(blockUpperHalf)
			default:
				sb.WriteString(blockFull)
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

func getPixel(bitmap [][]bool, x, y, size int) bool {
	if x < 0 || x >= size || y < 0 || y >= size {
		return false
	}

	return bitmap[y][x]
}
