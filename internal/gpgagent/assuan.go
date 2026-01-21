package gpgagent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

type AssuanConn struct {
	reader *bufio.Reader
	writer io.Writer
}

func NewAssuanConn(r io.Reader, w io.Writer) *AssuanConn {
	return &AssuanConn{
		reader: bufio.NewReader(r),
		writer: w,
	}
}

func (c *AssuanConn) ReadLine() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSuffix(line, "\n"), nil
}

func (c *AssuanConn) WriteOK(message string) error {
	if message == "" {
		_, err := fmt.Fprintf(c.writer, "OK\n")
		return err
	}

	_, err := fmt.Fprintf(c.writer, "OK %s\n", message)

	return err
}

func (c *AssuanConn) WriteError(code int, message string) error {
	_, err := fmt.Fprintf(c.writer, "ERR %d %s\n", code, message)

	return err
}

func (c *AssuanConn) WriteData(data []byte) error {
	encoded := percentEncode(data)
	_, err := fmt.Fprintf(c.writer, "D %s\n", encoded)

	return err
}

func (c *AssuanConn) WriteDataHex(data []byte) error {
	encoded := hex.EncodeToString(data)
	_, err := fmt.Fprintf(c.writer, "D %s\n", encoded)

	return err
}

func (c *AssuanConn) WriteStatus(keyword, value string) error {
	_, err := fmt.Fprintf(c.writer, "S %s %s\n", keyword, value)

	return err
}

func (c *AssuanConn) WriteComment(comment string) error {
	_, err := fmt.Fprintf(c.writer, "# %s\n", comment)

	return err
}

func (c *AssuanConn) WriteInquire(keyword string) error {
	_, err := fmt.Fprintf(c.writer, "INQUIRE %s\n", keyword)

	return err
}

func percentEncode(data []byte) string {
	var result strings.Builder

	for _, b := range data {
		if b == '%' || b == '\n' || b == '\r' || b < 32 || b > 126 {
			result.WriteString(fmt.Sprintf("%%%02X", b))
		} else {
			result.WriteByte(b)
		}
	}

	return result.String()
}

func percentDecode(s string) ([]byte, error) {
	var result []byte
	i := 0

	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			b, err := hex.DecodeString(s[i+1 : i+3])
			if err != nil {
				return nil, err
			}

			result = append(result, b[0])
			i += 3
		} else {
			result = append(result, s[i])
			i++
		}
	}

	return result, nil
}

func ParseCommand(line string) (cmd string, args string) {
	parts := strings.SplitN(line, " ", 2)
	cmd = strings.ToUpper(parts[0])

	if len(parts) > 1 {
		args = parts[1]
	}

	return cmd, args
}
