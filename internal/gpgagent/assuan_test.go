package gpgagent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssuanConn_ReadLine(t *testing.T) {
	input := "COMMAND arg1 arg2\n"
	reader := strings.NewReader(input)
	writer := &bytes.Buffer{}

	conn := NewAssuanConn(reader, writer)

	line, err := conn.ReadLine()
	require.NoError(t, err)
	assert.Equal(t, "COMMAND arg1 arg2", line)
}

func TestAssuanConn_WriteOK(t *testing.T) {
	t.Run("without message", func(t *testing.T) {
		reader := strings.NewReader("")
		writer := &bytes.Buffer{}

		conn := NewAssuanConn(reader, writer)

		err := conn.WriteOK("")
		require.NoError(t, err)
		assert.Equal(t, "OK\n", writer.String())
	})

	t.Run("with message", func(t *testing.T) {
		reader := strings.NewReader("")
		writer := &bytes.Buffer{}

		conn := NewAssuanConn(reader, writer)

		err := conn.WriteOK("success")
		require.NoError(t, err)
		assert.Equal(t, "OK success\n", writer.String())
	})
}

func TestAssuanConn_WriteError(t *testing.T) {
	reader := strings.NewReader("")
	writer := &bytes.Buffer{}

	conn := NewAssuanConn(reader, writer)

	err := conn.WriteError(123, "test error")
	require.NoError(t, err)
	assert.Equal(t, "ERR 123 test error\n", writer.String())
}

func TestAssuanConn_WriteData(t *testing.T) {
	reader := strings.NewReader("")
	writer := &bytes.Buffer{}

	conn := NewAssuanConn(reader, writer)

	err := conn.WriteData([]byte("hello world"))
	require.NoError(t, err)
	assert.Equal(t, "D hello world\n", writer.String())
}

func TestAssuanConn_WriteStatus(t *testing.T) {
	reader := strings.NewReader("")
	writer := &bytes.Buffer{}

	conn := NewAssuanConn(reader, writer)

	err := conn.WriteStatus("KEYINFO", "ABC123")
	require.NoError(t, err)
	assert.Equal(t, "S KEYINFO ABC123\n", writer.String())
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		input    string
		wantCmd  string
		wantArgs string
	}{
		{"NOP", "NOP", ""},
		{"GETINFO version", "GETINFO", "version"},
		{"SIGKEY ABC123DEF456", "SIGKEY", "ABC123DEF456"},
		{"option --flag value", "OPTION", "--flag value"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cmd, args := ParseCommand(tt.input)
			assert.Equal(t, tt.wantCmd, cmd)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

func TestPercentEncode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "hello"},
		{[]byte("hello world"), "hello world"},
		{[]byte("test\nline"), "test%0Aline"},
		{[]byte("100%"), "100%25"},
		{[]byte{0x00, 0x01, 0x02}, "%00%01%02"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := percentEncode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPercentDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"hello", []byte("hello")},
		{"hello world", []byte("hello world")},
		{"test%0Aline", []byte("test\nline")},
		{"100%25", []byte("100%")},
		{"%00%01%02", []byte{0x00, 0x01, 0x02}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := percentDecode(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
