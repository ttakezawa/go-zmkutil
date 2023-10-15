package zmkutil

import (
	"bytes"
	"testing"
)

func TestNewEDE2Cipher(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "new with key",
			args: args{
				key: []byte{
					0x3b, 0x38, 0x98, 0x37, 0x15, 0x20, 0xf7, 0x5e,
					0x92, 0x2f, 0xb5, 0x10, 0xc7, 0x1f, 0x43, 0x6e,
				},
			},
			wantErr: false,
		},
		{
			name: "new with invalid key",
			args: args{
				key: []byte{
					0x3b, 0x38, 0x98, 0x37, 0x15, 0x20, 0xf7, 0x5e,
				},
			},
			wantErr: true,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEDE2Cipher(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("#%d: NewEDE2Cipher() error = %v, wantErr %v", i, err, tt.wantErr)
			}
		})
	}
}

func TestEncryptEDE2(t *testing.T) {
	type args struct {
		key []byte
		in  []byte
	}
	type want struct {
		out []byte
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "encrypt sample data",
			args: args{
				key: []byte{
					0x3b, 0x38, 0x98, 0x37, 0x15, 0x20, 0xf7, 0x5e,
					0x92, 0x2f, 0xb5, 0x10, 0xc7, 0x1f, 0x43, 0x6e,
				},
				in: []byte{
					0x12, 0x3a, 0xbc, 0x45, 0x6d, 0xef, 0x78, 0x90,
				},
			},
			want: want{
				out: []byte{
					0x00, 0xda, 0x53, 0x9a, 0x1d, 0x81, 0x40, 0xbc,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewEDE2Cipher(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEDE2Cipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			out := make([]byte, len(tt.args.in))
			c.Encrypt(out, tt.args.in)

			if !bytes.Equal(out, tt.want.out) {
				t.Errorf("result: %x want: %x", out, tt.want.out)
			}
		})
	}
}

func TestDecryptEDE2(t *testing.T) {
	type args struct {
		key []byte
		in  []byte
	}
	type want struct {
		out []byte
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "encrypt sample data",
			args: args{
				key: []byte{
					0x3b, 0x38, 0x98, 0x37, 0x15, 0x20, 0xf7, 0x5e,
					0x92, 0x2f, 0xb5, 0x10, 0xc7, 0x1f, 0x43, 0x6e,
				},
				in: []byte{
					0x00, 0xda, 0x53, 0x9a, 0x1d, 0x81, 0x40, 0xbc,
				},
			},
			want: want{
				out: []byte{
					0x12, 0x3a, 0xbc, 0x45, 0x6d, 0xef, 0x78, 0x90,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewEDE2Cipher(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEDE2Cipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			out := make([]byte, len(tt.args.in))
			c.Decrypt(out, tt.args.in)

			if !bytes.Equal(out, tt.want.out) {
				t.Errorf("result: %x want: %x", out, tt.want.out)
			}
		})
	}
}
