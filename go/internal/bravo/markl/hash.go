package markl

import (
	"hash"
	"io"

	"github.com/amarbel-llc/piggy/go/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/interfaces"
)

type Hash struct {
	hash       hash.Hash
	formatHash *FormatHash
	written    int64
}

var _ domain_interfaces.Hash = &Hash{}

func (hash *Hash) Write(bites []byte) (written int, err error) {
	written, err = hash.hash.Write(bites)
	hash.written += int64(written)
	return written, err
}

func (hash *Hash) Sum(bites []byte) []byte {
	return hash.hash.Sum(bites)
}

func (hash *Hash) Reset() {
	hash.written = 0
	hash.hash.Reset()
}

func (hash *Hash) Size() int {
	return hash.hash.Size()
}

func (hash *Hash) BlockSize() int {
	return hash.hash.BlockSize()
}

func (hash *Hash) GetMarklFormat() domain_interfaces.MarklFormat {
	return hash.formatHash
}

func (hash *Hash) GetMarklId() (domain_interfaces.MarklIdMutable, interfaces.FuncRepool) {
	id, repool := idPool.GetWithRepool()
	buf := id.resetDataForFormat(hash.GetMarklFormat())
	id.data = hash.hash.Sum(buf[:0])

	return id, repool
}

func (hash *Hash) GetBlobIdForReader(
	reader io.Reader,
) (domain_interfaces.MarklId, interfaces.FuncRepool) {
	id, repool := idPool.GetWithRepool()
	buf := id.resetDataForFormat(hash.GetMarklFormat())

	if _, err := io.ReadFull(reader, buf); err != nil && err != io.EOF {
		panic(errors.Wrap(err))
	}

	return id, repool
}

func (hash *Hash) GetBlobIdForReaderAt(
	reader io.ReaderAt,
	off int64,
) (domain_interfaces.MarklId, interfaces.FuncRepool) {
	id, repool := idPool.GetWithRepool()
	buf := id.resetDataForFormat(hash.GetMarklFormat())

	if _, err := reader.ReadAt(buf, off); err != nil {
		panic(errors.Wrap(err))
	}

	return id, repool
}
