package markl

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/files"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/pool"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/ui"
)

func SetHexStringFromAbsolutePath(
	id domain_interfaces.MarklIdMutable,
	absOrRelPath string,
	base string,
) (err error) {
	if !filepath.IsAbs(absOrRelPath) {
		return SetHexStringFromRelPath(id, absOrRelPath)
	}

	if absOrRelPath, err = filepath.Rel(base, absOrRelPath); err != nil {
		err = errors.Wrap(err)
		return err
	}

	if err = SetHexStringFromRelPath(
		id,
		absOrRelPath,
	); err != nil {
		err = errors.Wrapf(
			err,
			"Base: %q",
			base,
		)

		return err
	}

	return err
}

func SetHexStringFromRelPath(
	id domain_interfaces.MarklIdMutable,
	relPath string,
) (err error) {
	if filepath.IsAbs(relPath) {
		err = errors.Err405MethodNotAllowed.Errorf(
			"absolute paths not supported",
		)
		return err
	}

	if err = SetHexBytes(
		id.GetMarklFormat().GetMarklFormatId(),
		id,
		[]byte(strings.ReplaceAll(relPath, string(filepath.Separator), "")),
	); err != nil {
		err = errors.Wrapf(
			err,
			"could not transform path into hex. Path: %q",
			relPath,
		)

		return err
	}

	return err
}

func ReadFrom(
	reader io.Reader,
	id *Id,
	formatHash FormatHash,
) (n int, err error) {
	buf := id.resetDataForFormat(formatHash)

	if n, err = io.ReadFull(reader, buf); err != nil {
		errors.WrapExceptSentinel(err, io.EOF)
		return n, err
	}

	return n, err
}

func CompareToReader(
	reader io.Reader,
	expected domain_interfaces.MarklId,
) int {
	actual, repool := idPool.GetWithRepool()
	defer repool()

	buf := actual.resetDataForFormat(expected.GetMarklFormat())

	if _, err := io.ReadFull(reader, buf); err != nil {
		panic(errors.Wrap(err))
	}

	return bytes.Compare(expected.GetBytes(), actual.GetBytes())
}

func CompareToReaderAt(
	readerAt io.ReaderAt,
	offset int64,
	expected domain_interfaces.MarklId,
) int {
	actual, repool := idPool.GetWithRepool()
	defer repool()

	buf := actual.resetDataForFormat(expected.GetMarklFormat())

	if _, err := readerAt.ReadAt(buf, offset); err != nil {
		panic(errors.Wrap(err))
	}

	return bytes.Compare(expected.GetBytes(), actual.GetBytes())
}

func SetHexBytes(
	formatId string,
	dst domain_interfaces.MarklIdMutable,
	bites []byte,
) (err error) {
	bites = bytes.TrimSpace(bites)

	if id, ok := dst.(*Id); ok {
		var format domain_interfaces.MarklFormat

		if format, err = GetFormatOrError(formatId); err != nil {
			err = errors.Wrapf(
				err,
				"failed to SetHexBytes with type %s and bites %s",
				formatId,
				bites,
			)
			return err
		}

		expectedSize := format.GetSize()
		decodedLen := hex.DecodedLen(len(bites))

		if decodedLen != expectedSize {
			err = errors.Errorf(
				"SetHexBytes: decoded length %d does not match format %q size %d (hex input: %q)",
				decodedLen,
				formatId,
				expectedSize,
				bites,
			)

			return err
		}

		buf := id.resetDataForFormat(format)

		if _, err = hex.Decode(buf, bites); err != nil {
			// Decode may have written partial bytes into buf — reset so
			// the Id returns to the null state rather than surfacing
			// corrupt content alongside an error.
			id.Reset()
			err = errors.Wrapf(err, "Data: %q", bites)
			return err
		}
	} else {
		var numberOfBytesDecoded int
		bytesDecoded := make([]byte, hex.DecodedLen(len(bites)))

		if numberOfBytesDecoded, err = hex.Decode(bytesDecoded, bites); err != nil {
			err = errors.Wrapf(err, "N: %d, Data: %q", numberOfBytesDecoded, bites)
			return err
		}

		if err = dst.SetMarklId(formatId, bytesDecoded[:numberOfBytesDecoded]); err != nil {
			err = errors.Wrap(err)
			return err
		}
	}

	return err
}

func SetDigester(
	dst domain_interfaces.MarklIdMutable,
	src domain_interfaces.MarklIdGetter,
) {
	digest := src.GetMarklId()
	errors.PanicIfError(
		dst.SetMarklId(
			digest.GetMarklFormat().GetMarklFormatId(),
			digest.GetBytes(),
		),
	)
}

func EqualsReader(
	expectedBlobId domain_interfaces.MarklId,
	bufferedReader *bufio.Reader,
) (ok bool, err error) {
	var actualBytes []byte
	bytesRead := expectedBlobId.GetSize()

	if actualBytes, err = bufferedReader.Peek(bytesRead); err != nil {
		err = errors.WrapExceptSentinel(err, io.EOF)
		return ok, err
	}

	ok = bytes.Equal(expectedBlobId.GetBytes(), actualBytes)

	if _, err = bufferedReader.Discard(bytesRead); err != nil {
		err = errors.WrapExceptSentinel(err, io.EOF)
		return ok, err
	}

	return ok, err
}

func IsNull(id domain_interfaces.MarklId) (ok bool) {
	if id == nil {
		return true
	}

	defer func() {
		if r := recover(); r == nil {
			return
		}

		ui.Debug().Printf("checking null for id resulted in panic: %q", id)
		ok = true
	}()

	ok = id.IsNull()

	return ok
}

func Equals(a, b domain_interfaces.MarklId) (ok bool) {
	aIsNull := IsNull(a)
	bIsNull := IsNull(b)

	switch {
	case aIsNull && bIsNull:
		return true

	case aIsNull || bIsNull:
		return false
	}

	var aFormatId, bFormatId string

	if a.GetMarklFormat() != nil {
		aFormatId = a.GetMarklFormat().GetMarklFormatId()
	}

	if b.GetMarklFormat() != nil {
		bFormatId = b.GetMarklFormat().GetMarklFormatId()
	}

	ok = aFormatId == bFormatId && bytes.Equal(a.GetBytes(), b.GetBytes())
	return ok
}

func Clone(src domain_interfaces.MarklId) (domain_interfaces.MarklId, interfaces.FuncRepool) {
	if !src.IsNull() {
		errors.PanicIfError(MakeErrEmptyType(src))
	}

	if src.GetMarklFormat() == nil {
		panic("empty markl type")
	}

	dst, repool := idPool.GetWithRepool()
	dst.ResetWithMarklId(src)

	return dst, repool
}

// Creates a human-readable string representation of a digest.
// TODO add type information
func FormatBytesAsHex(merkleId domain_interfaces.MarklId) string {
	return fmt.Sprintf("%x", merkleId.GetBytes())
}

func FormatOrEmptyOnNull(merkleId domain_interfaces.MarklId) string {
	if merkleId.IsNull() {
		return ""
	} else {
		return FormatBytesAsHex(merkleId)
	}
}

func SetFromPath(id domain_interfaces.MarklIdMutable, path string) (err error) {
	var file *os.File

	if file, err = files.Open(path); err != nil {
		err = errors.Wrap(err)
		return err
	}

	defer errors.DeferredCloser(&err, file)

	bufferedReader, repool := pool.GetBufferedReader(file)
	defer repool()

	var isEOF bool
	var key string

	for !isEOF {
		var line string
		line, err = bufferedReader.ReadString('\n')

		if err == io.EOF {
			isEOF = true
			err = nil
		} else if err != nil {
			err = errors.Wrap(err)
			return err
		}

		if len(line) > 0 {
			key = strings.TrimSpace(line)
		}
	}

	// if !strings.HasPrefix(maybeBech32String, "AGE-SECRET-KEY-1") {
	// 	value = maybeBech32String
	// }

	// var data []byte

	// if _, data, err = bech32.Decode(maybeBech32String); err != nil {
	// 	err = errors.Wrap(err)
	// 	return
	// }

	// if err = blobStoreConfig.Encryption.SetFormat(
	// 	markl.FormatIdMadderPrivateKeyV0,
	// ); err != nil {
	// 	err = errors.Wrap(err)
	// 	return
	// }

	// if err = blobStoreConfig.Encryption.SetMerkleId(
	// 	markl.TypeIdAgeX25519Sec,
	// 	data,
	// ); err != nil {
	// 	err = errors.Wrap(err)
	// 	return
	// }

	if err = id.Set(key); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}
