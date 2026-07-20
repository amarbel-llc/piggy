package markl

import (
	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
)

func (id Id) Verify(
	mes, sig domain_interfaces.MarklId,
) (err error) {
	var formatPub FormatPub

	{
		var ok bool

		if formatPub, ok = id.format.(FormatPub); !ok {
			err = errors.Wrap(ErrFormatOperationNotSupported{
				Format:        id.format,
				OperationName: "Verify",
			})

			return err
		}
	}

	if formatPub.Verify == nil {
		err = errors.Wrap(ErrFormatOperationNotSupported{
			Format:        id.format,
			OperationName: "Verify",
		})

		return err
	}

	defer errors.DeferredRecover(&err)

	if err = formatPub.Verify(id, mes, sig); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}
