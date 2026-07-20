package markl

//go:generate dagnabit export

import (
	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/pool"
)

var idPool interfaces.PoolPtr[Id, *Id] = pool.MakeWithResetable[Id]()

func GetId() (domain_interfaces.MarklIdMutable, interfaces.FuncRepool) {
	return idPool.GetWithRepool()
}
