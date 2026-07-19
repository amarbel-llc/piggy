package markl

//go:generate dagnabit export

import (
	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/pool"
)

var idPool interfaces.PoolPtr[Id, *Id] = pool.MakeWithResetable[Id]()

func GetId() (domain_interfaces.MarklIdMutable, interfaces.FuncRepool) {
	return idPool.GetWithRepool()
}
