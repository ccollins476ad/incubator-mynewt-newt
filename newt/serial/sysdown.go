package serial

import (
	"strconv"

	"mynewt.apache.org/newt/newt/sysdown"
	"mynewt.apache.org/newt/util"
)

type SysdownFunc struct {
	Name    string `json:"name"`
	Stage   int    `json:"stage"`
	PkgName string `json:"package"`
}

type Sysdown struct {
	Funcs []SysdownFunc `json:"funcs"`
	// XXX: InvalidSettings
	// XXX: Conflicts
}

func newSysdown(scfg sysdown.SysdownCfg) (Sysdown, error) {
	funcs := make([]SysdownFunc, len(scfg.StageFuncs))
	for i, f := range scfg.StageFuncs {
		stage, err := strconv.Atoi(f.Stage.Value)
		if err != nil {
			return Sysdown{}, util.ChildNewtError(err)
		}
		funcs[i] = SysdownFunc{
			Name:    f.Name,
			Stage:   stage,
			PkgName: f.Pkg.FullName(),
		}
	}

	return Sysdown{
		Funcs: funcs,
	}, nil
}
