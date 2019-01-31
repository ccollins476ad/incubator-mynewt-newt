package serial

import (
	"strconv"

	"mynewt.apache.org/newt/newt/sysinit"
	"mynewt.apache.org/newt/util"
)

type SysinitFunc struct {
	Name    string `json:"name"`
	Stage   int    `json:"stage"`
	PkgName string `json:"package"`
}

type Sysinit struct {
	Funcs []SysinitFunc `json:"funcs"`
	// XXX: InvalidSettings
	// XXX: Conflicts
}

func newSysinit(scfg sysinit.SysinitCfg) (Sysinit, error) {
	funcs := make([]SysinitFunc, len(scfg.StageFuncs))
	for i, f := range scfg.StageFuncs {
		stage, err := strconv.Atoi(f.Stage.Value)
		if err != nil {
			return Sysinit{}, util.ChildNewtError(err)
		}
		funcs[i] = SysinitFunc{
			Name:    f.Name,
			Stage:   stage,
			PkgName: f.Pkg.FullName(),
		}
	}

	return Sysinit{
		Funcs: funcs,
	}, nil
}
