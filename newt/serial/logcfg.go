package serial

import (
	"strconv"

	"mynewt.apache.org/newt/newt/logcfg"
	"mynewt.apache.org/newt/util"
)

type Log struct {
	Package string `json:"package"`
	Module  int    `json:"module"`
	Level   int    `json:"level"`
}

type Logcfg struct {
	Logs map[string]Log `json:"logs"`
	// XXX: InvalidSettings
	// XXX: ModuleConflicts
}

func newLogcfg(lcfg logcfg.LCfg) (Logcfg, error) {
	lm := make(map[string]Log, len(lcfg.Logs))
	for _, llog := range lcfg.Logs {
		mod, err := strconv.Atoi(llog.Module.Value)
		if err != nil {
			return Logcfg{}, util.ChildNewtError(err)
		}

		level, err := strconv.Atoi(llog.Level.Value)
		if err != nil {
			return Logcfg{}, util.ChildNewtError(err)
		}

		lm[llog.Name] = Log{
			Package: llog.Source.FullName(),
			Module:  mod,
			Level:   level,
		}
	}

	return Logcfg{
		Logs: lm,
	}, nil
}
