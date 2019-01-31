package serial

import (
	"sort"

	"mynewt.apache.org/newt/newt/builder"
	"mynewt.apache.org/newt/newt/parse"
)

type DepGraphEntry struct {
	PkgName     string              `json:"name"`
	DepExprs    []string            `json:"dep_exprs,omitempty"`
	ApiExprs    map[string][]string `json:"api_exprs,omitempty"`
	ReqApiExprs map[string][]string `json:"req_api_exprs,omitempty"`
}

type DepGraph map[string][]DepGraphEntry

func exprSetStrings(es parse.ExprSet) []string {
	ss := make([]string, 0, len(es))
	for s, _ := range es {
		ss = append(ss, s)
	}
	sort.Strings(ss)

	return ss
}

func exprMapStrings(em parse.ExprMap) map[string][]string {
	m := make(map[string][]string, len(em))
	for k, es := range em {
		m[k] = exprSetStrings(es)
	}

	return m
}

func newDepGraph(bdg builder.DepGraph) DepGraph {
	dg := make(DepGraph, len(bdg))

	for parent, children := range bdg {
		for _, child := range children {
			dg[parent] = append(dg[parent], DepGraphEntry{
				PkgName:     child.PkgName,
				DepExprs:    exprSetStrings(child.DepExprs),
				ApiExprs:    exprMapStrings(child.ApiExprs),
				ReqApiExprs: exprMapStrings(child.ReqApiExprs),
			})
		}
	}

	return dg
}
