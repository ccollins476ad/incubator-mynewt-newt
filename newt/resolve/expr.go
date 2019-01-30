package resolve

import (
	"github.com/spf13/cast"
	"mynewt.apache.org/newt/newt/parse"
	"mynewt.apache.org/newt/newt/ycfg"
	"mynewt.apache.org/newt/util"
)

type ExprSet map[string]*parse.Node
type ExprMap map[string]ExprSet

func (m ExprMap) Add(api string, exprs []*parse.Node) {
	for _, e := range exprs {
		es := m[api]
		if es == nil {
			es = ExprSet{}
			m[api] = es
		}
		es[e.String()] = e
	}
}

func (em ExprSet) Exprs() []*parse.Node {
	nodes := make([]*parse.Node, 0, len(em))
	for _, expr := range em {
		nodes = append(nodes, expr)
	}
	parse.SortNodes(nodes)
	return nodes
}

func getExprMapStringSlice(
	yc ycfg.YCfg, key string, settings map[string]string) (
	map[*parse.Node][]string, error) {

	entries := yc.GetSlice(key, settings)
	if len(entries) == 0 {
		return nil, nil
	}

	m := make(map[*parse.Node][]string, len(entries))
	for _, e := range entries {
		slice, err := cast.ToStringSliceE(e.Value)
		if err != nil {
			return nil, util.FmtNewtError(
				"ycfg node \"%s\" contains unexpected type; "+
					"have=%T want=[]string", e.Value)
		}

		m[e.Expr] = append(m[e.Expr], slice...)
	}

	return m, nil
}

func revExprMapStringSlice(
	ems map[*parse.Node][]string) map[string][]*parse.Node {

	m := map[string][]*parse.Node{}

	for expr, vals := range ems {
		for _, val := range vals {
			m[val] = append(m[val], expr)
		}
	}

	return m
}

func readExprMap(yc ycfg.YCfg, key string, settings map[string]string) (
	ExprMap, error) {

	ems, err := getExprMapStringSlice(yc, key, settings)
	if err != nil {
		return nil, err
	}

	em := ExprMap{}

	rev := revExprMapStringSlice(ems)
	for v, exprs := range rev {
		sub := ExprSet{}
		em[v] = sub
		for _, expr := range exprs {
			sub[expr.String()] = expr
		}
	}

	return em, nil
}
