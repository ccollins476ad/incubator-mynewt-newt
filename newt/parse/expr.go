package parse

type ExprSet map[string]*Node
type ExprMap map[string]ExprSet

func (es ExprSet) Exprs() []*Node {
	if len(es) == 0 {
		return nil
	}

	nodes := make([]*Node, 0, len(es))
	for _, expr := range es {
		nodes = append(nodes, expr)
	}
	SortNodes(nodes)
	return nodes
}

func (es ExprSet) Disjunction() *Node {
	return Disjunction(es.Exprs())
}

func (es ExprSet) Conjunction() *Node {
	return Conjunction(es.Exprs())
}

func (m ExprMap) Add(api string, exprs []*Node) {
	for _, e := range exprs {
		es := m[api]
		if es == nil {
			es = ExprSet{}
			m[api] = es
		}
		es[e.String()] = e
	}
}
