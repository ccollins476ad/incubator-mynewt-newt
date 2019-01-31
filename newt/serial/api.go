package serial

import "mynewt.apache.org/newt/newt/resolve"

func newApiMap(res *resolve.Resolution) map[string]string {
	m := make(map[string]string, len(res.ApiMap))
	for api, rpkg := range res.ApiMap {
		m[api] = rpkg.Lpkg.FullName()
	}

	return m
}

func newUnsatisfiedApis(res *resolve.Resolution) map[string][]string {
	m := make(map[string][]string, len(res.UnsatisfiedApis))
	for api, rpkgs := range res.UnsatisfiedApis {
		slice := make([]string, len(rpkgs))
		for i, rpkg := range rpkgs {
			slice[i] = rpkg.Lpkg.FullName()
		}
		m[api] = slice
	}

	return m
}

func newApiConflicts(res *resolve.Resolution) map[string][]string {
	m := make(map[string][]string, len(res.ApiConflicts))
	for _, c := range res.ApiConflicts {
		slice := make([]string, len(c.Pkgs))
		for i, rpkg := range c.Pkgs {
			slice[i] = rpkg.Lpkg.FullName()
		}
		m[c.Api] = slice
	}

	return m
}
