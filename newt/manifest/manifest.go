package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"mynewt.apache.org/newt/newt/builder"
	"mynewt.apache.org/newt/newt/image"
	"mynewt.apache.org/newt/newt/pkg"
	"mynewt.apache.org/newt/newt/syscfg"
	"mynewt.apache.org/newt/util"
)

/*
 * Data that's going to go to build manifest file
 */
type ManifestSizeArea struct {
	Name string `json:"name"`
	Size uint32 `json:"size"`
}

type ManifestSizeSym struct {
	Name  string              `json:"name"`
	Areas []*ManifestSizeArea `json:"areas"`
}

type ManifestSizeFile struct {
	Name string             `json:"name"`
	Syms []*ManifestSizeSym `json:"sym"`
}

type ManifestSizePkg struct {
	Name  string              `json:"name"`
	Files []*ManifestSizeFile `json:"files"`
}

type ManifestSizeCollector struct {
	Pkgs []*ManifestSizePkg
}

type Manifest struct {
	Name       string          `json:"name"`
	Date       string          `json:"build_time"`
	Version    string          `json:"build_version"`
	BuildID    string          `json:"id"`
	Image      string          `json:"image"`
	ImageHash  string          `json:"image_hash"`
	Loader     string          `json:"loader"`
	LoaderHash string          `json:"loader_hash"`
	Pkgs       []*ManifestPkg  `json:"pkgs"`
	LoaderPkgs []*ManifestPkg  `json:"loader_pkgs,omitempty"`
	TgtVars    []string        `json:"target"`
	Repos      []*ManifestRepo `json:"repos"`

	PkgSizes       []*ManifestSizePkg `json:"pkgsz"`
	LoaderPkgSizes []*ManifestSizePkg `json:"loader_pkgsz,omitempty"`
}

type ManifestOpts struct {
	TgtBldr    *builder.TargetBuilder
	LoaderHash []byte
	AppHash    []byte
	Version    image.ImageVersion
	BuildID    string
}

type ManifestPkg struct {
	Name string `json:"name"`
	Repo string `json:"repo"`
}

type ManifestRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty,omitempty"`
	URL    string `json:"url,omitempty"`
}

type RepoManager struct {
	repos map[string]ManifestRepo
}

func NewRepoManager() *RepoManager {
	return &RepoManager{
		repos: make(map[string]ManifestRepo),
	}
}

func (r *RepoManager) AllRepos() []*ManifestRepo {
	keys := make([]string, 0, len(r.repos))
	for k := range r.repos {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	repos := make([]*ManifestRepo, 0, len(keys))
	for _, key := range keys {
		r := r.repos[key]
		repos = append(repos, &r)
	}

	return repos
}

func (c *ManifestSizeCollector) AddPkg(pkg string) *ManifestSizePkg {
	p := &ManifestSizePkg{
		Name: pkg,
	}
	c.Pkgs = append(c.Pkgs, p)

	return p
}

func (c *ManifestSizePkg) AddSymbol(file string, sym string, area string,
	symSz uint32) {

	f := c.addFile(file)
	s := f.addSym(sym)
	s.addArea(area, symSz)
}

func (p *ManifestSizePkg) addFile(file string) *ManifestSizeFile {
	for _, f := range p.Files {
		if f.Name == file {
			return f
		}
	}
	f := &ManifestSizeFile{
		Name: file,
	}
	p.Files = append(p.Files, f)

	return f
}

func (f *ManifestSizeFile) addSym(sym string) *ManifestSizeSym {
	s := &ManifestSizeSym{
		Name: sym,
	}
	f.Syms = append(f.Syms, s)

	return s
}

func (s *ManifestSizeSym) addArea(area string, areaSz uint32) {
	a := &ManifestSizeArea{
		Name: area,
		Size: areaSz,
	}
	s.Areas = append(s.Areas, a)
}

func (r *RepoManager) GetManifestPkg(lpkg *pkg.LocalPackage) *ManifestPkg {
	ip := &ManifestPkg{
		Name: lpkg.FullName(),
	}

	var path string
	if lpkg.Repo().IsLocal() {
		ip.Repo = lpkg.Repo().Name()
		path = lpkg.BasePath()
	} else {
		ip.Repo = lpkg.Repo().Name()
		path = lpkg.BasePath()
	}

	if _, present := r.repos[ip.Repo]; present {
		return ip
	}

	repo := ManifestRepo{
		Name: ip.Repo,
	}

	// Make sure we restore the current working dir to whatever it was when
	// this function was called
	cwd, err := os.Getwd()
	if err != nil {
		log.Debugf("Unable to determine current working directory: %v", err)
		return ip
	}
	defer os.Chdir(cwd)

	if err := os.Chdir(path); err != nil {
		return ip
	}

	var res []byte

	res, err = util.ShellCommand([]string{
		"git",
		"rev-parse",
		"HEAD",
	}, nil)
	if err != nil {
		log.Debugf("Unable to determine commit hash for %s: %v", path, err)
		repo.Commit = "UNKNOWN"
	} else {
		repo.Commit = strings.TrimSpace(string(res))
		res, err = util.ShellCommand([]string{
			"git",
			"status",
			"--porcelain",
		}, nil)
		if err != nil {
			log.Debugf("Unable to determine dirty state for %s: %v", path, err)
		} else {
			if len(res) > 0 {
				repo.Dirty = true
			}
		}
		res, err = util.ShellCommand([]string{
			"git",
			"config",
			"--get",
			"remote.origin.url",
		}, nil)
		if err != nil {
			log.Debugf("Unable to determine URL for %s: %v", path, err)
		} else {
			repo.URL = strings.TrimSpace(string(res))
		}
	}
	r.repos[ip.Repo] = repo

	return ip
}

func ReadManifest(path string) (Manifest, error) {
	m := Manifest{}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return m, util.ChildNewtError(err)
	}

	if err := json.Unmarshal(content, &m); err != nil {
		return m, util.FmtNewtError(
			"Failure decoding manifest with path \"%s\": %s",
			path, err.Error())
	}

	return m, nil
}

func ManifestPkgSizes(b *builder.Builder) (ManifestSizeCollector, error) {
	msc := ManifestSizeCollector{}

	libs, err := builder.ParseMapFileSizes(b.AppMapPath())
	if err != nil {
		return msc, err
	}

	// Order libraries by name.
	pkgSizes := make(builder.PkgSizeArray, len(libs))
	i := 0
	for _, es := range libs {
		pkgSizes[i] = es
		i++
	}
	sort.Sort(pkgSizes)

	for _, es := range pkgSizes {
		p := msc.AddPkg(b.FindPkgNameByArName(es.Name))

		// Order symbols by name.
		symbols := make(builder.SymbolDataArray, len(es.Syms))
		i := 0
		for _, sym := range es.Syms {
			symbols[i] = sym
			i++
		}
		sort.Sort(symbols)
		for _, sym := range symbols {
			for area, areaSz := range sym.Sizes {
				if areaSz != 0 {
					p.AddSymbol(sym.ObjName, sym.Name, area, areaSz)
				}
			}
		}
	}

	return msc, nil
}

func CreateManifest(opts ManifestOpts) (Manifest, error) {
	t := opts.TgtBldr

	m := Manifest{
		Name:      t.GetTarget().FullName(),
		Date:      time.Now().Format(time.RFC3339),
		Version:   opts.Version.String(),
		BuildID:   opts.BuildID,
		Image:     t.AppBuilder.AppImgPath(),
		ImageHash: fmt.Sprintf("%x", opts.AppHash),
	}

	rm := NewRepoManager()
	for _, rpkg := range t.AppBuilder.SortedRpkgs() {
		m.Pkgs = append(m.Pkgs, rm.GetManifestPkg(rpkg.Lpkg))
	}

	m.Repos = rm.AllRepos()

	vars := t.GetTarget().TargetY.AllSettingsAsStrings()
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m.TgtVars = append(m.TgtVars, k+"="+vars[k])
	}
	syscfgKV := t.GetTarget().Package().SyscfgY.GetValStringMapString(
		"syscfg.vals", nil)
	if len(syscfgKV) > 0 {
		tgtSyscfg := fmt.Sprintf("target.syscfg=%s",
			syscfg.KeyValueToStr(syscfgKV))
		m.TgtVars = append(m.TgtVars, tgtSyscfg)
	}

	c, err := ManifestPkgSizes(t.AppBuilder)
	if err == nil {
		m.PkgSizes = c.Pkgs
	}

	if t.LoaderBuilder != nil {
		m.Loader = t.LoaderBuilder.AppImgPath()
		m.LoaderHash = fmt.Sprintf("%x", opts.LoaderHash)

		for _, rpkg := range t.LoaderBuilder.SortedRpkgs() {
			m.LoaderPkgs = append(m.LoaderPkgs, rm.GetManifestPkg(rpkg.Lpkg))
		}

		c, err = ManifestPkgSizes(t.LoaderBuilder)
		if err == nil {
			m.LoaderPkgSizes = c.Pkgs
		}
	}

	return m, nil
}

func (m *Manifest) Write(w io.Writer) (int, error) {
	buffer, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return 0, util.FmtNewtError("Cannot encode manifest: %s", err.Error())
	}

	cnt, err := w.Write(buffer)
	if err != nil {
		return 0, util.FmtNewtError("Cannot write manifest: %s", err.Error())
	}

	return cnt, nil
}
