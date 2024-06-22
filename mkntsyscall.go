// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Forked by leco (@_lec0_) to add support for:
// - indirect syscall (github.com/L-e-c-o)
// - manual module handle resolution (github.com/L-e-c-o)
// - manual function address resolution (github.com/L-e-c-o)
// - API hashing (fnv1a)

// mkntsyscall generates windows indirect system call bodies

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const fnvPrime uint32 = 0x01000193 // prime number

var (
	filename              = flag.String("output", "", "output file name (standard output if omitted)")
	fnvOffsetBasis uint32 = fnv0("Follow @_atsika & @_lec0_ on X !")
	packageName    string
	pkgtype        int
)

// Source files and functions.
type Source struct {
	Funcs           []*Fn
	DLLFuncNames    []*Fn
	Files           []string
	StdLibImports   []string
	ExternalImports []string
}

// Fn describes syscall function.
type Fn struct {
	Name        string
	Params      []*Param
	Rets        *Rets
	dllname     string
	dllfuncname string
	src         string
	// TODO: get rid of this field and just use parameter index instead
	curTmpVarIdx int // insure tmp variables have uniq names
}

// Param is function parameter
type Param struct {
	Name      string
	Type      string
	fn        *Fn
	tmpVarIdx int
}

// Rets describes function return parameters.
type Rets struct {
	Name          string
	Type          string
	ReturnsError  bool
	FailCond      string
	fnMaybeAbsent bool
}

// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
func fnv0(s string) uint32 {
	var h uint32 = 0

	for _, c := range []byte(s) {
		h *= fnvPrime
		h ^= uint32(c)
	}

	return h
}

// fnv1a algo
func hash(s string) uint32 {
	h := fnvOffsetBasis
	s = strings.ToUpper(s)

	for _, c := range []byte(s) {
		h ^= uint32(c)
		h *= fnvPrime
	}
	return h
}

func trim(s string) string {
	return strings.Trim(s, " \t")
}

// DLLFuncName returns DLL function name for function f.
func (f *Fn) DLLFuncName() string {
	if f.dllfuncname == "" {
		return f.Name
	}
	return f.dllfuncname
}

func packagename() string {
	return packageName
}

func syscalldot() string {
	if packageName == "syscall" {
		return ""
	}
	return "syscall."
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: mkntsyscall [flags] [path ...]\n")
	flag.PrintDefaults()
	os.Exit(1)
}

// HelperName returns name of function f helper.
func (f *Fn) HelperName() string {
	if !f.HasStringParam() {
		return f.Name
	}
	return "_" + f.Name
}

// join concatenates parameters ps into a string with sep separator.
// Each parameter is converted into string by applying fn to it
// before conversion.
func join(ps []*Param, fn func(*Param) string, sep string) string {
	if len(ps) == 0 {
		return ""
	}
	a := make([]string, 0)
	for _, p := range ps {
		a = append(a, fn(p))
	}
	return strings.Join(a, sep)
}

// HelperType returns type of parameter p used in helper function.
func (p *Param) HelperType() string {
	if p.Type == "string" {
		return p.fn.StrconvType()
	}
	return p.Type
}

// IsUTF16 is true, if f is W (utf16) function. It is false
// for all A (ascii) functions.
func (f *Fn) IsUTF16() bool {
	s := f.DLLFuncName()
	return s[len(s)-1] == 'W'
}

// StrconvType returns Go type name used for OS string for f.
func (f *Fn) StrconvType() string {
	if f.IsUTF16() {
		return "*uint16"
	}
	return "*byte"
}

// ErrorVarName returns error variable name for r.
func (r *Rets) ErrorVarName() string {
	if r.ReturnsError {
		return "err"
	}
	if r.Type == "error" {
		return r.Name
	}
	return ""
}

// tmpVar returns temp variable name that will be used to represent p during syscall.
func (p *Param) tmpVar() string {
	if p.tmpVarIdx < 0 {
		p.tmpVarIdx = p.fn.curTmpVarIdx
		p.fn.curTmpVarIdx++
	}
	return fmt.Sprintf("_p%d", p.tmpVarIdx)
}

// BoolTmpVarCode returns source code for bool temp variable.
func (p *Param) BoolTmpVarCode() string {
	const code = `var %[1]s uint32
	if %[2]s {
		%[1]s = 1
	}`
	return fmt.Sprintf(code, p.tmpVar(), p.Name)
}

// BoolPointerTmpVarCode returns source code for bool temp variable.
func (p *Param) BoolPointerTmpVarCode() string {
	const code = `var %[1]s uint32
	if *%[2]s {
		%[1]s = 1
	}`
	return fmt.Sprintf(code, p.tmpVar(), p.Name)
}

// SliceTmpVarCode returns source code for slice temp variable.
func (p *Param) SliceTmpVarCode() string {
	const code = `var %s *%s
	if len(%s) > 0 {
		%s = &%s[0]
	}`
	tmp := p.tmpVar()
	return fmt.Sprintf(code, tmp, p.Type[2:], p.Name, tmp, p.Name)
}

// StringTmpVarCode returns source code for string temp variable.
func (p *Param) StringTmpVarCode() string {
	errvar := p.fn.Rets.ErrorVarName()
	if errvar == "" {
		errvar = "_"
	}
	tmp := p.tmpVar()
	const code = `var %s %s
	%s, %s = %s(%s)`
	s := fmt.Sprintf(code, tmp, p.fn.StrconvType(), tmp, errvar, p.fn.StrconvFunc(), p.Name)
	if errvar == "-" {
		return s
	}
	const morecode = `
	if %s != nil {
		return
	}`
	return s + fmt.Sprintf(morecode, errvar)
}

// TmpVarCode returns source code for temp variable.
func (p *Param) TmpVarCode() string {
	switch {
	case p.Type == "bool":
		return p.BoolTmpVarCode()
	case p.Type == "*bool":
		return p.BoolPointerTmpVarCode()
	case strings.HasPrefix(p.Type, "[]"):
		return p.SliceTmpVarCode()
	default:
		return ""
	}
}

// TmpVarReadbackCode returns source code for reading back the temp variable into the original variable.
func (p *Param) TmpVarReadbackCode() string {
	switch {
	case p.Type == "*bool":
		return fmt.Sprintf("*%s = %s != 0", p.Name, p.tmpVar())
	default:
		return ""
	}
}

// TmpVarHelperCode returns source code for helper's temp variable.
func (p *Param) TmpVarHelperCode() string {
	if p.Type != "string" {
		return ""
	}
	return p.StringTmpVarCode()
}


// SyscallArgList returns source code fragments representing p parameter
// in syscall. Slices are translated into 2 syscall parameters: pointer to
// the first element and length.
func (p *Param) SyscallArgList() []string {
	t := p.HelperType()
	var s string
	switch {
	case t == "*bool":
		s = fmt.Sprintf("unsafe.Pointer(&%s)", p.tmpVar())
	case t[0] == '*':
		s = fmt.Sprintf("unsafe.Pointer(%s)", p.Name)
	case t == "bool":
		s = p.tmpVar()
	case strings.HasPrefix(t, "[]"):
		return []string{
			fmt.Sprintf("uintptr(unsafe.Pointer(%s))", p.tmpVar()),
			fmt.Sprintf("uintptr(len(%s))", p.Name),
		}
	default:
		s = p.Name
	}
	return []string{fmt.Sprintf("uintptr(%s)", s)}
}

// SyscallParamList returns source code for SyscallX parameters for function f.
func (f *Fn) SyscallParamList() string {
	a := make([]string, 0)
	for _, p := range f.Params {
		a = append(a, p.SyscallArgList()...)
	}
	return strings.Join(a, ", ")
}

// StrconvFunc returns name of Go string to OS string function for f.
func (f *Fn) StrconvFunc() string {
	if f.IsUTF16() {
		return syscalldot() + "UTF16PtrFromString"
	}
	return syscalldot() + "BytePtrFromString"
}

// ToParams converts r into slice of *Param.
func (r *Rets) ToParams() []*Param {
	ps := make([]*Param, 0)
	if len(r.Name) > 0 {
		ps = append(ps, &Param{Name: r.Name, Type: r.Type})
	}
	if r.ReturnsError {
		ps = append(ps, &Param{Name: "err", Type: "error"})
	}
	return ps
}

// List returns source code of syscall return parameters.
func (r *Rets) List() string {
	s := join(r.ToParams(), func(p *Param) string { return p.Name + " " + p.Type }, ", ")
	if len(s) > 0 {
		s = "(" + s + ")"
	} else if r.fnMaybeAbsent {
		s = "(err error)"
	}
	return s
}

// HelperParamList returns source code for helper function f parameters.
func (f *Fn) HelperParamList() string {
	return join(f.Params, func(p *Param) string { return p.Name + " " + p.HelperType() }, ", ")
}

// HasStringParam is true, if f has at least one string parameter.
// Otherwise it is false.
func (f *Fn) HasStringParam() bool {
	for _, p := range f.Params {
		if p.Type == "string" {
			return true
		}
	}
	return false
}

// extractSection extracts text out of string s starting after start
// and ending just before end. found return value will indicate success,
// and prefix, body and suffix will contain correspondent parts of string s.
func extractSection(s string, start, end rune) (prefix, body, suffix string, found bool) {
	s = trim(s)
	if strings.HasPrefix(s, string(start)) {
		// no prefix
		body = s[1:]
	} else {
		a := strings.SplitN(s, string(start), 2)
		if len(a) != 2 {
			return "", "", s, false
		}
		prefix = a[0]
		body = a[1]
	}
	a := strings.SplitN(body, string(end), 2)
	if len(a) != 2 {
		return "", "", "", false
	}
	return prefix, a[0], a[1], true
}

// DLLFuncNameHash returns DLL function name hash for function f.
func (f *Fn) DLLFuncNameHash() string {
	if f.dllfuncname == "" {
		return fmt.Sprintf("%#2x", hash(f.Name))
	}
	return fmt.Sprintf("%#2x", hash(f.dllfuncname))
}

// extractParams parses s to extract function parameters.
func extractParams(s string, f *Fn) ([]*Param, error) {
	s = trim(s)
	if s == "" {
		return nil, nil
	}
	a := strings.Split(s, ",")
	ps := make([]*Param, len(a))
	for i := range ps {
		s2 := trim(a[i])
		b := strings.Split(s2, " ")
		if len(b) != 2 {
			b = strings.Split(s2, "\t")
			if len(b) != 2 {
				return nil, errors.New("Could not extract function parameter from \"" + s2 + "\"")
			}
		}
		ps[i] = &Param{
			Name:      trim(b[0]),
			Type:      trim(b[1]),
			fn:        f,
			tmpVarIdx: -1,
		}
	}
	return ps, nil
}

// IsError determines if p parameter is used to return error.
func (p *Param) IsError() bool {
	return p.Name == "err" && p.Type == "error"
}

// newFn parses string s and return created function Fn.
func newFn(s string) (*Fn, error) {
	var err error
	s = trim(s)
	f := &Fn{
		Rets: &Rets{},
		src:  s,
	}
	// function name and args
	prefix, body, s, found := extractSection(s, '(', ')')
	if !found || prefix == "" {
		return nil, errors.New("Could not extract function name and parameters from \"" + f.src + "\"")
	}
	f.Name = prefix
	f.Params, err = extractParams(body, f)
	if err != nil {
		return nil, err
	}
	// return values
	_, body, s, found = extractSection(s, '(', ')')
	if found {
		r, err := extractParams(body, f)
		if err != nil {
			return nil, err
		}
		switch len(r) {
		case 0:
		case 1:
			if r[0].IsError() {
				f.Rets.ReturnsError = true
			} else {
				f.Rets.Name = r[0].Name
				f.Rets.Type = r[0].Type
			}
		case 2:
			if !r[1].IsError() {
				return nil, errors.New("Only last windows error is allowed as second return value in \"" + f.src + "\"")
			}
			f.Rets.ReturnsError = true
			f.Rets.Name = r[0].Name
			f.Rets.Type = r[0].Type
		default:
			return nil, errors.New("Too many return values in \"" + f.src + "\"")
		}
	}
	// fail condition
	_, body, s, found = extractSection(s, '[', ']')
	if found {
		f.Rets.FailCond = body
	}
	// dll and dll function names
	s = trim(s)
	if s == "" {
		return f, nil
	}
	if !strings.HasPrefix(s, "=") {
		return nil, errors.New("Could not extract dll name from \"" + f.src + "\"")
	}
	s = trim(s[1:])
	// Modif " = ntfuncname"
	f.dllfuncname = s
	if f.dllfuncname == "" {
		return nil, fmt.Errorf("function name is not specified in %q", s)
	}
	return f, nil
}

// ParseFile adds additional file path to a source set src.
func (src *Source) ParseFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	for s.Scan() {
		t := trim(s.Text())
		if len(t) < 7 {
			continue
		}
		if !strings.HasPrefix(t, "//sys") {
			continue
		}
		t = t[5:]
		if !(t[0] == ' ' || t[0] == '\t') {
			continue
		}
		f, err := newFn(t[1:])
		if err != nil {
			return err
		}
		src.Funcs = append(src.Funcs, f)
	}
	if err := s.Err(); err != nil {
		return err
	}
	src.Files = append(src.Files, path)

	// get package name
	fset := token.NewFileSet()
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}
	pkg, err := parser.ParseFile(fset, "", file, parser.PackageClauseOnly)
	if err != nil {
		return err
	}
	packageName = pkg.Name.Name

	return nil
}

// ParseFiles parses files listed in fs and extracts all syscall
// functions listed in sys comments. It returns source files
// and functions collection *Source if successful.
func ParseFiles(fs []string) (*Source, error) {
	src := &Source{
		Funcs: make([]*Fn, 0),
		Files: make([]string, 0),
		StdLibImports: []string{
			"unsafe",
		},
		ExternalImports: []string{
			"ntsyscall",
		},
	}
	for _, file := range fs {
		if err := src.ParseFile(file); err != nil {
			return nil, err
		}
	}
	src.DLLFuncNames = make([]*Fn, 0, len(src.Funcs))
	uniq := make(map[string]bool, len(src.Funcs))
	for _, fn := range src.Funcs {
		name := fn.DLLFuncName()
		if !uniq[name] {
			src.DLLFuncNames = append(src.DLLFuncNames, fn)
			uniq[name] = true
		}
	}
	return src, nil
}

// check if can be removed
// IsStdRepo reports whether src is part of standard library.
func (src *Source) IsStdRepo() (bool, error) {
	if len(src.Files) == 0 {
		return false, errors.New("no input files provided")
	}
	abspath, err := filepath.Abs(src.Files[0])
	if err != nil {
		return false, err
	}
	goroot := runtime.GOROOT()
	if runtime.GOOS == "windows" {
		abspath = strings.ToLower(abspath)
		goroot = strings.ToLower(goroot)
	}
	sep := string(os.PathSeparator)
	if !strings.HasSuffix(goroot, sep) {
		goroot += sep
	}
	return strings.HasPrefix(abspath, goroot), nil
}

// Generate output source file from a source set src.
func (src *Source) Generate(w io.Writer) error {
	const (
		pkgStd         = iota // any package in std library
		pkgXSysWindows        // x/sys/windows package
		pkgOther
	)

	isStdRepo, err := src.IsStdRepo()
	if err != nil {
		return err
	}

	switch {
	case isStdRepo:
		pkgtype = pkgStd
	case packageName == "windows":
		// TODO: this needs better logic than just using package name
		pkgtype = pkgXSysWindows
	default:
		pkgtype = pkgOther
	}

	funcMap := template.FuncMap{
		"packagename": packagename,
		"syscalldot":  syscalldot,
	}
	t := template.Must(template.New("main").Funcs(funcMap).Parse(srcTemplate))
	err = t.Execute(w, src)
	if err != nil {
		return errors.New("Failed to execute template: " + err.Error())
	}
	return nil
}

func writeTempSourceFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "mkntsyscall-generated-*.go")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name()) // best effort
		return "", err
	}
	return f.Name(), nil
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) <= 0 {
		fmt.Fprintf(os.Stderr, "no files to parse provided\n")
		usage()
	}

	src, err := ParseFiles(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	var buf bytes.Buffer
	if err := src.Generate(&buf); err != nil {
		log.Fatal(err)
	}

	data, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("failed to format source: %v", err)
		f, err := writeTempSourceFile(buf.Bytes())
		if err != nil {
			log.Fatalf("failed to write unformatted source to file: %v", err)
		}
		log.Fatalf("for diagnosis, wrote unformatted source to %v", f)
	}
	if *filename == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*filename, data, 0644)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// TODO: use println instead to print in the following template
const srcTemplate = `

{{define "main"}}// Code generated by 'go generate'; EDIT AT YOUR OWN RISK.

package {{packagename}}

import (
{{range .StdLibImports}}"{{.}}"
{{end}}

{{range .ExternalImports}}"{{.}}"
{{end}}
)


{{range .Funcs}}{{if .HasStringParam}}{{template "helperbody" .}}{{end}}{{template "funcbody" .}}{{end}}
{{end}}

{{/* help functions */}}

{{define "helperbody"}}
func {{.Name}}({{.ParamList}}) {{template "results" .}}{
{{template "helpertmpvars" .}}	return {{.HelperName}}({{.HelperCallParamList}})
}
{{end}}

{{define "funcbody"}}
func {{.HelperName}}({{.HelperParamList}}) {{template "results" .}}{
{{template "tmpvars" .}}	{{template "syscall" .}}
}
{{end}}

{{define "helpertmpvars"}}{{range .Params}}{{if .TmpVarHelperCode}}	{{.TmpVarHelperCode}}
{{end}}{{end}}{{end}}

{{define "tmpvars"}}{{range .Params}}{{if .TmpVarCode}}	{{.TmpVarCode}}
{{end}}{{end}}{{end}}

{{define "results"}}{{if .Rets.List}}{{.Rets.List}} {{end}}{{end}}

{{define "syscall"}}return ntsyscall.Syscalls[{{.DLLFuncNameHash}}].Call({{.SyscallParamList}}){{end}}

{{define "tmpvarsreadback"}}{{range .Params}}{{if .TmpVarReadbackCode}}
{{.TmpVarReadbackCode}}{{end}}{{end}}{{end}}

`
