// Package i18n provides JSON-backed translations. Each locale is a flat
// key->text map loaded once from an embedded filesystem (locales/<lang>.json).
package i18n

import (
	"encoding/json"
	"io/fs"
	"sort"
	"strings"
)

// Bundle holds the loaded locales and the fallback language.
type Bundle struct {
	messages map[string]map[string]string
	def      string
}

// Load reads every <lang>.json file from fsys. defaultLang is the fallback used
// when a key or language is missing.
func Load(fsys fs.FS, defaultLang string) (*Bundle, error) {
	b := &Bundle{messages: map[string]map[string]string{}, def: defaultLang}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		b.messages[strings.TrimSuffix(name, ".json")] = m
	}
	return b, nil
}

// Has reports whether lang was loaded.
func (b *Bundle) Has(lang string) bool {
	_, ok := b.messages[lang]
	return ok
}

// Resolve returns lang if loaded, otherwise the fallback language.
func (b *Bundle) Resolve(lang string) string {
	if b.Has(lang) {
		return lang
	}
	return b.def
}

// T translates key into lang, falling back to the default language and finally
// to the key itself.
func (b *Bundle) T(lang, key string) string {
	if m, ok := b.messages[lang]; ok {
		if v, ok := m[key]; ok && v != "" {
			return v
		}
	}
	if m, ok := b.messages[b.def]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// Languages returns the loaded language codes in sorted order.
func (b *Bundle) Languages() []string {
	out := make([]string, 0, len(b.messages))
	for k := range b.messages {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
