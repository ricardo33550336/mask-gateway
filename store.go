package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Store persists rules to a JSON file (no database needed).
type Store struct {
	mu     sync.RWMutex
	path   string
	rules  []Rule
	nextID int
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, nextID: 1}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		s.rules = []Rule{}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}

	if err := json.Unmarshal(data, &s.rules); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.rules == nil {
		s.rules = []Rule{}
	}
	for i := range s.rules {
		s.rules[i].normalize()
	}
	for _, r := range s.rules {
		if r.ID >= s.nextID {
			s.nextID = r.ID + 1
		}
	}
	return s, nil
}

// List returns a snapshot of all rules.
func (s *Store) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// EnabledRules returns a snapshot of enabled rules, used by the hot path.
func (s *Store) EnabledRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) Create(r Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.normalize()
	r.ID = s.nextID
	s.nextID++
	s.rules = append(s.rules, r)
	if err := s.saveLocked(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func (s *Store) Update(id int, r Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if s.rules[i].ID == id {
			r.normalize()
			r.ID = id
			s.rules[i] = r
			if err := s.saveLocked(); err != nil {
				return Rule{}, err
			}
			return r, nil
		}
	}
	return Rule{}, errors.New("rule not found")
}

func (s *Store) SetEnabled(id int, enabled bool) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if s.rules[i].ID == id {
			s.rules[i].Enabled = enabled
			if err := s.saveLocked(); err != nil {
				return Rule{}, err
			}
			return s.rules[i], nil
		}
	}
	return Rule{}, errors.New("rule not found")
}

func (s *Store) Delete(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if s.rules[i].ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("rule not found")
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// normalize makes empty slices non-nil so they serialize as [] (never null),
// which keeps the admin UI free of undefined/null checks.
func (r *Rule) normalize() {
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	if r.Fields == nil {
		r.Fields = []string{}
	}
}
