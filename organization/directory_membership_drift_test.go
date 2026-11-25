package scimorganization_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	scimorganization "github.com/faustbrian/go-scim/organization"
)

func TestClassifyDirectoryMembershipDriftSeparatesSourceAndLocalGrants(t *testing.T) {
	sources := []struct {
		name  string
		state scimorganization.DirectorySourceMembership
		kinds [5]scimorganization.DirectoryMembershipDriftKind
	}{
		{"present", scimorganization.DirectorySourceMembershipPresent, [5]scimorganization.DirectoryMembershipDriftKind{
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftMissingSourceGrant,
			scimorganization.DirectoryMembershipDriftMissingSourceGrant,
			scimorganization.DirectoryMembershipDriftInSync,
			scimorganization.DirectoryMembershipDriftInSync,
		}},
		{"absent", scimorganization.DirectorySourceMembershipAbsent, [5]scimorganization.DirectoryMembershipDriftKind{
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftInSync,
			scimorganization.DirectoryMembershipDriftInSync,
			scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant,
			scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant,
		}},
		{"inactive user", scimorganization.DirectorySourceMembershipInactiveUser, [5]scimorganization.DirectoryMembershipDriftKind{
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
		}},
		{"unproven", scimorganization.DirectorySourceMembershipUnproven, [5]scimorganization.DirectoryMembershipDriftKind{
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
			scimorganization.DirectoryMembershipDriftConflict,
		}},
	}
	locals := []struct {
		name  string
		state scimorganization.DirectoryLocalMembership
	}{
		{"unobserved", scimorganization.DirectoryLocalMembership{}},
		{"no grants", scimorganization.DirectoryLocalMembership{Observed: true}},
		{"local only", scimorganization.DirectoryLocalMembership{Observed: true, Local: true}},
		{"source only", scimorganization.DirectoryLocalMembership{Observed: true, Attributed: true}},
		{"source and local", scimorganization.DirectoryLocalMembership{Observed: true, Attributed: true, Local: true}},
	}
	for _, source := range sources {
		for index, local := range locals {
			t.Run(source.name+"/"+local.name, func(t *testing.T) {
				got, err := scimorganization.ClassifyDirectoryMembershipDrift(source.state, local.state)
				if err != nil {
					t.Fatal(err)
				}
				if got.Kind != source.kinds[index] || got.LocalGrant != local.state.Local {
					t.Fatal("classification changed source attribution or conflated an independent local grant")
				}
				again, err := scimorganization.ClassifyDirectoryMembershipDrift(source.state, local.state)
				if err != nil || again != got {
					t.Fatal("classification changed for identical observations")
				}
			})
		}
	}
}

func TestClassifyDirectoryMembershipDriftRejectsMalformedObservations(t *testing.T) {
	tests := []struct {
		name   string
		source scimorganization.DirectorySourceMembership
		local  scimorganization.DirectoryLocalMembership
	}{
		{"zero source", 0, scimorganization.DirectoryLocalMembership{Observed: true}},
		{"unknown source", 255, scimorganization.DirectoryLocalMembership{Observed: true, Attributed: true, Local: true}},
		{"zero source and unobserved local", 0, scimorganization.DirectoryLocalMembership{}},
	}
	for _, source := range []scimorganization.DirectorySourceMembership{
		scimorganization.DirectorySourceMembershipPresent,
		scimorganization.DirectorySourceMembershipAbsent,
		scimorganization.DirectorySourceMembershipInactiveUser,
		scimorganization.DirectorySourceMembershipUnproven,
	} {
		for _, local := range []scimorganization.DirectoryLocalMembership{
			{Attributed: true}, {Local: true}, {Attributed: true, Local: true},
		} {
			tests = append(tests, struct {
				name   string
				source scimorganization.DirectorySourceMembership
				local  scimorganization.DirectoryLocalMembership
			}{fmt.Sprintf("unobserved flags/%d/%t/%t", source, local.Attributed, local.Local), source, local})
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scimorganization.ClassifyDirectoryMembershipDrift(tt.source, tt.local)
			if !errors.Is(err, scimorganization.ErrInvalidMappingInput) || got != (scimorganization.DirectoryMembershipDrift{}) {
				t.Fatal("invalid input produced a classification or a non-stable error")
			}
		})
	}
}

func TestDirectoryMembershipDriftRedactsImplicitOutput(t *testing.T) {
	local := scimorganization.DirectoryLocalMembership{Observed: true, Attributed: true, Local: true}
	drift, err := scimorganization.ClassifyDirectoryMembershipDrift(scimorganization.DirectorySourceMembershipAbsent, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		value any
		name  string
	}{
		{local, "scimorganization.DirectoryLocalMembership(redacted)"},
		{drift, "scimorganization.DirectoryMembershipDrift(redacted)"},
	} {
		formatted := fmt.Sprintf("%v %+v %#v %s", tt.value, tt.value, tt.value, tt.value)
		if formatted != strings.Repeat(tt.name+" ", 3)+tt.name || tt.value.(slog.LogValuer).LogValue().String() != tt.name {
			t.Fatal("implicit formatting or logging exposed membership observations")
		}
		if _, err := json.Marshal(tt.value); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON exposed membership observations")
		}
		if _, err := tt.value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, scimorganization.ErrSensitiveSerialization) {
			t.Fatal("implicit text exposed membership observations")
		}
	}
}
