package scimpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	scim "github.com/faustbrian/go-scim"
)

// DirectoryUserDeprovisionEvidence selects one exact configured source User and
// revision. Deleted=false requires a live User explicitly marked active=false;
// Deleted=true requires a retained tombstone. Revision is the live Resource's
// strong ETag, or the quoted retained delete command ID for a tombstone. Neither
// an unknown resource nor a missing active attribute proves deprovisioning.
// This detached selection grants no permission, mapping policy or local effect.
type DirectoryUserDeprovisionEvidence struct {
	ResourceID string
	Revision   scim.Version
	Deleted    bool
}

// Field binds the exact source User, revision and selected state to the original
// feature command before reservation. The original source observation's Field
// is separately required. Invalid IDs or native revisions return Forbidden.
// The returned detached bytes own no resources and convey no authority.
func (e DirectoryUserDeprovisionEvidence) Field() (identity.FeatureField, error) {
	if _, err := identity.ParseSubjectID(e.ResourceID); err != nil || !nativeVersion(e.Revision) {
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(e)
	if err != nil {
		return identity.FeatureField{}, identity.ForbiddenError{}
	}
	defer clear(wire)
	digest := sha256.Sum256(append([]byte("scim-postgres/directory-user-deprovision/v1\x00"), wire...))
	return identity.FeatureField{Name: "scim.directory-user-deprovision", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

// RequireDirectoryUserDeprovision authenticates the exact registered SSO User
// child's original command, owner and synchronous Apply invocation, then fences
// the original source and current User projection. The stored User-to-identity
// mapping must equal command.Binding.UserID. It borrows Work and the existing
// connection writer lock, creates no transaction or policy decision and changes
// no resource. Propagate failure and call the matching final fence at commit;
// neither method renews the original observation's bounded freshness.
func (s *GroupsService) RequireDirectoryUserDeprovision(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserDeprovisionEvidence) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := s.requireDirectorySource(ctx, w, owner, command, observation, directoryUserDeprovisionRegistration()); err != nil {
		return err
	}
	return s.requireDirectoryUserDeprovision(ctx, w, command, observation, evidence)
}

// RequireDirectoryUserDeprovisionAtCommit recomputes the same selected source
// condition in the authenticated owner's CheckFeatureCommit invocation. The
// owner must first compare command with its retained original command: Work's
// original-command custody check is Apply-only. Missing, changed or expired
// evidence denies and must roll back every provisional effect. This final check
// cannot substitute for the Apply fence or renew the original observation.
func (s *GroupsService) RequireDirectoryUserDeprovisionAtCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserDeprovisionEvidence) error {
	if err := s.requireDirectorySource(ctx, w, owner, command, observation, directoryUserDeprovisionRegistration()); err != nil {
		return err
	}
	return s.requireDirectoryUserDeprovision(ctx, w, command, observation, evidence)
}

func directoryUserDeprovisionRegistration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{
		Contributor: kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-user-deprovision", Version: 1},
		Operation:   identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-deprovision", SchemaID: "sso.directory-user-deprovision", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential},
	}
}

const directoryUserDeprovisionSQL = `SELECT user_id,resource,deleted_at IS NOT NULL,command_id FROM scim.users WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5 AND octet_length(resource)<=131072`

func (s *GroupsService) requireDirectoryUserDeprovision(ctx context.Context, w kernel.Work, command identity.Command, observation DirectorySourceObservation, evidence DirectoryUserDeprovisionEvidence) error {
	expected, err := evidence.Field()
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return identity.ForbiddenError{}
	}
	matches := 0
	for _, field := range spec.Fields {
		if field.Name != expected.Name {
			continue
		}
		if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, expected.Value.Bytes) {
			return identity.ForbiddenError{}
		}
		matches++
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer cancel()
	// The source fence holds scim.connections FOR UPDATE, the serialization
	// owner used by every supported User projection writer. A full-PK read
	// observes that protected mapping without creating another lock owner.
	rows, err := w.Query(ctx, directoryUserDeprovisionSQL, append(scopeArgs(s.native.config().Scope), evidence.ResourceID)...)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var userID, commandID string
	var wire []byte
	var deleted bool
	if !rows.Next() || rows.Scan(&userID, &wire, &deleted, &commandID) != nil || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	rows.Close()
	defer clear(wire)
	if userID != string(spec.Binding.UserID) || deleted != evidence.Deleted {
		return identity.ForbiddenError{}
	}
	if deleted {
		// applyProjectionMutation clears the payload and retains the original
		// delete command ID, not the previous live Resource.Version.
		if !bytes.Equal(wire, []byte("null")) || evidence.Revision != scim.Version(`"`+commandID+`"`) {
			return identity.ForbiddenError{}
		}
	} else {
		resource, err := directoryGroupEdgeResource(wire, evidence.ResourceID, "User")
		if err != nil || resource.Version != evidence.Revision {
			return identity.ForbiddenError{}
		}
		active, explicit := resource.Attributes["active"].(bool)
		if !explicit || active {
			return identity.ForbiddenError{}
		}
	}
	// A bounded read can itself cross the unchanged original deadline.
	source := observation.admission.connection
	now, err := w.DatabaseTime(ctx)
	if err != nil || !now.Before(source.AuthorityValidUntil) || !now.Before(source.ExpiresAt) || !liveConnection(ctx, source) {
		return identity.ForbiddenError{}
	}
	return nil
}
