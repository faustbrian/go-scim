package scim

import (
	"net/url"
	"reflect"
	"strings"
	"time"
)

// Limits are explicit effective admission limits, shared by discovery and
// runtime. Zero is invalid. Limits may be lowered within the documented maxima;
// a configuration unable to encode its own discovery fails construction.
// SnapshotResources and SnapshotBytes bound fallback materialization independently
// of returned page/output limits. SnapshotBytes counts Resource JSON bytes, not RSS.
type Limits struct {
	PageDefault, PageMax                                            int
	FilterBytes, FilterTokens, FilterDepth, FilterNodes, PathBytes  int
	ResourceDepth, ResourceAttributes, StringBytes, PatchOperations int
	BodyBytes, ResponseBytes, SnapshotResources, ErrorDetailBytes   int
	SnapshotBytes                                                   int
}

// DefaultLimits returns a fresh bounded Users-profile configuration. These are
// the selected reference limits, not package-owned mutable state.
func DefaultLimits() Limits {
	return Limits{PageDefault: 100, PageMax: 1000, FilterBytes: 8192, FilterTokens: 512, FilterDepth: 16, FilterNodes: 256, PathBytes: 1024, ResourceDepth: 16, ResourceAttributes: 1000, StringBytes: 65536, PatchOperations: 100, BodyBytes: 1048576, ResponseBytes: 2097152, SnapshotResources: 10000, SnapshotBytes: 8388608, ErrorDetailBytes: 512}
}
func (l Limits) valid() bool {
	for _, pair := range [][2]int{{l.PageDefault, l.PageMax}, {l.PageMax, 1000}, {l.FilterBytes, 8192}, {l.FilterTokens, 512}, {l.FilterDepth, 16}, {l.FilterNodes, 256}, {l.PathBytes, 1024}, {l.ResourceDepth, 16}, {l.ResourceAttributes, 1000}, {l.StringBytes, 65536}, {l.PatchOperations, 100}, {l.BodyBytes, 2097152}, {l.ResponseBytes, 4194304}, {l.SnapshotResources, 10000}} {
		if pair[0] < 1 || pair[0] > pair[1] {
			return false
		}
	}
	return l.ErrorDetailBytes >= 0 && l.ErrorDetailBytes <= 512 && l.SnapshotBytes > 0 && l.SnapshotBytes <= 16777216
}

// Config is immutable after construction and deeply copied where mutable.
// Dependencies and Now must be safe for concurrent calls and honor deadlines.
// BaseURL is the absolute HTTPS Users-service root, without query or fragment.
// RequestTimeout must be positive and at most one minute. It bounds all external
// work; no goroutines are launched to disguise noncompliant implementations.
// It never extends authority: protected calls and disclosure use the earliest
// token/original authority deadline, at most twenty seconds from read beginning.
// Now and the trusted authority producers must use a consistent clock basis.
// Extensions may add declared attributes, but cannot replace the core schema.
// They cannot declare server uniqueness or required read-only values, or place
// read-only/immutable child fields under a multi-valued attribute.
// Number fields use signed 64-bit integers or exact bounded decimals.
// Only ErrorDetailBytes may be zero; zero suppresses the safe detail string.
// DocumentationURI is optional. Groups, Bulk and password writes are fixed off.
type Config struct {
	Store            Store
	Authenticator    Authenticator
	Authorizer       Authorizer
	Mapper           Mapper
	Limits           Limits
	BaseURL          string
	DocumentationURI string
	Extensions       []Schema
	Now              func() time.Time
	RequestTimeout   time.Duration
}

// UsersService executes the selected profile. It retains no mutable resources,
// locks, goroutines or background work. Concurrent safety depends on its trusted
// dependencies; each request receives detached inputs and a bounded context.
type UsersService struct{ service *protocolService }

type protocolService struct {
	config                Config
	profile               resourceProfile
	groups                groupDependencies
	discoveryProfiles     []discoveryProfile
	rootSearchUnavailable bool
}

// NewUsersService validates the entire effective runtime/discovery snapshot.
// Zero configuration, missing dependencies and impossible discovery limits fail
// without making external calls. It does not validate persistence or authority.
func NewUsersService(c Config) (*UsersService, error) {
	if nilInterface(c.Store) || nilInterface(c.Mapper) {
		return nil, failure(400, "invalidValue")
	}
	s, err := newProtocolService(c, userProfile(), groupDependencies{})
	if err != nil {
		return nil, err
	}
	return &UsersService{service: s}, nil
}

func newProtocolService(c Config, profile resourceProfile, groups groupDependencies) (*protocolService, error) {
	if nilInterface(c.Authenticator) || nilInterface(c.Authorizer) || !c.Limits.valid() || c.RequestTimeout <= 0 || c.RequestTimeout > time.Minute {
		return nil, failure(400, "invalidValue")
	}
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.BaseURL) > c.Limits.StringBytes {
		return nil, failure(400, "invalidValue")
	}
	if c.DocumentationURI != "" && (!validURI(c.DocumentationURI) || len(c.DocumentationURI) > c.Limits.StringBytes) {
		return nil, failure(400, "invalidValue")
	}
	if !validateSchemas(c.Extensions, c.Limits) {
		return nil, failure(400, "invalidValue")
	}
	for _, extension := range c.Extensions {
		if strings.EqualFold(extension.ID, profile.schema.ID) {
			return nil, failure(400, "invalidValue")
		}
	}
	c.Extensions = cloneSchemas(c.Extensions)
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.Now == nil {
		c.Now = time.Now
	}
	s := &protocolService{config: c, profile: profile, groups: groups}
	for _, op := range []Operation{ServiceProviderConfig, SchemasList, ResourceTypesList} {
		d, _ := s.discovery(op, "")
		if _, e := s.encodeDiscovery(d); e != nil {
			return nil, failure(400, "invalidValue")
		}
	}
	return s, nil
}
func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Slice, reflect.Interface, reflect.Chan:
		return r.IsNil()
	}
	return false
}
