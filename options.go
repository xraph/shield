package shield

// Option configures the Shield library at the top level.
// These options are used when constructing Shield via New().
type Option func(*Options)

// Options holds resolved top-level Shield configuration.
type Options struct {
	Config     Config
	Profile    string   // default safety profile name
	Instincts  []string // inline instinct names
	Awareness  []string // inline awareness names
	Values     []string // inline value names
	Boundaries []string // inline boundary names
	Judgments  []string // inline judgment names
	Reflexes   []string // inline reflex names
}

// WithConfig sets the Shield configuration.
func WithConfig(cfg Config) Option {
	return func(o *Options) { o.Config = cfg }
}

// WithProfile sets the default safety profile to resolve from the store.
func WithProfile(name string) Option {
	return func(o *Options) { o.Profile = name }
}

// WithInstincts adds inline instinct names for safety evaluation.
func WithInstincts(names ...string) Option {
	return func(o *Options) { o.Instincts = append(o.Instincts, names...) }
}

// WithAwareness adds inline awareness detector names.
func WithAwareness(names ...string) Option {
	return func(o *Options) { o.Awareness = append(o.Awareness, names...) }
}

// WithValues adds inline value names for ethical evaluation.
func WithValues(names ...string) Option {
	return func(o *Options) { o.Values = append(o.Values, names...) }
}

// WithBoundaries adds inline boundary names for hard limits.
func WithBoundaries(names ...string) Option {
	return func(o *Options) { o.Boundaries = append(o.Boundaries, names...) }
}

// WithJudgments adds inline judgment names for risk assessment.
func WithJudgments(names ...string) Option {
	return func(o *Options) { o.Judgments = append(o.Judgments, names...) }
}

// WithReflexes adds inline reflex names for condition→action rules.
func WithReflexes(names ...string) Option {
	return func(o *Options) { o.Reflexes = append(o.Reflexes, names...) }
}
