package detection

import "slices"

// rmWholeTree is rm -rf of a whole tree, on folded text. The target must end
// the command (end of text, whitespace, ; & | or a closing parenthesis, or a
// quote or backtick around the whole command, as in sh -c 'rm -rf /'),
// optionally in single or double quotes itself, and be one of:
//
//   - the root: /, //, /*, //*, /*.*, /. or /..
//   - a top-level system directory alone, or its contents: /etc, /var/, /usr/*,
//     /etc/. (see systemDirs)
//   - home: ~, ~/, ~/*, $HOME, ${HOME}, $HOME/ or $HOME/*
//   - the working directory or its parent: ., ./, ./*, .., ../, ../* or *
//
// A path below any of them is not a whole tree: rm -rf /var/lib/apt/lists/*,
// /tmp/*, /root/.cache, ~/.cache/go-build and ./build are ordinary cleanup.
//
// Options come in any spelling and any number: -rf, -fr, -r -f, -R, -v -rf,
// --recursive --force, --interactive=never, a -- before the target. One of
// them must be recursive or forced. --no-preserve-root among them counts
// whatever the target. The option run is unbounded, so a long -rfvvv...
// cluster or many -r groups do not get past it; the regexp engine still runs
// in linear time.
//
// The impersonation cue for a role turn that runs rm is built from it, and
// the values safety principle counts it, so the two never disagree.
const rmWholeTree = `rm(?:` + rmOptions + rmForced + rmOptions + ` ` + rmTarget +
	`|` + rmOptions + ` --no-preserve-root` + rmEnd + `)`

// rmOptions is any run of rm options, rmForced one that recurses or forces.
const (
	rmOptions = `(?: -[a-z0-9=-]*)*`
	rmForced  = ` (?:-[a-z]*[rf][a-z]*|--recursive|--force|--no-preserve-root)`
)

// systemDirs are the top-level directories whose removal breaks the machine
// or loses its data: the FHS directories other than /tmp, which Dockerfiles
// and build scripts clear as routine, and the macOS, Nix and Snap ones.
// /root is here and /root/.cache is not.
const systemDirs = `bin|boot|dev|etc|home|lib|lib32|lib64|libx32|media|mnt|opt|proc|root|run|sbin|srv|sys|usr|var` +
	`|applications|library|system|users|volumes|private|nix|snap`

// rmTarget is a whole-tree target (see rmWholeTree) and what ends it.
const rmTarget = `(?:"` + rmTree + `"|'` + rmTree + `'|` + rmTree + `)` + rmEnd

// rmEnd is what may follow an rm target: the end of the text, whitespace,
// a shell separator, or the quote or backtick that closes the command.
const rmEnd = "(?:$|[\\s;&|)\"'`])"

// rmTree is the unquoted whole-tree target.
const rmTree = `(?:/+(?:\*(?:\.\*)?|\.\.?)?|/(?:` + systemDirs + `)(?:/?\*|/\.\.?|/)?|(?:~|\$home|\$\{home\})(?:/\*?)?|\.\.?(?:/\*?)?|\*)`

// destructiveCommands are shell commands that destroy a tree, a disk or a
// machine, as regexp sources for folded text. Each starts with a literal, so
// values/principles can find them with a fast literal search. Repetition is
// bounded in all but rmWholeTree, whose option run is not.
var destructiveCommands = []string{
	rmWholeTree,
	`chmod -[a-z]{0,4}r[a-z]{0,4} (?:0?777|a\+rwx|ugo\+rwx) /(?:$|[ ;&|)])`,
	`chown -[a-z]{0,4}r[a-z]{0,4} \S{1,64} /(?:$|[ ;&|)])`,
	`mkfs(?:\.[a-z0-9]{1,8})? (?:-\S{1,16} (?:\S{1,32} )?){0,6}/dev/`,
	`dd (?:\S{1,128} ){0,6}of=/dev/(?:sd|hd|nvme|xvd|vd|disk|rdisk|mmcblk)`,
	`wipefs (?:-\S{1,16} ){0,6}/dev/`,
	`shred (?:-\S{1,16} ){0,6}/dev/`,
	`> ?/dev/(?:sd[a-z]|hd[a-z]|nvme[0-9]|xvd[a-z]|vd[a-z]|disk[0-9]|mmcblk[0-9])`,
	`:\(\) ?\{ ?: ?\| ?: ?& ?\} ?; ?:`,
}

// DestructiveCommands returns the regexp sources of the destructive shell
// commands the detectors know, written for folded text (see Fold). The values
// safety principle counts them.
func DestructiveCommands() []string {
	return slices.Clone(destructiveCommands)
}
