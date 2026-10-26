package detection

import "slices"

// rmWholeTree is rm -rf of a whole tree, on folded text. The target must end
// the command (end of text, whitespace, or ; & | or a closing parenthesis),
// optionally in single or double quotes, and be one of:
//
//   - the root: /, /* or /.
//   - a top-level system directory alone, or its contents: /etc, /var/, /usr/*
//     (see systemDirs)
//   - home: ~, ~/, ~/*, $HOME, ${HOME}, $HOME/ or $HOME/*
//   - the working directory or its parent: ., ./, ./*, .., ../, ../* or *
//
// A path below any of them is not a whole tree: rm -rf /var/lib/apt/lists/*,
// /tmp/*, /root/.cache, ~/.cache/go-build and ./build are ordinary cleanup.
// The impersonation cue for a role turn that runs rm is built from it, and
// the values safety principle counts it, so the two never disagree.
const rmWholeTree = `rm(?: -[a-z]{0,32}[rf][a-z]{0,32}| --no-preserve-root){1,16} ` + rmTarget

// systemDirs are the top-level directories whose removal breaks the machine
// or loses its data: the FHS directories other than /tmp, which Dockerfiles
// and build scripts clear as routine. /root is here and /root/.cache is not.
const systemDirs = `bin|boot|dev|etc|home|lib|lib32|lib64|libx32|media|mnt|opt|proc|root|run|sbin|srv|sys|usr|var`

// rmTarget is a whole-tree target (see rmWholeTree) and what ends it.
const rmTarget = `(?:"` + rmTree + `"|'` + rmTree + `'|` + rmTree + `)(?:$|[\s;&|)])`

// rmTree is the unquoted whole-tree target.
const rmTree = `(?:/[*.]?|/(?:` + systemDirs + `)/?\*?|(?:~|\$home|\$\{home\})(?:/\*?)?|\.\.?(?:/\*?)?|\*)`

// destructiveCommands are shell commands that destroy a tree, a disk or a
// machine, as regexp sources for folded text. Repetition is bounded and each
// starts with a literal, so values/principles can match them with a fast
// literal search.
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
// safety principle counts them; 4b tunes them here.
func DestructiveCommands() []string {
	return slices.Clone(destructiveCommands)
}
