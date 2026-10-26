package detection

import "slices"

// rmWholeTree is rm -rf of a whole tree, on folded text: a root path, or a
// bare ~, ~/, $HOME, ${HOME}, ., .., * or ./* ending the command. A path under
// home or a relative one (rm -rf ./build) is not one. The impersonation cue
// for a role turn that runs rm is built from it, and the values safety
// principle counts it, so the two never disagree.
const rmWholeTree = `rm(?: -[a-z]{0,32}[rf][a-z]{0,32}| --no-preserve-root){1,16} (?:/|(?:~|\$home|\$\{home\}|\.\.?|\.?/?\*)/?(?:$|[ ;&|]))`

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
